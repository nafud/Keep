/*
 * sys.c: see sys.h. The fields of /proc/self/mountinfo are those of
 * Documentation/filesystems/proc.rst, 3.5: an id, the parent's id, major:minor, the root, the
 * mount point, the options of the mount, any number of optional fields, a single hyphen, the
 * type, the source and the options of the file system. A space inside a field is written \040.
 */
#include "sys.h"
#include "util.h"

#include <dirent.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define TEXT_MAX (8u << 20)     /* a mount table beyond this is not one */
#define MOUNTS_NAMED 8
#define MAX_STACK 16            /* devices that stand on each other */

/* The next field of a line, cut out of it. NULL at the end of the line. */
static char *next_field(char **line)
{
    char *start = *line, *end;

    while (*start == ' ' || *start == '\t')
        start++;
    if (!*start)
        return NULL;
    end = start + strcspn(start, " \t");
    *line = *end ? end + 1 : end;
    *end = 0;
    return start;
}

struct mountline {
    char *devno, *point, *options, *type, *source;
};

/* One line of mountinfo into its fields, the mount point and the source without their escapes. */
static int parse_mountline(char *line, struct mountline *m)
{
    char *f;

    memset(m, 0, sizeof *m);
    if (!next_field(&line) || !next_field(&line) || !(m->devno = next_field(&line)) || !next_field(&line) ||
        !(m->point = next_field(&line)) || !(m->options = next_field(&line)))
        return -1;
    while ((f = next_field(&line)) && strcmp(f, "-"))
        ;
    if (!f || !(m->type = next_field(&line)) || !(m->source = next_field(&line)))
        return -1;
    unescape_octal(m->point);
    unescape_octal(m->source);
    return 0;
}

static int has_option(const char *options, const char *name)
{
    size_t n = strlen(name);
    const char *p;

    for (p = options; *p; p += strcspn(p, ","), p += *p == ',')
        if (!strncmp(p, name, n) && (p[n] == ',' || !p[n]))
            return 1;
    return 0;
}

void sys_mount_free(struct sys_mount *m)
{
    free(m->source);
    free(m->type);
    free(m->point);
    memset(m, 0, sizeof *m);
}

int sys_mount_of(const char *mountinfo, const char *path, struct sys_mount *m)
{
    char *text = read_text(mountinfo, TEXT_MAX, NULL), *line, *save = NULL;
    size_t best = 0, pathlen = strlen(path);
    int found = 0;

    memset(m, 0, sizeof *m);
    if (!text)
        return -1;
    for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        struct mountline ml;
        size_t n;

        if (parse_mountline(line, &ml))
            continue;
        n = strlen(ml.point);
        while (n > 1 && ml.point[n - 1] == '/')
            n--;
        /* a prefix that ends where a component of the path ends */
        if (strncmp(path, ml.point, n) || (n > 1 && pathlen > n && path[n] != '/'))
            continue;
        if (found && n < best)
            continue;
        sys_mount_free(m);
        m->source = strdup(ml.source);
        m->type = strdup(ml.type);
        m->point = strdup(ml.point);
        m->readonly = has_option(ml.options, "ro");
        if (!m->source || !m->type || !m->point) {
            sys_mount_free(m);
            free(text);
            return -1;
        }
        best = n;
        found = 1;
    }
    free(text);
    return found ? 0 : -1;
}

/* The device number of the block device at PATH, or 0 where it is none. */
static int blockdev_of(const char *path, unsigned *major, unsigned *minor)
{
    struct stat st;

    if (stat(path, &st) || !S_ISBLK(st.st_mode))
        return 0;
    *major = major(st.st_rdev);
    *minor = minor(st.st_rdev);
    return 1;
}

static char *first_line(const char *path)
{
    char *text = read_text(path, 4096, NULL);

    if (text)
        text[strcspn(text, "\n")] = 0;
    return text;
}

struct stacked {
    unsigned major, minor;
    char name[256];
};

struct stack {                          /* a device and everything that stands on it */
    struct stacked *v;
    size_t n, cap;
};

static int by_text(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* The names in a directory, sorted as a shell lists them. The caller frees them. */
static char **sorted_names(const char *dir, size_t *count)
{
    char **names = NULL, **grown;
    struct dirent *e;
    size_t n = 0, cap = 0;
    DIR *d = opendir(dir);

    *count = 0;
    if (!d)
        return NULL;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
            continue;
        if (n == cap) {
            if (!(grown = realloc(names, (cap ? cap * 2 : 16) * sizeof *names)))
                break;
            names = grown;
            cap = cap ? cap * 2 : 16;
        }
        if (!(names[n] = strdup(e->d_name)))
            break;
        n++;
    }
    closedir(d);
    if (names)
        qsort(names, n, sizeof *names, by_text);
    *count = n;
    return names;
}

/* The device and what stands on it, itself first: a device-mapper, md or bcache device is
   listed in holders/ of what it stands on. The name is that of the mapping where there is one.
   A device that is reached on two ways is listed once. */
static void stack_over(const char *sysfs, unsigned major, unsigned minor, struct stack *st, int depth)
{
    char path[PATH_MAX], real[PATH_MAX], *name, **holders;
    struct stacked *grown, *self;
    size_t nholders, i;

    for (i = 0; i < st->n; i++)
        if (st->v[i].major == major && st->v[i].minor == minor)
            return;
    if (depth > MAX_STACK || pathf(path, "%s/dev/block/%u:%u", sysfs, major, minor) || !realpath(path, real))
        return;
    if (st->n == st->cap) {
        if (!(grown = realloc(st->v, (st->cap ? st->cap * 2 : 16) * sizeof *st->v)))
            return;
        st->v = grown;
        st->cap = st->cap ? st->cap * 2 : 16;
    }
    self = &st->v[st->n++];
    self->major = major;
    self->minor = minor;
    if (!pathf(path, "%s/dm/name", real) && (name = first_line(path))) {
        snprintf(self->name, sizeof self->name, "%s", name);
        free(name);
    } else {
        snprintf(self->name, sizeof self->name, "%s", strrchr(real, '/') + 1);
    }
    if (pathf(path, "%s/holders", real))
        return;
    holders = sorted_names(path, &nholders);
    for (i = 0; i < nholders; i++) {
        char devfile[PATH_MAX], *devno;
        unsigned hmajor, hminor;

        if (!pathf(devfile, "%s/holders/%s/dev", real, holders[i]) && (devno = first_line(devfile))) {
            if (sscanf(devno, "%u:%u", &hmajor, &hminor) == 2)
                stack_over(sysfs, hmajor, hminor, st, depth + 1);
            free(devno);
        }
        free(holders[i]);
    }
    free(holders);
}

char *sys_in_use(const char *sysfs, const char *mountinfo, const char *swaps, unsigned major, unsigned minor)
{
    struct stack st = { 0 };
    const struct stacked *list;
    struct str out = { 0 };
    size_t i, count = 0;
    char *mounts = read_text(mountinfo, TEXT_MAX, NULL), *swap = read_text(swaps, TEXT_MAX, NULL);

    stack_over(sysfs, major, minor, &st, 0);
    list = st.v;
    for (i = 0; i < st.n; i++) {
        char *copy, *line, *save = NULL;

        if (mounts && (copy = strdup(mounts))) {
            for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
                struct mountline ml;
                unsigned mmajor, mminor;
                char known[PATH_MAX];

                if (parse_mountline(line, &ml) || sscanf(ml.devno, "%u:%u", &mmajor, &mminor) != 2)
                    continue;
                /* btrfs gives its mounts a device number of no device: the source is the device */
                if (pathf(known, "%s/dev/block/%u:%u", sysfs, mmajor, mminor))
                    continue;
                if (access(known, F_OK) && (ml.source[0] != '/' || !blockdev_of(ml.source, &mmajor, &mminor)))
                    continue;
                if (mmajor != list[i].major || mminor != list[i].minor)
                    continue;
                if (++count <= MOUNTS_NAMED)
                    str_addf(&out, "%s%s at %s", out.len ? ", " : "", list[i].name, ml.point);
            }
            free(copy);
        }
        if (swap && (copy = strdup(swap))) {
            for (line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
                char *path = next_field(&line);
                unsigned smajor, sminor;

                if (!path)
                    continue;
                unescape_octal(path);
                if (blockdev_of(path, &smajor, &sminor) && smajor == list[i].major && sminor == list[i].minor)
                    str_addf(&out, "%s%s as swap", out.len ? ", " : "", list[i].name);
            }
            free(copy);
        }
    }
    if (count > MOUNTS_NAMED)
        str_addf(&out, " and %zu more mounts", count - MOUNTS_NAMED);
    free(mounts);
    free(swap);
    free(st.v);
    if (!out.s)
        return strdup("");
    return out.s;
}

char *sys_other_filesystems(const char *mounts)
{
    static const char *const types[] = { "ecryptfs", "zfs", "fuse.gocryptfs", "fuse.cryfs", "fuse.encfs" };
    const char *found[sizeof types / sizeof types[0]];
    char *text = read_text(mounts, TEXT_MAX, NULL), *line, *save = NULL;
    struct str out = { 0 };
    size_t n = 0, i, k;

    for (line = text ? strtok_r(text, "\n", &save) : NULL; line; line = strtok_r(NULL, "\n", &save)) {
        char *type;

        if (!next_field(&line) || !next_field(&line) || !(type = next_field(&line)))
            continue;
        for (i = 0; i < sizeof types / sizeof types[0]; i++) {
            if (strcmp(type, types[i]))
                continue;
            for (k = 0; k < n && found[k] != types[i]; k++)
                ;
            if (k == n)
                found[n++] = types[i];
        }
    }
    free(text);
    qsort(found, n, sizeof found[0], by_text);
    for (i = 0; i < n; i++)
        str_addf(&out, "%s%s", i ? " " : "", found[i]);
    return out.s ? out.s : strdup("");
}

void sys_lockdown(const char *path, char *out, size_t outlen)
{
    char *line = first_line(path), *open, *close;

    out[0] = 0;
    if (!line)
        return;
    if ((open = strchr(line, '[')) && (close = strchr(open, ']'))) {
        *close = 0;
        snprintf(out, outlen, "%s", open + 1);
    } else {
        snprintf(out, outlen, "%s", line);
    }
    free(line);
}

/* A variable in efivarfs is four bytes of attributes and then its value. SecureBoot has one
   byte, so the last byte of the file is the value. */
void sys_secure_boot(const char *dir, char *out, size_t outlen)
{
    char chosen[NAME_MAX + 1] = "", path[PATH_MAX], *data;
    struct dirent *e;
    size_t len;
    DIR *d = opendir(dir);

    out[0] = 0;
    if (!d)
        return;
    while ((e = readdir(d)))
        if (!strncmp(e->d_name, "SecureBoot-", 11) && (!chosen[0] || strcmp(e->d_name, chosen) < 0))
            snprintf(chosen, sizeof chosen, "%s", e->d_name);
    closedir(d);
    if (!chosen[0])
        return;
    if (pathf(path, "%s/%s", dir, chosen))
        return;
    if ((data = read_text(path, 64, &len)) && len)
        snprintf(out, outlen, "%u", (unsigned)(unsigned char)data[len - 1]);
    free(data);
}

void sys_os_name(const char *first, const char *second, char *out, size_t outlen)
{
    char *text = read_text(first, 65536, NULL), *line, *save = NULL;
    size_t n = 0;

    out[0] = 0;
    if (!text && !(text = read_text(second, 65536, NULL)))
        return;
    for (line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        const char *p;

        if (strncmp(line, "PRETTY_NAME=", 12))
            continue;
        for (p = line + 12; *p && n + 1 < outlen; p++)
            if (*p != '"')
                out[n++] = *p;
        break;
    }
    out[n] = 0;
    free(text);
}

int sys_device_path(const char *sysfs, unsigned major, unsigned minor, char *out, size_t outlen)
{
    char path[PATH_MAX], real[PATH_MAX], *name, *p;
    int r;

    if (pathf(path, "%s/dev/block/%u:%u", sysfs, major, minor) || !realpath(path, real))
        return -1;
    if (!pathf(path, "%s/dm/name", real) && (name = first_line(path))) {
        r = snprintf(out, outlen, "/dev/mapper/%s", name);
        free(name);
    } else {
        r = snprintf(out, outlen, "/dev/%s", strrchr(real, '/') + 1);
        for (p = out + 5; *p; p++)              /* the kernel writes cciss/c0d0 as cciss!c0d0 */
            if (*p == '!')
                *p = '/';
    }
    return r < 0 || (size_t)r >= outlen ? -1 : 0;
}
