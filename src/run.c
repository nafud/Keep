/*
 * run.c: the folder that a run of Keep writes into the destination, and its report.
 *
 * Every line of a run goes to the screen and to triage.txt. Every file is created anew, by this
 * process with umask 077, and is named in manifest.sha256 with its SHA-256. A failed write or
 * flush is remembered, and the run then ends with status 1.
 */
#include "run.h"
#include "hash.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

void run_say(struct run *r, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
    va_start(ap, fmt);
    if (vfprintf(r->report, fmt, ap) < 0 || fputc('\n', r->report) == EOF)
        r->write_failed = 1;
    va_end(ap);
}

static int add(struct run *r, const char *rel, const char *hex)
{
    struct run_file *grown;
    char *copy;

    if (!(grown = realloc(r->files, (r->nfiles + 1) * sizeof *grown)))
        return -1;
    r->files = grown;
    if (!(copy = strdup(rel)))
        return -1;
    r->files[r->nfiles].name = copy;
    snprintf(r->files[r->nfiles].sha256, sizeof r->files[r->nfiles].sha256, "%s", hex);
    r->nfiles++;
    return 0;
}

int run_create(struct run *r, const char *rel, int flags, mode_t mode)
{
    char path[PATH_MAX];
    int fd;

    if (pathf(path, "%s/%s", r->out, rel)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if ((fd = open(path, flags | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode)) < 0)
        return -1;
    if (add(r, rel, "")) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    return fd;
}

int run_add(struct run *r, const char *rel, const uint8_t sha256[32])
{
    char hex[65];

    hex_encode(sha256, 32, hex);
    return add(r, rel, hex);
}

int run_flush(struct run *r, int fd, const char *dir)
{
    char path[PATH_MAX];

    if (fsync(fd) || pathf(path, "%s/%s", r->out, dir) || flush_path(path)) {
        r->write_failed = 1;
        return -1;
    }
    return 0;
}

void run_stem(struct run *r, char *stem, size_t size)
{
    char **grown;
    size_t i;

    for (i = 0; i < r->nstems; i++)
        if (!strcasecmp(r->stems[i], stem) && strlen(stem) + 1 < size) {
            strcat(stem, "_");
            i = (size_t)-1;
        }
    if ((grown = realloc(r->stems, (r->nstems + 1) * sizeof *grown))) {
        r->stems = grown;
        if ((r->stems[r->nstems] = strdup(stem)))
            r->nstems++;
    }
}

int run_keep_key(struct run *r, const char *stem, const uint8_t *key, size_t n, char name[17])
{
    char rel[PATH_MAX];
    uint8_t digest[32];
    int fd, ok;

    if (pathf(rel, "keys/%s.vk", stem) || (fd = run_create(r, rel, O_WRONLY, 0600)) < 0) {
        r->write_failed = 1;
        return -1;
    }
    ok = !write_all(fd, key, n) && !run_flush(r, fd, "keys");
    if (close(fd) || !ok) {
        r->write_failed = 1;
        return -1;
    }
    sha256(key, n, digest);
    hex_encode(digest, 8, name);
    return 0;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct run_file *)a)->name, ((const struct run_file *)b)->name);
}

void run_manifest(struct run *r)
{
    char path[PATH_MAX], hex[65];
    uint8_t buf[65536], digest[32];
    struct hash_ctx ctx;
    FILE *f;
    size_t i, count = r->nfiles;
    ssize_t got;
    int fd, mfd;

    qsort(r->files, count, sizeof r->files[0], by_name);
    if ((mfd = run_create(r, "manifest.sha256", O_WRONLY, 0600)) < 0 || !(f = fdopen(mfd, "w"))) {
        r->write_failed = 1;
        if (mfd >= 0)
            close(mfd);
        return;
    }
    for (i = 0; i < count; i++) {
        if (r->files[i].sha256[0]) {
            fprintf(f, "%s  %s\n", r->files[i].sha256, r->files[i].name);
            continue;
        }
        if (pathf(path, "%s/%s", r->out, r->files[i].name) || (fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
            r->write_failed = 1;
            continue;
        }
        hash_init(&ctx, hash_by_name("sha256"));
        while ((got = read(fd, buf, sizeof buf)) > 0)
            hash_update(&ctx, buf, (size_t)got);
        hash_final(&ctx, digest);
        close(fd);
        if (got < 0)
            r->write_failed = 1;
        hex_encode(digest, 32, hex);
        fprintf(f, "%s  %s\n", hex, r->files[i].name);
    }
    explicit_bzero(buf, sizeof buf);    /* the files of keys/ passed through it */
    if (fflush(f) || fsync(mfd))
        r->write_failed = 1;
    fclose(f);
}

/* A text as the inside of a JSON string: the two characters that end or escape it, control
   characters as spaces, and a byte that is no UTF-8 as the replacement character. */
static void json_text(FILE *f, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    while (*p) {
        size_t n = *p < 0x80 ? 1 : (*p & 0xe0) == 0xc0 && *p >= 0xc2 ? 2 : (*p & 0xf0) == 0xe0 ? 3
                 : (*p & 0xf8) == 0xf0 && *p <= 0xf4 ? 4 : 0, i;

        for (i = 1; i < n && (p[i] & 0xc0) == 0x80; i++)
            ;
        if (!n || i < n) {
            fputs("\xef\xbf\xbd", f);
            p++;
        } else if (n > 1) {
            fwrite(p, 1, n, f);
            p += n;
        } else {
            if (*p == '"' || *p == '\\')
                fputc('\\', f);
            fputc(*p < 0x20 ? ' ' : *p, f);
            p++;
        }
    }
}

void run_json(FILE *f, const char *s)
{
    if (!s || !*s) {
        fputs("null", f);
    } else {
        fputc('"', f);
        json_text(f, s);
        fputc('"', f);
    }
}

void run_free(struct run *r)
{
    size_t i;

    for (i = 0; i < r->nfiles; i++)
        free(r->files[i].name);
    free(r->files);
    for (i = 0; i < r->nstems; i++)
        free(r->stems[i]);
    free(r->stems);
    r->files = NULL;
    r->stems = NULL;
    r->nfiles = r->nstems = 0;
}

int run_lock_memory(char why[160])
{
    struct rlimit limit;
    unsigned long long caps = 0;
    char *status, *line;

    /* CAP_IPC_LOCK, bit 14 of the effective capabilities, takes the limit off (mlock_future_ok
       in mm/mmap.c). With the limit in force, what is allocated later could not be mapped. */
    if ((status = read_text("/proc/self/status", 65536, NULL))) {
        if ((line = strstr(status, "\nCapEff:")))
            caps = strtoull(line + 8, NULL, 16);
        free(status);
    }
    if (!(caps >> 14 & 1) && (getrlimit(RLIMIT_MEMLOCK, &limit) || limit.rlim_cur != RLIM_INFINITY)) {
        snprintf(why, 160, "the memory of this program is not locked, because this user may lock only a part of it, "
                 "so a key can reach the swap space");
        return -1;
    }
    if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
        snprintf(why, 160, "the memory of this program could not be locked (%s), so a key can reach the swap space",
                 strerror(errno));
        return -1;
    }
    return 0;
}

void run_utc(char out[32], int for_name)
{
    time_t now = time(NULL);
    struct tm tm;

    gmtime_r(&now, &tm);
    if (for_name)
        strftime(out, 32, "%Y%m%d_%H%M%S", &tm);
    else
        strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int run_die(const char *fmt, ...)
{
    va_list ap;

    fputs("keep: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return 1;
}
