/*
 * memory.c: the memory image of a run on the running system, the work of AVML.
 *
 * It is taken after the keys, because an event can close their window within seconds and an
 * image of a large machine takes minutes. The memory is read once from /proc/kcore (image.c)
 * and written into memory/ of the folder of the run, as memory.lime, memory.raw or
 * memory.avml. The SHA-256 of an image is computed while it is written and goes into the
 * manifest.
 *
 * An image is started only where the destination has room for it and 64 MiB more. The size of
 * a compressed image is known only when it is written: it is for a destination with less room
 * than the machine has memory, so it is started whatever room there is. One that cannot be
 * written to its end is removed, so that the report still has room, and counts as failed. Kernel lockdown in the mode confidentiality refuses /proc/kcore, and with it every
 * image.
 *
 * Beside the image go the kernel banner (/proc/version), the release, os-release and
 * System.map, which Volatility 3 needs to find the symbol table of exactly this kernel. A
 * System.map is kept only when it lists _stext or linux_banner: some distributions keep a
 * placeholder without symbols in /boot. These files of the examined system are copied as bytes.
 */
#include "memory.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define MIB 1048576ull
#define SPARE (64 * MIB)        /* left free in the destination beside an image */

static const char CAPTURED[] = "captured", SKIPPED[] = "skipped", FAILED[] = "failed", INTERRUPTED[] = "interrupted";

enum run_tone memory_tone(const struct memory_image *m)
{
    return m->status == CAPTURED ? RUN_REACHED : m->status == SKIPPED ? RUN_OPEN : RUN_NOT;
}

/* An image on the screen is named by its file in memory/, which says its format. */
static void label_of(const struct memory_image *m, char label[16])
{
    snprintf(label, 16, "memory.%s", image_name(m->format));
}

static void settle(struct run *r, struct memory_image *m, const char *status, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void settle(struct run *r, struct memory_image *m, const char *status, const char *fmt, ...)
{
    va_list ap;
    char label[16];

    m->status = status;
    va_start(ap, fmt);
    vsnprintf(m->note, sizeof m->note, fmt, ap);
    va_end(ap);
    label_of(m, label);
    run_mark(r, label, memory_tone(m), status, "%s", m->note);
}

struct progress {
    struct run *r;
    uint64_t total, done;
    time_t start, last;
};

/* How far the read is, so that a long one is seen to go on. A run that was asked to end
   ends the read here, before the end of the memory. */
static int progress(void *arg, uint64_t done)
{
    struct progress *p = arg;
    char read[32], all[32];

    p->done = done;
    if (done >= p->total)
        return 0;
    if (run_interrupted)
        return 1;
    if (!run_due(p->r, &p->last))
        return 0;
    size_text(done, read);
    size_text(p->total, all);
    run_progress(p->r, "reading", "%s of %s, %u %%, %lld s", read, all, (unsigned)(done * 100 / p->total),
                 (long long)(time(NULL) - p->start));
    return 0;
}

/* Whether the first DONE bytes of the memory of a source are whole ranges of it. */
static int whole_ranges(const struct image_source *src, uint64_t done)
{
    uint64_t sum = 0;
    size_t i;

    for (i = 0; i < src->nranges && sum < done; i++)
        sum += src->ranges[i].end - src->ranges[i].start;
    return sum == done;
}

/* A file of memory/ with the bytes of BUF. */
static int keep_bytes(struct run *r, const char *name, const char *buf, size_t n)
{
    char rel[64];
    int fd, ok;

    snprintf(rel, sizeof rel, "memory/%s", name);
    if ((fd = run_create(r, rel, O_WRONLY, 0600)) < 0) {
        r->write_failed = 1;
        return -1;
    }
    ok = !write_all(fd, buf, n) && !run_flush(r, fd, "memory");
    if (close(fd) || !ok) {
        r->write_failed = 1;
        return -1;
    }
    return 0;
}

/* Whether a text of the form of System.map names the symbol: a line that ends with " NAME". */
static int names_symbol(const char *text, const char *name)
{
    size_t n = strlen(name);
    const char *p;

    for (p = text; (p = strstr(p, name)); p += n)
        if (p > text && p[-1] == ' ' && (p[n] == '\n' || !p[n]))
            return 1;
    return 0;
}

/* What the lab needs to find the symbol table of exactly this kernel. */
static void beside(struct run *r, struct memory_result *res)
{
    char path[PATH_MAX], placeholder[PATH_MAX] = "", *text;
    struct utsname un;
    size_t len, i;

    uname(&un);
    if ((text = read_text("/proc/version", 65536, &len))) {
        keep_bytes(r, "banner.txt", text, len);
        free(text);
    }
    snprintf(path, sizeof path, "%s\n", un.release);
    keep_bytes(r, "kernel-release.txt", path, strlen(path));
    if ((text = read_text("/etc/os-release", 1 << 20, &len)) || (text = read_text("/usr/lib/os-release", 1 << 20, &len))) {
        keep_bytes(r, "os-release", text, len);
        free(text);
    }
    for (i = 0; i < 3 && !res->system_map[0]; i++) {
        if ((i == 0 ? pathf(path, "/boot/System.map-%s", un.release) :
             i == 1 ? pathf(path, "/lib/modules/%s/System.map", un.release) :
                      pathf(path, "/usr/lib/modules/%s/System.map", un.release)) ||
            !(text = read_text(path, 256 << 20, &len)))
            continue;
        if (names_symbol(text, "_stext") || names_symbol(text, "linux_banner")) {
            if (!keep_bytes(r, "System.map", text, len))
                snprintf(res->system_map, sizeof res->system_map, "%s", path);
        } else {
            snprintf(placeholder, sizeof placeholder, "%s", path);
        }
        free(text);
    }
    run_field(r, "beside it", "the kernel banner, the release and os-release");
    if (res->system_map[0])
        run_field(r, "symbols", "System.map from %s", res->system_map);
    else if (placeholder[0])
        run_field(r, "symbols", "no System.map kept, %s is a placeholder without symbols", placeholder);
    else
        run_field(r, "symbols", "no System.map found on this system");
}

void memory_run(struct run *r, const enum image_format *formats, size_t n, struct memory_result *res)
{
    char path[PATH_MAX], err[IMAGE_ERR_LEN], size_of[32], label[16], *iomem = NULL;
    struct image_file files[IMAGE_FORMATS];
    struct memory_image *of[IMAGE_FORMATS];
    struct image_source src = { 0 };
    struct progress pr = { .r = r };
    struct statvfs vfs;
    uint64_t room = 0, unread = 0;
    size_t i, nfiles = 0;
    int core = -1, ended;

    memset(res, 0, sizeof *res);
    res->nimages = n < IMAGE_FORMATS ? n : IMAGE_FORMATS;
    for (i = 0; i < res->nimages; i++) {
        res->images[i].format = formats[i];
        res->images[i].status = FAILED;
    }
    run_title(r, "memory image");
    if (run_interrupted) {
        for (i = 0; i < res->nimages; i++)
            settle(r, &res->images[i], INTERRUPTED, "not begun: the run was asked to end before the image");
        return;
    }
    if (pathf(path, "%s/memory", r->out) || mkdir(path, 0700)) {
        r->write_failed = 1;
        for (i = 0; i < res->nimages; i++)
            settle(r, &res->images[i], FAILED, "the folder memory/ cannot be made: %s", strerror(errno));
        return;
    }

    /* the source: what the kernel names as RAM, as far as /proc/kcore offers it */
    err[0] = 0;
    if ((core = open("/proc/kcore", O_RDONLY | O_CLOEXEC)) < 0)
        snprintf(err, sizeof err, "/proc/kcore cannot be opened: %s%s", strerror(errno),
                 !strcmp(r->lockdown, "confidentiality") ? ". Kernel lockdown in the mode confidentiality refuses it" : "");
    else if (!(iomem = read_text("/proc/iomem", 4 << 20, NULL)))
        snprintf(err, sizeof err, "/proc/iomem cannot be read: %s", strerror(errno));
    else
        image_source(iomem, core, &src, err);
    free(iomem);
    if (err[0]) {
        for (i = 0; i < res->nimages; i++)
            settle(r, &res->images[i], FAILED, "%s", err);
        goto out;
    }
    size_text(src.bytes, size_of);
    run_field(r, "source", "/proc/kcore, %zu range%s of RAM, %s", src.nranges, src.nranges == 1 ? "" : "s", size_of);
    if (src.bytes < src.ram)
        run_field(r, "not offered", "%llu bytes of the RAM ranges of /proc/iomem are in no segment of /proc/kcore and in no image",
                  (unsigned long long)(src.ram - src.bytes));

    /* each image has its file, where the destination has room for it */
    if (!statvfs(r->out, &vfs))
        room = (uint64_t)vfs.f_bavail * vfs.f_frsize;
    for (i = 0; i < res->nimages; i++) {
        struct memory_image *m = &res->images[i];
        int exact;
        uint64_t size = image_size(m->format, &src, &exact);

        /* Beside other images a compressed one needs the room for the most it can take, so
           that it cannot take theirs. */
        if ((exact || res->nimages > 1) && (room < size || room - size < SPARE)) {
            settle(r, m, SKIPPED, "the destination has %llu MiB free for it and the image takes %llu MiB",
                   (unsigned long long)(room / MIB), (unsigned long long)(size / MIB));
            continue;
        }
        snprintf(m->file, sizeof m->file, "memory/memory.%s", image_name(m->format));
        if (pathf(path, "%s/%s", r->out, m->file) || image_open(&files[nfiles], path)) {
            m->file[0] = 0;
            settle(r, m, FAILED, "its file cannot be made: %s", strerror(errno));
            r->write_failed = 1;
            continue;
        }
        files[nfiles].format = m->format;
        of[nfiles++] = m;
        room = room > size ? room - size : 0;
    }
    if (!nfiles)
        goto out;

    pr.total = src.bytes;
    pr.start = pr.last = time(NULL);
    ended = image_write(core, &src, files, nfiles, progress, &pr, &unread, err);
    res->seconds = (unsigned)(time(NULL) - pr.start);
    for (i = 0; i < nfiles; i++) {
        struct memory_image *m = of[i];
        int why = files[i].failed;

        if (!why && (image_settle(&files[i]) || run_flush(r, files[i].fd, "memory")))
            why = errno ? errno : EIO;
        if (close(files[i].fd) && !why)
            why = errno;
        if (why) {
            /* the part is of no use and takes the room of the report */
            if (!pathf(path, "%s/%s", r->out, m->file))
                unlink(path);
            m->file[0] = 0;
            r->write_failed = 1;
            settle(r, m, FAILED, "the write failed: %s. The part that was written is removed", strerror(why));
            continue;
        }
        m->bytes = files[i].bytes;
        m->direct = files[i].direct;
        hex_encode(files[i].sha256, 32, m->sha256);
        if (run_add(r, m->file, files[i].sha256))
            r->write_failed = 1;
        label_of(m, label);
        if (ended == 1) {
            /* The file is kept: it is the memory up to the place where the read was ended,
               and is named as that and not as an image of the machine. A LiME image states
               the end of a range before the range, so one that was ended inside a range has
               a last range that is shorter than its header says. */
            int inside = m->format == IMAGE_LIME && !whole_ranges(&src, pr.done);

            m->status = INTERRUPTED;
            snprintf(m->note, sizeof m->note, "the read was ended by a signal: the file holds the first %llu of %llu "
                     "bytes of the memory%s", (unsigned long long)pr.done, (unsigned long long)pr.total,
                     inside ? ", and its last range ends before the end that its header states" : "");
            run_mark(r, label, RUN_NOT, INTERRUPTED, "%llu bytes, %u s", (unsigned long long)m->bytes, res->seconds);
            run_field(r, "holds", "the first %llu of %llu bytes of the memory%s", (unsigned long long)pr.done,
                      (unsigned long long)pr.total, inside ? ". Its last range ends before the end that its header states" : "");
        } else {
            m->status = CAPTURED;
            res->captured++;
            run_mark(r, label, RUN_REACHED, CAPTURED, "%llu bytes, %u s", (unsigned long long)m->bytes, res->seconds);
        }
        run_field(r, "sha256", "%s", m->sha256);
        run_field(r, "written", "%s", m->direct ? "direct (O_DIRECT), pages released from the page cache"
                                                : "through the page cache, pages released from it: the file system of the "
                                                  "destination takes no direct writes");
    }
    if (ended < 0 && res->captured)
        run_field(r, "warning", "%s", err);
    if (unread && res->captured) {
        run_field(r, "warning", "%llu bytes could not be read from /proc/kcore and are zeros in the image", (unsigned long long)unread);
        for (i = 0; i < nfiles; i++)
            if (of[i]->status == CAPTURED)
                snprintf(of[i]->note, sizeof of[i]->note, "%llu bytes could not be read and are zeros", (unsigned long long)unread);
    }
out:
    if (core >= 0)
        close(core);
    image_source_free(&src);
    beside(r, res);
}
