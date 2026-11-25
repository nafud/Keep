/*
 * image.c: the memory of the machine as an image file.
 *
 * What is read. /proc/iomem names the ranges of physical addresses that are RAM, and
 * /proc/kcore offers the memory of the kernel as an ELF64 core whose PT_LOAD segments state the
 * physical address they begin at (kcore.c: p_paddr, from Linux 4.12 at the latest, Linux 4.9
 * states 0). An image holds the RAM ranges as far as a segment offers them, each byte once.
 * This is how AVML reads /proc/kcore (snapshot.rs of AVML 0.21.0), with one difference: RAM
 * that a driver added to the running system is named "System RAM (driver)" by the kernel
 * (add_memory_driver_managed in mm/memory_hotplug.c, from Linux 5.8), and it is taken here as
 * well. AVML and LiME take only the name "System RAM".
 *
 * The other sources of memory are of no use here. /dev/mem is refused under lockdown, and where
 * the kernel has STRICT_DEVMEM it hands out no page that is RAM (devmem_is_allowed in
 * arch/x86/mm/init.c). /dev/crash exists only where its module is loaded.
 *
 * What is written. The memory is read once, in blocks, and each block goes to every file that
 * was asked for, so that the files of one run hold the same bytes.
 *
 *   LiME   Each range behind a header of 32 bytes: the magic 0x4C694D45, the version 1, the
 *          first and the last address of the range, and 8 bytes of zeros, all little-endian
 *          (lime.h of LiME). A range is written whole, also where it is all zeros.
 *   raw    Each byte at the file offset that is its physical address. What lies between the
 *          ranges is not written and reads as zeros.
 *   avml   The compressed format of AVML, version 2, as AVML 0.21.0 writes it (image.rs and
 *          io/snappy.rs): a range is cut into blocks of 16 MiB, and a block that is all zeros
 *          is left out. Each other block is a header as that of LiME with the magic
 *          0x4C4D5641 and the version 2, a framed Snappy stream of the block (snappy.c), and
 *          the length of that stream in 8 bytes. A reader cannot tell a block of zeros from
 *          memory that is not there, which is why the other two formats leave nothing out.
 *
 * How it is written. A file that is written in the usual way goes through the page cache of
 * the machine: the kernel takes free memory for the pages of the file, and what lay in that
 * memory is gone, also the part of it that the image has not reached yet. So the file is
 * opened with O_DIRECT, as LiME does with its option dio (disk.c of LiME 1.9.1), and its bytes
 * go from a buffer of this program to the device. Such a write must be whole blocks of the
 * device, in the file and in memory (__blockdev_direct_IO in fs/direct-io.c), so the bytes
 * are gathered in a buffer at a page address and written a mebibyte at a time. What is left
 * at the end is less than a block and is written in the usual way, as dd of GNU coreutils
 * writes its last block (iwrite in dd.c of coreutils 9.4): it is one page of the cache.
 *
 * Not every file system has such writes. One without them refuses the file at open (EINVAL,
 * do_dentry_open in fs/open.c: ramfs is one), and the file is then opened without O_DIRECT.
 * A write that is refused with EINVAL later ends the direct writes of that file in the same
 * way. FAT takes a direct write that makes a file longer through the cache by itself
 * (fat_direct_IO), and the kernel then writes those pages and drops them before the write
 * returns (direct_write_fallback in fs/libfs.c of Linux 6.12, __generic_file_write_iter in
 * Linux 4.18), so the cache holds a mebibyte of the image at a time and not the image. btrfs
 * does the same from Linux 6.18 on for every direct write to a file with checksums of its
 * data, which is every file unless they are turned off (btrfs_direct_write in
 * fs/btrfs/direct-io.c of Linux 6.18, 7.0 and 7.2, not in 6.12). The kernel drops only the
 * pages that are free to go at that moment: on a guest with btrfs and Linux 7.2, 65 to 512
 * pages of an image of 2 GiB were still in the cache at the end. tmpfs keeps a file in the
 * page cache, whichever way it is written.
 *
 * So a file that is written and flushed is named to the kernel as one whose pages are not
 * needed (POSIX_FADV_DONTNEED), which lets go what the cache still holds of it: the last
 * page, and what a file system took through the cache. dd does this after its last block
 * (invalidate_cache in dd.c).
 *
 * The SHA-256 of each file is computed while it is written, so the file is not read again.
 * A stretch that the kernel does not hand out is written as zeros and counted. The kernel
 * itself hands out zeros for a page of a range that is not in use as RAM (read_kcore_iter).
 */
#include "image.h"
#include "snappy.h"
#include "util.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BLOCK (16u << 20)       /* read and handed to the formats at once. The block of AVML */
#define PIECE (1u << 20)        /* asked of the source at once */
#define PAGE  4096u
#define ALIGN 4096u             /* of a direct write: its place in the file, its length, its memory */
#define CHUNK (1u << 20)        /* written to a file at once, a multiple of ALIGN */
#define NO_ADDRESS (~(uint64_t)0)       /* p_paddr of a segment that is not physical memory */

static const char *const names[IMAGE_FORMATS] = { "lime", "raw", "avml" };

const char *image_name(enum image_format f)
{
    return names[f];
}

int image_by_name(const char *name, enum image_format *f)
{
    int i;

    for (i = 0; i < IMAGE_FORMATS; i++)
        if (!strcmp(name, names[i])) {
            *f = (enum image_format)i;
            return 0;
        }
    return -1;
}

static int by_start(const void *a, const void *b)
{
    const struct image_range *x = a, *y = b;

    if (x->start != y->start)
        return x->start < y->start ? -1 : 1;
    return x->end > y->end ? -1 : x->end < y->end;      /* of two at one address the longer first */
}

static int grow(struct image_range **list, size_t *n, uint64_t start, uint64_t end, uint64_t offset)
{
    struct image_range *grown = realloc(*list, (*n + 1) * sizeof *grown);

    if (!grown)
        return -1;
    *list = grown;
    grown[*n].start = start;
    grown[*n].end = end;
    grown[*n].offset = offset;
    (*n)++;
    return 0;
}

/* One hexadecimal number of /proc/iomem. Returns the place behind it, or NULL. */
static const char *hex_number(const char *p, uint64_t *out)
{
    uint64_t v = 0;
    int digits = 0;

    for (;; p++, digits++) {
        unsigned d;

        if (*p >= '0' && *p <= '9') d = (unsigned)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') d = (unsigned)(*p - 'a') + 10;
        else break;
        if (digits == 16)
            return NULL;
        v = v << 4 | d;
    }
    *out = v;
    return digits ? p : NULL;
}

/*
 * The RAM ranges of the text of /proc/iomem, sorted, with ranges that touch as one. A line is
 * "start-end : name" with the end included (r_show in kernel/resource.c), and a line that
 * begins with a space is a part of the line above it.
 */
static int ram_ranges(const char *iomem, struct image_range **ram, size_t *nram, char err[IMAGE_ERR_LEN])
{
    const char *line, *next, *p;
    size_t i, kept = 0;

    for (line = iomem; *line; line = next) {
        uint64_t start, end;
        size_t len = strcspn(line, "\n");

        next = line + len + (line[len] == '\n');
        if (!(p = hex_number(line, &start)) || *p++ != '-' || !(p = hex_number(p, &end)) || strncmp(p, " : ", 3))
            continue;
        p += 3;
        len -= (size_t)(p - line);
        if (!(len == 10 && !memcmp(p, "System RAM", 10)) && !(len > 12 && !memcmp(p, "System RAM (", 12)))
            continue;
        if (!start && !end) {
            snprintf(err, IMAGE_ERR_LEN, "/proc/iomem states no addresses, which it does for a reader that is not root");
            return -1;
        }
        if (end < start || end == NO_ADDRESS) {
            snprintf(err, IMAGE_ERR_LEN, "/proc/iomem names a RAM range that ends before it begins or at the last address");
            return -1;
        }
        if (grow(ram, nram, start, end + 1, 0)) {
            snprintf(err, IMAGE_ERR_LEN, "the RAM ranges of /proc/iomem: no memory");
            return -1;
        }
    }
    if (!*nram) {
        snprintf(err, IMAGE_ERR_LEN, "/proc/iomem names no RAM range (no line \"System RAM\")");
        return -1;
    }
    qsort(*ram, *nram, sizeof **ram, by_start);
    for (i = 1; i < *nram; i++) {
        if ((*ram)[i].start <= (*ram)[kept].end) {
            if ((*ram)[i].end > (*ram)[kept].end)
                (*ram)[kept].end = (*ram)[i].end;
        } else {
            (*ram)[++kept] = (*ram)[i];
        }
    }
    *nram = kept + 1;
    return 0;
}

static int read_at(int fd, void *buf, size_t n, uint64_t off)
{
    uint8_t *p = buf;

    while (n) {
        ssize_t got = pread(fd, p, n, (off_t)off);

        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return -1;
        p += got;
        n -= (size_t)got;
        off += (uint64_t)got;
    }
    return 0;
}

/* The segments of an ELF64 core that state a physical address, sorted by it. */
static int core_segments(int core, struct image_range **segs, size_t *nsegs, char err[IMAGE_ERR_LEN])
{
    Elf64_Ehdr eh;
    Elf64_Phdr ph;
    size_t at_zero = 0;
    unsigned i;

    if (read_at(core, &eh, sizeof eh, 0)) {
        snprintf(err, IMAGE_ERR_LEN, "the header of /proc/kcore cannot be read");
        return -1;
    }
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_ident[EI_DATA] != ELFDATA2LSB || eh.e_phentsize != sizeof ph) {
        snprintf(err, IMAGE_ERR_LEN, "/proc/kcore is not an ELF64 core in the byte order of this program");
        return -1;
    }
    for (i = 0; i < eh.e_phnum; i++) {
        if (eh.e_phoff > NO_ADDRESS - (uint64_t)i * sizeof ph || read_at(core, &ph, sizeof ph, eh.e_phoff + (uint64_t)i * sizeof ph)) {
            snprintf(err, IMAGE_ERR_LEN, "segment %u of /proc/kcore cannot be read", i);
            return -1;
        }
        if (ph.p_type != PT_LOAD || !ph.p_filesz || ph.p_paddr == NO_ADDRESS)
            continue;
        if (ph.p_filesz > NO_ADDRESS - ph.p_paddr || ph.p_filesz > NO_ADDRESS - ph.p_offset) {
            snprintf(err, IMAGE_ERR_LEN, "segment %u of /proc/kcore reaches beyond the last address", i);
            return -1;
        }
        at_zero += !ph.p_paddr;
        if (grow(segs, nsegs, ph.p_paddr, ph.p_paddr + ph.p_filesz, ph.p_offset)) {
            snprintf(err, IMAGE_ERR_LEN, "the segments of /proc/kcore: no memory");
            return -1;
        }
    }
    /* Before Linux 4.12 every segment states the address 0, and memory cannot be placed. */
    if (at_zero > 1) {
        snprintf(err, IMAGE_ERR_LEN, "/proc/kcore of this kernel states no physical addresses");
        return -1;
    }
    if (!*nsegs) {
        snprintf(err, IMAGE_ERR_LEN, "/proc/kcore has no segment with a physical address");
        return -1;
    }
    qsort(*segs, *nsegs, sizeof **segs, by_start);
    return 0;
}

int image_source(const char *iomem, int core, struct image_source *src, char err[IMAGE_ERR_LEN])
{
    struct image_range *ram = NULL, *segs = NULL;
    size_t nram = 0, nsegs = 0, i, k;
    int r = -1;

    memset(src, 0, sizeof *src);
    if (ram_ranges(iomem, &ram, &nram, err) || core_segments(core, &segs, &nsegs, err))
        goto out;
    /* Each RAM range, as far as segments hold it. The segments are passed in the order of
       their addresses, and what one has given is not taken from a later one, so that memory
       which two segments offer, as the text of the kernel, is read once. */
    for (i = 0; i < nram; i++) {
        uint64_t pos = ram[i].start;

        src->ram += ram[i].end - ram[i].start;
        for (k = 0; k < nsegs && pos < ram[i].end && segs[k].start < ram[i].end; k++) {
            uint64_t from = segs[k].start > pos ? segs[k].start : pos;
            uint64_t to = segs[k].end < ram[i].end ? segs[k].end : ram[i].end;
            struct image_range *last = src->nranges ? &src->ranges[src->nranges - 1] : NULL;

            if (to <= from)
                continue;
            src->bytes += to - from;
            pos = to;
            /* a stretch that goes on where the last one ended, in memory and in the source */
            if (last && last->end == from && last->offset + (last->end - last->start) == segs[k].offset + (from - segs[k].start)) {
                last->end = to;
            } else if (grow(&src->ranges, &src->nranges, from, to, segs[k].offset + (from - segs[k].start))) {
                snprintf(err, IMAGE_ERR_LEN, "the ranges of the image: no memory");
                goto out;
            }
        }
    }
    if (!src->nranges) {
        snprintf(err, IMAGE_ERR_LEN, "/proc/kcore offers none of the RAM ranges that /proc/iomem names");
        goto out;
    }
    r = 0;
out:
    free(ram);
    free(segs);
    if (r)
        image_source_free(src);
    return r;
}

void image_source_free(struct image_source *src)
{
    free(src->ranges);
    memset(src, 0, sizeof *src);
}

uint64_t image_size(enum image_format f, const struct image_source *src, int *exact)
{
    uint64_t size = 0;
    size_t i;

    *exact = f != IMAGE_AVML;
    if (f == IMAGE_RAW)
        return src->nranges ? src->ranges[src->nranges - 1].end : 0;
    if (f == IMAGE_LIME)
        return src->bytes + 32 * (uint64_t)src->nranges;
    /* no block of zeros, and no chunk that is shorter compressed */
    for (i = 0; i < src->nranges; i++) {
        uint64_t len = src->ranges[i].end - src->ranges[i].start;
        uint64_t blocks = (len + BLOCK - 1) / BLOCK, chunks = (len + SNAPPY_CHUNK - 1) / SNAPPY_CHUNK + blocks;

        size += len + blocks * (32 + sizeof snappy_stream_start + 8) + chunks * (SNAPPY_CHUNK_MAX - SNAPPY_CHUNK);
    }
    return size;
}

int image_open(struct image_file *f, const char *path)
{
    const int flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW;

    f->direct = 1;
    if ((f->fd = open(path, flags | O_DIRECT, 0600)) >= 0 || errno != EINVAL)
        return f->fd < 0 ? -1 : 0;
    /* A file system without direct writes. The kernel made the file before it refused it
       (the file is created in lookup_open, and refused in do_dentry_open after that). */
    f->direct = 0;
    if (unlink(path) && errno != ENOENT)
        return -1;
    return (f->fd = open(path, flags, 0600)) < 0 ? -1 : 0;
}

/* N bytes of the buffer of a file to the offset where they belong. */
static int out_write(struct image_file *f, size_t n)
{
    const uint8_t *p = f->out;
    uint64_t off = f->at;

    while (n) {
        ssize_t put = pwrite(f->fd, p, n, (off_t)off);

        if (put < 0 && errno == EINTR)
            continue;
        if (put < 0 && errno == EINVAL && f->direct) {
            /* a file system that opens a file for direct writes and takes none of ours */
            int fl = fcntl(f->fd, F_GETFL);

            if (fl < 0 || fcntl(f->fd, F_SETFL, fl & ~O_DIRECT))
                return -1;
            f->direct = 0;
            continue;
        }
        if (put <= 0) {
            if (!put)
                errno = EIO;
            return -1;
        }
        p += put;
        off += (uint64_t)put;
        n -= (size_t)put;
    }
    return 0;
}

/* Write the buffer where it is full, or with PAD also the blocks that have begun, their rest
   as zeros. */
static void out_flush(struct image_file *f, int pad)
{
    size_t n = pad ? (f->fill + ALIGN - 1) / ALIGN * ALIGN : f->fill == CHUNK ? CHUNK : 0;

    if (f->failed || !n)
        return;
    memset(f->out + f->fill, 0, n - f->fill);
    if (out_write(f, n)) {
        f->failed = errno ? errno : EIO;
        return;
    }
    f->at += n;
    f->fill = 0;
}

/* Bytes to a file and into its SHA-256. After a failed write the file takes nothing more. */
static void put(struct image_file *f, const void *buf, size_t n)
{
    const uint8_t *p = buf;

    if (f->failed)
        return;
    hash_update(&f->hash, buf, n);
    f->bytes += n;
    while (n && !f->failed) {
        size_t k = n < CHUNK - f->fill ? n : CHUNK - f->fill;

        memcpy(f->out + f->fill, p, k);
        f->fill += k;
        p += k;
        n -= k;
        out_flush(f, 0);
    }
}

/*
 * A stretch of a raw image that is no memory, and reads as zeros. It is not written, but for
 * the blocks of the file that it shares with memory, which are written whole.
 */
static void hole(struct image_file *f, uint64_t n)
{
    static const uint8_t zeros[65536];
    uint64_t to = f->at + f->fill + n, left = n;

    if (f->failed || !n)
        return;
    f->bytes += n;
    while (left) {
        size_t step = left < sizeof zeros ? (size_t)left : sizeof zeros;

        hash_update(&f->hash, zeros, step);
        left -= step;
    }
    if (to - f->at > (f->fill + ALIGN - 1) / ALIGN * ALIGN) {
        /* it ends behind the block that has begun: the file goes on at the block of its end */
        out_flush(f, 1);
        if (f->failed)
            return;
        f->at = to / ALIGN * ALIGN;
        f->fill = 0;
    }
    memset(f->out + f->fill, 0, (size_t)(to - f->at) - f->fill);
    f->fill = (size_t)(to - f->at);
    out_flush(f, 0);
}

/* What is left in the buffer at the end of an image: its whole blocks, and then the rest,
   which no direct write takes. */
static void out_end(struct image_file *f)
{
    size_t whole = f->fill / ALIGN * ALIGN, rest = f->fill - whole;

    if (f->failed)
        return;
    if (whole && out_write(f, whole)) {
        f->failed = errno ? errno : EIO;
        return;
    }
    if (!rest)
        return;
    memmove(f->out, f->out + whole, rest);
    f->at += whole;
    if (f->direct) {
        int fl = fcntl(f->fd, F_GETFL);

        if (fl < 0 || fcntl(f->fd, F_SETFL, fl & ~O_DIRECT)) {
            f->failed = errno ? errno : EIO;
            return;
        }
    }
    if (out_write(f, rest))
        f->failed = errno ? errno : EIO;
}

static void le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void le64(uint8_t *p, uint64_t v)
{
    le32(p, (uint32_t)v);
    le32(p + 4, (uint32_t)(v >> 32));
}

/* The header of a stretch of memory in the LiME format and in that of AVML. */
static void header(struct image_file *f, uint32_t magic, uint32_t version, uint64_t start, uint64_t end)
{
    uint8_t head[32] = { 0 };

    le32(head, magic);
    le32(head + 4, version);
    le64(head + 8, start);
    le64(head + 16, end - 1);
    put(f, head, sizeof head);
}

/* One block in the compressed format of AVML. */
static void avml_block(struct image_file *f, uint64_t start, const uint8_t *buf, size_t n)
{
    uint8_t chunk[SNAPPY_CHUNK_MAX], count[8];
    uint64_t stream = sizeof snappy_stream_start;
    size_t at;

    if (!buf[0] && !memcmp(buf, buf + 1, n - 1))
        return;
    header(f, 0x4c4d5641, 2, start, start + n);
    put(f, snappy_stream_start, sizeof snappy_stream_start);
    for (at = 0; at < n && !f->failed; at += SNAPPY_CHUNK) {
        size_t len = snappy_chunk(buf + at, n - at < SNAPPY_CHUNK ? n - at : SNAPPY_CHUNK, chunk);

        put(f, chunk, len);
        stream += len;
    }
    le64(count, stream);
    put(f, count, sizeof count);
}

/* One block of memory, the bytes from the address START, to a file. FIRST marks the first block
   of the range. */
static void block(struct image_file *f, const struct image_range *range, uint64_t start, const uint8_t *buf,
                  size_t n, int first)
{
    switch (f->format) {
    case IMAGE_LIME:
        if (first)
            header(f, 0x4c694d45, 1, range->start, range->end);
        put(f, buf, n);
        break;
    case IMAGE_AVML:
        avml_block(f, start, buf, n);
        break;
    case IMAGE_RAW:
        hole(f, start - f->pos);
        put(f, buf, n);
        f->pos = start + n;
        break;
    case IMAGE_FORMATS:
        break;
    }
}

static ssize_t read_some(int core, uint8_t *buf, size_t n, uint64_t off)
{
    ssize_t got;

    do
        got = pread(core, buf, n, (off_t)off);
    while (got < 0 && errno == EINTR);
    return got;
}

/*
 * N bytes of the source at OFF, which are the memory from the address ADDR. A read that fails
 * says nothing about the pages before the one it failed at (read_kcore_iter returns the error
 * alone), so its first page is then asked for by itself, and only a page that cannot be read
 * alone is zeros and counted.
 */
static void read_block(int core, uint64_t off, uint64_t addr, uint8_t *buf, size_t n, uint64_t *unread)
{
    size_t done = 0;

    while (done < n) {
        size_t want = n - done < PIECE ? n - done : PIECE;
        ssize_t got = read_some(core, buf + done, want, off + done);

        if (got <= 0) {
            size_t page = PAGE - (size_t)((addr + done) % PAGE);

            if (page > want)
                page = want;
            got = page < want ? read_some(core, buf + done, page, off + done) : 0;
            if (got <= 0) {
                memset(buf + done, 0, page);
                *unread += page;
                got = (ssize_t)page;
            }
        }
        done += (size_t)got;
    }
}

int image_settle(struct image_file *f)
{
    if (fsync(f->fd))
        return -1;
    /* Advice, which the kernel follows for the pages that are clean and in no use. A page
       that stays is a page of the cache as before, and the file is whole without it. */
    posix_fadvise(f->fd, 0, 0, POSIX_FADV_DONTNEED);
    return 0;
}

int image_write(int core, const struct image_source *src, struct image_file *files, size_t nfiles,
                void (*progress)(void *arg, uint64_t done), void *arg, uint64_t *unread,
                char err[IMAGE_ERR_LEN])
{
    uint8_t *buf;
    uint64_t done = 0;
    size_t i, k, alive = nfiles;
    int no_memory;

    *unread = 0;
    buf = malloc(BLOCK);
    no_memory = !buf;
    for (k = 0; k < nfiles; k++) {
        void *out = NULL;

        if (posix_memalign(&out, ALIGN, CHUNK))
            out = NULL;
        no_memory |= !out;
        files[k].out = out;
        files[k].fill = 0;
        files[k].failed = 0;
        files[k].bytes = files[k].pos = files[k].at = 0;
        hash_init(&files[k].hash, hash_by_name("sha256"));
    }
    if (no_memory) {
        for (k = 0; k < nfiles; k++) {
            free(files[k].out);
            files[k].out = NULL;
            files[k].failed = ENOMEM;
        }
        free(buf);
        snprintf(err, IMAGE_ERR_LEN, "the block of the image: no memory");
        return -1;
    }
    for (i = 0; i < src->nranges && alive; i++) {
        const struct image_range *range = &src->ranges[i];
        uint64_t at;

        for (at = range->start; at < range->end && alive; ) {
            size_t n = range->end - at < BLOCK ? (size_t)(range->end - at) : BLOCK;

            read_block(core, range->offset + (at - range->start), at, buf, n, unread);
            for (k = 0, alive = 0; k < nfiles; k++) {
                block(&files[k], range, at, buf, n, at == range->start);
                alive += !files[k].failed;
            }
            at += n;
            done += n;
            if (progress)
                progress(arg, done);
        }
    }
    explicit_bzero(buf, BLOCK);         /* memory of the machine, which holds its keys */
    free(buf);
    for (k = 0, alive = 0; k < nfiles; k++) {
        out_end(&files[k]);
        alive += !files[k].failed;
        explicit_bzero(files[k].out, CHUNK);
        free(files[k].out);
        files[k].out = NULL;
        hash_final(&files[k].hash, files[k].sha256);
    }
    if (!alive) {
        snprintf(err, IMAGE_ERR_LEN, "no image could be written to its end");
        return -1;
    }
    return 0;
}
