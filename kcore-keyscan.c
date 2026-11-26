/*
 * kcore-keyscan: find AES-128 and AES-256 key schedules in memory.
 *
 *   kcore-keyscan [-s STEP] [-r] [FILE]   FILE defaults to /proc/kcore
 *
 *   -s STEP   test only the addresses that are a multiple of STEP
 *   -r        read FILE as raw bytes, whatever its first bytes are
 *
 * FILE is the running kernel's /proc/kcore (route R3, nothing is written), or a memory image
 * (route R4). The format is recognised from the first bytes:
 *   ELF64 core   /proc/kcore, or "virsh dump --memory-only --format=elf". Every PT_LOAD segment
 *                that has a physical address is read. /proc/kcore gives the vmalloc and module
 *                areas the physical address -1, so those are left out and RAM is read once.
 *   LiME         the image AVML writes: a 32-byte header with the physical range, then the range.
 *   AVML         the image "avml --compress" writes (version 2): the same header with another
 *                mark, then the range as a framed Snappy stream and the length of that stream.
 *                Each chunk of at most 64 KiB is decompressed and compared with its CRC-32C.
 *   raw          anything else, scanned from the first byte to the last.
 * A schedule is found only where it lies in the file as it lay in memory. A file that begins
 * like a kdump or makedumpfile file, or a gzip, xz, zstd, bzip2 or lz4 file holds memory in
 * another form, and searching it as raw bytes finds some schedules or none and looks like a
 * search that found no key. Such a file is refused with status 1. -r searches it all the same,
 * for a raw image that happens to begin with one of those marks.
 *
 * An image that ends early or is damaged is searched up to that place: a file that ends inside
 * a segment or a range, or a compressed stream that does not follow its format. The place and
 * the number of bytes of the file that were not searched are reported, and the status is 1. So
 * is it where the list of the schedules could not be written.
 *
 * A key schedule is the list of round keys that AES derives from a key (FIPS-197, section 5.2).
 * The kernel keeps the schedule, not only the key, and the first 16 or 32 bytes of the schedule
 * are the key itself. Each later word of the schedule follows from earlier words, so a position
 * holds a schedule only if every word passes that rule: 176 bytes for AES-128, 240 for AES-256.
 * The test is exact. Random data passes the first word with probability 2^-32.
 *
 * Output, one line per schedule on standard output:
 *   AES-256 phys 0x000000010a3c5010 virt 0xffff8f1b4a3c5010 key <64 hex digits>
 * "phys" is the physical address and "virt" the kernel address, "-" where the format has none
 * (for a raw file "phys" is the file offset). The counts and the time go to standard error, so
 * the keys can be sent to a file and the summary stays on the screen.
 *
 * Build:  gcc -static -O2 -Wall -o kcore-keyscan kcore-keyscan.c
 * /proc/kcore needs root, and the kernel refuses it in lockdown mode "confidentiality".
 *
 * Built with -DKEYSCAN_LIBRARY the file has no main: the C program of Keep links the same
 * search as keyscan_run (src/keyscan.h) and takes the schedules from memory.
 */
#define _FILE_OFFSET_BITS 64
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "src/keyscan.h"

#define CHUNK   (1u << 20)      /* bytes read at once */
#define KEEP    240             /* longest schedule: bytes kept in front of the next chunk */
#define MAXHIT  4096
#define VERSION "1.3"
#define NONE    (~0ULL)

static uint8_t sbox[256];
static const uint8_t rcon[11] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 0x1b, 0x36};

static struct keyscan_hit hits[MAXHIT];
static int nhit, dropped;
static unsigned long long nbytes, nfail;
static unsigned step = 1;
static FILE *keys_out, *msg_out;        /* the schedules, and the counts and messages */

/*
 * What a search says beyond its two lines of counts: what it warns of, or why it read nothing.
 * Each goes to the messages as a line with the name of the scanner before it, and is kept
 * without that name for the program that links the search (keyscan_said).
 */
#define MAXSAID 8
static char said[MAXSAID][640];
static const char *said_list[MAXSAID];
static int nsaid;

static void say(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void say(const char *fmt, ...)
{
    char line[sizeof said[0]];
    va_list ap;
    size_t len;

    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    len = strlen(line);
    if (len && line[len - 1] == '\n')
        line[len - 1] = 0;
    fprintf(msg_out, "kcore-keyscan: %s\n", line);
    if (nsaid < MAXSAID) {
        memcpy(said[nsaid], line, sizeof line);
        said_list[nsaid] = said[nsaid];
        nsaid++;
    }
}

const char *const *keyscan_said(int *n)
{
    *n = nsaid;
    return said_list;
}

static void init_sbox(void)
{
    uint8_t p = 1, q = 1, x;

    do {    /* p runs through the powers of 3 in GF(2^8), q through their inverses */
        p = p ^ (uint8_t)(p << 1) ^ ((p & 0x80) ? 0x1b : 0);
        q ^= q << 1; q ^= q << 2; q ^= q << 4;
        if (q & 0x80) q ^= 0x09;
        x = q ^ (uint8_t)(q << 1 | q >> 7) ^ (uint8_t)(q << 2 | q >> 6)
              ^ (uint8_t)(q << 3 | q >> 5) ^ (uint8_t)(q << 4 | q >> 4);
        sbox[p] = x ^ 0x63;
    } while (p != 1);
    sbox[0] = 0x63;
}

/* The word that the rule gives for position i (in words), from the words before it. */
static inline void next_word(const uint8_t *s, int i, int nk, uint8_t w[4])
{
    const uint8_t *t = s + 4 * (i - 1), *b = s + 4 * (i - nk);

    if (i % nk == 0) {
        w[0] = b[0] ^ sbox[t[1]] ^ rcon[i / nk];
        w[1] = b[1] ^ sbox[t[2]];
        w[2] = b[2] ^ sbox[t[3]];
        w[3] = b[3] ^ sbox[t[0]];
    } else if (nk == 8 && i % 8 == 4) {
        w[0] = b[0] ^ sbox[t[0]]; w[1] = b[1] ^ sbox[t[1]];
        w[2] = b[2] ^ sbox[t[2]]; w[3] = b[3] ^ sbox[t[3]];
    } else {
        w[0] = b[0] ^ t[0]; w[1] = b[1] ^ t[1]; w[2] = b[2] ^ t[2]; w[3] = b[3] ^ t[3];
    }
}

/* nk is 4 for AES-128 (44 words) and 8 for AES-256 (60 words). */
static int is_schedule(const uint8_t *s, int nk)
{
    int i, words = nk == 4 ? 44 : 60;
    uint8_t w[4];

    for (i = nk; i < words; i++) {
        next_word(s, i, nk, w);
        if (memcmp(w, s + 4 * i, 4))
            return 0;
    }
    return 1;
}

/* The scanner is checked against the two expansions printed in FIPS-197, appendix A. */
static int selftest(void)
{
    static const uint8_t k128[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                                     0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    static const uint8_t k256[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,
        0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,
        0x09,0x14,0xdf,0xf4};
    static const uint8_t last128[4] = {0xb6,0x63,0x0c,0xa6}, last256[4] = {0x70,0x6c,0x63,0x1e};
    uint8_t s[240];
    int i;

    memcpy(s, k128, 16);
    for (i = 4; i < 44; i++) next_word(s, i, 4, s + 4 * i);
    if (memcmp(s + 172, last128, 4) || !is_schedule(s, 4)) goto bad;
    s[100] ^= 1;
    if (is_schedule(s, 4)) goto bad;
    memcpy(s, k256, 32);
    for (i = 8; i < 60; i++) next_word(s, i, 8, s + 4 * i);
    if (memcmp(s + 236, last256, 4) || !is_schedule(s, 8)) goto bad;
    return 0;
bad:
    say("self-test failed, the result would not be reliable\n");
    return -1;
}

static void report(int nk, const uint8_t *s, uint64_t phys, uint64_t virt)
{
    int i, len = nk * 4;

    /* The kernel text is also inside the RAM segment, so the same schedule can come twice.
       A core whose segments state no physical address has another key at the same number. */
    for (i = 0; i < nhit; i++)
        if (hits[i].phys == phys && hits[i].nk == nk && !memcmp(hits[i].key, s, (size_t)len))
            return;
    if (nhit == MAXHIT) { dropped++; return; }
    hits[nhit].nk = nk; hits[nhit].phys = phys; memcpy(hits[nhit].key, s, len); nhit++;
    fprintf(keys_out, "AES-%d phys 0x%016llx virt ", len * 8, (unsigned long long)phys);
    if (virt == NONE) fprintf(keys_out, "-"); else fprintf(keys_out, "0x%016llx", (unsigned long long)virt);
    fprintf(keys_out, " key ");
    for (i = 0; i < len; i++) fprintf(keys_out, "%02x", s[i]);
    fprintf(keys_out, "\n");
}

/*
 * The bytes not yet searched, with the addresses of the first of them. A segment that begins
 * where the one before it ended continues the same run of bytes, so a schedule that lies across
 * the border of two adjacent ranges is still found. AVML writes RAM as ranges of at most 16 MiB.
 */
static uint8_t buf[KEEP + CHUNK];
static size_t have;
static uint64_t bphys, bvirt;
static uint64_t file_size;              /* of the file that is searched, as fstat states it */

/* A program that links the search can look at the memory as well: each byte is handed to it
   once, in the order of the search, with the address of the first of them. */
static void (*watcher)(void *arg, const uint8_t *p, size_t n, uint64_t phys);
static void *watcher_arg;

void keyscan_watch(void (*fn)(void *arg, const uint8_t *p, size_t n, uint64_t phys), void *arg)
{
    watcher = fn;
    watcher_arg = arg;
}

/* A program that links the search can end it before its end. */
static const char HALTED[] = "the search was interrupted";
static const volatile sig_atomic_t *halt;

void keyscan_until(const volatile sig_atomic_t *stop)
{
    halt = stop;
}

static int halted(void)
{
    return halt && *halt;
}

/* Search the buffered bytes. Unless LAST, the final 239 bytes wait for the bytes after them. */
static void sweep(int last)
{
    size_t end = last ? have : (have >= KEEP ? have - KEEP + 1 : 0), i;

    for (i = (size_t)((step - bphys % step) % step); i < end; i += step) {
        const uint8_t *p = buf + i;
        uint8_t w[4];

        if (i + 176 <= have) {
            next_word(p, 4, 4, w);
            if (!memcmp(w, p + 16, 4) && is_schedule(p, 4))
                report(4, p, bphys + i, bvirt == NONE ? NONE : bvirt + i);
        }
        if (i + 240 <= have) {
            next_word(p, 8, 8, w);
            if (!memcmp(w, p + 32, 4) && is_schedule(p, 8))
                report(8, p, bphys + i, bvirt == NONE ? NONE : bvirt + i);
        }
    }
    if (watcher && end)
        watcher(watcher_arg, buf, end, bphys);
    memmove(buf, buf + end, have - end);
    have -= end; bphys += end;
    if (bvirt != NONE) bvirt += end;
}

static ssize_t read_some(int fd, void *p, size_t n, uint64_t off)
{
    ssize_t got;

    do
        got = pread(fd, p, n, (off_t)off);
    while (got < 0 && errno == EINTR);
    return got;
}

/*
 * Read LEN bytes of the file from offset OFF. PHYS and VIRT are the addresses of the first byte.
 * Returns 0, or 1 where the file ends before them or the search is ended (halted), with the
 * offset of that place in *ENDED: the bytes up to there are searched.
 *
 * A stretch that cannot be read counts as zeros. A read that fails says nothing about the pages
 * before the one it failed at (read_kcore_iter of the kernel returns the error alone), so its
 * first page is then asked for by itself, and only a page that cannot be read alone is zeros.
 */
static int scan(int fd, uint64_t off, uint64_t len, uint64_t phys, uint64_t virt, uint64_t *ended)
{
    uint64_t done = 0;
    size_t want, page;
    ssize_t n;

    if (have && (phys != bphys + have || virt != (bvirt == NONE ? NONE : bvirt + have)))
        sweep(1);
    if (!have) { bphys = phys; bvirt = virt; }
    while (done < len) {
        if (halted()) {
            *ended = off + done;
            return 1;
        }
        want = len - done < CHUNK ? (size_t)(len - done) : CHUNK;
        n = read_some(fd, buf + have, want, off + done);
        if (n == 0 && off + done >= file_size) {
            *ended = off + done;
            return 1;
        }
        if (n <= 0) {
            page = 4096 - (size_t)((phys + done) % 4096);
            if (page > want)
                page = want;
            n = page < want ? read_some(fd, buf + have, page, off + done) : 0;
            if (n <= 0) {
                n = (ssize_t)page;
                memset(buf + have, 0, page);
                nfail += page;
            }
        }
        done += (uint64_t)n; have += (size_t)n; nbytes += (unsigned long long)n;
        sweep(0);
    }
    return 0;
}

static int full_read(int fd, void *p, size_t n, uint64_t off)
{
    return pread(fd, p, n, (off_t)off) == (ssize_t)n;
}

/* N bytes that are already in memory, to be searched. PHYS is the address of the first of them. */
static void feed(const uint8_t *p, size_t n, uint64_t phys)
{
    size_t k;

    if (have && (phys != bphys + have || bvirt != NONE))
        sweep(1);
    if (!have) { bphys = phys; bvirt = NONE; }
    while (n) {
        k = n < CHUNK ? n : CHUNK;
        memcpy(buf + have, p, k);
        have += k; nbytes += k; p += k; n -= k;
        sweep(0);
    }
}

/*
 * Snappy, for the compressed image of AVML. A block (format_description.txt of Snappy) is the
 * length of the data as a varint, then literals and copies of earlier bytes. Returns the length
 * of the data, or -1 for a block that does not follow the format or does not fit CAP.
 */
static long snappy_block(const uint8_t *in, size_t n, uint8_t *out, size_t cap)
{
    size_t i = 0, o = 0, len, off, want = 0;
    int shift = 0;

    for (;;) {
        if (i == n || shift > 28) return -1;
        want |= (size_t)(in[i] & 0x7f) << shift;
        if (!(in[i++] & 0x80)) break;
        shift += 7;
    }
    if (want > cap) return -1;
    while (i < n) {
        unsigned tag = in[i++];

        if ((tag & 3) == 0) {                       /* a literal */
            len = tag >> 2;
            if (len >= 60) {
                unsigned extra = (unsigned)len - 59, j;

                if (i + extra > n) return -1;
                for (len = 0, j = 0; j < extra; j++) len |= (size_t)in[i + j] << (8 * j);
                i += extra;
            }
            len++;
            if (len > n - i || len > want - o) return -1;
            memcpy(out + o, in + i, len);
            i += len; o += len;
            continue;
        }
        if ((tag & 3) == 1) {                       /* a copy with an offset of 11 bits */
            if (i + 1 > n) return -1;
            len = ((tag >> 2) & 7) + 4;
            off = ((size_t)(tag >> 5) << 8) | in[i];
            i += 1;
        } else if ((tag & 3) == 2) {                /* a copy with an offset of 16 bits */
            if (i + 2 > n) return -1;
            len = (tag >> 2) + 1;
            off = in[i] | (size_t)in[i + 1] << 8;
            i += 2;
        } else {                                    /* a copy with an offset of 32 bits */
            if (i + 4 > n) return -1;
            len = (tag >> 2) + 1;
            off = in[i] | (size_t)in[i + 1] << 8 | (size_t)in[i + 2] << 16 | (size_t)in[i + 3] << 24;
            i += 4;
        }
        if (!off || off > o || len > want - o) return -1;
        for (; len; len--, o++)                     /* byte by byte: a copy may run into itself */
            out[o] = out[o - off];
    }
    return o == want ? (long)o : -1;
}

/* CRC-32C (Castagnoli), eight bytes at a time, as the framed format of Snappy uses it. */
static uint32_t crctab[8][256];

static void init_crc(void)
{
    uint32_t c;
    int i, j;

    for (i = 0; i < 256; i++) {
        for (c = (uint32_t)i, j = 0; j < 8; j++) c = (c >> 1) ^ ((c & 1) ? 0x82f63b78u : 0);
        crctab[0][i] = c;
    }
    for (i = 0; i < 256; i++)
        for (j = 1; j < 8; j++)
            crctab[j][i] = (crctab[j - 1][i] >> 8) ^ crctab[0][crctab[j - 1][i] & 0xff];
}

static uint32_t masked_crc32c(const uint8_t *p, size_t n)
{
    uint32_t c = 0xffffffffu, lo, hi;

    for (; n >= 8; n -= 8, p += 8) {
        memcpy(&lo, p, 4); memcpy(&hi, p + 4, 4);       /* little-endian, as x86-64 is */
        lo ^= c;
        c = crctab[7][lo & 0xff] ^ crctab[6][(lo >> 8) & 0xff] ^ crctab[5][(lo >> 16) & 0xff] ^ crctab[4][lo >> 24]
          ^ crctab[3][hi & 0xff] ^ crctab[2][(hi >> 8) & 0xff] ^ crctab[1][(hi >> 16) & 0xff] ^ crctab[0][hi >> 24];
    }
    for (; n; n--, p++) c = crctab[0][(c ^ *p) & 0xff] ^ (c >> 8);
    c ^= 0xffffffffu;
    return ((c >> 15) | (c << 17)) + 0xa282ead8u;   /* framing_format.txt, section 3 */
}

#define SNAPMAX 65536           /* a chunk of the framed format holds at most 64 KiB of data */
static unsigned long long nbadcrc;

/*
 * One range of a compressed AVML image (src/image.rs and src/io/snappy.rs of AVML): at OFF a
 * framed Snappy stream (framing_format.txt) that holds LEN bytes of memory from PHYS on, and
 * after it the length of that stream in 8 bytes. Returns the length of the stream with those
 * 8 bytes, or 0 where the stream ends early or does not follow the format, with the reason in WHY
 * and the file offset up to which the stream was taken in STOP.
 */
static uint8_t packed_in[4 + SNAPMAX + SNAPMAX / 6 + 64], packed_out[SNAPMAX];   /* a chunk, and its data */

static uint64_t avml_range(int fd, uint64_t off, uint64_t len, uint64_t phys, const char **why, uint64_t *stop)
{
    uint8_t *const in = packed_in, *const out = packed_out;
    uint64_t at = off, done = 0, stored;
    uint8_t h[4];
    uint32_t size, crc;
    long n;

    for (; done < len; *stop = at) {
        if (halted()) { *why = HALTED; return 0; }
        if (!full_read(fd, h, 4, at)) { *why = "the file ends inside a range"; return 0; }
        size = h[1] | (uint32_t)h[2] << 8 | (uint32_t)h[3] << 16;
        if (h[0] >= 0x80) {                             /* the stream identifier, padding, skippable chunks */
            if (h[0] == 0xff && (size != 6 || !full_read(fd, in, 6, at + 4) || memcmp(in, "sNaPpY", 6))) {
                *why = "a stream identifier that is not that of Snappy"; return 0;
            }
            at += 4 + size;
            continue;
        }
        if (h[0] > 1) { *why = "a chunk of a kind that the framed format reserves"; return 0; }
        if (size < 4 || size > sizeof packed_in) { *why = "a chunk with an impossible length"; return 0; }
        if (!full_read(fd, in, size, at + 4)) { *why = "the file ends inside a chunk"; return 0; }
        memcpy(&crc, in, 4);
        if (h[0] == 0) {
            n = snappy_block(in + 4, size - 4, out, sizeof packed_out);
            if (n < 0) { *why = "a chunk that cannot be decompressed"; return 0; }
        } else {
            n = (long)size - 4;
            if (n > SNAPMAX) { *why = "a chunk with an impossible length"; return 0; }
            memcpy(out, in + 4, (size_t)n);
        }
        if ((uint64_t)n > len - done) { *why = "more data than the range of the header"; return 0; }
        if (masked_crc32c(out, (size_t)n) != crc)
            nbadcrc++;
        feed(out, (size_t)n, phys + done);
        done += (uint64_t)n;
        at += 4 + size;
    }
    if (!full_read(fd, &stored, 8, at) || stored != at - off) {
        *why = "the length after a range is missing or differs from the length read"; return 0;
    }
    return at - off + 8;
}

/*
 * The first bytes of the formats that hold memory in another form than it had, each from the
 * specification or the source of its format, and what to do with such a file.
 */
static const struct { const char *mark; size_t len; const char *name, *advice; } packed[] = {
    /* AVML src/image.rs: AVML_MAGIC 0x4c4d5641 little-endian. Version 2 is read, see main(). */
    {"AVML", 4, "an AVML image of another version than 2", "only version 2, the compressed image, is read"},
    /* makedumpfile diskdump_mod.h: KDUMP_SIGNATURE and DISK_DUMP_SIGNATURE; makedumpfile.h: MAKEDUMPFILE_SIGNATURE */
    {"KDUMP   ", 8, "a kdump file of makedumpfile", "a dump that \"makedumpfile -E\" writes is in the ELF format, which is read"},
    {"DISKDUMP", 8, "a diskdump file", "a dump that \"makedumpfile -E\" writes is in the ELF format, which is read"},
    {"makedumpfile", 12, "a makedumpfile file in the flattened format", "\"makedumpfile -R OUT < FILE\" rebuilds the dump file"},
    {"\x1f\x8b", 2, "a gzip file", "decompress it first"},              /* RFC 1952, 2.3.1 */
    {"\xfd" "7zXZ", 6, "an xz file", "decompress it first"},           /* .xz file format, 2.1.1.1 */
    {"\x28\xb5\x2f\xfd", 4, "a zstd file", "decompress it first"},    /* RFC 8878, 3.1.1: 0xFD2FB528 */
    {"BZh", 3, "a bzip2 file", "decompress it first"},
    {"\x04\x22\x4d\x18", 4, "an lz4 file", "decompress it first"},    /* LZ4 frame format: 0x184D2204 */
};

static struct keyscan_summary summary;
static int summarised;

const struct keyscan_summary *keyscan_summary(void)
{
    return summarised ? &summary : NULL;
}

const struct keyscan_hit *keyscan_hits(int *n)
{
    *n = nhit;
    return hits;
}

void keyscan_wipe(void)
{
    explicit_bzero(hits, sizeof hits);
    explicit_bzero(buf, sizeof buf);
    explicit_bzero(packed_in, sizeof packed_in);
    explicit_bzero(packed_out, sizeof packed_out);
    nhit = 0;
}

/*
 * The search of one file. The schedules go to KEYS, one line each, and stay in memory for
 * keyscan_hits. The counts and every message go to MSG. *FAILED is the errno of a file that
 * could not be opened or read at its start, else 0. Returns the exit status of kcore-keyscan:
 * 0, 1 for an input that is unreadable, refused or could not be read to its end, 3 for a failed
 * self-test.
 */
int keyscan_run(const char *path, int raw, unsigned every, FILE *keys, FILE *msg, int *failed)
{
    const char *format;
    unsigned char head[64];
    struct timespec t0, t1;
    struct stat st;
    const char *why = NULL;
    uint64_t stopped = 0;
    ssize_t headlen;
    int fd, i, j, nseg = 0, n128 = 0, n256 = 0, u128 = 0, u256 = 0, status = 1, unwritten;

    keys_out = keys; msg_out = msg; step = every;
    nhit = dropped = 0; nbytes = nfail = nbadcrc = 0; have = 0;
    summarised = 0;
    nsaid = 0;
    *failed = 0;
    init_sbox();
    init_crc();
    if (selftest())
        return 3;
    fd = open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &st)) {
        *failed = errno;
        say("%s: %s\n", path, strerror(errno));
        if (fd >= 0) close(fd);
        return 1;
    }
    file_size = (uint64_t)st.st_size;
    memset(head, 0, sizeof head);
    if ((headlen = pread(fd, head, sizeof head, 0)) < 0) {
        *failed = errno;
        say("%s: %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }
    for (i = 0; !raw && i < (int)(sizeof packed / sizeof packed[0]); i++)
        if (!memcmp(head, packed[i].mark, packed[i].len) && memcmp(head, "AVML\2\0\0\0", 8)) {
            say("%s begins like %s. Such a file holds memory in another form, and a "
                    "search of its bytes misses key schedules, so it is not searched: %s.%s\n",
                    path, packed[i].name, packed[i].advice,
#ifdef KEYSCAN_LIBRARY
                    ""
#else
                    " -r searches it as raw bytes all the same."
#endif
                    );
            goto out;
        }
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (raw) {
        format = "raw";
        if (scan(fd, 0, file_size, 0, NONE, &stopped) && halted())
            why = HALTED;
        nseg = 1;
    } else if (!memcmp(head, ELFMAG, SELFMAG) && head[EI_CLASS] == ELFCLASS64 && head[EI_DATA] == ELFDATA2LSB) {
        Elf64_Ehdr eh;
        Elf64_Phdr ph;

        format = "ELF64 core";
        if ((size_t)headlen < sizeof eh) {   /* by what was read: a file of /proc need not state its size */
            say("%s ends inside its ELF header\n", path);
            goto out;
        }
        memcpy(&eh, head, sizeof eh);
        for (i = 0; i < eh.e_phnum; i++) {
            if (!full_read(fd, &ph, sizeof ph, eh.e_phoff + (uint64_t)i * eh.e_phentsize)) {
                say("cannot read program header %d\n", i);
                goto out;
            }
            if (ph.p_type != PT_LOAD || !ph.p_filesz || ph.p_paddr == NONE)
                continue;
            /* an image taken from outside the guest has no kernel addresses: 0 or the physical one */
            if (scan(fd, ph.p_offset, ph.p_filesz, ph.p_paddr,
                     ph.p_vaddr && ph.p_vaddr != ph.p_paddr ? ph.p_vaddr : NONE, &stopped)) {
                why = halted() ? HALTED : "the file ends inside a segment";
                break;
            }
            nseg++;
        }
    } else if (!memcmp(head, "EMiL", 4) || !memcmp(head, "AVML\2\0\0\0", 8)) {
        /* AVML src/image.rs: the marks 0x4C694D45 and 0x4C4D5641 little-endian, with the versions
           1 for a range as it is and 2 for a compressed one. Its reader takes each range by its
           own header, so both kinds may follow each other. */
        uint64_t off = 0, s, e, used;
        int packed_ranges = !memcmp(head, "AVML", 4);

        while (full_read(fd, head, 32, off)) {
            int v2 = !memcmp(head, "AVML\2\0\0\0", 8);

            if (!v2 && memcmp(head, "EMiL", 4)) { stopped = off; why = "no header of a range"; break; }
            memcpy(&s, head + 8, 8); memcpy(&e, head + 16, 8);
            if (e < s) { stopped = off; why = "a header whose range ends before it begins"; break; }
            if (v2) {
                stopped = off + 32;
                used = avml_range(fd, off + 32, e - s + 1, s, &why, &stopped);
                if (!used) break;
                off += 32 + used;
                packed_ranges++;
            } else {
                if (scan(fd, off + 32, e - s + 1, s, NONE, &stopped)) {
                    why = halted() ? HALTED : "the file ends inside a range";
                    break;
                }
                off += 32 + (e - s + 1);
            }
            nseg++;
        }
        if (!why && off < (uint64_t)st.st_size) { stopped = off; why = "the file ends inside the header of a range"; }
        format = packed_ranges ? "AVML compressed" : "LiME";
    } else {
        format = "raw";
        if (scan(fd, 0, file_size, 0, NONE, &stopped) && halted())
            why = HALTED;
        nseg = 1;
    }
    sweep(1);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    for (i = 0; i < nhit; i++) {
        for (j = 0; j < i; j++)
            if (hits[j].nk == hits[i].nk && !memcmp(hits[j].key, hits[i].key, hits[i].nk * 4))
                break;
        if (hits[i].nk == 4) { n128++; u128 += j == i; } else { n256++; u256 += j == i; }
    }
    unwritten = fflush(keys_out) || ferror(keys_out);
    summary.format = format;
    summary.segments = nseg;
    summary.bytes = nbytes;
    summary.seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    summary.halted = why == HALTED;
    summarised = 1;
    fprintf(msg_out, "kcore-keyscan %s: %s, %s, %d segment%s, %llu bytes (%.2f GiB), %.1f seconds\n",
            VERSION, path, format, nseg, nseg == 1 ? "" : "s", nbytes, nbytes / 1073741824.0, summary.seconds);
    fprintf(msg_out, "kcore-keyscan: AES-128 schedules: %d (%d different keys), "
            "AES-256 schedules: %d (%d different keys)\n", n128, u128, n256, u256);
    if (nfail)
        say("%llu bytes could not be read and count as zeros\n", nfail);
    if (nbadcrc)
        say("chunks that differ from their checksum: %llu. Their data is searched as it is\n", nbadcrc);
    if (unwritten)
        say("the list of the schedules could not be written to its end\n");
    if (why == HALTED) {
        say("%s, at file offset %llu: what lies behind that place is not searched.\n", why, (unsigned long long)stopped);
        goto out;
    }
    if (why) {
        say("the image is damaged or ends early at file offset %llu: %s. "
                "%llu bytes of the file from there on are not searched.\n",
                (unsigned long long)stopped, why, (unsigned long long)(file_size > stopped ? file_size - stopped : 0));
        goto out;
    }
    if (unwritten)
        goto out;
    if (dropped)
        say("%d further schedules were not listed (more than %d)\n",
                dropped, MAXHIT);
    status = 0;
out:
    fflush(msg_out);
    close(fd);
    return status;
}

#ifndef KEYSCAN_LIBRARY
int main(int argc, char **argv)
{
    const char *path = "/proc/kcore";
    unsigned every = 1;
    int raw = 0, failed;

    while (argc > 1 && argv[1][0] == '-') {
        if (!strcmp(argv[1], "-s") && argc > 2 && atoi(argv[2]) > 0) {
            every = (unsigned)atoi(argv[2]); argv += 2; argc -= 2;
        } else if (!strcmp(argv[1], "-r")) {
            raw = 1; argv++; argc--;
        } else {
            fprintf(stderr, "usage: kcore-keyscan [-s STEP] [-r] [FILE]   (FILE defaults to /proc/kcore)\n");
            return 2;
        }
    }
    if (argc > 1) path = argv[1];
    return keyscan_run(path, raw, every, stdout, stderr, &failed);
}
#endif
