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
 *   raw          anything else, scanned from the first byte to the last.
 * A schedule is found only where it lies in the file as it lay in memory. A file that begins
 * like a compressed AVML image, a kdump or makedumpfile file, or a gzip, xz, zstd, bzip2 or lz4
 * file holds memory in another form, and searching it as raw bytes finds some schedules or none
 * and looks like a search that found no key. Such a file is refused with status 1. -r searches
 * it all the same, for a raw image that happens to begin with one of those marks.
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
 */
#define _FILE_OFFSET_BITS 64
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define CHUNK   (1u << 20)      /* bytes read at once */
#define KEEP    240             /* longest schedule: bytes kept in front of the next chunk */
#define MAXHIT  4096
#define VERSION "1.1"
#define NONE    (~0ULL)

static uint8_t sbox[256];
static const uint8_t rcon[11] = {0, 1, 2, 4, 8, 16, 32, 64, 128, 0x1b, 0x36};

static struct hit { int nk; uint64_t phys; uint8_t key[32]; } hits[MAXHIT];
static int nhit, dropped;
static unsigned long long nbytes, nfail;
static unsigned step = 1;

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
static void selftest(void)
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
    return;
bad:
    fprintf(stderr, "kcore-keyscan: self-test failed, the result would not be reliable\n");
    exit(3);
}

static void report(int nk, const uint8_t *s, uint64_t phys, uint64_t virt)
{
    int i, len = nk * 4;

    for (i = 0; i < nhit; i++)      /* the kernel text is also inside the RAM segment */
        if (hits[i].phys == phys && hits[i].nk == nk)
            return;
    if (nhit == MAXHIT) { dropped++; return; }
    hits[nhit].nk = nk; hits[nhit].phys = phys; memcpy(hits[nhit].key, s, len); nhit++;
    printf("AES-%d phys 0x%016llx virt ", len * 8, (unsigned long long)phys);
    if (virt == NONE) printf("-"); else printf("0x%016llx", (unsigned long long)virt);
    printf(" key ");
    for (i = 0; i < len; i++) printf("%02x", s[i]);
    printf("\n");
}

/*
 * The bytes not yet searched, with the addresses of the first of them. A segment that begins
 * where the one before it ended continues the same run of bytes, so a schedule that lies across
 * the border of two adjacent ranges is still found. AVML writes RAM as ranges of at most 16 MiB.
 */
static uint8_t buf[KEEP + CHUNK];
static size_t have;
static uint64_t bphys, bvirt;

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
    memmove(buf, buf + end, have - end);
    have -= end; bphys += end;
    if (bvirt != NONE) bvirt += end;
}

/* Read LEN bytes of the file from offset OFF. PHYS and VIRT are the addresses of the first byte. */
static void scan(int fd, uint64_t off, uint64_t len, uint64_t phys, uint64_t virt)
{
    uint64_t done = 0;
    size_t want;
    ssize_t n;

    if (have && (phys != bphys + have || virt != (bvirt == NONE ? NONE : bvirt + have)))
        sweep(1);
    if (!have) { bphys = phys; bvirt = virt; }
    while (done < len) {
        want = len - done < CHUNK ? (size_t)(len - done) : CHUNK;
        n = pread(fd, buf + have, want, (off_t)(off + done));
        if (n <= 0) {                        /* an unreadable stretch counts as zeros */
            n = want < 4096 ? (ssize_t)want : 4096;
            memset(buf + have, 0, (size_t)n);
            nfail += (unsigned long long)n;
        }
        done += (uint64_t)n; have += (size_t)n; nbytes += (unsigned long long)n;
        sweep(0);
    }
}

static int full_read(int fd, void *p, size_t n, uint64_t off)
{
    return pread(fd, p, n, (off_t)off) == (ssize_t)n;
}

/*
 * The first bytes of the formats that hold memory in another form than it had, each from the
 * specification or the source of its format, and what to do with such a file.
 */
static const struct { const char *mark; size_t len; const char *name, *advice; } packed[] = {
    /* AVML src/image.rs: AVML_MAGIC 0x4c4d5641 little-endian, with version 2 for snappy blocks */
    {"AVML\2\0\0\0", 8, "a compressed AVML image", "\"avml convert FILE OUT\" writes it as a LiME image"},
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

int main(int argc, char **argv)
{
    const char *path = "/proc/kcore", *format;
    unsigned char head[64];
    struct timespec t0, t1;
    struct stat st;
    int fd, i, j, raw = 0, nseg = 0, n128 = 0, n256 = 0, u128 = 0, u256 = 0;

    while (argc > 1 && argv[1][0] == '-') {
        if (!strcmp(argv[1], "-s") && argc > 2 && atoi(argv[2]) > 0) {
            step = (unsigned)atoi(argv[2]); argv += 2; argc -= 2;
        } else if (!strcmp(argv[1], "-r")) {
            raw = 1; argv++; argc--;
        } else {
            fprintf(stderr, "usage: kcore-keyscan [-s STEP] [-r] [FILE]   (FILE defaults to /proc/kcore)\n");
            return 2;
        }
    }
    if (argc > 1) path = argv[1];
    init_sbox();
    selftest();
    fd = open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &st)) {
        fprintf(stderr, "kcore-keyscan: %s: %s\n", path, strerror(errno));
        return 1;
    }
    memset(head, 0, sizeof head);
    if (pread(fd, head, sizeof head, 0) < 0) {
        fprintf(stderr, "kcore-keyscan: %s: %s\n", path, strerror(errno));
        return 1;
    }
    for (i = 0; !raw && i < (int)(sizeof packed / sizeof packed[0]); i++)
        if (!memcmp(head, packed[i].mark, packed[i].len)) {
            fprintf(stderr, "kcore-keyscan: %s begins like %s. Such a file holds memory in another form, and a "
                    "search of its bytes misses key schedules, so it is not searched: %s. -r searches it as "
                    "raw bytes all the same.\n",
                    path, packed[i].name, packed[i].advice);
            return 1;
        }
    clock_gettime(CLOCK_MONOTONIC, &t0);

    if (raw) {
        format = "raw";
        scan(fd, 0, (uint64_t)st.st_size, 0, NONE);
        nseg = 1;
    } else if (!memcmp(head, ELFMAG, SELFMAG) && head[EI_CLASS] == ELFCLASS64 && head[EI_DATA] == ELFDATA2LSB) {
        Elf64_Ehdr eh;
        Elf64_Phdr ph;

        format = "ELF64 core";
        memcpy(&eh, head, sizeof eh);
        for (i = 0; i < eh.e_phnum; i++) {
            if (!full_read(fd, &ph, sizeof ph, eh.e_phoff + (uint64_t)i * eh.e_phentsize)) {
                fprintf(stderr, "kcore-keyscan: cannot read program header %d\n", i);
                return 1;
            }
            if (ph.p_type != PT_LOAD || !ph.p_filesz || ph.p_paddr == NONE)
                continue;
            /* an image taken from outside the guest has no kernel addresses: 0 or the physical one */
            scan(fd, ph.p_offset, ph.p_filesz, ph.p_paddr,
                 ph.p_vaddr && ph.p_vaddr != ph.p_paddr ? ph.p_vaddr : NONE);
            nseg++;
        }
    } else if (!memcmp(head, "EMiL", 4)) {      /* 0x4C694D45, little-endian */
        uint64_t off = 0, s, e;

        format = "LiME";
        while (full_read(fd, head, 32, off) && !memcmp(head, "EMiL", 4)) {
            memcpy(&s, head + 8, 8); memcpy(&e, head + 16, 8);
            if (e < s) break;
            scan(fd, off + 32, e - s + 1, s, NONE);
            off += 32 + (e - s + 1);
            nseg++;
        }
    } else {
        format = "raw";
        scan(fd, 0, (uint64_t)st.st_size, 0, NONE);
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
    fflush(stdout);
    fprintf(stderr, "kcore-keyscan %s: %s, %s, %d segment%s, %llu bytes (%.2f GiB), %.1f seconds\n",
            VERSION, path, format, nseg, nseg == 1 ? "" : "s", nbytes, nbytes / 1073741824.0,
            (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9);
    fprintf(stderr, "kcore-keyscan: AES-128 schedules: %d (%d different keys), "
            "AES-256 schedules: %d (%d different keys)\n", n128, u128, n256, u256);
    if (nfail)
        fprintf(stderr, "kcore-keyscan: %llu bytes could not be read and count as zeros\n", nfail);
    if (dropped)
        fprintf(stderr, "kcore-keyscan: %d further schedules were not listed (more than %d)\n",
                dropped, MAXHIT);
    return 0;
}
