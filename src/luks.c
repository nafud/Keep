/*
 * luks.c: the header of a LUKS volume, read from the device as cryptsetup reads it.
 *
 * LUKS1 (lib/luks1 of cryptsetup). A binary header of 592 bytes with big-endian numbers: hash
 * name at 72, payload offset at 104, key bytes at 108, digest at 112, salt at 132, iterations at
 * 164, UUID at 168 and eight keyslots of 48 bytes from 208, each with the sector of its key
 * material at 40 and its stripes at 44.
 *
 * LUKS2 (lib/luks2 of cryptsetup). A binary header of 4096 bytes, followed by a JSON area, and
 * the same once more behind it as the second copy: size of header and JSON area at 8, sequence
 * number at 16, checksum function at 72, UUID at 168, own offset at 256, checksum at 448. The
 * checksum is over the header with a zeroed checksum field and the whole JSON area. The copy
 * with the higher sequence number is the one in use. Where cryptsetup finds one copy damaged it
 * writes it anew from the other. This code only reads.
 *
 * The device is read through the page cache. cryptsetup writes a header with direct I/O, which
 * drops the cached pages of what it wrote, so both ways give the bytes of the device.
 */
#include "luks.h"
#include "json.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SECTOR                  512
#define LUKS1_HEADER            592     /* what the fields take */
#define LUKS1_PHDR              1024    /* sizeof(struct luks_phdr), padded to two sectors */
#define LUKS1_SLOTS             8
#define LUKS1_STRIPES           4000
#define LUKS1_ALIGN_KEYSLOTS    4096
#define LUKS2_BIN               4096
#define LUKS2_SMALLEST          0x4000          /* LUKS2_HDR_16K_LEN */
#define LUKS2_LARGEST           0x400000        /* LUKS2_HDR_OFFSET_MAX */
#define LUKS2_MAX_KEYSLOTS      0x8000000       /* LUKS2_MAX_KEYSLOTS_SIZE */
#define LUKS_SALT               32
#define LUKS_DIGEST             20
#define LARGEST_AREA            (256ull << 20)  /* beyond every header that cryptsetup writes */
#define COPY_CHUNK              (1u << 20)

static const uint8_t magic_first[6] = { 'L', 'U', 'K', 'S', 0xba, 0xbe };
static const uint8_t magic_second[6] = { 'S', 'K', 'U', 'L', 0xba, 0xbe };

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }

/* Read n bytes at off. Returns 0, 1 where the device or file ends before them, -1 on an error. */
static int read_at(int fd, void *buf, size_t n, uint64_t off)
{
    uint8_t *p = buf;

    while (n) {
        ssize_t got = pread(fd, p, n, (off_t)off);

        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            return -1;
        if (got == 0)
            return 1;
        p += got; n -= (size_t)got; off += (uint64_t)got;
    }
    return 0;
}

/* A text field of a header, which need not end with a zero byte. */
static void field(char *out, size_t outlen, const uint8_t *p, size_t n)
{
    size_t len = n < outlen - 1 ? n : outlen - 1;

    memcpy(out, p, len);
    out[len] = 0;
}

/* ---- LUKS1 ---------------------------------------------------------------------------------- */

/* The rules of _check_and_convert_hdr, LUKS_check_keyslots and LUKS_check_device_size, which
   cryptsetup applies before it backs a header up. */
static int luks1(const uint8_t *b, struct luks_header *h, char err[LUKS_ERR_LEN])
{
    uint32_t payload = be32(b + 104), key_bytes = be32(b + 108), offset[LUKS1_SLOTS];
    uint64_t af_sectors, last = 0;
    struct luks_digest *d = &h->digests[0];
    int i, j;

    if (!key_bytes) {
        snprintf(err, LUKS_ERR_LEN, "a LUKS1 header with a key of 0 bytes");
        return -1;
    }
    af_sectors = ((uint64_t)key_bytes * LUKS1_STRIPES + SECTOR - 1) / SECTOR;   /* AF_split_sectors */
    for (i = 0; i < LUKS1_SLOTS; i++) {
        const uint8_t *slot = b + 208 + 48 * i;

        offset[i] = be32(slot + 40);
        if (be32(slot + 44) != LUKS1_STRIPES || (uint64_t)offset[i] * SECTOR < LUKS1_PHDR ||
            (payload && (payload <= offset[i] || payload < offset[i] + af_sectors))) {
            snprintf(err, LUKS_ERR_LEN, "a LUKS1 header whose keyslot %d is invalid", i);
            return -1;
        }
        if (offset[i] > last)
            last = offset[i];
    }
    for (i = 0; i < LUKS1_SLOTS; i++)           /* no keyslot inside another one */
        for (j = 0; j < LUKS1_SLOTS; j++)
            if (i != j && offset[j] >= offset[i] && offset[j] < offset[i] + af_sectors) {
                snprintf(err, LUKS_ERR_LEN, "a LUKS1 header whose keyslots %d and %d overlap", i, j);
                return -1;
            }
    h->version = 1;
    field(h->uuid, sizeof h->uuid, b + 168, 40);
    h->area = (last + af_sectors) * SECTOR;     /* LUKS_device_sectors */
    if (h->area < LUKS1_ALIGN_KEYSLOTS || h->area > LARGEST_AREA) {
        snprintf(err, LUKS_ERR_LEN, "a LUKS1 header with a keyslot area of %llu bytes", (unsigned long long)h->area);
        return -1;
    }
    if ((uint64_t)offset[0] * SECTOR == LUKS1_ALIGN_KEYSLOTS) {
        h->zero_from = LUKS1_PHDR;
        h->zero_to = LUKS1_ALIGN_KEYSLOTS;
    }
    field(d->hash, sizeof d->hash, b + 72, 32);
    d->alg = hash_by_name(d->hash);
    memcpy(d->digest, b + 112, LUKS_DIGEST);
    d->digestlen = LUKS_DIGEST;
    memcpy(d->salt, b + 132, LUKS_SALT);
    d->saltlen = LUKS_SALT;
    d->iterations = be32(b + 164);
    h->ndigests = d->iterations ? 1 : 0;
    return 0;
}

/* ---- LUKS2 ---------------------------------------------------------------------------------- */
/* luks2 returns 0, 1 where no copy of a LUKS2 header holds, and -1 on a failed read or metadata
   that are not understood. */

struct copy {                           /* one of the two copies of the header */
    int valid;
    uint64_t size, seqid;               /* of binary header and JSON area */
    uint8_t bin[LUKS2_BIN];
    char *json;                         /* size - LUKS2_BIN bytes */
};

/* hdr_read_disk and hdr_disk_sanity_check_pre of cryptsetup. A copy that does not hold counts as
   not valid, a failed read is an error. */
static int read_copy(int fd, uint64_t offset, int second, struct copy *c, char err[LUKS_ERR_LEN])
{
    const struct hash_alg *alg;
    struct hash_ctx ctx;
    uint8_t sum[HASH_MAX_DIGEST], zeroed[LUKS2_BIN];
    char name[33];
    int r;

    memset(c, 0, sizeof *c);
    if ((r = read_at(fd, c->bin, LUKS2_BIN, offset)) < 0)
        goto unreadable;
    if (r || memcmp(c->bin, second ? magic_second : magic_first, 6) || be16(c->bin + 6) != 2 ||
        be64(c->bin + 256) != offset)
        return 0;
    c->size = be64(c->bin + 8);
    c->seqid = be64(c->bin + 16);
    if (c->size < LUKS2_SMALLEST || c->size > LUKS2_LARGEST || (second && offset != c->size))
        return 0;
    field(name, sizeof name, c->bin + 72, 32);
    if (!(alg = hash_by_name(name)))
        return 0;
    if (!(c->json = malloc(c->size - LUKS2_BIN + 1))) {
        snprintf(err, LUKS_ERR_LEN, "no memory for the metadata of a LUKS2 header");
        return -1;
    }
    if ((r = read_at(fd, c->json, c->size - LUKS2_BIN, offset + LUKS2_BIN)) < 0)
        goto unreadable;
    if (!r) {
        memcpy(zeroed, c->bin, LUKS2_BIN);
        memset(zeroed + 448, 0, 64);
        hash_init(&ctx, alg);
        hash_update(&ctx, zeroed, LUKS2_BIN);
        hash_update(&ctx, c->json, c->size - LUKS2_BIN);
        hash_final(&ctx, sum);
        c->valid = !memcmp(sum, c->bin + 448, hash_len(alg));
    }
    if (c->valid) {
        c->json[c->size - LUKS2_BIN] = 0;       /* the text ends at the first zero byte */
    } else {
        free(c->json);
        c->json = NULL;
    }
    return 0;
unreadable:
    snprintf(err, LUKS_ERR_LEN, "read at offset %llu: %s", (unsigned long long)offset, strerror(errno));
    free(c->json);
    c->json = NULL;
    return -1;
}

/* Standard base64 with padding, as cryptsetup writes a salt and a digest. Returns the number of
   bytes, or -1 for a text that is no base64 or does not fit. */
static long base64(const char *s, uint8_t *out, size_t room)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(s), i, n = 0;

    if (!len || len % 4)
        return -1;
    for (i = 0; i < len; i += 4) {
        uint32_t v = 0;
        int k, pad = 0;

        for (k = 0; k < 4; k++) {
            const char *at = s[i + k] ? strchr(alphabet, s[i + k]) : NULL;

            if (at && !pad)
                v = v << 6 | (uint32_t)(at - alphabet);
            else if (s[i + k] == '=' && i + 4 == len && k >= 2) {
                v <<= 6;
                pad++;
            } else
                return -1;
        }
        for (k = 0; k < 3 - pad; k++) {
            if (n == room)
                return -1;
            out[n++] = (uint8_t)(v >> (16 - 8 * k));
        }
    }
    return (long)n;
}

/* One member of "digests": PBKDF2_digest_verify of cryptsetup states what it must hold. A digest
   that names no segment belongs to no data and proves no volume key. */
static void digest(const struct json *j, struct luks_header *h)
{
    struct luks_digest *d = &h->digests[h->ndigests];
    const struct json *segments = json_member(j, "segments");
    const char *type = json_string(json_member(j, "type"));
    const char *hash = json_string(json_member(j, "hash"));
    const char *salt = json_string(json_member(j, "salt"));
    const char *value = json_string(json_member(j, "digest"));
    uint64_t iterations;
    long n;

    if (h->ndigests == LUKS_MAX_DIGESTS || !type || strcmp(type, "pbkdf2") || !hash || !salt || !value ||
        !segments || segments->type != JSON_ARRAY || !segments->first ||
        json_u64(json_member(j, "iterations"), &iterations) || !iterations || iterations > UINT32_MAX)
        return;
    memset(d, 0, sizeof *d);
    snprintf(d->hash, sizeof d->hash, "%s", hash);
    d->alg = hash_by_name(hash);
    d->iterations = (uint32_t)iterations;
    if (base64(salt, d->salt, sizeof d->salt) != LUKS_SALT)
        return;
    d->saltlen = LUKS_SALT;
    if ((n = base64(value, d->digest, sizeof d->digest)) < LUKS_DIGEST ||
        (n != LUKS_DIGEST && d->alg && (size_t)n != hash_len(d->alg)))
        return;
    d->digestlen = (size_t)n;
    h->ndigests++;
}

static int luks2(int fd, struct luks_header *h, char err[LUKS_ERR_LEN])
{
    static const uint64_t second_at[] = { 0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000,
                                          0x100000, 0x200000, 0x400000 };      /* LUKS2_HDR2_OFFSETS */
    struct copy first, second, *use;
    const struct json *config, *m;
    struct json *meta = NULL;
    const char *why = NULL;
    uint64_t json_size, keyslots_size;
    size_t i;
    int r = -1;

    memset(&second, 0, sizeof second);
    if (read_copy(fd, 0, 0, &first, err))
        return -1;
    if (first.valid) {
        if (read_copy(fd, first.size, 1, &second, err))
            goto out;
    } else {
        for (i = 0; i < sizeof second_at / sizeof second_at[0] && !second.valid; i++)
            if (read_copy(fd, second_at[i], 1, &second, err))
                goto out;
    }
    if (!first.valid && !second.valid) {
        r = 1;
        goto out;
    }
    use = first.valid && (!second.valid || first.seqid >= second.seqid) ? &first : &second;
    h->version = 2;
    h->secondary = use == &second;
    field(h->uuid, sizeof h->uuid, use->bin + 168, 40);

    meta = json_parse(use->json, strlen(use->json), &why);
    config = json_member(meta, "config");
    if (!meta || json_string(json_member(config, "json_size")) == NULL ||
        json_string(json_member(config, "keyslots_size")) == NULL ||
        json_u64(json_member(config, "json_size"), &json_size) ||
        json_u64(json_member(config, "keyslots_size"), &keyslots_size)) {
        snprintf(err, LUKS_ERR_LEN, "a LUKS2 header whose metadata are not understood%s%s",
                 why ? ": " : "", why ? why : "");
        goto out;
    }
    if (json_size != use->size - LUKS2_BIN || keyslots_size % 4096 || keyslots_size > LUKS2_MAX_KEYSLOTS) {
        snprintf(err, LUKS_ERR_LEN, "a LUKS2 header whose metadata state sizes that cryptsetup refuses");
        goto out;
    }
    h->area = 2 * use->size + keyslots_size;    /* LUKS2_hdr_and_areas_size */
    m = json_member(meta, "digests");
    for (m = m && m->type == JSON_OBJECT ? m->first : NULL; m; m = m->next)
        if (m->type == JSON_OBJECT)
            digest(m, h);
    r = 0;
out:
    json_free(meta);
    free(first.json);
    free(second.json);
    return r;
}

int luks_read(int fd, struct luks_header *h, char err[LUKS_ERR_LEN])
{
    uint8_t b[LUKS1_PHDR] = { 0 };
    int r;

    memset(h, 0, sizeof *h);
    if ((r = read_at(fd, b, sizeof b, 0)) < 0) {
        snprintf(err, LUKS_ERR_LEN, "read at offset 0: %s", strerror(errno));
        return -1;
    }
    if (!r && !memcmp(b, magic_first, 6) && be16(b + 6) == 1)
        return luks1(b, h, err);
    /* A LUKS2 header whose first copy is overwritten still has its second one. */
    if ((r = luks2(fd, h, err)) <= 0)
        return r;
    memset(h, 0, sizeof *h);
    if (memcmp(b, magic_first, 6)) {
        snprintf(err, LUKS_ERR_LEN, "no LUKS header at the start of the device");
        return 1;
    }
    if (be16(b + 6) == 2)
        snprintf(err, LUKS_ERR_LEN, "a LUKS2 header of which no copy has its checksum");
    else
        snprintf(err, LUKS_ERR_LEN, "a LUKS header of version %u", (unsigned)be16(b + 6));
    return -1;
}

int luks_backup(int fd, const struct luks_header *h, int out, uint64_t *written, char err[LUKS_ERR_LEN])
{
    uint64_t page = (uint64_t)sysconf(_SC_PAGESIZE), total = (h->area + page - 1) / page * page, off;
    uint8_t *buf = malloc(COPY_CHUNK);
    int r = -1;

    *written = 0;
    if (!buf) {
        snprintf(err, LUKS_ERR_LEN, "no memory for the copy of the header");
        return -1;
    }
    for (off = 0; off < total; off += COPY_CHUNK) {
        size_t n = total - off < COPY_CHUNK ? (size_t)(total - off) : COPY_CHUNK;
        size_t have = off >= h->area ? 0 : h->area - off < n ? (size_t)(h->area - off) : n;
        int got = have ? read_at(fd, buf, have, off) : 0;

        if (got) {
            snprintf(err, LUKS_ERR_LEN, got < 0 ? "read of the header at offset %llu: %s"
                     : "the device ends inside the header, at offset %llu%s",
                     (unsigned long long)off, got < 0 ? strerror(errno) : "");
            goto out;
        }
        memset(buf + have, 0, n - have);
        if (h->zero_to > off && h->zero_from < off + n) {       /* LUKS_hdr_backup: "Wipe unused area" */
            uint64_t from = h->zero_from > off ? h->zero_from - off : 0;
            uint64_t to = h->zero_to < off + n ? h->zero_to - off : n;

            memset(buf + from, 0, (size_t)(to - from));
        }
        if (write_all(out, buf, n)) {
            snprintf(err, LUKS_ERR_LEN, "write of the copy of the header: %s", strerror(errno));
            goto out;
        }
        *written += n;
    }
    r = 0;
out:
    free(buf);
    return r;
}

int luks_proves(const struct luks_header *h, const uint8_t *key, size_t keylen, const char **hash)
{
    uint8_t out[HASH_MAX_DIGEST];
    int computed = 0;
    size_t i;

    *hash = NULL;
    for (i = 0; i < h->ndigests; i++) {
        const struct luks_digest *d = &h->digests[i];

        if (!d->alg) {
            *hash = d->hash;
            continue;
        }
        computed = 1;
        pbkdf2(d->alg, key, keylen, d->salt, d->saltlen, d->iterations, out, d->digestlen);
        if (!memcmp(out, d->digest, d->digestlen)) {
            explicit_bzero(out, sizeof out);
            return 1;
        }
    }
    explicit_bzero(out, sizeof out);
    return computed ? 0 : -1;
}

int luks_uuid_matches(const struct luks_header *h, const char *dm_uuid)
{
    const char *p, *u;

    if (strncmp(dm_uuid, "CRYPT-", 6) || !(p = strchr(dm_uuid + 6, '-')))
        return 0;
    for (p++, u = h->uuid; *u; u++) {
        if (*u == '-')
            continue;
        if (!*p || *p == '-' || *p != *u)
            return 0;
        p++;
    }
    return 1;
}
