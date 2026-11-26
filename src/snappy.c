/*
 * snappy.c: the framed Snappy format, written. It is what the compressed image of AVML holds.
 *
 * Written from the two documents of Snappy 1.2.1, format_description.txt and
 * framing_format.txt. A stream is a chain of chunks: a type of one byte, a length of three
 * bytes, and the data. The first chunk names the stream. A data chunk holds at most 64 KiB
 * and begins with the masked CRC-32C of that data, which follows compressed (type 0x00) or as
 * it is (type 0x01).
 *
 * Compressed data is the length of the data as a varint and then literals and copies. A copy
 * names bytes that lie up to 65535 bytes back in the same chunk. They are found here as the
 * reference implementation finds them, with a table of the places where four bytes were last
 * seen, by their hash. Which copies a compressor finds is its own matter: any chain of
 * literals and copies that gives the data is the format, so a stream written here is not the
 * stream that AVML writes of the same memory, and both read as the same memory.
 */
#include "snappy.h"

#include <string.h>

#define HASH_BITS 14
#define WORK_MAX (32 + SNAPPY_CHUNK + SNAPPY_CHUNK / 6)  /* MaxCompressedLength of the reference */

const uint8_t snappy_stream_start[10] = { 0xff, 0x06, 0x00, 0x00, 's', 'N', 'a', 'P', 'p', 'Y' };

static uint32_t crc_table[8][256];
static int crc_ready;

/* CRC-32C, RFC 3720, 12.1: the polynomial 0x1EDC6F41, here with its bits in the order of the
   bytes, 0x82F63B78. Eight tables take eight bytes of the data at a time. */
static void crc_init(void)
{
    uint32_t i, k, c;

    for (i = 0; i < 256; i++) {
        c = i;
        for (k = 0; k < 8; k++)
            c = c & 1 ? c >> 1 ^ 0x82f63b78 : c >> 1;
        crc_table[0][i] = c;
    }
    for (i = 0; i < 256; i++)
        for (k = 1; k < 8; k++)
            crc_table[k][i] = crc_table[k - 1][i] >> 8 ^ crc_table[0][crc_table[k - 1][i] & 0xff];
    crc_ready = 1;
}

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t crc32c(const uint8_t *p, size_t n)
{
    uint32_t c = 0xffffffff;

    if (!crc_ready)
        crc_init();
    for (; n >= 8; n -= 8, p += 8) {
        uint32_t a = load32(p) ^ c, b = load32(p + 4);

        c = crc_table[7][a & 0xff] ^ crc_table[6][a >> 8 & 0xff] ^ crc_table[5][a >> 16 & 0xff] ^ crc_table[4][a >> 24] ^
            crc_table[3][b & 0xff] ^ crc_table[2][b >> 8 & 0xff] ^ crc_table[1][b >> 16 & 0xff] ^ crc_table[0][b >> 24];
    }
    for (; n; n--, p++)
        c = c >> 8 ^ crc_table[0][(c ^ *p) & 0xff];
    return c ^ 0xffffffff;
}

/* The checksum as a chunk stores it (framing_format.txt, 3). */
static uint32_t masked(uint32_t crc)
{
    return (crc >> 15 | crc << 17) + 0xa282ead8;
}

static uint8_t *literal(uint8_t *out, const uint8_t *p, size_t n)
{
    if (!n)
        return out;
    if (n <= 60) {
        *out++ = (uint8_t)((n - 1) << 2);
    } else if (n <= 256) {
        *out++ = 60 << 2;
        *out++ = (uint8_t)(n - 1);
    } else {
        *out++ = 61 << 2;
        *out++ = (uint8_t)(n - 1);
        *out++ = (uint8_t)((n - 1) >> 8);
    }
    memcpy(out, p, n);
    return out + n;
}

/* One copy element: 4 to 11 bytes from less than 2048 bytes back take two bytes, any other
   length up to 64 takes three. */
static uint8_t *copy_element(uint8_t *out, size_t offset, size_t n)
{
    if (n >= 4 && n <= 11 && offset < 2048) {
        *out++ = (uint8_t)(1 | (n - 4) << 2 | (offset >> 8) << 5);
        *out++ = (uint8_t)offset;
    } else {
        *out++ = (uint8_t)(2 | (n - 1) << 2);
        *out++ = (uint8_t)offset;
        *out++ = (uint8_t)(offset >> 8);
    }
    return out;
}

static uint8_t *copy(uint8_t *out, size_t offset, size_t n)
{
    for (; n >= 68; n -= 64)
        out = copy_element(out, offset, 64);
    if (n > 64) {                       /* 60 leave at least four for the element that follows */
        out = copy_element(out, offset, 60);
        n -= 60;
    }
    return copy_element(out, offset, n);
}

/* The N bytes of IN, at most SNAPPY_CHUNK, as compressed data. OUT has room for WORK_MAX. */
static size_t compress(const uint8_t *in, size_t n, uint8_t *out)
{
    uint16_t seen[1 << HASH_BITS];      /* the place where these four bytes were last seen */
    uint8_t *start = out;
    size_t at = 0, pending = 0, v, skip = 32;

    for (v = n; v >= 0x80; v >>= 7)
        *out++ = (uint8_t)(v | 0x80);
    *out++ = (uint8_t)v;
    memset(seen, 0, sizeof seen);
    while (at + 4 <= n) {
        uint32_t four = load32(in + at);
        size_t slot = four * 0x1e35a7bdu >> (32 - HASH_BITS), back = seen[slot], len;

        seen[slot] = (uint16_t)at;
        if (back >= at || load32(in + back) != four) {
            /* where nothing repeats, more and more bytes are passed between two looks */
            at += skip++ >> 5;
            continue;
        }
        for (len = 4; at + len < n && in[back + len] == in[at + len]; len++)
            ;
        out = literal(out, in + pending, at - pending);
        out = copy(out, at - back, len);
        at += len;
        pending = at;
        skip = 32;
    }
    out = literal(out, in + pending, n - pending);
    return (size_t)(out - start);
}

static uint8_t work[WORK_MAX];          /* a chunk, compressed: wiped by snappy_wipe */

void snappy_wipe(void)
{
    explicit_bzero(work, sizeof work);
}

size_t snappy_chunk(const uint8_t *in, size_t n, uint8_t out[SNAPPY_CHUNK_MAX])
{
    uint32_t crc = masked(crc32c(in, n));
    size_t packed = compress(in, n, work), len = packed < n ? packed : n;

    out[0] = packed < n ? 0x00 : 0x01;
    out[1] = (uint8_t)(len + 4);
    out[2] = (uint8_t)((len + 4) >> 8);
    out[3] = (uint8_t)((len + 4) >> 16);
    out[4] = (uint8_t)crc;
    out[5] = (uint8_t)(crc >> 8);
    out[6] = (uint8_t)(crc >> 16);
    out[7] = (uint8_t)(crc >> 24);
    memcpy(out + 8, packed < n ? work : in, len);
    return 8 + len;
}

const char *snappy_selftest(void)
{
    /* RFC 3720, B.4: 32 bytes of zeros, of ones, rising and falling */
    static const uint32_t want[4] = { 0x8a9136aa, 0x62a8ab43, 0x46dd794e, 0x113fdb5c };
    uint8_t data[32];
    unsigned i, k;

    for (k = 0; k < 4; k++) {
        for (i = 0; i < 32; i++)
            data[i] = (uint8_t)(k == 0 ? 0 : k == 1 ? 0xff : k == 2 ? i : 31 - i);
        if (crc32c(data, 32) != want[k])
            return "CRC-32C";
    }
    return NULL;
}
