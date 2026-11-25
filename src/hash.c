/*
 * hash.c: SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 (FIPS 180-4), HMAC (RFC 2104) and PBKDF2
 * (RFC 8018, section 5.2).
 *
 * A LUKS header stores a PBKDF2 digest of its volume key, and Keep names a key by its SHA-256
 * and lists the files of a run by theirs. The code is written from the standards, with no
 * library, so that the program is one static file. hash_selftest compares it with the examples
 * of the standards at every start.
 *
 * A memory image is as long as the memory of the machine, and its SHA-256 is computed while it
 * is written. Where the processor has the SHA instructions (CPUID leaf 7, EBX bit 29), a block
 * of SHA-256 is computed with them, which is several times as fast. The self-test computes its
 * examples both ways.
 */
#include "hash.h"

#include <string.h>

#if defined(__x86_64__)
#include <cpuid.h>
#include <immintrin.h>
#endif

/* The round constants of FIPS 180-4, 4.2.2 and 4.2.3: the first 32 and 64 bits of the
   fractional parts of the cube roots of the first 64 and 80 primes. */
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

/* The initial values of FIPS 180-4, 5.3: fractional parts of the square roots of primes. */
static const uint32_t H1[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
static const uint32_t H224[8] = {
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};
static const uint32_t H256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};
static const uint64_t H384[8] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL
};
static const uint64_t H512[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

enum family { SHA_1, SHA_256, SHA_512 };

struct hash_alg {
    const char *name;
    enum family family;
    size_t digest_len, block_len;
    const void *initial;
};

static const struct hash_alg algs[] = {
    { "sha1",   SHA_1,   20, 64,  H1 },
    { "sha224", SHA_256, 28, 64,  H224 },
    { "sha256", SHA_256, 32, 64,  H256 },
    { "sha384", SHA_512, 48, 128, H384 },
    { "sha512", SHA_512, 64, 128, H512 },
};

const struct hash_alg *hash_by_name(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof algs / sizeof algs[0]; i++)
        if (!strcmp(name, algs[i].name))
            return &algs[i];
    return NULL;
}

const char *hash_name(const struct hash_alg *alg) { return alg->name; }
size_t hash_len(const struct hash_alg *alg) { return alg->digest_len; }

static inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static inline uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline uint64_t be64(const uint8_t *p)
{
    return (uint64_t)be32(p) << 32 | be32(p + 4);
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

/* FIPS 180-4, 6.1.2 */
static void sha1_block(uint32_t h[5], const uint8_t *p)
{
    uint32_t w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f, k, t;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = be32(p + 4 * i);
    for (; i < 80; i++)
        w[i] = rol32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & c) ^ (~b & d);          k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) ^ (b & d) ^ (c & d); k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;                   k = 0xca62c1d6; }
        t = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

/* FIPS 180-4, 6.2.2 */
static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], s[8], t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = be32(p + 4 * i);
    for (; i < 64; i++)
        w[i] = (ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10)) + w[i - 7]
             + (ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 16];
    memcpy(s, h, sizeof s);
    for (i = 0; i < 64; i++) {
        t1 = s[7] + (ror32(s[4], 6) ^ ror32(s[4], 11) ^ ror32(s[4], 25))
           + ((s[4] & s[5]) ^ (~s[4] & s[6])) + K256[i] + w[i];
        t2 = (ror32(s[0], 2) ^ ror32(s[0], 13) ^ ror32(s[0], 22))
           + ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));
        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = s[3] + t1;
        s[3] = s[2]; s[2] = s[1]; s[1] = s[0]; s[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++)
        h[i] += s[i];
}

#if defined(__x86_64__)
/*
 * The same block with the SHA instructions (Intel SDM, volume 2: SHA256RNDS2, SHA256MSG1,
 * SHA256MSG2). SHA256RNDS2 does two rounds on the state as the two registers ABEF and CDGH,
 * with two words of the message and their constants. Four words of the schedule are
 * W[t-16] + s0(W[t-15]), which SHA256MSG1 gives, plus W[t-7], plus s1(W[t-2]), which
 * SHA256MSG2 adds.
 */
__attribute__((target("sha,sse4.1,ssse3")))
static void sha256_block_cpu(uint32_t h[8], const uint8_t *p)
{
    const __m128i swap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    __m128i m[4], abef, cdgh, abef0, cdgh0, t;
    int g;

    t = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(const void *)&h[0]), 0xb1);         /* CDAB */
    cdgh = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(const void *)&h[4]), 0x1b);      /* EFGH */
    abef = _mm_alignr_epi8(t, cdgh, 8);
    cdgh = _mm_blend_epi16(cdgh, t, 0xf0);
    abef0 = abef;
    cdgh0 = cdgh;
    for (g = 0; g < 16; g++) {
        __m128i *w = &m[g & 3];         /* the four words of 16 rounds before, then of these four */

        if (g < 4)
            *w = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(p + 16 * g)), swap);
        else
            *w = _mm_sha256msg2_epu32(_mm_add_epi32(_mm_sha256msg1_epu32(*w, m[(g + 1) & 3]),
                                                    _mm_alignr_epi8(m[(g + 3) & 3], m[(g + 2) & 3], 4)),
                                      m[(g + 3) & 3]);
        t = _mm_add_epi32(*w, _mm_loadu_si128((const __m128i *)(const void *)&K256[4 * g]));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, t);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(t, 0x0e));
    }
    abef = _mm_add_epi32(abef, abef0);
    cdgh = _mm_add_epi32(cdgh, cdgh0);
    t = _mm_shuffle_epi32(abef, 0x1b);                                                          /* FEBA */
    cdgh = _mm_shuffle_epi32(cdgh, 0xb1);                                                       /* DCHG */
    _mm_storeu_si128((__m128i *)(void *)&h[0], _mm_blend_epi16(t, cdgh, 0xf0));
    _mm_storeu_si128((__m128i *)(void *)&h[4], _mm_alignr_epi8(cdgh, t, 8));
}

static int cpu_has_sha(void)
{
    unsigned a, b, c, d;

    if (!__get_cpuid(1, &a, &b, &c, &d) || !(c & bit_SSSE3) || !(c & bit_SSE4_1))
        return 0;
    return __get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & bit_SHA);
}
#else
static void sha256_block_cpu(uint32_t h[8], const uint8_t *p) { (void)h; (void)p; }
static int cpu_has_sha(void) { return 0; }
#endif

static int with_cpu = -1;               /* -1 until the processor is asked */

int hash_with_cpu(void)
{
    if (with_cpu < 0)
        with_cpu = cpu_has_sha();
    return with_cpu;
}

void hash_plain(int on)
{
    with_cpu = on ? 0 : -1;
}

/* FIPS 180-4, 6.4.2 */
static void sha512_block(uint64_t h[8], const uint8_t *p)
{
    uint64_t w[80], s[8], t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = be64(p + 8 * i);
    for (; i < 80; i++)
        w[i] = (ror64(w[i - 2], 19) ^ ror64(w[i - 2], 61) ^ (w[i - 2] >> 6)) + w[i - 7]
             + (ror64(w[i - 15], 1) ^ ror64(w[i - 15], 8) ^ (w[i - 15] >> 7)) + w[i - 16];
    memcpy(s, h, sizeof s);
    for (i = 0; i < 80; i++) {
        t1 = s[7] + (ror64(s[4], 14) ^ ror64(s[4], 18) ^ ror64(s[4], 41))
           + ((s[4] & s[5]) ^ (~s[4] & s[6])) + K512[i] + w[i];
        t2 = (ror64(s[0], 28) ^ ror64(s[0], 34) ^ ror64(s[0], 39))
           + ((s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2]));
        s[7] = s[6]; s[6] = s[5]; s[5] = s[4]; s[4] = s[3] + t1;
        s[3] = s[2]; s[2] = s[1]; s[1] = s[0]; s[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++)
        h[i] += s[i];
}

static void block(struct hash_ctx *c, const uint8_t *p)
{
    switch (c->alg->family) {
    case SHA_1:   sha1_block(c->h.w32, p); break;
    case SHA_256:
        if (hash_with_cpu())
            sha256_block_cpu(c->h.w32, p);
        else
            sha256_block(c->h.w32, p);
        break;
    case SHA_512: sha512_block(c->h.w64, p); break;
    }
}

void hash_init(struct hash_ctx *c, const struct hash_alg *alg)
{
    memset(c, 0, sizeof *c);
    c->alg = alg;
    if (alg->family == SHA_512)
        memcpy(c->h.w64, alg->initial, sizeof c->h.w64);
    else
        memcpy(c->h.w32, alg->initial, alg->family == SHA_1 ? 20 : 32);
}

void hash_update(struct hash_ctx *c, const void *data, size_t n)
{
    const uint8_t *p = data;
    size_t bl = c->alg->block_len, take;

    if (!n)                             /* also a null pointer, which memcpy must not be given */
        return;
    c->total += n;
    if (c->fill) {
        take = bl - c->fill < n ? bl - c->fill : n;
        memcpy(c->buf + c->fill, p, take);
        c->fill += take; p += take; n -= take;
        if (c->fill < bl)
            return;
        block(c, c->buf);
        c->fill = 0;
    }
    for (; n >= bl; p += bl, n -= bl)
        block(c, p);
    memcpy(c->buf, p, n);
    c->fill = n;
}

/*
 * The padding of FIPS 180-4, 5.1: a one bit, zeros, and the length of the message in bits as
 * the last 8 bytes of a block, or the last 16 where the block has 128. A message of 2^61 bytes
 * and more does not occur here, so the upper 8 of the 16 are zero.
 */
void hash_final(struct hash_ctx *c, uint8_t *out)
{
    size_t bl = c->alg->block_len, lenlen = bl / 8, i;
    uint64_t bits = c->total * 8;

    c->buf[c->fill++] = 0x80;
    if (c->fill > bl - lenlen) {
        memset(c->buf + c->fill, 0, bl - c->fill);
        block(c, c->buf);
        c->fill = 0;
    }
    memset(c->buf + c->fill, 0, bl - c->fill);
    put_be64(c->buf + bl - 8, bits);
    block(c, c->buf);
    if (c->alg->family == SHA_512) {
        uint8_t full[64];

        for (i = 0; i < 8; i++)
            put_be64(full + 8 * i, c->h.w64[i]);
        memcpy(out, full, c->alg->digest_len);
    } else {
        uint8_t full[32];

        for (i = 0; i < (c->alg->family == SHA_1 ? 5u : 8u); i++)
            put_be32(full + 4 * i, c->h.w32[i]);
        memcpy(out, full, c->alg->digest_len);
    }
    explicit_bzero(c, sizeof *c);
}

void sha256(const void *data, size_t n, uint8_t out[32])
{
    struct hash_ctx c;

    hash_init(&c, hash_by_name("sha256"));
    hash_update(&c, data, n);
    hash_final(&c, out);
}

/*
 * HMAC with its two key blocks absorbed once: the states after the inner and the outer pad are
 * kept, and every further message starts from a copy of them. PBKDF2 runs HMAC once per
 * iteration with the same key, so this halves its work.
 */
struct hmac {
    struct hash_ctx inner, outer;
};

static void hmac_key(struct hmac *m, const struct hash_alg *alg, const uint8_t *key, size_t keylen)
{
    uint8_t k[HASH_MAX_BLOCK], pad[HASH_MAX_BLOCK];
    size_t i;

    memset(k, 0, sizeof k);
    if (keylen > alg->block_len) {
        hash_init(&m->inner, alg);
        hash_update(&m->inner, key, keylen);
        hash_final(&m->inner, k);
    } else {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < alg->block_len; i++)
        pad[i] = k[i] ^ 0x36;
    hash_init(&m->inner, alg);
    hash_update(&m->inner, pad, alg->block_len);
    for (i = 0; i < alg->block_len; i++)
        pad[i] = k[i] ^ 0x5c;
    hash_init(&m->outer, alg);
    hash_update(&m->outer, pad, alg->block_len);
    explicit_bzero(k, sizeof k);
    explicit_bzero(pad, sizeof pad);
}

static void hmac_of(const struct hmac *m, const uint8_t *a, size_t alen, const uint8_t *b, size_t blen,
                    uint8_t *out)
{
    struct hash_ctx c = m->inner;
    size_t dl = c.alg->digest_len;

    hash_update(&c, a, alen);
    hash_update(&c, b, blen);
    hash_final(&c, out);
    c = m->outer;
    hash_update(&c, out, dl);
    hash_final(&c, out);
}

void hmac(const struct hash_alg *alg, const uint8_t *key, size_t keylen,
          const uint8_t *data, size_t n, uint8_t *out)
{
    struct hmac m;

    hmac_key(&m, alg, key, keylen);
    hmac_of(&m, data, n, NULL, 0, out);
    explicit_bzero(&m, sizeof m);
}

void pbkdf2(const struct hash_alg *alg, const uint8_t *key, size_t keylen,
            const uint8_t *salt, size_t saltlen, uint32_t iterations, uint8_t *out, size_t outlen)
{
    struct hmac m;
    uint8_t u[HASH_MAX_DIGEST], t[HASH_MAX_DIGEST], index[4];
    size_t dl = alg->digest_len, i, take;
    uint32_t n, blockno = 1;

    hmac_key(&m, alg, key, keylen);
    for (; outlen; out += take, outlen -= take, blockno++) {
        put_be32(index, blockno);
        hmac_of(&m, salt, saltlen, index, 4, u);
        memcpy(t, u, dl);
        for (n = 1; n < iterations; n++) {
            hmac_of(&m, u, dl, NULL, 0, u);
            for (i = 0; i < dl; i++)
                t[i] ^= u[i];
        }
        take = outlen < dl ? outlen : dl;
        memcpy(out, t, take);
    }
    explicit_bzero(&m, sizeof m);
    explicit_bzero(u, sizeof u);
    explicit_bzero(t, sizeof t);
}

/*
 * The examples of the standards: SHA of "abc" (FIPS 180-4, the examples of NIST for each
 * function), HMAC-SHA-256 of RFC 4231, test case 2, and PBKDF2-HMAC-SHA1 of RFC 6070 with 2
 * iterations. Returns the name of what failed, or NULL.
 */
const char *hash_selftest(void)
{
    static const struct { const char *name; uint8_t first[8]; } abc[] = {
        { "sha1",   { 0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a } },
        { "sha224", { 0x23, 0x09, 0x7d, 0x22, 0x34, 0x05, 0xd8, 0x22 } },
        { "sha256", { 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea } },
        { "sha384", { 0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b } },
        { "sha512", { 0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba } },
    };
    static const uint8_t abc256[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    static const uint8_t rfc4231[32] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    };
    static const uint8_t rfc6070[20] = {
        0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
        0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
    };
    /* FIPS 180-2, B.2: a message of two blocks */
    static const char two[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const uint8_t two256[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1,
    };
    uint8_t out[HASH_MAX_DIGEST];
    struct hash_ctx c;
    size_t i;
    int plain;

    /* with the instructions of the processor where it has them, and without them */
    for (plain = 0; plain < 2; plain++) {
        hash_plain(plain);
        for (i = 0; i < sizeof abc / sizeof abc[0]; i++) {
            hash_init(&c, hash_by_name(abc[i].name));
            hash_update(&c, "abc", 3);
            hash_final(&c, out);
            if (memcmp(out, abc[i].first, 8))
                break;
        }
        if (i < sizeof abc / sizeof abc[0]) {
            hash_plain(0);
            return abc[i].name;
        }
        sha256("abc", 3, out);
        if (!memcmp(out, abc256, 32))
            sha256(two, sizeof two - 1, out);
        if (memcmp(out, two256, 32)) {
            hash_plain(0);
            return plain ? "sha256" : "sha256 with the instructions of the processor";
        }
    }
    hash_plain(0);
    hmac(hash_by_name("sha256"), (const uint8_t *)"Jefe", 4,
         (const uint8_t *)"what do ya want for nothing?", 28, out);
    if (memcmp(out, rfc4231, 32))
        return "hmac";
    pbkdf2(hash_by_name("sha1"), (const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 2, out, 20);
    if (memcmp(out, rfc6070, 20))
        return "pbkdf2";
    return NULL;
}
