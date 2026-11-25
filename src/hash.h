/*
 * hash.h: the hash functions that Keep computes itself, HMAC and PBKDF2 (see hash.c).
 */
#ifndef KEEP_HASH_H
#define KEEP_HASH_H

#include <stddef.h>
#include <stdint.h>

#define HASH_MAX_DIGEST 64
#define HASH_MAX_BLOCK  128

struct hash_alg;

struct hash_ctx {
    const struct hash_alg *alg;
    union { uint32_t w32[8]; uint64_t w64[8]; } h;
    uint8_t buf[HASH_MAX_BLOCK];
    size_t fill;
    uint64_t total;
};

/* The function of a name as cryptsetup writes it into a header: sha1, sha224, sha256, sha384,
   sha512. NULL for a name that is not computed here. */
const struct hash_alg *hash_by_name(const char *name);
const char *hash_name(const struct hash_alg *alg);
size_t hash_len(const struct hash_alg *alg);

void hash_init(struct hash_ctx *c, const struct hash_alg *alg);
void hash_update(struct hash_ctx *c, const void *data, size_t n);
void hash_final(struct hash_ctx *c, uint8_t *out);              /* hash_len bytes, wipes c */

void sha256(const void *data, size_t n, uint8_t out[32]);
void hmac(const struct hash_alg *alg, const uint8_t *key, size_t keylen,
          const uint8_t *data, size_t n, uint8_t *out);
void pbkdf2(const struct hash_alg *alg, const uint8_t *key, size_t keylen,
            const uint8_t *salt, size_t saltlen, uint32_t iterations, uint8_t *out, size_t outlen);

const char *hash_selftest(void);        /* NULL, or the name of what does not compute right */

/* SHA-224 and SHA-256 are computed with the SHA instructions of the processor where it has
   them. hash_with_cpu says whether they are in use, and hash_plain(1) has every digest computed
   without them, so that the checks can compare both ways on one machine. */
int hash_with_cpu(void);
void hash_plain(int on);

#endif
