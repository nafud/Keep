/*
 * luks.h: the header of a LUKS1 or LUKS2 volume: what it says, a copy of it for the evidence,
 * and the proof of a volume key against its digest.
 */
#ifndef KEEP_LUKS_H
#define KEEP_LUKS_H

#include "hash.h"

#include <stddef.h>
#include <stdint.h>

#define LUKS_ERR_LEN 256
#define LUKS_MAX_DIGESTS 8              /* LUKS2_DIGEST_MAX of cryptsetup */

struct luks_digest {                    /* PBKDF2 of a volume key, as the header stores it */
    char hash[32];                      /* the name in the header */
    const struct hash_alg *alg;         /* NULL for a function that is not computed here */
    uint8_t salt[64], digest[HASH_MAX_DIGEST];
    size_t saltlen, digestlen;
    uint32_t iterations;
};

struct luks_header {
    int version;                        /* 1 or 2 */
    int secondary;                      /* LUKS2: the second copy is the one in use */
    char uuid[41];
    uint64_t area;                      /* bytes of the header and the keyslots on the device */
    uint64_t zero_from, zero_to;        /* LUKS1: a stretch that a backup holds as zeros */
    size_t ndigests;
    struct luks_digest digests[LUKS_MAX_DIGESTS];
};

/*
 * Read the header at the start of fd, a device or a file. Returns 0, 1 where there is no LUKS
 * header (err says what is there instead) and -1 where a read failed or a header is damaged.
 */
int luks_read(int fd, struct luks_header *h, char err[LUKS_ERR_LEN]);

/*
 * Write to out what "cryptsetup luksHeaderBackup" writes for this header: the header and the
 * keyslot area as they are on the device, to a multiple of the page size. *written is the number
 * of bytes. Returns 0, or -1 with err.
 */
int luks_backup(int fd, const struct luks_header *h, int out, uint64_t *written, char err[LUKS_ERR_LEN]);

/*
 * Whether a key gives a digest of the header: 1 yes, 0 no, and -1 where no digest of the header
 * can be computed here, with the name of its hash function in *hash.
 */
int luks_proves(const struct luks_header *h, const uint8_t *key, size_t keylen, const char **hash);

/* Whether the UUID of a mapping, as cryptsetup sets it (CRYPT-LUKS2-<32 digits>-<name>), names
   this header: crypt_uuid_cmp of cryptsetup. */
int luks_uuid_matches(const struct luks_header *h, const char *dm_uuid);

#endif
