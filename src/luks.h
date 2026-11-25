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
    unsigned number;                    /* LUKS2: the number that names it in the metadata */
    char hash[32];                      /* the name in the header */
    const struct hash_alg *alg;         /* NULL for a function that is not computed here */
    uint8_t salt[64], digest[HASH_MAX_DIGEST];
    size_t saltlen, digestlen;
    uint32_t iterations;
    size_t key_bytes;                   /* of the key it stands for, 0 where the header does not say */
    char cipher[72];                    /* of the data that key encrypts, as aes-xts-plain64, or empty */
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
 * What of a header can lie in the memory of a machine by itself, and proves a key all the same.
 * luks_header1 reads the 592 bytes of a LUKS1 header, as the kernel has them in its cache of
 * the device. luks_digests reads the object that stands behind "digests" in the metadata of a
 * LUKS2 header, as a program that has read the header has it in its memory: TEXT begins at
 * the brace of that object and need not end with it. Both return 0 with at least one digest,
 * or -1.
 */
int luks_header1(const uint8_t *bytes, size_t len, struct luks_header *h);
int luks_digests(const char *text, size_t len, struct luks_header *h);

/* The same for a header that begins BASE bytes into fd, as that of a partition in the image of
   a disk. */
int luks_read_at(int fd, uint64_t base, struct luks_header *h, char err[LUKS_ERR_LEN]);

/*
 * Write to out what "cryptsetup luksHeaderBackup" writes for this header: the header and the
 * keyslot area as they are on the device, to a multiple of the page size. *written is the number
 * of bytes. Returns 0, or -1 with err.
 */
int luks_backup(int fd, const struct luks_header *h, int out, uint64_t *written, char err[LUKS_ERR_LEN]);

/*
 * Whether a key gives a digest of the header. Returns the number of that digest, counted from 1,
 * or 0 where it gives none, or -1 where no digest could be tried because none of them is
 * computed here, with the name of the hash function in *hash. A header in re-encryption has a
 * digest for the old key and one for the new: TAKEN has bit n set for the digest n + 1 that
 * another key of the volume gives already, and that digest is not tried.
 */
int luks_proves(const struct luks_header *h, const uint8_t *key, size_t keylen, unsigned taken, const char **hash);

/* Whether the UUID of a mapping, as cryptsetup sets it (CRYPT-LUKS2-<32 digits>-<name>), names
   this header: crypt_uuid_cmp of cryptsetup. */
int luks_uuid_matches(const struct luks_header *h, const char *dm_uuid);

#endif
