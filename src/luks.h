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
/*
 * The most iterations of a digest that are computed. cryptsetup makes a digest to cost 125 ms
 * on the machine that formats (LUKS_MKD_ITERATIONS_MS in lib/luks1/luks.h and
 * lib/luks2/luks2_digest_pbkdf2.c), which is some hundred thousand iterations: about 430000
 * with SHA-256 where the processor has its instructions. A header can state up to 4294967295,
 * and one attempt with that many takes from 21 minutes to more than an hour. So a digest
 * beyond this bound is
 * named as one that is not computed here, like one with an unknown function, and the key and
 * the list of the schedules are kept for the lab.
 */
#define LUKS_MOST_ITERATIONS (1u << 24)

struct luks_digest {                    /* PBKDF2 of a volume key, as the header stores it */
    unsigned number;                    /* LUKS2: the number that names it in the metadata */
    char hash[32];                      /* the name in the header */
    const struct hash_alg *alg;         /* NULL for a function that is not computed here */
    char uncomputed[64];                /* what of it is not computed here: the function, or its number of
                                           iterations. Empty for a digest that is */
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
 * Open a device or a file for the reads of its header, read-only: with O_DIRECT, which reads
 * past the page cache, as cryptsetup opens a device, and in the usual way where the open or a
 * first read with it is refused. *direct says which. Returns the descriptor, or -1 with errno.
 */
int luks_open(const char *path, int *direct);

/*
 * Read the header at the start of fd, a device or a file. A descriptor that is open with
 * O_DIRECT is read in whole blocks, past the page cache. Returns 0, 1 where there is no LUKS
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

struct luks_copy {                      /* the copy of a header that luks_backup writes */
    int direct;                         /* set by the caller: the file is open for direct writes (create_direct).
                                           0 afterwards where a write had to go through the page cache */
    uint64_t bytes;                     /* written */
    uint8_t sha256[32];                 /* of a copy that is complete */
    int write_failed;                   /* it failed at a write to the file, and not at a read of the device */
};

/*
 * Write to out, an empty file, what "cryptsetup luksHeaderBackup" writes for this header: the
 * header and the keyslot area as they are on the device, to a multiple of the page size.
 * Returns 0, or -1 with err.
 */
int luks_backup(int fd, const struct luks_header *h, int out, struct luks_copy *copy, char err[LUKS_ERR_LEN]);

/*
 * Whether a key gives a digest of the header. Returns the number of that digest, counted from 1,
 * or 0 where it gives none, or -1 where no digest could be tried because none of them is
 * computed here, with what is not, the hash function or the number of iterations, in *hash. A header in re-encryption has a
 * digest for the old key and one for the new: TAKEN has bit n set for the digest n + 1 that
 * another key of the volume gives already, and that digest is not tried.
 */
int luks_proves(const struct luks_header *h, const uint8_t *key, size_t keylen, unsigned taken, const char **hash);

/* Whether the UUID of a mapping, as cryptsetup sets it (CRYPT-LUKS2-<32 digits>-<name>), names
   this header: crypt_uuid_cmp of cryptsetup. */
int luks_uuid_matches(const struct luks_header *h, const char *dm_uuid);

#endif
