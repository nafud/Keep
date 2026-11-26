/*
 * volume.h: the encrypted volumes that the tables of the mapped devices describe.
 *
 * A volume is mostly one mapped device with one crypt target. cryptsetup builds two kinds of
 * volume from more than that, and this part reads both off the tables as cryptsetup itself does
 * when it is asked about an open volume (_init_by_name_crypt in lib/setup.c):
 *
 *   integrity       LUKS2 with integrity. The crypt target of NAME lies on the dm-integrity
 *                   device NAME_dif, and the header of the volume lies on the device below
 *                   that one (create_or_reload_device_with_integrity).
 *   re-encryption   While cryptsetup re-encrypts an open volume, NAME is a linear target on
 *                   NAME-overlay, whose table has the crypt targets with the old and the new
 *                   key, and one of those lies on NAME-hotzone-forward or -backward
 *                   (reencrypt_init_device_stack in luks2_reencrypt.c). The two helpers carry
 *                   the UUID CRYPT-SUBDEV-<UUID of the volume>-<name> and are the volume's by
 *                   that, also in the moment in which cryptsetup has made them and not yet put
 *                   them below NAME. A volume that was closed or interrupted in that state has
 *                   the crypt targets of both keys in the table of NAME itself
 *                   (LUKS2_assembly_multisegment_dmd).
 *
 * Nothing here asks the kernel anything: the tables are given, so the checks can give their own.
 */
#ifndef KEEP_VOLUME_H
#define KEEP_VOLUME_H

#include "dm.h"
#include "util.h"

#define VOL_ERR_LEN 256
#define VOL_CIPHER_LEN 128

struct vol_crypt {                      /* the line of a crypt target, as crypt_status writes it */
    const char *cipher, *key;           /* inside the line. The key is hexadecimal, a reference */
    size_t cipher_len, key_len;         /* ":size:type:description" or "-" for none */
    unsigned major, minor;              /* the device below */
    unsigned tag_size;                  /* of the option integrity:<size>:<algorithm>, else 0 */
    char auth[128];                     /* its algorithm, a name of the kernel's crypto API */
};

/* 0, or -1 for a line that is not the line of a crypt target. */
int vol_crypt_line(const char *params, struct vol_crypt *c);

struct vol_key {                        /* one key of a volume, and the crypt targets that use it */
    char cipher[VOL_CIPHER_LEN];        /* as the table names it */
    const char *field;                  /* the key field, inside the buffer of a table */
    size_t field_len;
    uint64_t sectors;                   /* how much those targets map, in sectors of 512 bytes */
    const struct dm_table *counted;     /* while the tables are read: the one that is counted */
    uint64_t in_table;                  /* and what the key maps in it */
};

struct vol {
    const struct dm_table *top;         /* the device that carries the name of the volume */
    const struct dm_table **parts;      /* the helper devices of a re-encryption that are part of */
    size_t nparts;                      /* it: those that its tables name, in that order, then the rest */
    const struct dm_table *below;       /* the dm-integrity device below its crypt target, or NULL */
    struct vol_key *keys;               /* in the order of the tables, each once */
    size_t nkeys;
    size_t not_understood;              /* crypt targets whose line could not be read */
    int has_device;                     /* the device with the data and, for LUKS, the header */
    unsigned major, minor;
    unsigned tag_size;                  /* integrity: the size of a tag and its algorithm */
    char auth[128];
};

/*
 * The volumes among these tables, sorted by name. Returns 0, or -1 with err. The volumes point
 * into the tables, which must stay as long as they are used. vol_free frees the list.
 */
int vol_find(const struct dm_table *tabs, size_t ntabs, struct vol **vols, size_t *nvols, char err[VOL_ERR_LEN]);
void vol_free(struct vol *vols, size_t nvols);

/* What the kernel said about a mapped device, added to TEXT as "dmsetup table" prints it, with
   each key replaced by zeros: the key of a crypt target, and the keys that a dm-integrity
   target can have for its hash, for the encryption of its journal and for the journal's MAC
   (hide_key in dmsetup.c of LVM2 2.03.22). */
void vol_table_text(struct str *text, const struct dm_table *t);

#endif
