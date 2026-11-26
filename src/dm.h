/*
 * dm.h: what Keep asks of the kernel's device-mapper, through its control device.
 *
 * Keep reads two things: the list of the mapped devices and the table of one of them. Both are
 * ioctls of /dev/mapper/control that change nothing (DM_LIST_DEVICES and DM_TABLE_STATUS in
 * drivers/md/dm-ioctl.c). The table of a crypt target is what "dmsetup table --showkeys" prints:
 * the kernel hands the key of a mapping to every caller with CAP_SYS_ADMIN, and it is dmsetup
 * that replaces it by zeros (_status in dmsetup.c of LVM2).
 */
#ifndef KEEP_DM_H
#define KEEP_DM_H

#include <stddef.h>
#include <stdint.h>

#define DM_NAME_LEN 128                 /* with the final zero byte, as in the kernel */
#define DM_UUID_LEN 129
#define DM_TYPE_LEN 16

struct dm_dev {                         /* one mapped device of the list */
    char name[DM_NAME_LEN];
    unsigned major, minor;
};

struct dm_target {                      /* one line of a table */
    uint64_t start, length;             /* in sectors of 512 bytes */
    char type[DM_TYPE_LEN + 1];
    char *params;                       /* inside the buffer of the table */
};

struct dm_table {
    char name[DM_NAME_LEN];
    char uuid[DM_UUID_LEN];             /* empty where the device has none */
    unsigned major, minor;
    size_t ntargets;
    struct dm_target *targets;
    void *buf;                          /* what the kernel wrote: it can hold a key */
    size_t buflen;
};

/* Every function returns 0, or -1 with one line in err that says what failed. */
#define DM_ERR_LEN 256

int dm_open(char err[DM_ERR_LEN]);                              /* returns the descriptor */
int dm_list(int fd, struct dm_dev **devs, size_t *ndevs, char err[DM_ERR_LEN]);
/* The table of the device NAME. Also returns 1, where the kernel has no device of that name:
   one that was removed since the list was read. */
int dm_table(int fd, const char *name, struct dm_table *t, char err[DM_ERR_LEN]);
void dm_table_free(struct dm_table *t);                         /* wipes the buffer */

/* The two answers of the kernel as bytes, which is what dm_list and dm_table read them from.
   dm_table_answer takes the buffer, which malloc gave, as its own, also where it fails. */
int dm_list_answer(const void *buf, size_t len, struct dm_dev **devs, size_t *ndevs, char err[DM_ERR_LEN]);
int dm_table_answer(void *buf, size_t len, struct dm_table *t, char err[DM_ERR_LEN]);

#endif
