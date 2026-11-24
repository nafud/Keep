/*
 * dm.c: the list of the mapped devices and the table of one of them, read from the kernel.
 *
 * The structures and numbers below are those of include/uapi/linux/dm-ioctl.h, interface
 * version 4, which has not changed its layout since Linux 2.6. They are written out here
 * because a C library does not carry that header, and a static build must not depend on the
 * kernel headers of the machine that builds it.
 *
 * A request names version 4.0.0, as dmsetup does for "names" and "table" (_cmd_data_v4 in
 * libdm-iface.c): the kernel refuses a caller whose minor version is above its own
 * (check_version in dm-ioctl.c), and neither request needs anything newer.
 */
#include "dm.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct dm_ioctl {
    uint32_t version[3];
    uint32_t data_size;                 /* of the whole buffer, this structure included */
    uint32_t data_start;                /* offset of the data from the start of the buffer */
    uint32_t target_count;
    int32_t  open_count;
    uint32_t flags;
    uint32_t event_nr;
    uint32_t padding;
    uint64_t dev;
    char name[DM_NAME_LEN];
    char uuid[DM_UUID_LEN];
    char data[7];
};

struct dm_target_spec {
    uint64_t sector_start;
    uint64_t length;
    int32_t  status;
    uint32_t next;                      /* from the first of them to the next one */
    char target_type[DM_TYPE_LEN];
};

struct dm_name_list {
    uint64_t dev;
    uint32_t next;                      /* from this one to the next one, 0 at the last */
    char name[];
};

_Static_assert(sizeof(struct dm_ioctl) == 312, "struct dm_ioctl of the kernel has 312 bytes");
_Static_assert(sizeof(struct dm_target_spec) == 40, "struct dm_target_spec of the kernel has 40 bytes");
_Static_assert(offsetof(struct dm_name_list, name) == 12, "the name of a dm_name_list begins at 12");

#define DM_IOCTL_TYPE           0xfd
#define DM_LIST_DEVICES         _IOWR(DM_IOCTL_TYPE, 2, struct dm_ioctl)
#define DM_TABLE_STATUS         _IOWR(DM_IOCTL_TYPE, 12, struct dm_ioctl)

#define DM_STATUS_TABLE_FLAG    (1u << 4)       /* in: the table, not the status */
#define DM_BUFFER_FULL_FLAG     (1u << 8)       /* out: the answer did not fit */
#define DM_SECURE_DATA_FLAG     (1u << 15)      /* in: the kernel wipes its copy of the buffer */

#define FIRST_BUFFER            (16u * 1024)    /* what libdevmapper starts with */
#define LARGEST_BUFFER          (16u * 1024 * 1024)

static void wipe_free(void *p, size_t n)
{
    if (p) {
        explicit_bzero(p, n);
        free(p);
    }
}

/* The device number as the kernel packs it into 64 bits (new_encode_dev in kdev_t.h). */
static void decode_dev(uint64_t dev, unsigned *major, unsigned *minor)
{
    *major = (unsigned)((dev & 0xfff00) >> 8);
    *minor = (unsigned)((dev & 0xff) | ((dev >> 12) & 0xfff00));
}

/*
 * One request. The buffer is doubled as long as the kernel says that its answer did not fit.
 * On success the buffer is the caller's, with its length in *len.
 */
static int request(int fd, unsigned long cmd, const char *what, const char *name, uint32_t flags,
                   struct dm_ioctl **out, size_t *len, char err[DM_ERR_LEN])
{
    size_t n;

    for (n = FIRST_BUFFER; n <= LARGEST_BUFFER; n *= 2) {
        struct dm_ioctl *io = calloc(1, n);

        if (!io) {
            snprintf(err, DM_ERR_LEN, "%s: no memory for %zu bytes", what, n);
            return -1;
        }
        io->version[0] = 4;
        io->data_size = (uint32_t)n;
        io->data_start = sizeof *io;
        io->flags = flags;
        if (name)
            memcpy(io->name, name, strlen(name));
        if (ioctl(fd, cmd, io) < 0) {
            snprintf(err, DM_ERR_LEN, "%s: %s", what, strerror(errno));
            wipe_free(io, n);
            return -1;
        }
        if (!(io->flags & DM_BUFFER_FULL_FLAG)) {
            *out = io;
            *len = n;
            return 0;
        }
        wipe_free(io, n);
    }
    snprintf(err, DM_ERR_LEN, "%s: the answer of the kernel does not fit %u bytes", what, LARGEST_BUFFER);
    return -1;
}

/*
 * Where the data of an answer lies. An answer without data states a size below the start of
 * the data (ctl_ioctl sets it to the offset of the member data), which is no data.
 */
static size_t answer(const struct dm_ioctl *io, size_t len, const char **data)
{
    if (io->data_size > len || io->data_start < sizeof *io || io->data_start >= io->data_size)
        return 0;
    *data = (const char *)io + io->data_start;
    return io->data_size - io->data_start;
}

int dm_open(char err[DM_ERR_LEN])
{
    int fd = open("/dev/mapper/control", O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        snprintf(err, DM_ERR_LEN, "/dev/mapper/control: %s", strerror(errno));
    return fd;
}

int dm_list(int fd, struct dm_dev **devs, size_t *ndevs, char err[DM_ERR_LEN])
{
    struct dm_ioctl *io;
    size_t len;
    int r;

    *devs = NULL;
    *ndevs = 0;
    if (request(fd, DM_LIST_DEVICES, "the list of the mapped devices", NULL, 0, &io, &len, err))
        return -1;
    r = dm_list_answer(io, len, devs, ndevs, err);
    free(io);
    return r;
}

int dm_list_answer(const void *buf, size_t len, struct dm_dev **devs, size_t *ndevs, char err[DM_ERR_LEN])
{
    const struct dm_ioctl *io = buf;
    struct dm_dev *list = NULL;
    const char *data = NULL;
    size_t avail, off = 0, count = 0, room = 0;
    int r = -1;

    *devs = NULL;
    *ndevs = 0;
    if (len < sizeof *io)
        goto malformed;
    avail = answer(io, len, &data);
    while (avail) {
        struct dm_name_list head;
        const char *name, *end;

        if (avail - off <= offsetof(struct dm_name_list, name))
            goto malformed;
        memcpy(&head, data + off, offsetof(struct dm_name_list, name));
        if (off == 0 && head.dev == 0)          /* list_devices: "Flags no data" */
            break;
        name = data + off + offsetof(struct dm_name_list, name);
        end = memchr(name, 0, avail - off - offsetof(struct dm_name_list, name));
        if (!end || end == name || (size_t)(end - name) >= DM_NAME_LEN)
            goto malformed;
        if (count == room) {
            struct dm_dev *grown = realloc(list, (room ? room * 2 : 16) * sizeof *list);

            if (!grown) {
                snprintf(err, DM_ERR_LEN, "the list of the mapped devices: no memory");
                goto out;
            }
            list = grown;
            room = room ? room * 2 : 16;
        }
        memset(&list[count], 0, sizeof list[count]);
        memcpy(list[count].name, name, (size_t)(end - name));
        decode_dev(head.dev, &list[count].major, &list[count].minor);
        count++;
        if (!head.next)
            break;
        if (head.next <= offsetof(struct dm_name_list, name) || head.next >= avail - off)
            goto malformed;
        off += head.next;
    }
    *devs = list;
    *ndevs = count;
    list = NULL;
    r = 0;
    goto out;
malformed:
    snprintf(err, DM_ERR_LEN, "the list of the mapped devices: the answer of the kernel is not understood");
out:
    free(list);
    return r;
}

int dm_table(int fd, const char *name, struct dm_table *t, char err[DM_ERR_LEN])
{
    struct dm_ioctl *io;
    size_t len;

    memset(t, 0, sizeof *t);
    if (!*name || strlen(name) >= DM_NAME_LEN) {
        snprintf(err, DM_ERR_LEN, "the table of a mapped device: a name of %zu bytes", strlen(name));
        return -1;
    }
    if (request(fd, DM_TABLE_STATUS, "the table of a mapped device", name,
                DM_STATUS_TABLE_FLAG | DM_SECURE_DATA_FLAG, &io, &len, err))
        return -1;
    return dm_table_answer(io, len, t, err);
}

int dm_table_answer(void *buf, size_t len, struct dm_table *t, char err[DM_ERR_LEN])
{
    struct dm_ioctl *io = buf;
    const char *data = NULL;
    size_t avail, off = 0, i;

    memset(t, 0, sizeof *t);
    t->buf = buf;
    t->buflen = len;
    if (len < sizeof *io)
        goto malformed;
    io->name[DM_NAME_LEN - 1] = 0;
    io->uuid[DM_UUID_LEN - 1] = 0;
    memcpy(t->name, io->name, DM_NAME_LEN);
    memcpy(t->uuid, io->uuid, DM_UUID_LEN);
    decode_dev(io->dev, &t->major, &t->minor);
    avail = answer(io, len, &data);
    if (!io->target_count)
        return 0;
    if (io->target_count > avail / (sizeof(struct dm_target_spec) + 1))  /* each has a line of a byte at least */
        goto malformed;
    t->targets = calloc(io->target_count, sizeof *t->targets);
    if (!t->targets) {
        snprintf(err, DM_ERR_LEN, "the table of a mapped device: no memory");
        dm_table_free(t);
        return -1;
    }
    for (i = 0; i < io->target_count; i++) {
        struct dm_target_spec spec;
        char *params;

        if (off >= avail || avail - off <= sizeof spec)
            goto malformed;
        memcpy(&spec, data + off, sizeof spec);
        params = (char *)io + io->data_start + off + sizeof spec;
        if (!memchr(params, 0, avail - off - sizeof spec))
            goto malformed;
        t->targets[i].start = spec.sector_start;
        t->targets[i].length = spec.length;
        memcpy(t->targets[i].type, spec.target_type, DM_TYPE_LEN);
        t->targets[i].params = params;
        t->ntargets = i + 1;
        if (spec.next <= off)                   /* the next one lies behind this one */
            goto malformed;
        off = spec.next;
    }
    return 0;
malformed:
    snprintf(err, DM_ERR_LEN, "the table of a mapped device: the answer of the kernel is not understood");
    dm_table_free(t);
    return -1;
}

void dm_table_free(struct dm_table *t)
{
    free(t->targets);
    wipe_free(t->buf, t->buflen);
    memset(t, 0, sizeof *t);
}
