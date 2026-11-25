/*
 * image.h: the memory of the machine as an image file (see image.c).
 */
#ifndef KEEP_IMAGE_H
#define KEEP_IMAGE_H

#include "hash.h"

#include <stddef.h>
#include <stdint.h>

#define IMAGE_ERR_LEN 256

enum image_format {
    IMAGE_LIME,                 /* LiME: each range behind a header with its addresses */
    IMAGE_RAW,                  /* raw: each byte at the offset that is its physical address */
    IMAGE_AVML,                 /* the compressed format of AVML, version 2 */
    IMAGE_FORMATS
};

/* The name of a format as an option names it, and the ending of its file. */
const char *image_name(enum image_format f);
int image_by_name(const char *name, enum image_format *f);      /* 0, or -1 for another name */

struct image_range {
    uint64_t start, end;        /* physical addresses, the end not included */
    uint64_t offset;            /* of the first byte in the source */
};

struct image_source {
    struct image_range *ranges; /* in the order of their addresses, each byte in one of them */
    size_t nranges;
    uint64_t bytes;             /* in the ranges: the memory that an image holds */
    uint64_t ram;               /* in the RAM ranges that the kernel names */
};

/*
 * What an image of this machine holds: the RAM ranges that IOMEM names (the text of
 * /proc/iomem), as far as CORE offers them (a descriptor of /proc/kcore, an ELF64 core whose
 * segments state physical addresses). Returns 0, or -1 with err.
 */
int image_source(const char *iomem, int core, struct image_source *src, char err[IMAGE_ERR_LEN]);
void image_source_free(struct image_source *src);

/* The size of the image file of a format for this source. For a compressed format it is the
   most that the file can take, and *exact is 0. */
uint64_t image_size(enum image_format f, const struct image_source *src, int *exact);

struct image_file {
    enum image_format format;   /* set by the caller */
    int fd;                     /* an empty file, open for writing: image_open */
    int direct;                 /* it is written with direct writes: image_open, image_write */
    int failed;                 /* the errno of the write that failed, 0 for a complete image */
    uint64_t bytes;             /* the size of the file */
    uint8_t sha256[32];         /* of the file, computed while it was written */
    struct hash_ctx hash;
    uint64_t pos;               /* the address behind the last byte written, for the raw format */
    uint8_t *out;               /* what is not yet in the file, at an address that a direct write takes */
    size_t fill;
    uint64_t at;                /* the offset of the file at which out begins */
};

/*
 * Make the file of an image at PATH, which must not exist, for its owner alone. It is opened
 * for direct writes (O_DIRECT), which pass the page cache, and where the file system has
 * none of those, for writes through the cache, with f->direct 0. Returns 0, or -1 with errno.
 */
int image_open(struct image_file *f, const char *path);

/*
 * Read the memory of SRC once from CORE and write it to every file of FILES, each in its
 * format. A file whose write fails is left as it is and the others go on. A stretch that
 * cannot be read is written as zeros and counted in *unread. PROGRESS, where given, is called
 * with the bytes of memory done so far. Returns 0 when the memory was read to its end and at
 * least one file is complete, or -1 with err. A file that refused a direct write is written
 * through the page cache from there on and has direct 0.
 */
int image_write(int core, const struct image_source *src, struct image_file *files, size_t nfiles,
                void (*progress)(void *arg, uint64_t done), void *arg, uint64_t *unread,
                char err[IMAGE_ERR_LEN]);

/*
 * Flush a file that image_write has written to its device, and let the pages that the page
 * cache holds of it go. Returns 0, or -1 with errno where the flush failed.
 */
int image_settle(struct image_file *f);

#endif
