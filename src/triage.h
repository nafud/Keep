/*
 * triage.h: the triage of the running system (see triage.c).
 */
#ifndef KEEP_TRIAGE_H
#define KEEP_TRIAGE_H

#define KEEP_VERSION "2.0-pre6 (2026-11)"
#include "image.h"

#include <stddef.h>

struct triage_options {
    const char *dest;           /* the destination directory */
    unsigned budget;            /* proof attempts per key on the memory route */
    enum image_format formats[IMAGE_FORMATS];   /* of the memory images to take after the keys */
    size_t nformats;
};

/* Returns the exit status: 0 when the run completed and was flushed, 1 when it could not start,
   a write or a flush to the destination failed, or a memory image that was asked for is not
   there. */
int triage_run(const struct triage_options *o);

#endif
