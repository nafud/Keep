/*
 * memory.h: the memory image of a run on the running system (see memory.c).
 */
#ifndef KEEP_MEMORY_H
#define KEEP_MEMORY_H

#include "image.h"
#include "run.h"

struct memory_image {                   /* one image that was asked for, and what became of it */
    enum image_format format;
    const char *status;                 /* captured, skipped or failed */
    char file[48];                      /* in the folder of the run, empty where none is kept */
    uint64_t bytes;
    char sha256[65];
    char note[400];
};

struct memory_result {
    struct memory_image images[IMAGE_FORMATS];
    size_t nimages, captured;
    unsigned seconds;                   /* that the one read of the memory took */
    char system_map[PATH_MAX];          /* the file that memory/System.map is a copy of */
};

/* Take the memory of the machine once and write it in each of the N formats into memory/ of
   the folder of the run, with what the lab needs beside it to name the kernel. */
void memory_run(struct run *r, const enum image_format *formats, size_t n, struct memory_result *res);

#endif
