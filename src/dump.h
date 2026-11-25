/*
 * dump.h: the search of a memory dump that exists (see dump.c).
 */
#ifndef KEEP_DUMP_H
#define KEEP_DUMP_H

#include <stddef.h>

struct dump_options {
    const char *dump;           /* the memory dump */
    const char *dest;           /* the destination directory */
    char **files;               /* header backups and raw images of disks, to prove the keys against */
    size_t nfiles;
    int plain;                  /* -n: no colour on the screen and no line that is written over */
};

/* Returns the exit status: that of the search of the dump, 1 when the run could not start or a
   write or a flush to the destination failed, and with files 1 also where no header was found
   in them or a header has a key that is not proven. */
int dump_run(const struct dump_options *o);

#endif
