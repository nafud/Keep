/*
 * dump.h: the search of a memory dump that exists (see dump.c).
 */
#ifndef KEEP_DUMP_H
#define KEEP_DUMP_H

struct dump_options {
    const char *dump;           /* the memory dump */
    const char *dest;           /* the destination directory */
};

/* Returns the exit status: that of the search of the dump, or 1 when the run could not start
   or a write or a flush to the destination failed. */
int dump_run(const struct dump_options *o);

#endif
