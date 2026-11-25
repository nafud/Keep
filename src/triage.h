/*
 * triage.h: the triage of the running system (see triage.c).
 */
#ifndef KEEP_TRIAGE_H
#define KEEP_TRIAGE_H

#define KEEP_VERSION "2.0-pre4 (2026-11)"
#define TRIAGE_ERR_LEN 256

struct triage_options {
    const char *dest;           /* the destination directory */
    unsigned budget;            /* proof attempts per key on the memory route */
};

/* Returns the exit status: 0 when the run completed and was flushed, 1 when it could not start
   or a write or a flush to the destination failed. */
int triage_run(const struct triage_options *o);

#endif
