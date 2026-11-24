/*
 * triage.h: the triage of the running system (see triage.c).
 */
#ifndef KEEP_TRIAGE_H
#define KEEP_TRIAGE_H

#define KEEP_VERSION "2.0-pre3 (2026-11)"
#define TRIAGE_ERR_LEN 256

struct triage_options {
    const char *dest;           /* the destination directory */
    unsigned budget;            /* proof attempts per key on the memory route */
};

/* Returns the exit status: 0 when the run completed and was flushed, 1 when it could not start
   or a write or a flush to the destination failed. */
int triage_run(const struct triage_options *o);

/* The open dm-crypt volumes as the triage will list them, for the dialogue: their number, and
   in *names their names for the screen with a space between, which the caller frees. Returns
   -1 with err where the kernel cannot be asked. Needs root. */
int triage_volume_names(char **names, char err[TRIAGE_ERR_LEN]);

#endif
