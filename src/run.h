/*
 * run.h: the folder that a run of Keep writes into the destination, and its report (see run.c).
 */
#ifndef KEEP_RUN_H
#define KEEP_RUN_H

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

struct run_file {
    char *name;                         /* relative to the folder of the run */
    char sha256[65];                    /* in hexadecimal, where it was computed while the file was written */
};

struct run {
    char out[PATH_MAX];                 /* the folder of this run */
    FILE *report;                       /* triage.txt, which takes every line of the screen */
    int write_failed;                   /* a write or a flush failed: the run ends with status 1 */
    struct run_file *files;             /* every file of the run, for the manifest */
    size_t nfiles;
    char **stems;                       /* the names that files of volumes and keys have taken */
    size_t nstems;
    char lockdown[64];                  /* the lockdown mode of the kernel */
    unsigned budget;                    /* proof attempts per key in the search of memory */
    int scanned, scan_ok, scan_refused; /* the search of /proc/kcore, made once */
    char scan_error[256];
};

/* One line to the screen and to the report. */
void run_say(struct run *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* A new file of the run, opened with FLAGS. It must not exist, so nothing of an earlier run is
   written over. Returns the descriptor, or -1 with errno. */
int run_create(struct run *r, const char *rel, int flags, mode_t mode);

/* A file that was written without run_create and whose SHA-256 was computed on the way, for the
   manifest. Returns 0, or -1 without memory. */
int run_add(struct run *r, const char *rel, const uint8_t sha256[32]);

/* fsync of a file of the run and of the directory DIR of the run that names it. A failure is
   remembered in write_failed. Returns 0 or -1. */
int run_flush(struct run *r, int fd, const char *dir);

/*
 * A name for the files of a volume or of a key that no other has in this run. FAT and exFAT
 * fold the case of a name, so two names that are the same but for that are kept apart by a
 * further _. Where the room for those is used up the name stays, and the second file is then
 * refused, because no file of a run is written over.
 */
void run_stem(struct run *r, char *stem, size_t size);

/* Write a key to keys/STEM.vk and flush it. Only then does it count as captured. NAME takes
   the first 16 digits of its SHA-256, by which a key is named. Returns 0 or -1. */
int run_keep_key(struct run *r, const char *stem, const uint8_t *key, size_t n, char name[17]);

/* manifest.sha256: every file of the run with its SHA-256, in the form of sha256sum, by name. */
void run_manifest(struct run *r);

/* A text as a JSON string, or null for an empty one or none. The two characters that end or
   escape a string are escaped, control characters become spaces, and a byte that is no UTF-8
   becomes the replacement character. */
void run_json(FILE *f, const char *s);

void run_free(struct run *r);

/*
 * Keys pass through the memory of a run. Locked memory is not written to the swap space. The
 * memory is locked, also what is allocated later, where the lock can hold: where the limit of
 * locked memory does not apply to this process, or is none. Elsewhere a lock would make every
 * larger allocation fail, so none is taken. Returns 0, or -1 with WHY, a line for the report.
 */
int run_lock_memory(char why[160]);

/* The time now in UTC, for a line of the report or as part of the name of a folder. */
void run_utc(char out[32], int for_name);

/* A run that cannot start: the message to standard error. Returns 1, the exit status. */
int run_die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
