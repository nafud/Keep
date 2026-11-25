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

/* manifest.sha256: every file of the run with its SHA-256, in the form of sha256sum, by name. */
void run_manifest(struct run *r);

void run_free(struct run *r);

/* The time now in UTC, for a line of the report or as part of the name of a folder. */
void run_utc(char out[32], int for_name);

/* A run that cannot start: the message to standard error. Returns 1, the exit status. */
int run_die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
