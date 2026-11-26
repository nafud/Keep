/*
 * keyscan.h: the search for AES key schedules of kcore-keyscan.c, for the program that links it.
 */
#ifndef KEEP_KEYSCAN_H
#define KEEP_KEYSCAN_H

#include <signal.h>
#include <stdint.h>
#include <stdio.h>

struct keyscan_hit {
    int nk;                     /* words of the key: 4 for AES-128, 8 for AES-256 */
    uint64_t phys;              /* the physical address of the schedule */
    uint8_t key[32];            /* its first 4 * nk bytes */
};

int keyscan_run(const char *path, int raw, unsigned every, FILE *keys, FILE *msg, int *failed);
const struct keyscan_hit *keyscan_hits(int *n);         /* in the order they were found */

/* Before a search: FN is then handed the memory that the search reads, each byte once and in
   the order of the search, N bytes at a time with the physical address of the first. Bytes
   that follow each other in memory come in calls that follow each other. NULL ends it. */
void keyscan_watch(void (*fn)(void *arg, const uint8_t *p, size_t n, uint64_t phys), void *arg);
void keyscan_wipe(void);

/* Before a search: the search then ends before its next read once *STOP is not 0. The
   schedules up to there are listed, the search says at which offset of the file it ended,
   and its status is 1. NULL ends it. */
void keyscan_until(const volatile sig_atomic_t *stop);

/* What the last search read, as its message says it: the format it took the file for, the
   segments or ranges of memory, their bytes and the time. NULL for a search that read no
   memory: a file that could not be opened or was refused. */
struct keyscan_summary {
    const char *format;
    int segments;
    unsigned long long bytes;
    double seconds;
    int halted;                 /* the search was ended before its end (keyscan_until) */
};
const struct keyscan_summary *keyscan_summary(void);

/* What the last search said beyond its two lines of counts, N lines: what it warns of (bytes
   that could not be read, an image that ends early, a list that could not be written), or
   why it read nothing. Each is a line of its messages without the name of the scanner. */
const char *const *keyscan_said(int *n);

#endif
