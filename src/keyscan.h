/*
 * keyscan.h: the search for AES key schedules of kcore-keyscan.c, for the program that links it.
 */
#ifndef KEEP_KEYSCAN_H
#define KEEP_KEYSCAN_H

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

/* What the last search read, as its message says it: the format it took the file for, the
   segments or ranges of memory, their bytes and the time. NULL for a search that read no
   memory: a file that could not be opened or was refused. */
struct keyscan_summary {
    const char *format;
    int segments;
    unsigned long long bytes;
    double seconds;
};
const struct keyscan_summary *keyscan_summary(void);

#endif
