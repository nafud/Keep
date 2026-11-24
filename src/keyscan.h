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
void keyscan_wipe(void);

#endif
