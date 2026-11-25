/*
 * snappy.h: the framed Snappy format, written (see snappy.c).
 */
#ifndef KEEP_SNAPPY_H
#define KEEP_SNAPPY_H

#include <stddef.h>
#include <stdint.h>

#define SNAPPY_CHUNK     65536u                 /* the most data that one chunk holds */
#define SNAPPY_CHUNK_MAX (8 + SNAPPY_CHUNK)     /* the most bytes that one chunk takes */

/* The chunk that every stream begins with. */
extern const uint8_t snappy_stream_start[10];

/* One chunk of a stream with the N bytes of IN, at most SNAPPY_CHUNK: compressed where that
   makes it shorter, and as it is else. Returns its length. */
size_t snappy_chunk(const uint8_t *in, size_t n, uint8_t out[SNAPPY_CHUNK_MAX]);

/* NULL, or what does not compute the example of its standard. */
const char *snappy_selftest(void);

#endif
