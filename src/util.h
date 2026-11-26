/*
 * util.h: small things that several parts of the program need.
 */
#ifndef KEEP_UTIL_H
#define KEEP_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* A text that grows. After a failed allocation it stays as it was and failed is set. */
struct str {
    char *s;
    size_t len, cap;
    int failed;
};
void str_add(struct str *t, const char *s);
void str_addn(struct str *t, const char *s, size_t n);
void str_addf(struct str *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
const char *str_text(const struct str *t);              /* never NULL */
void str_free(struct str *t);

/* The whole of a small text file, with a zero byte behind it, or NULL. At most max bytes are
   read. The files of /proc and /sys state no size, so the file is read until it ends. */
char *read_text(const char *path, size_t max, size_t *len);

/* A name of the examined system for the screen: the kernel takes any byte in a host name and
   in a mapping name, so control characters become spaces before the name reaches a terminal. */
void name_clean(char *s);
/* The same name as part of a file name in the destination: every byte that is not a letter, a
   digit or one of . _ + = @ , - becomes _, so that the name cannot leave the destination and
   FAT and exFAT take it, and so does a point at its start, which would make a file that a
   listing does not show. An empty name becomes _. */
void name_file(const char *name, char *out, size_t outlen);

/* \ooo in a field of /proc/self/mountinfo, /proc/mounts or /proc/swaps, in place. */
void unescape_octal(char *s);

/* A size for a reader: in GiB or MiB with two decimals, rounded, and below a MiB in bytes. */
void size_text(uint64_t bytes, char out[32]);

int hex_decode(const char *hex, size_t digits, uint8_t *out);  /* 0, or -1 for another character */
void hex_encode(const uint8_t *p, size_t n, char *out);        /* 2 * n digits and a zero byte */

/* A path from its parts, as printf writes it. Returns -1 where it does not fit PATH_MAX bytes. */
int pathf(char *out, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

int write_all(int fd, const void *buf, size_t n);              /* 0, or -1 with errno */
/* Flush a stream that was written. Returns 0, or -1 where the flush or a write before it
   failed: a stream drops what it could not write and remembers only that it could not, and a
   later flush of the rest then succeeds. */
int written(FILE *f);
int flush_path(const char *path);                              /* fsync of a file or directory */

/*
 * Writes that pass the page cache (O_DIRECT). A file that is written in the usual way takes
 * free memory of the machine for its pages, and what lay in that memory is gone. A direct write
 * goes from the memory of the program to the device. It must be whole blocks: its place in the
 * file, its length and the address of its memory are multiples of DIRECT_BLOCK, which is a
 * multiple of the block of every device that Linux has up to a page.
 */
#define DIRECT_BLOCK 4096u

/*
 * Make the file PATH, which must not exist, with MODE, and open it as ACCESS says (O_WRONLY or
 * O_RDWR) for direct writes. A file system without them refuses the file at open, and it is
 * then opened for writes through the page cache, with *direct 0. Returns the descriptor, or -1
 * with errno.
 */
int create_direct(const char *path, int access, mode_t mode, int *direct);

/*
 * Write n bytes at OFF of a file. Where *direct is set and the file system refuses the write
 * (EINVAL), the descriptor has O_DIRECT taken off, *direct becomes 0 and the bytes go through
 * the page cache, as all that follow. Returns 0, or -1 with errno.
 */
int pwrite_all(int fd, const void *buf, size_t n, uint64_t off, int *direct);

#endif
