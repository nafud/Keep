/*
 * util.h: small things that several parts of the program need.
 */
#ifndef KEEP_UTIL_H
#define KEEP_UTIL_H

#include <stddef.h>
#include <stdint.h>

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
   FAT and exFAT take it. An empty name becomes _. */
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
int flush_path(const char *path);                              /* fsync of a file or directory */

#endif
