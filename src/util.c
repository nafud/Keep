/*
 * util.c: see util.h.
 */
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void str_addn(struct str *t, const char *s, size_t n)
{
    if (t->len + n + 1 > t->cap) {
        size_t cap = t->cap ? t->cap : 64;
        char *grown;

        while (cap < t->len + n + 1)
            cap *= 2;
        if (!(grown = realloc(t->s, cap))) {
            t->failed = 1;
            return;
        }
        t->s = grown;
        t->cap = cap;
    }
    memcpy(t->s + t->len, s, n);
    t->len += n;
    t->s[t->len] = 0;
}

void str_add(struct str *t, const char *s)
{
    str_addn(t, s, strlen(s));
}

void str_addf(struct str *t, const char *fmt, ...)
{
    char small[256], *big;
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(small, sizeof small, fmt, ap);
    va_end(ap);
    if (n < 0) {
        t->failed = 1;
    } else if ((size_t)n < sizeof small) {
        str_addn(t, small, (size_t)n);
    } else if (!(big = malloc((size_t)n + 1))) {
        t->failed = 1;
    } else {
        va_start(ap, fmt);
        vsnprintf(big, (size_t)n + 1, fmt, ap);
        va_end(ap);
        str_addn(t, big, (size_t)n);
        free(big);
    }
}

const char *str_text(const struct str *t)
{
    return t->s ? t->s : "";
}

void str_free(struct str *t)
{
    free(t->s);
    memset(t, 0, sizeof *t);
}

char *read_text(const char *path, size_t max, size_t *len)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    char *buf;
    size_t n = 0;
    ssize_t got = 0;

    if (fd < 0)
        return NULL;
    if (!(buf = malloc(max + 1))) {
        close(fd);
        return NULL;
    }
    while (n < max && (got = read(fd, buf + n, max - n)) != 0) {
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            break;
        n += (size_t)got;
    }
    close(fd);
    if (got < 0) {
        free(buf);
        return NULL;
    }
    buf[n] = 0;
    if (len)
        *len = n;
    return buf;
}

void name_clean(char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            *s = ' ';
}

void size_text(uint64_t bytes, char out[32])
{
    uint64_t unit = bytes >= 1ull << 30 ? 1ull << 30 : 1ull << 20, hundredths;

    if (bytes < 1ull << 20) {
        snprintf(out, 32, "%llu bytes", (unsigned long long)bytes);
        return;
    }
    /* in two steps, so that no size of 64 bits is too large for the product */
    hundredths = bytes / unit * 100 + (bytes % unit * 100 + unit / 2) / unit;
    snprintf(out, 32, "%llu.%02llu %s", (unsigned long long)(hundredths / 100), (unsigned long long)(hundredths % 100),
             unit == 1ull << 30 ? "GiB" : "MiB");
}

void name_file(const char *name, char *out, size_t outlen)
{
    size_t i;

    for (i = 0; name[i] && i + 1 < outlen; i++) {
        char c = name[i];
        int kept = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                   (c && strchr("._+=@,-", c));

        out[i] = kept ? c : '_';
    }
    if (!i && outlen > 1)
        out[i++] = '_';
    out[i] = 0;
}

void unescape_octal(char *s)
{
    char *o = s;

    for (; *s; s++) {
        if (s[0] == '\\' && s[1] >= '0' && s[1] <= '3' && s[2] >= '0' && s[2] <= '7' && s[3] >= '0' && s[3] <= '7') {
            *o++ = (char)((s[1] - '0') << 6 | (s[2] - '0') << 3 | (s[3] - '0'));
            s += 3;
        } else {
            *o++ = *s;
        }
    }
    *o = 0;
}

static int digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_decode(const char *hex, size_t digits, uint8_t *out)
{
    size_t i;

    if (digits % 2)
        return -1;
    for (i = 0; i < digits; i += 2) {
        int hi = digit(hex[i]), lo = digit(hex[i + 1]);

        if (hi < 0 || lo < 0)
            return -1;
        out[i / 2] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

void hex_encode(const uint8_t *p, size_t n, char *out)
{
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = digits[p[i] >> 4];
        out[2 * i + 1] = digits[p[i] & 15];
    }
    out[2 * n] = 0;
}

int pathf(char *out, const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(out, PATH_MAX, fmt, ap);
    va_end(ap);
    return n < 0 || n >= PATH_MAX ? -1 : 0;
}

int write_all(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;

    while (n) {
        ssize_t put = write(fd, p, n);

        if (put < 0 && errno == EINTR)
            continue;
        if (put < 0)
            return -1;
        p += put;
        n -= (size_t)put;
    }
    return 0;
}

int flush_path(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC), r, saved;

    if (fd < 0)
        return -1;
    r = fsync(fd);
    saved = errno;
    close(fd);
    errno = saved;
    return r;
}

int create_direct(const char *path, int access, mode_t mode, int *direct)
{
    const int flags = access | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW;
    int fd;

    *direct = 1;
    if ((fd = open(path, flags | O_DIRECT, mode)) >= 0 || errno != EINVAL)
        return fd;
    /* A file system without direct writes. The kernel made the file before it refused it
       (the file is created in lookup_open, and refused in do_dentry_open after that). */
    *direct = 0;
    if (unlink(path) && errno != ENOENT)
        return -1;
    return open(path, flags, mode);
}

int pwrite_all(int fd, const void *buf, size_t n, uint64_t off, int *direct)
{
    const uint8_t *p = buf;

    while (n) {
        ssize_t put = pwrite(fd, p, n, (off_t)off);

        if (put < 0 && errno == EINTR)
            continue;
        if (put < 0 && errno == EINVAL && *direct) {
            /* a file system that opens a file for direct writes and takes none of ours */
            int fl = fcntl(fd, F_GETFL);

            if (fl < 0 || fcntl(fd, F_SETFL, fl & ~O_DIRECT))
                return -1;
            *direct = 0;
            continue;
        }
        if (put <= 0) {
            if (!put)
                errno = EIO;
            return -1;
        }
        p += put;
        off += (uint64_t)put;
        n -= (size_t)put;
    }
    return 0;
}
