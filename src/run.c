/*
 * run.c: the folder that a run of Keep writes into the destination, and its report.
 *
 * Every line of a run goes to the screen and to triage.txt. Every file is created anew, by this
 * process with umask 077, and is named in manifest.sha256 with its SHA-256. A failed write or
 * flush is remembered, and the run then ends with status 1.
 *
 * Colour on the screen is the SGR sequences of ECMA-48 for bold (1), a foreground colour (30 to
 * 37) and the end of both (0), which the console of Linux has in 4.18 as in 6.12 (csi_m in
 * drivers/tty/vt/vt.c), and every terminal emulator. They are written where the screen is a
 * terminal whose TERM is set and not "dumb", which is how git decides it (check_auto_color in
 * color.c and is_terminal_dumb in editor.c of git 2.43.0), and where NO_COLOR is not set to a
 * value (no-color.org). sudo hands NO_COLOR on to no program by its defaults
 * (initial_keepenv_table in env.c of sudo 1.9.15p5), so the option -n says the same. A line of
 * progress is written over with a carriage return and spaces, which needs no sequence.
 */
#include "run.h"
#include "hash.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define WIDTH 80                        /* columns of a line */
#define LABEL 11                        /* columns of a label */

static const char BOLD[] = "\033[1m", CYAN[] = "\033[36m", GREEN[] = "\033[1;32m", BLUE[] = "\033[1;34m",
                  END[] = "\033[0m";

struct span {                           /* a part of a line that has a colour on a terminal */
    size_t at, len;
    const char *sgr;
};

static const char *sgr_of(enum run_tone tone)
{
    return tone == RUN_REACHED ? GREEN : tone == RUN_OPEN ? BLUE : tone == RUN_NOT ? BOLD : NULL;
}

void run_screen(struct run *r, int plain)
{
    const char *term = getenv("TERM"), *no_colour = getenv("NO_COLOR");

    r->in_place = !plain && isatty(STDOUT_FILENO) && term && strcmp(term, "dumb");
    r->colour = r->in_place && !(no_colour && no_colour[0]);
    r->started = time(NULL);
}

unsigned run_seconds(const struct run *r)
{
    return (unsigned)(time(NULL) - r->started);
}

/* A line of progress that stands on the screen is taken away, so that the next line begins
   where it began. */
static void clear_progress(struct run *r)
{
    if (!r->progress)
        return;
    printf("\r%*s\r", (int)r->progress, "");
    r->progress = 0;
}

/* A text as printf writes it, in memory of its own, or NULL. */
static char *text_of(const char *fmt, va_list ap)
{
    va_list count;
    char *text;
    int n;

    va_copy(count, ap);
    n = vsnprintf(NULL, 0, fmt, count);
    va_end(count);
    if (n < 0 || !(text = malloc((size_t)n + 1)))
        return NULL;
    vsnprintf(text, (size_t)n + 1, fmt, ap);
    return text;
}

/* A part of a line to the screen, with the colours of the spans that lie in it, and to the
   report without them. AT is where the part begins in its line. */
static void part(struct run *r, const char *text, size_t at, size_t len, const struct span *spans, size_t nspans)
{
    size_t end = at + len, i, from = at;

    if (r->report && fwrite(text + at, 1, len, r->report) != len)
        r->write_failed = 1;
    for (i = 0; r->colour && i < nspans; i++) {
        size_t a = spans[i].at > from ? spans[i].at : from, b = spans[i].at + spans[i].len < end ? spans[i].at + spans[i].len : end;

        if (!spans[i].sgr || a >= b)
            continue;
        fwrite(text + from, 1, a - from, stdout);
        fputs(spans[i].sgr, stdout);
        fwrite(text + a, 1, b - a, stdout);
        fputs(END, stdout);
        from = b;
    }
    fwrite(text + from, 1, end - from, stdout);
}

/* The last space of TEXT at or before FROM and behind LOW, the first of its run, or LOW. */
static size_t space_back(const char *text, size_t low, size_t from)
{
    size_t e = from;

    while (e > low && text[e] != ' ')
        e--;
    while (e > low && text[e - 1] == ' ')
        e--;
    return e;
}

/* Whether the word that ends at END is a number: digits, with points or without. */
static int number_ends(const char *text, size_t low, size_t end)
{
    size_t w = end, digits = 0;

    for (; w > low && text[w - 1] != ' '; w--) {
        if (text[w - 1] >= '0' && text[w - 1] <= '9')
            digits++;
        else if (text[w - 1] != '.')
            return 0;
    }
    return digits > 0;
}

/* The space E or the nearest one before it that follows no number, or LOW where there is none. */
static size_t no_number(const char *text, size_t low, size_t e)
{
    while (e > low && number_ends(text, low, e))
        e = space_back(text, low, e - 1);
    return e;
}

/*
 * Where a line of TEXT that begins at AT and has ROOM columns is broken: at the last space
 * that keeps it within the width and lies behind LOW. Two things move the break to an
 * earlier space. A number is not parted from the word behind it, which is its unit. And the
 * last line does not hold one word alone, where that word and the one before it fit a line
 * of NEXT columns. LOW is returned where the width has no space.
 */
static size_t break_at(const char *text, size_t len, size_t at, size_t low, size_t room, size_t next)
{
    size_t last = space_back(text, low, at + room), e, p, rest;

    if (last == low)
        return low;
    if ((e = no_number(text, low, last)) == low)
        return last;                            /* a number is the first word: no other place */
    if (e != last)
        return e;
    for (rest = last; rest < len && text[rest] == ' '; rest++)
        ;
    if (memchr(text + rest, ' ', len - rest))
        return last;
    p = no_number(text, low, space_back(text, low, last - 1));
    for (rest = p; rest < len && text[rest] == ' '; rest++)
        ;
    return p > low && len - rest <= next ? p : last;
}

/*
 * One line to the screen and to the report. Where it has more than WIDTH columns it is
 * continued in further lines that begin in the column HANG, each broken at a space that
 * keeps it within the width (see break_at), and never before HANG, where the label ends. A
 * word that does not fit a line stands in one alone and is as long as it is. The spans follow
 * each other and lie before the first break. A HANG beyond the middle leaves no room worth a
 * break.
 */
static void line(struct run *r, char *text, size_t hang, const struct span *spans, size_t nspans)
{
    size_t len = strlen(text), at = 0, i;
    int first = 1;

    clear_progress(r);
    for (i = 0; i < len; i++)
        if ((unsigned char)text[i] < 0x20 || text[i] == 0x7f)
            text[i] = ' ';
    while (len && text[len - 1] == ' ')
        len--;
    do {
        size_t room = WIDTH - (first ? 0 : hang), floor = first ? hang : 0, end = len;

        if (hang <= WIDTH / 2 && len - at > room) {
            end = break_at(text, len, at, at + floor, room, WIDTH - hang);
            if (end == at + floor)              /* no space in the width: the word stays whole */
                for (end = at + room; end < len && text[end] != ' '; end++)
                    ;
        }
        while (end > at && text[end - 1] == ' ')
            end--;
        if (!first) {
            printf("%*s", (int)hang, "");
            if (r->report && fprintf(r->report, "%*s", (int)hang, "") < 0)
                r->write_failed = 1;
        }
        part(r, text, at, end - at, first ? spans : NULL, first ? nspans : 0);
        putchar('\n');
        if (r->report && fputc('\n', r->report) == EOF)
            r->write_failed = 1;
        for (at = end; at < len && text[at] == ' '; at++)
            ;
        first = 0;
    } while (at < len);
    fflush(stdout);
    r->begun = 1;
}

/* The text of a line that could not be put together, which only a lack of memory does. */
static char no_memory[] = "(no memory for this line)";

void run_say(struct run *r, const char *fmt, ...)
{
    va_list ap;
    char *text;

    va_start(ap, fmt);
    text = text_of(fmt, ap);
    va_end(ap);
    line(r, text ? text : no_memory, text ? strspn(text, " ") : 0, NULL, 0);
    free(text);
}

void run_title(struct run *r, const char *fmt, ...)
{
    struct span bold = { .sgr = BOLD };
    va_list ap;
    char *text, empty[1] = "";

    if (r->begun)
        line(r, empty, 0, NULL, 0);
    va_start(ap, fmt);
    text = text_of(fmt, ap);
    va_end(ap);
    bold.len = strlen(text ? text : no_memory);
    line(r, text ? text : no_memory, 0, &bold, 1);
    free(text);
}

/* "  label        " and what follows it, with the place where the value begins. */
static char *labelled(const char *label, const char *word, const char *rest, size_t *value)
{
    size_t n = strlen(label) > LABEL ? strlen(label) : LABEL, size;
    char *text;

    *value = 2 + n + 2;
    size = *value + strlen(word) + 2 + strlen(rest) + 1;
    if (!(text = malloc(size)))
        return NULL;
    snprintf(text, size, "  %-*s  %s%s%s", (int)n, label, word, word[0] && rest[0] ? ", " : "", rest);
    return text;
}

void run_field(struct run *r, const char *label, const char *fmt, ...)
{
    struct span cyan = { .at = 2, .len = strlen(label), .sgr = CYAN };
    va_list ap;
    char *rest, *text = NULL;
    size_t value = 0;

    va_start(ap, fmt);
    rest = text_of(fmt, ap);
    va_end(ap);
    if (rest)
        text = labelled(label, "", rest, &value);
    line(r, text ? text : no_memory, value, &cyan, text ? 1 : 0);
    free(rest);
    free(text);
}

void run_mark(struct run *r, const char *label, enum run_tone tone, const char *word, const char *fmt, ...)
{
    struct span spans[2] = { { .at = 2, .len = strlen(label), .sgr = CYAN }, { .len = strlen(word), .sgr = sgr_of(tone) } };
    va_list ap;
    char *rest, *text = NULL;
    size_t value = 0;

    va_start(ap, fmt);
    rest = text_of(fmt, ap);
    va_end(ap);
    if (rest)
        text = labelled(label, word, rest, &value);
    spans[1].at = value;
    line(r, text ? text : no_memory, value, spans, text ? 2 : 0);
    free(rest);
    free(text);
}

void run_row(struct run *r, const char *name, int name_width, enum run_tone tone, const char *word, int word_width,
             const char *fmt, ...)
{
    struct span span = { .len = strlen(word), .sgr = sgr_of(tone) };
    va_list ap;
    char *rest, *text = NULL;
    size_t size, hang = 0;

    va_start(ap, fmt);
    rest = text_of(fmt, ap);
    va_end(ap);
    if (name_width < (int)strlen(name))
        name_width = (int)strlen(name);
    if (word_width < (int)strlen(word))
        word_width = (int)strlen(word);
    span.at = 2 + (size_t)name_width + 2;
    hang = span.at + (size_t)word_width + 2;
    size = hang + (rest ? strlen(rest) : 0) + 1;
    if (rest && (text = malloc(size))) {
        if (rest[0])
            snprintf(text, size, "  %-*s  %-*s  %s", name_width, name, word_width, word, rest);
        else
            snprintf(text, size, "  %-*s  %s", name_width, name, word);
    }
    line(r, text ? text : no_memory, hang, &span, text ? 1 : 0);
    free(rest);
    free(text);
}

int run_due(const struct run *r, time_t *last)
{
    time_t now = time(NULL);

    if (now - *last < (r->in_place ? 1 : 15))
        return 0;
    *last = now;
    return 1;
}

void run_progress(struct run *r, const char *label, const char *fmt, ...)
{
    va_list ap;
    char *rest, *text = NULL;
    size_t value, len, before = r->progress;

    va_start(ap, fmt);
    rest = text_of(fmt, ap);
    va_end(ap);
    if (rest)
        text = labelled(label, "", rest, &value);
    free(rest);
    if (!text)
        return;
    len = strlen(text);
    if (r->in_place) {
        /* over the line that stands there, and spaces over what of it is longer */
        putchar('\r');
        if (r->colour)
            printf("  %s%s%s%s", CYAN, label, END, text + 2 + strlen(label));
        else
            fputs(text, stdout);
        if (before > len)
            printf("%*s", (int)(before - len), "");
        r->progress = before > len ? before : len;
    } else {
        puts(text);
    }
    fflush(stdout);
    r->begun = 1;
    free(text);
}

void run_tell(struct run *r, const char *fmt, ...)
{
    va_list ap;

    clear_progress(r);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

static int add(struct run *r, const char *rel, const char *hex)
{
    struct run_file *grown;
    char *copy;

    if (!(grown = realloc(r->files, (r->nfiles + 1) * sizeof *grown)))
        return -1;
    r->files = grown;
    if (!(copy = strdup(rel)))
        return -1;
    r->files[r->nfiles].name = copy;
    snprintf(r->files[r->nfiles].sha256, sizeof r->files[r->nfiles].sha256, "%s", hex);
    r->nfiles++;
    return 0;
}

int run_create(struct run *r, const char *rel, int flags, mode_t mode)
{
    char path[PATH_MAX];
    int fd;

    if (pathf(path, "%s/%s", r->out, rel)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if ((fd = open(path, flags | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode)) < 0)
        return -1;
    if (add(r, rel, "")) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    return fd;
}

int run_add(struct run *r, const char *rel, const uint8_t sha256[32])
{
    char hex[65];

    hex_encode(sha256, 32, hex);
    return add(r, rel, hex);
}

int run_flush(struct run *r, int fd, const char *dir)
{
    char path[PATH_MAX];

    if (fsync(fd) || pathf(path, "%s/%s", r->out, dir) || flush_path(path)) {
        r->write_failed = 1;
        return -1;
    }
    return 0;
}

void run_stem(struct run *r, char *stem, size_t size)
{
    char **grown;
    size_t i;

    for (i = 0; i < r->nstems; i++)
        if (!strcasecmp(r->stems[i], stem) && strlen(stem) + 1 < size) {
            strcat(stem, "_");
            i = (size_t)-1;
        }
    if ((grown = realloc(r->stems, (r->nstems + 1) * sizeof *grown))) {
        r->stems = grown;
        if ((r->stems[r->nstems] = strdup(stem)))
            r->nstems++;
    }
}

int run_keep_key(struct run *r, const char *stem, const uint8_t *key, size_t n, char name[17])
{
    char rel[PATH_MAX];
    uint8_t digest[32];
    int fd, ok;

    if (pathf(rel, "keys/%s.vk", stem) || (fd = run_create(r, rel, O_WRONLY, 0600)) < 0) {
        r->write_failed = 1;
        return -1;
    }
    ok = !write_all(fd, key, n) && !run_flush(r, fd, "keys");
    if (close(fd) || !ok) {
        r->write_failed = 1;
        return -1;
    }
    sha256(key, n, digest);
    hex_encode(digest, 8, name);
    return 0;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct run_file *)a)->name, ((const struct run_file *)b)->name);
}

void run_manifest(struct run *r)
{
    char path[PATH_MAX], hex[65];
    uint8_t buf[65536], digest[32];
    struct hash_ctx ctx;
    FILE *f;
    size_t i, count = r->nfiles;
    ssize_t got;
    int fd, mfd;

    qsort(r->files, count, sizeof r->files[0], by_name);
    if ((mfd = run_create(r, "manifest.sha256", O_WRONLY, 0600)) < 0 || !(f = fdopen(mfd, "w"))) {
        r->write_failed = 1;
        if (mfd >= 0)
            close(mfd);
        return;
    }
    for (i = 0; i < count; i++) {
        if (r->files[i].sha256[0]) {
            fprintf(f, "%s  %s\n", r->files[i].sha256, r->files[i].name);
            continue;
        }
        if (pathf(path, "%s/%s", r->out, r->files[i].name) || (fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
            r->write_failed = 1;
            continue;
        }
        hash_init(&ctx, hash_by_name("sha256"));
        while ((got = read(fd, buf, sizeof buf)) > 0)
            hash_update(&ctx, buf, (size_t)got);
        hash_final(&ctx, digest);
        close(fd);
        if (got < 0)
            r->write_failed = 1;
        hex_encode(digest, 32, hex);
        fprintf(f, "%s  %s\n", hex, r->files[i].name);
    }
    explicit_bzero(buf, sizeof buf);    /* the files of keys/ passed through it */
    if (fflush(f) || fsync(mfd))
        r->write_failed = 1;
    fclose(f);
}

/* A text as the inside of a JSON string: the two characters that end or escape it, control
   characters as spaces, and a byte that is no UTF-8 as the replacement character. */
static void json_text(FILE *f, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    while (*p) {
        size_t n = *p < 0x80 ? 1 : (*p & 0xe0) == 0xc0 && *p >= 0xc2 ? 2 : (*p & 0xf0) == 0xe0 ? 3
                 : (*p & 0xf8) == 0xf0 && *p <= 0xf4 ? 4 : 0, i;

        for (i = 1; i < n && (p[i] & 0xc0) == 0x80; i++)
            ;
        if (!n || i < n) {
            fputs("\xef\xbf\xbd", f);
            p++;
        } else if (n > 1) {
            fwrite(p, 1, n, f);
            p += n;
        } else {
            if (*p == '"' || *p == '\\')
                fputc('\\', f);
            fputc(*p < 0x20 ? ' ' : *p, f);
            p++;
        }
    }
}

void run_json(FILE *f, const char *s)
{
    if (!s || !*s) {
        fputs("null", f);
    } else {
        fputc('"', f);
        json_text(f, s);
        fputc('"', f);
    }
}

void run_free(struct run *r)
{
    size_t i;

    for (i = 0; i < r->nfiles; i++)
        free(r->files[i].name);
    free(r->files);
    for (i = 0; i < r->nstems; i++)
        free(r->stems[i]);
    free(r->stems);
    r->files = NULL;
    r->stems = NULL;
    r->nfiles = r->nstems = 0;
}

int run_lock_memory(char why[160])
{
    struct rlimit limit;
    unsigned long long caps = 0;
    char *status, *line;

    /* CAP_IPC_LOCK, bit 14 of the effective capabilities, takes the limit off (mlock_future_ok
       in mm/mmap.c). With the limit in force, what is allocated later could not be mapped. */
    if ((status = read_text("/proc/self/status", 65536, NULL))) {
        if ((line = strstr(status, "\nCapEff:")))
            caps = strtoull(line + 8, NULL, 16);
        free(status);
    }
    if (!(caps >> 14 & 1) && (getrlimit(RLIMIT_MEMLOCK, &limit) || limit.rlim_cur != RLIM_INFINITY)) {
        snprintf(why, 160, "the memory of this program is not locked, because this user may lock only a part of it, "
                 "so a key can reach the swap space");
        return -1;
    }
    if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
        snprintf(why, 160, "the memory of this program could not be locked (%s), so a key can reach the swap space",
                 strerror(errno));
        return -1;
    }
    return 0;
}

void run_utc(char out[32], int for_name)
{
    time_t now = time(NULL);
    struct tm tm;

    gmtime_r(&now, &tm);
    if (for_name)
        strftime(out, 32, "%Y%m%d_%H%M%S", &tm);
    else
        strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

int run_die(const char *fmt, ...)
{
    va_list ap;

    fputs("keep: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return 1;
}
