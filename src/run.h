/*
 * run.h: the folder that a run of Keep writes into the destination, and its report (see run.c).
 */
#ifndef KEEP_RUN_H
#define KEEP_RUN_H

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

struct run_file {
    char *name;                         /* relative to the folder of the run */
    char sha256[65];                    /* in hexadecimal, where it was computed while the file was written */
};

struct run {
    char out[PATH_MAX];                 /* the folder of this run */
    FILE *report;                       /* triage.txt, which takes every line of the screen */
    int colour;                         /* the screen is a terminal that is given colour */
    int in_place;                       /* the screen is a terminal, where a line of progress is written over */
    size_t progress;                    /* the length of such a line that stands on the screen */
    int begun;                          /* a line was printed */
    time_t started;
    int write_failed;                   /* a write or a flush failed: the run ends with status 1 */
    int line_lost;                      /* a line could not be put together for lack of memory: the same */
    struct run_file *files;             /* every file of the run, for the manifest */
    size_t nfiles;
    char **stems;                       /* the names that files of volumes and keys have taken */
    size_t nstems;
    char lockdown[64];                  /* the lockdown mode of the kernel */
    unsigned budget;                    /* proof attempts per key in the search of memory */
    int scanned, scan_ok, scan_refused; /* the search of /proc/kcore, made once */
    char scan_error[256];
};

/*
 * The screen of a run. Every line goes to the screen and to the report, the same text in both:
 * a title of a block, and below it one fact in a line, as a label of at most 11 characters and
 * a value that begins in column 16. A line of more than 80 columns is continued in the next
 * below its value, at a space: a word that is longer than that, as a path can be, stays whole.
 * A control character in a text becomes a space before it is printed.
 *
 * On a terminal the titles are bold, the labels cyan and the word that says how far a key or
 * an image is has the colour of its tone. Only bold and the eight colours that every terminal
 * has are used, so that its own settings decide the shade. The report holds no escape
 * sequence, and neither does the screen where it is no terminal.
 */
enum run_tone {
    RUN_PLAIN,                          /* nothing to reach: the mapping has no key */
    RUN_REACHED,                        /* green: captured and proven, proven, an image captured */
    RUN_OPEN,                           /* blue: captured and not proven here, or to be had from a memory image */
    RUN_NOT                             /* bold: not reached, or a write that failed */
};

/* Before the first line: whether the screen is a terminal that is given colour and lines that
   are written over. PLAIN is the option -n. */
void run_screen(struct run *r, int plain);

/* triage.txt of the folder of the run, which takes every line from here on. Each line is
   written when it is whole, so that a run that is ended from outside leaves the lines it
   had. Returns 0, or -1 with errno. */
int run_report(struct run *r);

/* One line as it is. */
void run_say(struct run *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* The title of a block, with an empty line before it unless it is the first line. */
void run_title(struct run *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* A label and its value. */
void run_field(struct run *r, const char *label, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
/* A label, a word in the colour of TONE, and after a comma what is to say about it, which can
   be empty. */
void run_mark(struct run *r, const char *label, enum run_tone tone, const char *word, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
/* A row of the result: a name in NAME_WIDTH columns, a word in the colour of TONE in
   WORD_WIDTH columns, and what is to say about it, which can be empty. */
void run_row(struct run *r, const char *name, int name_width, enum run_tone tone, const char *word, int word_width,
             const char *fmt, ...) __attribute__((format(printf, 7, 8)));

/*
 * How far a long step is, for the screen alone. On a terminal the line is written over by the
 * next one and taken away by the next line of the run. Elsewhere each is a line of its own.
 * run_due says whether the next is due, a second after the last on a terminal and a quarter of
 * a minute elsewhere, and then notes the time in *last.
 */
int run_due(const struct run *r, time_t *last);
void run_progress(struct run *r, const char *label, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
/* One line to the screen alone, as the last word of a run when its report is closed. */
void run_tell(struct run *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
/* The seconds since run_screen. */
unsigned run_seconds(const struct run *r);

/* A new file of the run, opened with FLAGS. It must not exist, so nothing of an earlier run is
   written over. Returns the descriptor, or -1 with errno. */
int run_create(struct run *r, const char *rel, int flags, mode_t mode);

/* The same for a file that is written with direct writes, which pass the page cache, where the
   file system of the destination has them (create_direct of util.h). ACCESS is O_WRONLY or
   O_RDWR, and *direct says which way the file is open. */
int run_create_direct(struct run *r, const char *rel, int access, mode_t mode, int *direct);

/* The SHA-256 of a file of run_create that was computed while it was written, so that the
   manifest does not read the file again. */
void run_hashed(struct run *r, const char *rel, const uint8_t sha256[32]);

/* Take a file of run_create away again, from the folder and from the manifest: the part of a
   file whose write failed, which would take the room of what is still to be written. */
void run_remove(struct run *r, const char *rel);

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
