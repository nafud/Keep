/*
 * menu.c: the dialogue of Keep, in the manner of ewfacquire. It is what "keep" without a command
 * runs, and it does the work of keep-menu.sh.
 *
 * It asks for the parameters of one run as plain questions, one per line. A question shows its
 * choices in parentheses and its default in square brackets, and Enter takes the default. A
 * value that cannot be used is asked for again. The values are then listed, a confirmation is
 * asked for, and the run is made in this process, with its output shown as it runs. "no" at
 * the confirmation starts the questions again. One run per start.
 *
 *   system   the open volumes of this running system: the triage, as "keep triage -d DIR -b N"
 *   dump     a memory dump that exists: the search for AES key schedules, as "keep scan DUMP",
 *            into DIR/scan_<dump>_<time>/keys/candidates.txt, for the proof in the lab
 *
 * Nothing but lines of text is written and read: no escape sequence, no cursor movement, no
 * terminfo and no line editor, so the dialogue works on a console, over SSH, on a serial line
 * and through a pipe, and no file of the examined system takes part in it. An input that ends
 * before the parameters are complete ends the run with status 1, so a closed pipe cannot loop.
 * It never shows a key.
 */
#include "menu.h"
#include "keyscan.h"
#include "sys.h"
#include "triage.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define AGAIN "try again or end with Ctrl+C."

struct answers {                        /* the parameters of one run */
    int dump;                           /* a memory dump is searched, not the running system */
    char dest[PATH_MAX];                /* the destination directory */
    char file[PATH_MAX];                /* the memory dump */
    char scan[PATH_MAX];                /* the folder of the search of a dump */
    unsigned budget;
};

static char *input;                     /* the line that was read last */
static size_t input_room;

static void fail(const char *fmt, ...) __attribute__((format(printf, 1, 2), noreturn));
static void fail(const char *fmt, ...)
{
    va_list ap;

    fflush(stdout);
    fputs("\nkeep: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputs("\nkeep: FAILURE\n", stderr);
    exit(1);
}

/* One line of input, without its end. An input that ends, ends the run. */
static const char *read_line(void)
{
    ssize_t n = getline(&input, &input_room, stdin);

    if (n < 0) {
        putchar('\n');
        fail("the input ended before the parameters were complete");
    }
    if (n && input[n - 1] == '\n')
        input[n - 1] = 0;
    return input;
}

/* A question with its default in square brackets. Enter takes the default. */
static const char *ask(const char *prompt, const char *def)
{
    const char *answer;

    if (def && *def)
        printf("%s [%s]: ", prompt, def);
    else
        printf("%s: ", prompt);
    fflush(stdout);
    answer = read_line();
    return *answer || !def ? answer : def;
}

/* A question with its choices in parentheses. Returns the number of the choice. */
static int choose(const char *prompt, const char *const *choices, int count, int def)
{
    struct str question = { 0 };
    int i;

    str_addf(&question, "%s (", prompt);
    for (i = 0; i < count; i++)
        str_addf(&question, "%s%s", i ? ", " : "", choices[i]);
    str_add(&question, ")");
    for (;;) {
        const char *answer = ask(str_text(&question), choices[def]);

        for (i = 0; i < count; i++)
            if (!strcmp(answer, choices[i])) {
                str_free(&question);
                return i;
            }
        printf("Unsupported value, %s\n", AGAIN);
    }
}

/* A path as an absolute one: a relative path is one below the directory of the start. Returns
   -1 where it does not fit. */
static int absolute(const char *path, char out[PATH_MAX])
{
    char here[PATH_MAX];
    int n;

    if (path[0] == '/')
        n = snprintf(out, PATH_MAX, "%s", path);
    else if (getcwd(here, sizeof here))
        n = snprintf(out, PATH_MAX, "%s/%s", here, path);
    else
        return -1;
    return n < 0 || n >= PATH_MAX ? -1 : 0;
}

/* A regular file that can be read, as an absolute path. */
static void ask_file(const char *prompt, char out[PATH_MAX])
{
    struct stat st;

    for (;;) {
        const char *answer = ask(prompt, NULL);

        if (*answer && !stat(answer, &st) && S_ISREG(st.st_mode) && !access(answer, R_OK) && !absolute(answer, out))
            return;
        printf("Not a readable file, %s\n", AGAIN);
    }
}

/* A directory that can be written to, as an absolute path. A dry run writes nothing, so there
   the directory only has to exist. */
static void ask_dir(const char *prompt, const char *def, int dry, char out[PATH_MAX])
{
    struct stat st;

    for (;;) {
        const char *answer = ask(prompt, def);

        if (stat(answer, &st) || !S_ISDIR(st.st_mode) || absolute(answer, out))
            printf("%s is not a directory, %s\n", answer, AGAIN);
        else if (!dry && access(answer, W_OK))
            printf("%s is not writable, %s\n", answer, AGAIN);
        else
            return;
    }
}

static void utc(char out[32], int for_name)
{
    time_t now = time(NULL);
    struct tm tm;

    gmtime_r(&now, &tm);
    if (for_name)
        strftime(out, 32, "%Y%m%d_%H%M%S", &tm);
    else
        strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void info(const char *label, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void info(const char *label, const char *fmt, ...)
{
    char name[64];
    va_list ap;

    snprintf(name, sizeof name, "%s:", label);
    printf("    %-24s", name);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

/* What a triage will meet. The files of the examined system are read as text only. */
static void system_information(void)
{
    char host[256], os[256], lockdown[64], err[TRIAGE_ERR_LEN], *names = NULL;
    unsigned long long kib;
    struct utsname un;
    int count;

    uname(&un);
    snprintf(host, sizeof host, "%s", un.nodename);
    name_clean(host);
    sys_os_name("/etc/os-release", "/usr/lib/os-release", os, sizeof os);
    name_clean(os);
    sys_lockdown("/sys/kernel/security/lockdown", lockdown, sizeof lockdown);
    printf("\nSystem information:\n");
    info("Host", "%s", host);
    info("System", "%s", os[0] ? os : "unknown");
    info("Kernel", "%s", un.release);
    info("Kernel lockdown", "%s", lockdown[0] ? lockdown : "unknown");
    if (sys_memory("/proc/meminfo", &kib))
        info("Memory", "unknown");
    else
        info("Memory", "%llu MiB", kib / 1024);
    if (geteuid() != 0)
        info("Open dm-crypt volumes", "not listed, that needs root");
    else if ((count = triage_volume_names(&names, err)) < 0)
        info("Open dm-crypt volumes", "not listed: %s", err);
    else if (count)
        info("Open dm-crypt volumes", "%d (%s)", count, names);
    else
        info("Open dm-crypt volumes", "0");
    free(names);
    putchar('\n');
}

/* One line of the list of the values. */
static void row(struct str *rows, const char *label, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void row(struct str *rows, const char *label, const char *fmt, ...)
{
    char name[64], value[2 * PATH_MAX + 64];
    va_list ap;

    snprintf(name, sizeof name, "%s:", label);
    va_start(ap, fmt);
    vsnprintf(value, sizeof value, fmt, ap);
    va_end(ap);
    str_addf(rows, "%-28s%s\n", name, value);
}

static void row_destination(struct str *rows, const char *dest)
{
    struct statvfs vfs;

    if (statvfs(dest, &vfs))
        row(rows, "Destination directory", "%s", dest);
    else
        row(rows, "Destination directory", "%s (%llu MiB free)", dest,
            (unsigned long long)vfs.f_bavail * vfs.f_frsize / 1048576);
}

static void from_system(struct answers *a, struct str *rows, int dry, const char *start)
{
    char number[16];

    if (!dry && geteuid() != 0)
        fail("the keys of a running system need root, start keep under sudo");
    system_information();
    ask_dir("Destination directory", start, dry, a->dest);
    for (;;) {
        const char *answer = ask("Proof attempts per key on the memory route", "64");
        char *end;
        unsigned long n;

        errno = 0;
        n = strtoul(answer, &end, 10);
        if (*answer && answer[0] != '0' && strspn(answer, "0123456789") == strlen(answer) && !errno && !*end &&
            n <= 0x7fffffff) {
            a->budget = (unsigned)n;
            break;
        }
        printf("A whole number from 1 is needed, %s\n", AGAIN);
    }
    snprintf(number, sizeof number, "%u", a->budget);
    row(rows, "Search for keys in", "this running system");
    row_destination(rows, a->dest);
    row(rows, "Proof attempts per key", "%s", number);
    row(rows, "Memory dump", "no, this program takes none yet");
    row(rows, "Command", "keep triage -d %s -b %s", a->dest, number);
}

static void from_dump(struct answers *a, struct str *rows, int dry, const char *start)
{
    char stamp[32], name[NAME_MAX + 1];
    const char *base;

    ask_file("Memory dump (raw, LiME, compressed AVML or ELF core)", a->file);
    printf("The dump is searched for AES key schedules, and the list of them goes to the lab for the proof.\n");
    for (;;) {
        ask_dir("Destination directory", start, dry, a->dest);
        base = strrchr(a->file, '/');
        name_file(base ? base + 1 : a->file, name, sizeof name);
        utc(stamp, 1);
        if (!pathf(a->scan, "%s/scan_%s_%s", a->dest, name, stamp) && strlen(a->scan) + sizeof "/keys/candidates.txt" <= PATH_MAX)
            break;
        printf("The path of that directory is too long, %s\n", AGAIN);
    }
    row(rows, "Search for keys in", "a memory dump");
    row(rows, "Memory dump", "%s", a->file);
    row_destination(rows, a->dest);
    row(rows, "Proof", "none here, the candidate list goes to the lab");
    row(rows, "Command", "keep scan %s > %s/keys/candidates.txt", a->file, a->scan);
}

/* A new file of the search of a dump. It must not exist. */
static FILE *new_file(const char *dir, const char *name, int *fd)
{
    char path[PATH_MAX];
    FILE *f;

    if (pathf(path, "%s/%s", dir, name)) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    if ((*fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)) < 0)
        return NULL;
    if (!(f = fdopen(*fd, "w")))
        close(*fd);
    return f;
}

/*
 * The search of a dump: the schedules, which are key material, go to keys/candidates.txt of the
 * folder of the search, and what the scanner says about the dump to scan.txt, which is shown.
 * Both are flushed to the destination. Returns the status of the scanner, or 1 where a file
 * could not be written.
 */
static int scan_dump(const struct answers *a)
{
    char keysdir[PATH_MAX], path[PATH_MAX], *said;
    FILE *keys = NULL, *msg = NULL;
    int kfd = -1, mfd = -1, failed = 0, status, written = 1;

    umask(077);                         /* the candidate list holds key material */
    if (mlockall(MCL_CURRENT | MCL_FUTURE))
        printf("the memory of this program could not be locked (%s), so a part of it can reach the swap space\n",
               strerror(errno));
    if (pathf(keysdir, "%s/keys", a->scan) || pathf(path, "%s/scan.txt", a->scan))
        errno = ENAMETOOLONG;
    else if (!mkdir(a->scan, 0700) && !mkdir(keysdir, 0700) && (keys = new_file(keysdir, "candidates.txt", &kfd)))
        msg = new_file(a->scan, "scan.txt", &mfd);
    if (!msg) {
        printf("keep: the folder of the search cannot be written, %s: %s\n", a->scan, strerror(errno));
        if (keys)
            fclose(keys);
        return 1;
    }
    status = keyscan_run(a->file, 0, 1, keys, msg, &failed);
    keyscan_wipe();
    if (fflush(keys) || fflush(msg) || fsync(kfd) || fsync(mfd))
        written = 0;
    if (fclose(keys) || fclose(msg) || flush_path(keysdir) || flush_path(a->scan) || flush_path(a->dest))
        written = 0;
    if ((said = read_text(path, 1 << 20, NULL))) {
        fputs(said, stdout);
        free(said);
    }
    if (!written) {
        printf("keep: a write or a flush to the destination FAILED, the folder of the search is not complete\n");
        return status ? status : 1;
    }
    return status;
}

int menu_run(int dry)
{
    static const char *const sources[] = { "system", "dump" }, *const yes_no[] = { "yes", "no" };
    char start[PATH_MAX], now[32];
    struct answers a;
    struct str rows = { 0 };
    int status;

    if (!getcwd(start, sizeof start))
        fail("the directory of the start cannot be named: %s", strerror(errno));
    printf("keep %s\n\n", KEEP_VERSION);
    if (dry)
        printf("Dry run: the command is shown and not run.\n\n");
    for (;;) {
        memset(&a, 0, sizeof a);
        str_free(&rows);
        printf("Parameters required, please provide the necessary input\n");
        a.dump = choose("Search for keys in", sources, 2, 0);
        if (a.dump)
            from_dump(&a, &rows, dry, start);
        else
            from_system(&a, &rows, dry, start);
        if (rows.failed)
            fail("no memory");
        printf("\nThe following parameters were provided:\n%s\n", str_text(&rows));
        if (choose("Continue with these values", yes_no, 2, 0) == 0)
            break;
        putchar('\n');
    }
    str_free(&rows);
    free(input);
    input = NULL;
    input_room = 0;

    putchar('\n');
    if (dry) {
        printf("keep: dry run, nothing was run\n");
        return 0;
    }
    utc(now, 0);
    printf("%s started at: %s\n\n", a.dump ? "Scan" : "Triage", now);
    fflush(stdout);
    if (a.dump) {
        status = scan_dump(&a);
    } else {
        struct triage_options o = { .dest = a.dest, .budget = a.budget };

        status = triage_run(&o);
    }
    utc(now, 0);
    printf("\n%s completed at: %s\n", a.dump ? "Scan" : "Triage", now);
    if (a.dump)
        printf("In the lab: python3 -I vkverify.py %s/keys/candidates.txt --image DISK\n", a.scan);
    if (status)
        printf("\nkeep: FAILURE (exit status %d)\n", status);
    else
        printf("\nkeep: SUCCESS\n");
    return status;
}
