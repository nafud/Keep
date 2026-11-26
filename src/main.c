/*
 * keep: finds the keys of the encrypted volumes of an unlocked Linux system, as one static program.
 *
 *   sudo ./keep [-n] [-d DIR] [-b N] [-m [-f FORMAT | -F]]
 *   ./keep -s DUMP [-n] [-d DIR] [FILE...]
 *   ./keep -h | -V
 *
 * Without -s   For every open dm-crypt volume of the running system, decide whether its volume
 *              key can be kept as evidence and proven now. The characteristics of the system
 *              and one verdict per volume are printed, and the keys, the header backups and
 *              the report go into a folder triage_<host>_<time>/ of the destination. Needs
 *              root.
 * -s DUMP      Search a memory dump that exists (raw, LiME, compressed AVML or ELF core) for
 *              AES key schedules, and prove which of them is the volume key of each LUKS
 *              header in the FILEs: header backups, raw images of disks or partitions, or
 *              devices. The proven keys and the list of the schedules, which is key
 *              material, go into a folder scan_<dump>_<time>/ of the destination, below keys/.
 *              The dump itself is searched for headers as well: without a FILE a key is
 *              proven where the memory still holds the header or the digests of its volume.
 * -m           after the keys, take a memory image of the running system into memory/ of
 *              that folder, in LiME format
 * -f FORMAT    the format of the image: lime (default), raw, or avml, which is compressed.
 *              Only with -m.
 * -F           the image in every format: the memory is read once and written to three
 *              files, so that they hold the same bytes and one that is damaged later does
 *              not take the others with it. Only with -m.
 * -d DIR       the destination directory, where that folder is made (default: the current
 *              directory)
 * -b N         stop after N proof attempts per key in the search of memory (default 64). Only
 *              for the running system.
 * -n           a plain screen: no colour, and no line of progress that is written over. A
 *              screen that is no terminal, as a pipe or a file, is plain without it, and so is
 *              one whose TERM is not set or is "dumb". NO_COLOR with a value takes the colour
 *              alone.
 * -h, -V       the help, the version
 *
 * The screen is one fact in a line, a label and its value, in at most 80 columns where no
 * name of the examined system is longer, and the report triage.txt holds the same lines. On a
 * terminal the labels and the verdicts have colour, which says nothing that the words do not.
 *
 * The program asks no question: what a run does is said by its options. It starts no other
 * program and reads no file of the examined system as anything but text. It asks the kernel for
 * the mapped devices and their tables, reads the LUKS header from the backing device, and
 * computes the proof of a key itself. It writes into the destination and nowhere else, and it
 * prints no key: a key is named by its length and the first 16 digits of its SHA-256.
 *
 * Exit status: 0, 1 when a run could not start, a write to the destination failed or a memory
 * image that was asked for is not there, 2 for a wrong option. With -s: 1 also for a dump that
 * could not be read to its end and, with FILEs, where they hold no header or a header has a
 * key that is not proven, 3 for a failed self-test of the search.
 */
#include "dump.h"
#include "triage.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

static const char usage[] =
    "usage: keep [-n] [-d DIR] [-b N] [-m [-f FORMAT | -F]]\n"
    "       keep -s DUMP [-n] [-d DIR] [FILE...]\n"
    "       keep -h | -V\n";

static const char help[] =
    "keep " KEEP_VERSION "\n"
    "Finds the keys of the encrypted volumes of an unlocked Linux system.\n"
    "\n"
    "  sudo ./keep [-n] [-d DIR] [-b N] [-m [-f FORMAT | -F]]\n"
    "      For every open dm-crypt volume of this system, decide whether its volume\n"
    "      key can be kept as evidence and proven now. The keys, the header backups\n"
    "      and the report go into a folder triage_<host>_<time>/ of the destination.\n"
    "      With -m the memory of the machine is taken after the keys, into memory/\n"
    "      of that folder.\n"
    "\n"
    "  ./keep -s DUMP [-n] [-d DIR] [FILE...]\n"
    "      Search a memory dump that exists (raw, LiME, compressed AVML or ELF core)\n"
    "      for AES key schedules, and prove which of them is the volume key of each\n"
    "      LUKS header in the FILEs: header backups, raw images of disks or\n"
    "      partitions, or devices. The proven keys go into keys/ of a folder\n"
    "      scan_<dump>_<time>/ of the destination. The dump itself is searched for\n"
    "      headers as well, so without a FILE a key is proven where the memory\n"
    "      still holds the header or the digests of its volume. Pairs of schedules\n"
    "      that lie as the kernel keeps the two keys of a volume, and that no\n"
    "      header proves, are kept as candidates.\n"
    "\n"
    "  -m         take a memory image of the running system, after the keys\n"
    "  -f FORMAT  the format of the image: lime (default), raw, or avml (compressed)\n"
    "  -F         the image in every format, from one read of the memory. The files\n"
    "             hold the same bytes, need about three times the room of the\n"
    "             memory, and the read lasts as long as the slowest is written\n"
    "  -s DUMP    search this memory dump, not the running system\n"
    "  -d DIR     the destination directory (default: the current directory)\n"
    "  -b N       proof attempts per key in the search of memory (default 64)\n"
    "  -n         a plain screen: no colour, and no line of progress that is\n"
    "             written over. A pipe or a file gets one without it, and NO_COLOR\n"
    "             with a value takes the colour alone\n"
    "  -h         this help\n"
    "  -V         the version\n"
    "\n"
    "  A verdict says how far the key of a volume is:\n"
    "    captured and proven   in keys/, and it gives the digest of the header\n"
    "    captured, in use      read from the table, the volume has no header digest\n"
    "    captured, not proven  in keys/, no header backup or the header refused it\n"
    "    needs a memory read   not reached in this run, a memory image keeps it open\n"
    "    live copy only        no key route is open, only a copy of the mounted files\n"
    "    no key needed         the mapping has no key, which is the null cipher\n"
    "  With -s a header is proven, not proven or an unreadable header, and a pair\n"
    "  of schedules that no header proves is found in memory, not proven.\n"
    "\n"
    "  The program starts no other program and writes into the destination and\n"
    "  nowhere else. No key is printed: a key is named by its length and the first\n"
    "  16 digits of its SHA-256.\n";

/* A number of an option: digits only, from 1, and one that an unsigned takes. */
static int number(const char *s, unsigned *out)
{
    char *end;
    unsigned long v;

    if (!*s || strspn(s, "0123456789") != strlen(s))
        return -1;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno || *end || v < 1 || v > 0x7fffffff)
        return -1;
    *out = (unsigned)v;
    return 0;
}

/*
 * A run that has begun is brought to its end, with its files in the destination and its
 * status, whatever becomes of its screen and whatever limit the shell of the examined system
 * had. Three signals would end the program in the middle by their default, which is to
 * terminate (signal(7)), and are not taken:
 *
 *   SIGPIPE   the screen is a pipe whose reader has gone (pipe_write in fs/pipe.c). The write
 *             then fails with EPIPE, and the lines are in triage.txt.
 *   SIGHUP    the terminal has hung up, as that of a session over a network that is lost
 *             (tty_signal_session_leader in drivers/tty/tty_jobctrl.c of Linux 6.12).
 *   SIGXFSZ   a write beyond the limit of the size of a file (RLIMIT_FSIZE:
 *             generic_write_checks in mm/filemap.c of Linux 4.18, generic_write_check_limits
 *             in fs/read_write.c of 6.12). The write then fails with EFBIG, as any write
 *             that fails.
 *
 * That limit, and the limit of processor time, whose signal SIGXCPU cannot be refused for
 * good, are taken off where the process may, which root may: they are settings of a shell of
 * the examined system, and would cut a memory image or a long proof. An interrupt from the
 * keyboard and SIGTERM end the run as before: they are the examiner's.
 */
static void undisturbed(void)
{
    const struct rlimit none = { RLIM_INFINITY, RLIM_INFINITY };

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGXFSZ, SIG_IGN);
    setrlimit(RLIMIT_FSIZE, &none);
    setrlimit(RLIMIT_CPU, &none);
}

static int wrong(const char *what)
{
    if (what)
        fprintf(stderr, "keep: %s\n", what);
    fputs(usage, stderr);
    return 2;
}

int main(int argc, char **argv)
{
    const char *dest = ".", *dump = NULL;
    enum image_format format = IMAGE_LIME;
    unsigned budget = 64;
    int c, has_budget = 0, memory = 0, has_format = 0, every = 0, plain = 0;

    /* A process that is not dumpable leaves no core file, which would hold keys and would be
       written to the examined system (do_coredump in fs/coredump.c), and no other user's
       process can read its memory. */
    prctl(PR_SET_DUMPABLE, 0);
    undisturbed();
    while ((c = getopt(argc, argv, "+d:b:s:mf:FnhV")) != -1) {
        switch (c) {
        case 'd':
            dest = optarg;
            break;
        case 'b':
            if (number(optarg, &budget))
                return wrong("-b takes a whole number from 1");
            has_budget = 1;
            break;
        case 's':
            dump = optarg;
            break;
        case 'm':
            memory = 1;
            break;
        case 'f':
            if (image_by_name(optarg, &format))
                return wrong("-f takes one of the formats lime, raw and avml");
            has_format = 1;
            break;
        case 'F':
            every = 1;
            break;
        case 'n':
            plain = 1;
            break;
        case 'h':
            fputs(help, stdout);
            return 0;
        case 'V':
            puts("keep " KEEP_VERSION);
            return 0;
        default:
            return wrong(NULL);
        }
    }
    if (optind != argc && !dump)
        return wrong("an argument that belongs to no option");
    if (dump && has_budget)
        return wrong("-b belongs to the search of the running system, not to -s");
    if (dump && memory)
        return wrong("-m takes an image of the running system, and -s searches one that exists");
    if ((has_format || every) && !memory)
        return wrong("-f and -F name the format of the image that -m takes");
    if (has_format && every)
        return wrong("-f names one format and -F all of them");
    if (dump) {
        struct dump_options o = { .dump = dump, .dest = dest, .files = argv + optind, .nfiles = (size_t)(argc - optind),
                                  .plain = plain };

        return dump_run(&o);
    } else {
        struct triage_options o = { .dest = dest, .budget = budget, .plain = plain };

        if (memory && every)
            for (c = 0; c < IMAGE_FORMATS; c++)
                o.formats[o.nformats++] = (enum image_format)c;
        else if (memory)
            o.formats[o.nformats++] = format;
        return triage_run(&o);
    }
}
