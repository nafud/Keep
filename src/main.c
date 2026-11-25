/*
 * keep: finds the keys of the encrypted volumes of an unlocked Linux system, as one static program.
 *
 *   sudo ./keep [-d DIR] [-b N] [-m [-f FORMAT | -F]]
 *   ./keep -s DUMP [-d DIR]
 *   ./keep -h | -V
 *
 * Without -s   For every open dm-crypt volume of the running system, decide whether its volume
 *              key can be kept as evidence and proven now. The characteristics of the system
 *              and one verdict per volume are printed, and the keys, the header backups and
 *              the report go into a folder triage_<host>_<time>/ of the destination. Needs
 *              root.
 * -s DUMP      Search a memory dump that exists (raw, LiME, compressed AVML or ELF core) for
 *              AES key schedules. The list of them, which is key material, goes into a folder
 *              scan_<dump>_<time>/ of the destination, below keys/.
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
 * -h, -V       the help, the version
 *
 * The program asks no question: what a run does is said by its options. It starts no other
 * program and reads no file of the examined system as anything but text. It asks the kernel for
 * the mapped devices and their tables, reads the LUKS header from the backing device, and
 * computes the proof of a key itself. It writes into the destination and nowhere else, and it
 * prints no key: a key is named by its length and the first 16 digits of its SHA-256.
 *
 * Exit status: 0, 1 when a run could not start, a write to the destination failed or a memory
 * image that was asked for is not there, 2 for a wrong option. With -s it is the status of the search: 1 also for a dump that could not be
 * read to its end, 3 for a failed self-test.
 */
#include "dump.h"
#include "triage.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static const char usage[] =
    "usage: keep [-d DIR] [-b N] [-m [-f FORMAT | -F]]\n"
    "       keep -s DUMP [-d DIR]\n"
    "       keep -h | -V\n";

static const char help[] =
    "keep " KEEP_VERSION ": finds the keys of the encrypted volumes of an unlocked Linux system\n"
    "\n"
    "  sudo ./keep [-d DIR] [-b N] [-m [-f FORMAT | -F]]\n"
    "      For every open dm-crypt volume of this system, decide whether its volume key can\n"
    "      be kept as evidence and proven now. The characteristics of the system and one\n"
    "      verdict per volume are printed. The keys, the header backups and the report go\n"
    "      into a folder triage_<host>_<time>/ of the destination. With -m the memory of\n"
    "      the machine is taken after the keys, into memory/ of that folder.\n"
    "\n"
    "  ./keep -s DUMP [-d DIR]\n"
    "      Search a memory dump that exists (raw, LiME, compressed AVML or ELF core) for AES\n"
    "      key schedules. The list goes into a folder scan_<dump>_<time>/ of the destination,\n"
    "      below keys/.\n"
    "\n"
    "  -m         take a memory image of the running system, after the keys\n"
    "  -f FORMAT  the format of the image: lime (default), raw, or avml (compressed)\n"
    "  -F         the image in every format, from one read of the memory. The files hold\n"
    "             the same bytes, need about three times the room of the memory, and the\n"
    "             read lasts as long as the slowest of them is written\n"
    "  -s DUMP    search this memory dump, not the running system\n"
    "  -d DIR     the destination directory (default: the current directory)\n"
    "  -b N       proof attempts per key in the search of memory (default 64)\n"
    "  -h         this help\n"
    "  -V         the version\n"
    "\n"
    "  The program starts no other program and writes into the destination and nowhere else.\n"
    "  No key is printed: a key is named by its length and the first 16 digits of its SHA-256.\n";

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
    int c, has_budget = 0, memory = 0, has_format = 0, every = 0;

    /* A process that is not dumpable leaves no core file, which would hold keys and would be
       written to the examined system (do_coredump in fs/coredump.c), and no other user's
       process can read its memory. */
    prctl(PR_SET_DUMPABLE, 0);
    while ((c = getopt(argc, argv, "+d:b:s:mf:FhV")) != -1) {
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
    if (optind != argc)
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
        struct dump_options o = { .dump = dump, .dest = dest };

        return dump_run(&o);
    } else {
        struct triage_options o = { .dest = dest, .budget = budget };

        if (memory && every)
            for (c = 0; c < IMAGE_FORMATS; c++)
                o.formats[o.nformats++] = (enum image_format)c;
        else if (memory)
            o.formats[o.nformats++] = format;
        return triage_run(&o);
    }
}
