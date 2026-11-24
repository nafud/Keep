/*
 * keep: decryption-readiness triage for an unlocked Linux system, as one static program.
 *
 *   sudo ./keep [-n]
 *   sudo ./keep triage [-d DIR] [-b N]
 *   ./keep scan [-s STEP] [-r] [FILE]
 *   ./keep -h | -V
 *
 * Without a command it asks for the parameters of one run as plain questions, lists them and
 * runs the triage or the search of a memory dump (menu.c). -n asks and lists and runs nothing.
 *
 * triage   For every open dm-crypt volume of the running system, decide whether its volume key
 *          can be kept as evidence and proven now, and write the keys, the header backups and
 *          the report into a folder triage_<host>_<time>/ of the destination. Needs root.
 *            -d DIR   destination directory, where that folder is made (default: the current
 *                     directory)
 *            -b N     stop after N proof attempts per key on the memory route (default 64)
 * scan     Search FILE, a memory image or by default /proc/kcore, for AES key schedules, as
 *          kcore-keyscan does. The schedules go to standard output, so the output holds key
 *          material. -s STEP tests only the addresses that are a multiple of STEP, -r reads the
 *          file as raw bytes.
 *
 * The program starts no other program and reads no file of the examined system as anything but
 * text. It asks the kernel for the mapped devices and their tables, reads the LUKS header from
 * the backing device, and computes the proof of a key itself. It writes into the destination
 * and nowhere else.
 *
 * This is the C program of Keep while it is built. It takes no memory image yet: keytriage.sh
 * on the tool medium does.
 *
 * Exit status: 0, 1 when a run could not start, a write to the destination failed or the
 * dialogue ended without a run, 2 for a wrong option. scan ends with the status of
 * kcore-keyscan, and the dialogue with the status of the run it made.
 */
#include "keyscan.h"
#include "menu.h"
#include "triage.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static const char usage[] =
    "usage: keep [-n]\n"
    "       keep triage [-d DIR] [-b N]\n"
    "       keep scan [-s STEP] [-r] [FILE]\n"
    "       keep -h | -V\n";

static const char help[] =
    "keep " KEEP_VERSION ": decryption-readiness triage for an unlocked Linux system\n"
    "\n"
    "  sudo ./keep [-n]\n"
    "      Ask for the parameters of one run, one question per line, list them and run it:\n"
    "      the triage of this system, or the search of a memory dump that exists. Enter takes\n"
    "      the default of a question. -n asks and lists and runs nothing.\n"
    "\n"
    "  sudo ./keep triage [-d DIR] [-b N]\n"
    "      For every open dm-crypt volume, decide whether its volume key can be kept as\n"
    "      evidence and proven now. The keys, the header backups and the report go into a\n"
    "      folder triage_<host>_<time>/ of the destination.\n"
    "        -d DIR   destination directory (default: the current directory)\n"
    "        -b N     proof attempts per key on the memory route (default 64)\n"
    "\n"
    "  ./keep scan [-s STEP] [-r] [FILE]\n"
    "      Search a memory image, or by default /proc/kcore, for AES key schedules. They go\n"
    "      to standard output, which then holds key material.\n"
    "\n"
    "  The program starts no other program and writes into the destination and nowhere else.\n"
    "  No key is printed: a key is named by the first 16 digits of its SHA-256.\n";

/* A number of an option: digits only, and one that an unsigned takes. */
static int number(const char *s, unsigned *out)
{
    char *end;
    unsigned long v;

    if (!*s || strspn(s, "0123456789") != strlen(s))
        return -1;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno || *end || v > 0x7fffffff)
        return -1;
    *out = (unsigned)v;
    return 0;
}

static int cmd_triage(int argc, char **argv)
{
    struct triage_options o = { .dest = ".", .budget = 64 };
    int c;

    while ((c = getopt(argc, argv, "+d:b:")) != -1) {
        if (c == 'd') {
            o.dest = optarg;
        } else if (c == 'b' && !number(optarg, &o.budget)) {
            continue;
        } else {
            fputs(c == 'b' ? "keep: the number of proof attempts must be a number\n" : usage, stderr);
            return 2;
        }
    }
    if (optind != argc) {
        fputs(usage, stderr);
        return 2;
    }
    return triage_run(&o);
}

static int cmd_scan(int argc, char **argv)
{
    unsigned every = 1;
    int c, raw = 0, failed;

    while ((c = getopt(argc, argv, "+s:r")) != -1) {
        if (c == 'r') {
            raw = 1;
        } else if (c == 's' && !number(optarg, &every) && every) {
            continue;
        } else {
            fputs(usage, stderr);
            return 2;
        }
    }
    if (argc - optind > 1) {
        fputs(usage, stderr);
        return 2;
    }
    return keyscan_run(optind < argc ? argv[optind] : "/proc/kcore", raw, every, stdout, stderr, &failed);
}

int main(int argc, char **argv)
{
    /* A process that is not dumpable leaves no core file, which would hold keys and would be
       written to the examined system (do_coredump in fs/coredump.c), and no other user's
       process can read its memory. */
    prctl(PR_SET_DUMPABLE, 0);
    if (argc == 1)
        return menu_run(0);
    if (argc == 2 && !strcmp(argv[1], "-n"))
        return menu_run(1);
    if (argc >= 2 && !strcmp(argv[1], "triage"))
        return cmd_triage(argc - 1, argv + 1);
    if (argc >= 2 && !strcmp(argv[1], "scan"))
        return cmd_scan(argc - 1, argv + 1);
    if (argc == 2 && !strcmp(argv[1], "-h")) {
        fputs(help, stdout);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "-V")) {
        puts("keep " KEEP_VERSION);
        return 0;
    }
    fputs(usage, stderr);
    return 2;
}
