/*
 * dump.c: the search of a memory dump that exists, "keep -s DUMP".
 *
 * The dump is searched for AES key schedules with the search of kcore-keyscan.c, which reads a
 * raw dump, a LiME image, a compressed AVML image and an ELF core. The run writes a folder
 * scan_<dump>_<time>/ into the destination:
 *
 *   keys/candidates.txt   the schedules that were found, one per line. This is key material.
 *   scan.txt              what the search said about the dump: the counts, and where an image
 *                         is cut or damaged
 *
 * A schedule is a key that some part of the kernel used. Which of them is the key of a volume
 * is decided by a proof against the header of that volume, which this run does not make:
 * vkverify.py makes it in the lab. The dump is only read, and no key is shown.
 */
#include "dump.h"
#include "keyscan.h"
#include "run.h"
#include "triage.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* A new file of the run. It must not exist. */
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

int dump_run(const struct dump_options *o)
{
    char dump[PATH_MAX], dest[PATH_MAX], out[PATH_MAX], keysdir[PATH_MAX], path[PATH_MAX];
    char name[NAME_MAX + 1], stamp[32], *said;
    const char *base;
    FILE *keys, *msg;
    struct stat st;
    struct tm tm;
    time_t now = time(NULL);
    int kfd = -1, mfd = -1, failed = 0, status, written = 1, found = 0;

    /* The list of the schedules is key material: it passes through the memory of this process,
       which is kept out of the swap space, and its file is for the owner alone. */
    if (mlockall(MCL_CURRENT | MCL_FUTURE))
        fprintf(stderr, "keep: the memory of this program could not be locked (%s), so a part of it can reach the swap space\n",
                strerror(errno));
    umask(077);
    if (!realpath(o->dump, dump))
        return run_die("the memory dump %s: %s", o->dump, strerror(errno));
    if (stat(dump, &st) || !S_ISREG(st.st_mode) || access(dump, R_OK))
        return run_die("%s is not a file that can be read", dump);
    if (!realpath(o->dest, dest))
        return run_die("the destination directory %s: %s", o->dest, strerror(errno));
    if (stat(dest, &st) || !S_ISDIR(st.st_mode))
        return run_die("%s is not a directory", dest);
    if (access(dest, W_OK))
        return run_die("%s is not writable", dest);

    base = strrchr(dump, '/');
    name_file(base ? base + 1 : dump, name, sizeof name);
    gmtime_r(&now, &tm);
    strftime(stamp, sizeof stamp, "%Y%m%d_%H%M%S", &tm);
    if (pathf(out, "%s/scan_%s_%s", dest, name, stamp) || pathf(keysdir, "%s/keys", out) ||
        pathf(path, "%s/scan.txt", out) || strlen(keysdir) + sizeof "/candidates.txt" > PATH_MAX)
        return run_die("the path of the folder of this run is too long: %s/scan_%s_%s", dest, name, stamp);
    if (mkdir(out, 0700) || mkdir(keysdir, 0700))
        return run_die("cannot create %s: %s", out, strerror(errno));
    if (!(keys = new_file(keysdir, "candidates.txt", &kfd)))
        return run_die("cannot create %s/candidates.txt: %s", keysdir, strerror(errno));
    if (!(msg = new_file(out, "scan.txt", &mfd))) {
        fclose(keys);
        return run_die("cannot create %s: %s", path, strerror(errno));
    }

    printf("keep %s\n", KEEP_VERSION);
    printf("memory dump: %s\n", dump);
    printf("output: %s\n\n", out);
    fflush(stdout);

    status = keyscan_run(dump, 0, 1, keys, msg, &failed);
    keyscan_hits(&found);
    keyscan_wipe();
    if (fflush(keys) || fflush(msg) || fsync(kfd) || fsync(mfd))
        written = 0;
    if (fclose(keys) || fclose(msg) || flush_path(keysdir) || flush_path(out) || flush_path(dest))
        written = 0;
    if ((said = read_text(path, 1 << 20, NULL))) {
        fputs(said, stdout);
        free(said);
    }
    printf("\n%d schedules are listed in keys/candidates.txt. None of them is proven: the key of a volume is the\n"
           "one that the header of that volume accepts, which vkverify.py tests in the lab.\n", found);
    if (!written) {
        fprintf(stderr, "keep: a write or a flush to the destination FAILED, the folder is not complete\n");
        return status ? status : 1;
    }
    printf("keep: every file of this run is flushed to the destination\n");
    return status;
}
