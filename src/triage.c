/*
 * triage.c: the triage of the running system, the work of keytriage.sh in one program.
 *
 * For every open dm-crypt volume the first route that is open is taken:
 *
 *   R1 table    the table of the mapping carries the key (LUKS1, plain, tcrypt, LUKS2 opened with
 *               --disable-keyring). The key is read from the kernel and, for LUKS, proven
 *               against the digest of the header.
 *   R3 memory   the table carries a reference into the kernel keyring (the default of LUKS2).
 *               The AES key schedules are searched in /proc/kcore, once for all volumes, and
 *               proven against the header.
 *   R5 live     no key route is open: only a copy of the mounted files remains.
 *
 * The program starts no other program. The list of the mappings and their tables come from the
 * kernel (dm.c), the header is read from the backing device and copied as "cryptsetup
 * luksHeaderBackup" copies it (luks.c), and the proof is the PBKDF2 digest of the header,
 * computed here (hash.c). Nothing is written outside the destination.
 *
 * No key is printed. A key is written only below keys/ of the folder of the run, by this
 * process with umask 077, counts as captured only after it is flushed, and is named by the first
 * 16 digits of its SHA-256.
 */
#include "triage.h"
#include "dm.h"
#include "keyscan.h"
#include "luks.h"
#include "sys.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define XTS_DISTANCE 496        /* data schedule minus tweak schedule, struct aesni_xts_ctx */

static const char V_PROVEN[] = "captured and proven", V_IN_USE[] = "captured, in use",
                  V_NOT_PROVEN[] = "captured, not proven", V_MEMORY[] = "needs a memory read",
                  V_LIVE[] = "live copy only", V_NO_KEY[] = "no key needed";
static const char R_TABLE[] = "R1 table", R_MEMORY[] = "R3 memory";

struct volume {
    char name[DM_NAME_LEN];             /* as the kernel has it */
    char shown[DM_NAME_LEN];            /* for the screen */
    char file[DM_NAME_LEN + 64];        /* as part of a file name */
    char type[16], cipher[128], device[PATH_MAX], keyhash[17], note[320];
    const char *location, *route, *verdict;
    unsigned key_bits;
    int has_key_bits, has_header;
    char *in_use;
};

struct run {
    char out[PATH_MAX];                 /* the folder of this run */
    FILE *report;
    int write_failed;
    char **files;                       /* every file of the run, relative to the folder */
    size_t nfiles;
    char lockdown[64];
    unsigned budget;
    int scanned, scan_ok, scan_refused;
    char scan_error[256];
};

static void say(struct run *r, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say(struct run *r, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
    va_start(ap, fmt);
    if (vfprintf(r->report, fmt, ap) < 0 || fputc('\n', r->report) == EOF)
        r->write_failed = 1;
    va_end(ap);
}

static int pathf(char out[PATH_MAX], const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int pathf(char out[PATH_MAX], const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(out, PATH_MAX, fmt, ap);
    va_end(ap);
    return n < 0 || n >= PATH_MAX ? -1 : 0;
}

/* A new file of the run. It must not exist, so nothing of an earlier run is written over. */
static int create(struct run *r, const char *rel, int flags, mode_t mode)
{
    char path[PATH_MAX], **grown, *copy;
    int fd;

    if (pathf(path, "%s/%s", r->out, rel)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    if ((fd = open(path, flags | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode)) < 0)
        return -1;
    if (!(grown = realloc(r->files, (r->nfiles + 1) * sizeof *grown)) || !(copy = strdup(rel))) {
        if (grown)
            r->files = grown;
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    r->files = grown;
    r->files[r->nfiles++] = copy;
    return fd;
}

/* fsync of a file of the run and of the directory that names it. A failure is remembered: the
   run then ends with status 1. */
static int flush(struct run *r, int fd, const char *dir)
{
    char path[PATH_MAX];

    if (fsync(fd) || pathf(path, "%s/%s", r->out, dir) || flush_path(path)) {
        r->write_failed = 1;
        return -1;
    }
    return 0;
}

/* The time now in UTC, for a line of the report or as part of the name of the folder. */
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

static void key_name(const uint8_t *key, size_t n, char out[17])
{
    uint8_t digest[32];

    sha256(key, n, digest);
    hex_encode(digest, 8, out);
}

/* Close a volume: print the verdict and keep it for the summary and for verdict.json. */
static void verdict(struct run *r, struct volume *v, const char *what, const char *route, const char *fmt, ...)
    __attribute__((format(printf, 5, 6)));
static void verdict(struct run *r, struct volume *v, const char *what, const char *route, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(v->note, sizeof v->note, fmt, ap);
    va_end(ap);
    v->verdict = what;
    v->route = route;
    if (v->note[0])
        say(r, "  VERDICT: %s (%s)", what, v->note);
    else
        say(r, "  VERDICT: %s", what);
    say(r, "%s", "");
}

/* Write a key to keys/ and flush it. Only then does it count as captured. */
static int keep_key(struct run *r, struct volume *v, const uint8_t *key, size_t n)
{
    char rel[PATH_MAX];
    int fd, ok;

    if (pathf(rel, "keys/%s.vk", v->file) || (fd = create(r, rel, O_WRONLY, 0600)) < 0) {
        r->write_failed = 1;
        return -1;
    }
    ok = !write_all(fd, key, n) && !flush(r, fd, "keys");
    if (close(fd) || !ok) {
        r->write_failed = 1;
        return -1;
    }
    key_name(key, n, v->keyhash);
    return 0;
}

/* The search of /proc/kcore, run once and used for every volume that needs it. */
static void scan_once(struct run *r)
{
    FILE *keys = NULL, *msg = NULL;
    char path[PATH_MAX], *text;
    int kfd, mfd, failed = 0, status, n;

    if (r->scanned) {
        if (!r->scan_ok)
            say(r, "  R3 memory: the search of /proc/kcore failed, as above");
        return;
    }
    r->scanned = 1;
    say(r, "  R3 memory: searching /proc/kcore for AES key schedules");
    kfd = create(r, "keys/kcore-candidates.txt", O_WRONLY, 0600);
    mfd = create(r, "log/kcore-keyscan.txt", O_WRONLY, 0600);
    if (kfd < 0 || mfd < 0 || !(keys = fdopen(kfd, "w")) || !(msg = fdopen(mfd, "w"))) {
        snprintf(r->scan_error, sizeof r->scan_error, "the list of the schedules cannot be written: %s", strerror(errno));
        say(r, "  the search failed: %s", r->scan_error);
        r->write_failed = 1;
        if (keys) fclose(keys); else if (kfd >= 0) close(kfd);
        if (msg) fclose(msg); else if (mfd >= 0) close(mfd);
        return;
    }
    status = keyscan_run("/proc/kcore", 0, 1, keys, msg, &failed);
    if (fflush(keys) || fflush(msg))
        r->write_failed = 1;
    if (status == 0) {
        keyscan_hits(&n);
        r->scan_ok = 1;
        say(r, "  %d schedules found, list in keys/kcore-candidates.txt", n);
        if (flush(r, kfd, "keys"))
            say(r, "  the list could not be flushed to the destination");
    } else {
        r->scan_refused = failed == EPERM;
        if (!pathf(path, "%s/log/kcore-keyscan.txt", r->out) && (text = read_text(path, sizeof r->scan_error - 1, NULL))) {
            text[strcspn(text, "\n")] = 0;
            snprintf(r->scan_error, sizeof r->scan_error, "%s", text);
            free(text);
        }
        say(r, "  the search failed: %s", r->scan_error[0] ? r->scan_error : "no message");
    }
    fclose(keys);
    fclose(msg);
}

/* The type of a mapping by the UUID that cryptsetup gave it, CRYPT-<type>-..., in the order of
   crypt_init_by_name_and_header. A mapping that another program made has none. */
static void type_of_uuid(const char *uuid, char type[16])
{
    static const char *const known[] = { "PLAIN", "LOOPAES", "LUKS1", "LUKS2", "VERITY", "TCRYPT",
                                         "INTEGRITY", "BITLK", "FVAULT2" };
    size_t i;

    snprintf(type, 16, "n/a");
    if (strncmp(uuid, "CRYPT-", 6))
        return;
    for (i = 0; i < sizeof known / sizeof known[0]; i++)
        if (!strncmp(uuid + 6, known[i], strlen(known[i]))) {
            snprintf(type, 16, "%s", known[i]);
            return;
        }
}

/*
 * The LUKS header of a mapping: open the backing device and read the header at its start. A
 * mapping whose device holds no header of its type, or the header of another volume, is taken
 * as one without a header, as cryptsetup takes it (_init_by_name_crypt), and its type is then
 * "n/a". Returns the descriptor of the device, or -1 with the line that says why.
 */
static int find_header(struct volume *v, const char *uuid, unsigned major, unsigned minor,
                       struct luks_header *on_device, struct str *why)
{
    char err[LUKS_ERR_LEN];
    struct stat st;
    int dev, found;

    if ((dev = open(v->device, O_RDONLY | O_CLOEXEC)) < 0) {
        str_addf(why, "header backup FAILED for %s: %s", v->device, strerror(errno));
        return -1;
    }
    if (fstat(dev, &st) || !S_ISBLK(st.st_mode) || st.st_rdev != makedev(major, minor)) {
        str_addf(why, "header backup FAILED for %s: it is not the block device %u:%u of the table", v->device, major, minor);
    } else if ((found = luks_read(dev, on_device, err)) < 0) {
        str_addf(why, "header backup FAILED for %s: %s", v->device, err);
    } else if (found > 0) {
        str_addf(why, "%s: %s. The mapping is taken as one without a header", v->device, err);
        snprintf(v->type, sizeof v->type, "n/a");
    } else if (on_device->version != (v->type[4] == '1' ? 1 : 2) || !luks_uuid_matches(on_device, uuid)) {
        str_addf(why, "%s: the LUKS%d header there, UUID %s, is not that of this mapping. The mapping is taken as "
                 "one without a header", v->device, on_device->version, on_device->uuid);
        snprintf(v->type, sizeof v->type, "n/a");
    } else {
        return dev;
    }
    close(dev);
    return -1;
}

/*
 * Copy the header to headers/ and read the copy, which is what the proof is made against: a
 * key that is proven is proven against the file that is kept.
 */
static void back_up_header(struct run *r, struct volume *v, int dev, const struct luks_header *on_device,
                           struct luks_header *h)
{
    char err[LUKS_ERR_LEN], rel[PATH_MAX];
    uint64_t written = 0;
    int out;

    if (on_device->secondary)
        say(r, "  the first copy of the LUKS2 header is damaged and the second one is in use. Both are copied as they are");
    if (pathf(rel, "headers/%s.hdr", v->file) || (out = create(r, rel, O_RDWR, 0400)) < 0) {
        say(r, "  header backup FAILED for %s: %s", v->device, strerror(errno));
        r->write_failed = 1;
        return;
    }
    if (luks_backup(dev, on_device, out, &written, err)) {
        say(r, "  header backup FAILED for %s: %s", v->device, err);
    } else {
        say(r, "  header backed up: %s (%llu bytes)", rel, (unsigned long long)written);
        if (flush(r, out, "headers"))
            say(r, "  the header backup could not be flushed to the destination");
        if (luks_read(out, h, err))
            say(r, "  the header backup cannot be read back: %s", err);
        else
            v->has_header = 1;
    }
    close(out);
}

/* The memory route for a volume whose header is backed up: pair or take the schedules, prove. */
static void memory_route(struct run *r, struct volume *v, const struct luks_header *h, int xts)
{
    const struct keyscan_hit *hits;
    const char *hash = NULL;
    uint8_t key[64];
    unsigned bits = xts ? v->key_bits / 2 : v->key_bits, tried = 0;
    int n, i, j, nk = bits == 128 ? 4 : bits == 256 ? 8 : 0, count = 0, proven = 0, uncomputed = 0;

    hits = keyscan_hits(&n);
    for (i = 0; i < n; i++)
        count += hits[i].nk == nk;
    say(r, "  %d schedules of AES-%u", count, bits);
    for (i = 0; i < n && tried < r->budget && !proven && !uncomputed; i++) {
        size_t len = (size_t)nk * 4;
        int result;

        if (hits[i].nk != nk)
            continue;
        if (xts) {
            /* The volume key is the data key and then the tweak key. The kernel keeps the tweak
               schedule first and the data schedule 496 bytes after it, so for a tweak schedule
               at P the data schedule at P + 496 is taken. */
            for (j = 0; j < n && !(hits[j].nk == nk && hits[j].phys == hits[i].phys + XTS_DISTANCE); j++)
                ;
            if (j == n)
                continue;
            memcpy(key, hits[j].key, len);
            memcpy(key + len, hits[i].key, len);
            len *= 2;
        } else {
            memcpy(key, hits[i].key, len);
        }
        tried++;
        if ((result = luks_proves(h, key, len, &hash)) < 0) {
            uncomputed = 1;
        } else if (result) {
            proven = 1;
            if (keep_key(r, v, key, len)) {
                say(r, "  the key could not be written to the destination");
                verdict(r, v, V_MEMORY, NULL, "the write of the key to the destination failed");
            } else {
                say(r, "  recovered a volume key of %zu bytes, sha256 %s", len, v->keyhash);
                if (xts)
                    say(r, "  the tweak schedule is at 0x%016llx and the data schedule 496 bytes after it at 0x%016llx",
                        (unsigned long long)hits[i].phys, (unsigned long long)hits[i].phys + XTS_DISTANCE);
                else
                    say(r, "  its schedule is at 0x%016llx", (unsigned long long)hits[i].phys);
                verdict(r, v, V_PROVEN, R_MEMORY, "opens the header");
            }
        }
    }
    explicit_bzero(key, sizeof key);
    if (uncomputed) {
        say(r, "  the digest of the header uses %s, which this program does not compute", hash ? hash : "no known function");
        verdict(r, v, V_MEMORY, NULL, "no proof on scene, the candidate list is kept for the lab verifier");
    } else if (!proven) {
        say(r, "  no candidate proved within %u test(s) of budget %u", tried, r->budget);
        verdict(r, v, V_MEMORY, NULL, "the candidate list is kept for the lab verifier");
    }
}

/* What the kernel said about the mapping, kept in log/ with the key replaced by zeros, as
   "dmsetup table" prints it. */
static void log_table(struct run *r, const struct volume *v, const struct dm_table *t)
{
    char rel[PATH_MAX];
    struct str text = { 0 };
    size_t i;
    int fd;

    str_addf(&text, "name %s\nuuid %s\ndevice %u:%u\n", t->name, t->uuid[0] ? t->uuid : "-", t->major, t->minor);
    for (i = 0; i < t->ntargets; i++) {
        const char *p = t->targets[i].params, *key = strchr(p, ' ');

        str_addf(&text, "%llu %llu %s ", (unsigned long long)t->targets[i].start,
                 (unsigned long long)t->targets[i].length, t->targets[i].type);
        if (!strcmp(t->targets[i].type, "crypt") && key && key[1] != ':') {
            size_t n = strcspn(++key, " ");

            str_addn(&text, p, (size_t)(key - p));
            for (; n; n--)
                str_add(&text, "0");
            str_add(&text, key + strcspn(key, " "));
        } else {
            str_add(&text, p);
        }
        str_add(&text, "\n");
    }
    if (text.failed || pathf(rel, "log/%s.table.txt", v->file) || (fd = create(r, rel, O_WRONLY, 0600)) < 0) {
        r->write_failed = 1;
    } else {
        if (write_all(fd, str_text(&text), text.len))
            r->write_failed = 1;
        close(fd);
    }
    str_free(&text);
}

static void one_volume(struct run *r, int dm, struct volume *v)
{
    char err[DM_ERR_LEN], *params = NULL, *field[5] = { 0 }, *p;
    struct luks_header header, on_device;
    struct dm_table table;
    struct str why = { 0 };
    unsigned major = 0, minor = 0;
    size_t i, keylen;
    int have_device, xts, aes, luks, dev = -1;

    say(r, "==== %s", v->shown);
    snprintf(v->type, sizeof v->type, "n/a");
    if (dm_table(dm, v->name, &table, err)) {
        say(r, "  R1 table: %s, so the table route is not open", err);
        verdict(r, v, V_MEMORY, NULL, "the table of the mapping could not be read");
        return;
    }
    log_table(r, v, &table);                    /* as the kernel gave it, before the line is cut into fields */
    for (i = 0; i < table.ntargets && strcmp(table.targets[i].type, "crypt"); i++)
        ;
    if (i < table.ntargets)
        params = table.targets[i].params;
    /* a crypt target: cipher, key, IV offset, device, offset, and then its options */
    for (i = 0, p = params; p && i < 5; i++) {
        field[i] = p;
        if ((p = strchr(p, ' ')))
            *p++ = 0;
    }
    if (!field[4]) {
        say(r, "  R1 table: the kernel gave no table line of a crypt target that is understood");
        verdict(r, v, V_MEMORY, NULL, "the table of the mapping is not understood");
        dm_table_free(&table);
        return;
    }
    snprintf(v->cipher, sizeof v->cipher, "%s", field[0]);
    keylen = strlen(field[1]);
    type_of_uuid(table.uuid, v->type);
    if (field[1][0] == ':') {
        v->location = "keyring";
        v->has_key_bits = sscanf(field[1] + 1, "%u", &v->key_bits) == 1;
        v->key_bits *= 8;
    } else {
        v->location = "dm-crypt";
        v->has_key_bits = 1;
        v->key_bits = strcmp(field[1], "-") ? (unsigned)keylen * 4 : 0;
    }
    have_device = sscanf(field[3], "%u:%u", &major, &minor) == 2 &&
                  !sys_device_path("/sys", major, minor, v->device, sizeof v->device);
    /* the header decides with the UUID what the mapping is, so it is read before the type is named */
    luks = !strcmp(v->type, "LUKS1") || !strcmp(v->type, "LUKS2");
    if (luks && have_device)
        dev = find_header(v, table.uuid, major, minor, &on_device, &why);
    else if (luks)
        str_addf(&why, "header backup FAILED: no device node for %s", field[3]);
    if (v->has_key_bits)
        say(r, "  type %s, cipher %s, keysize %u bits, key location %s", v->type, v->cipher, v->key_bits, v->location);
    else
        say(r, "  type %s, cipher %s, keysize ? bits, key location %s", v->type, v->cipher, v->location);
    say(r, "  backing device %s", have_device ? v->device : "?");
    v->in_use = sys_in_use("/sys", "/proc/self/mountinfo", "/proc/swaps", table.major, table.minor);
    if (v->in_use)
        name_clean(v->in_use);
    say(r, "  in use: %s", v->in_use && v->in_use[0] ? v->in_use
        : "not mounted and not swap, also nothing that stands on it");

    xts = !strncmp(v->cipher, "aes-xts-", 8) || !strncmp(v->cipher, "capi:xts(aes)-", 14);
    aes = xts || !strncmp(v->cipher, "aes-", 4);

    /* a key is useless without the header, so the header comes first */
    if (why.len)
        say(r, "  %s", str_text(&why));
    str_free(&why);
    if (dev >= 0) {
        back_up_header(r, v, dev, &on_device, &header);
        close(dev);
    }

    if (!strcmp(field[1], "-")) {
        /* dm-crypt writes "-" for a key of size 0 (crypt_status), which is the null cipher */
        say(r, "  R1 table: the mapping has no key (key size 0), the device holds the data as they are");
        verdict(r, v, V_NO_KEY, R_TABLE, "key size 0 in the table, cipher %s", v->cipher);
    } else if (field[1][0] != ':') {
        uint8_t *key = keylen % 2 ? NULL : malloc(keylen / 2 + 1);
        const char *hash = NULL;
        int result;

        if (!key || hex_decode(field[1], keylen, key)) {
            say(r, "  R1 table: the key field of the table line is neither a key in hexadecimal nor a keyring reference");
            verdict(r, v, V_MEMORY, NULL, "the key field of the table line is not understood");
        } else if (keep_key(r, v, key, keylen / 2)) {
            say(r, "  R1 table: the key is in the table and could not be written to the destination");
            verdict(r, v, V_MEMORY, NULL, "the write of the key to the destination failed");
        } else {
            say(r, "  R1 table: key of %zu bytes, sha256 %s", keylen / 2, v->keyhash);
            if (!v->has_header && (!strcmp(v->type, "LUKS1") || !strcmp(v->type, "LUKS2")))
                verdict(r, v, V_NOT_PROVEN, R_TABLE, "no header backup to prove against");
            else if (!v->has_header)
                verdict(r, v, V_IN_USE, R_TABLE, "the key of the live mapping, no header digest exists, the lab open confirms");
            else if ((result = luks_proves(&header, key, keylen / 2, &hash)) > 0)
                verdict(r, v, V_PROVEN, R_TABLE, "opens the header");
            else if (result == 0)
                verdict(r, v, V_NOT_PROVEN, R_TABLE, "the header does not accept the key, unexpected");
            else
                verdict(r, v, V_NOT_PROVEN, R_TABLE, "the digest of the header uses %s, which this program does not "
                        "compute, the lab verifier proves it", hash ? hash : "no known function");
        }
        if (key) {
            explicit_bzero(key, keylen / 2);
            free(key);
        }
    } else {
        say(r, "  R1 table: keyring reference %s (no key in the table)", field[1]);
        if (!aes) {
            say(r, "  R3 memory: the cipher %s is not AES, so the AES schedule search does not apply", v->cipher);
            verdict(r, v, V_LIVE, NULL, "a memory image keeps another method open");
        } else if (!strcmp(r->lockdown, "confidentiality")) {
            say(r, "  R3 memory: /proc/kcore is blocked under lockdown confidentiality");
            verdict(r, v, V_LIVE, NULL, "lockdown confidentiality");
        } else {
            scan_once(r);
            if (!r->scan_ok && r->scan_refused) {
                verdict(r, v, V_LIVE, NULL, "the kernel refused the read of /proc/kcore");
            } else if (!r->scan_ok) {
                verdict(r, v, V_MEMORY, NULL, "the search of /proc/kcore failed");
            } else if (!v->has_header || !v->has_key_bits) {
                say(r, "  R3 memory: no header backup or no key size to prove against");
                verdict(r, v, V_MEMORY, NULL, "no proof on scene, the candidate list is kept for the lab verifier");
            } else {
                memory_route(r, v, &header, xts);
            }
        }
    }
    dm_table_free(&table);
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

static void json_value(FILE *f, const char *s)
{
    if (!s || !*s) {
        fputs("null", f);
    } else {
        fputc('"', f);
        json_text(f, s);
        fputc('"', f);
    }
}

static int by_text(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct volume *)a)->name, ((const struct volume *)b)->name);
}

/* manifest.sha256: every file of the run with its SHA-256, in the form of sha256sum, by name. */
static void write_manifest(struct run *r)
{
    char path[PATH_MAX], hex[65];
    uint8_t buf[65536], digest[32];
    struct hash_ctx ctx;
    FILE *f;
    size_t i, count = r->nfiles;
    ssize_t got;
    int fd, mfd;

    qsort(r->files, count, sizeof r->files[0], by_text);
    if ((mfd = create(r, "manifest.sha256", O_WRONLY, 0600)) < 0 || !(f = fdopen(mfd, "w"))) {
        r->write_failed = 1;
        if (mfd >= 0)
            close(mfd);
        return;
    }
    for (i = 0; i < count; i++) {
        if (pathf(path, "%s/%s", r->out, r->files[i]) || (fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
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
        fprintf(f, "%s  %s\n", hex, r->files[i]);
    }
    explicit_bzero(buf, sizeof buf);
    if (fflush(f) || fsync(mfd))
        r->write_failed = 1;
    fclose(f);
}

static int die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static int die(const char *fmt, ...)
{
    va_list ap;

    fputs("keep: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return 1;
}

int triage_run(const struct triage_options *o)
{
    char dest[PATH_MAX], path[PATH_MAX], host[256], hostfile[256], started[32], finished[32], stamp[32];
    char secure_boot[16], os[256], err[DM_ERR_LEN], *other;
    struct run run = { .budget = o->budget }, *r = &run;
    struct volume *vols = NULL;
    struct dm_dev *devs = NULL;
    struct sys_mount mount;
    struct statvfs vfs;
    struct utsname un;
    struct str medium = { 0 };
    const char *bad;
    size_t ndevs = 0, nvols = 0, i, k;
    FILE *json;
    int dm = -1, fd;

    umask(077);
    if ((bad = hash_selftest()))
        return die("%s does not compute the example of its standard, so a proof would not be reliable", bad);
    if (geteuid() != 0)
        return die("must run as root (sudo)");
    if (!realpath(o->dest, dest))
        return die("the destination directory %s: %s", o->dest, strerror(errno));
    /* the file system that holds the destination, for the report. Where the destination lies is
       the examiner's decision and is not tested. */
    if (sys_mount_of("/proc/self/mountinfo", dest, &mount))
        return die("no mount that holds %s in /proc/self/mountinfo", dest);
    str_addf(&medium, "%s (%s) mounted at %s", mount.source, mount.type, mount.point);
    if (medium.failed)
        return die("no memory");
    if (mount.readonly)
        return die("%s is on a file system that is mounted read-only: %s", dest, medium.s);
    sys_mount_free(&mount);
    if (access(dest, W_OK))
        return die("%s is not writable", dest);

    uname(&un);
    snprintf(host, sizeof host, "%s", un.nodename);
    name_clean(host);
    name_file(host, hostfile, sizeof hostfile);
    utc(stamp, 1);
    utc(started, 0);
    if (pathf(r->out, "%s/triage_%s_%s", dest, hostfile, stamp) || mkdir(r->out, 0700))
        return die("cannot create %s/triage_%s_%s: %s", dest, hostfile, stamp, strerror(errno));
    for (i = 0; i < 3; i++)
        if (pathf(path, "%s/%s", r->out, i == 0 ? "headers" : i == 1 ? "keys" : "log") || mkdir(path, 0700))
            return die("cannot create %s: %s", path, strerror(errno));
    if ((fd = create(r, "triage.txt", O_WRONLY, 0600)) < 0 || !(r->report = fdopen(fd, "w")))
        return die("cannot create %s/triage.txt: %s", r->out, strerror(errno));

    sys_lockdown("/sys/kernel/security/lockdown", r->lockdown, sizeof r->lockdown);
    sys_secure_boot("/sys/firmware/efi/efivars", secure_boot, sizeof secure_boot);
    sys_os_name("/etc/os-release", "/usr/lib/os-release", os, sizeof os);
    name_clean(os);

    say(r, "keep %s", KEEP_VERSION);
    say(r, "host %s, %s, kernel %s", host, started, un.release);
    say(r, "system: %s", os[0] ? os : "unknown");
    say(r, "kernel lockdown: %s", r->lockdown[0] ? r->lockdown : "unknown");
    if (secure_boot[0])
        say(r, "secure boot: %s (1 enabled)", secure_boot);
    else
        say(r, "secure boot: no SecureBoot variable");
    say(r, "output: %s", r->out);
    if (statvfs(r->out, &vfs))
        say(r, "destination: %s", medium.s);
    else
        say(r, "destination: %s, %llu MiB free", medium.s,
            (unsigned long long)vfs.f_bavail * vfs.f_frsize / 1048576);
    if (o->lock_errno)
        say(r, "the memory of this program could not be locked (%s), so a part of it can reach the swap space",
            strerror(o->lock_errno));
    say(r, "%s", "");

    /* The open crypt volumes: every mapped device with a crypt target in its table, which is
       what "dmsetup ls --target crypt" lists. The control device is opened only where the
       kernel has device-mapper: its node can exist without it, and opening it would then load
       the module (the alias devname:mapper/control of dm-mod). */
    if (access("/sys/class/misc/device-mapper", F_OK)) {
        say(r, "this kernel has no device-mapper loaded, so there is no dm-crypt volume");
    } else if ((dm = dm_open(err)) < 0 || dm_list(dm, &devs, &ndevs, err)) {
        say(r, "the mapped devices cannot be listed: %s", err);
        r->write_failed = 1;
    }
    if (ndevs && !(vols = calloc(ndevs, sizeof *vols)))
        return die("no memory");
    for (i = 0; i < ndevs; i++) {
        struct dm_table t;

        if (dm_table(dm, devs[i].name, &t, err))
            continue;                           /* removed since the list was read */
        for (k = 0; k < t.ntargets && strcmp(t.targets[k].type, "crypt"); k++)
            ;
        if (k < t.ntargets)
            memcpy(vols[nvols++].name, devs[i].name, DM_NAME_LEN);
        dm_table_free(&t);
    }
    free(devs);
    if (nvols)
        qsort(vols, nvols, sizeof *vols, by_name);
    for (i = 0; i < nvols; i++) {
        /* FAT and exFAT fold the case of a name, so two names that are the same but for that
           are kept apart by a further _. Where the room for those is used up the names stay the
           same, and the second file is then refused, because no file of a run is written over. */
        memcpy(vols[i].shown, vols[i].name, DM_NAME_LEN);
        name_clean(vols[i].shown);
        name_file(vols[i].name, vols[i].file, DM_NAME_LEN);
        for (k = 0; k < i; k++)
            if (!strcasecmp(vols[k].file, vols[i].file) && strlen(vols[i].file) + 1 < sizeof vols[i].file) {
                strcat(vols[i].file, "_");
                k = (size_t)-1;
            }
    }
    if (!nvols) {
        say(r, "no open dm-crypt volumes");
    } else {
        struct str names = { 0 };

        for (i = 0; i < nvols; i++)
            str_addf(&names, "%s%s", i ? " " : "", vols[i].shown);
        say(r, "%zu open dm-crypt volume(s): %s", nvols, str_text(&names));
        str_free(&names);
    }
    /* mounted file systems that can carry their own encryption. They are not dm-crypt, so they
       are named, so that their absence from the verdicts is not read as "clear". */
    other = sys_other_filesystems("/proc/mounts");
    if (other && other[0])
        say(r, "mounted and not examined here (file systems that can encrypt by themselves): %s", other);
    say(r, "%s", "");

    for (i = 0; i < nvols; i++)
        one_volume(r, dm, &vols[i]);
    if (dm >= 0)
        close(dm);
    keyscan_wipe();

    say(r, "==== verdicts");
    for (i = 0; i < nvols; i++)
        say(r, "  %-16s  %s", vols[i].shown, vols[i].verdict ? vols[i].verdict : "unknown");
    say(r, "%s", "");
    utc(finished, 0);
    say(r, "finished %s", finished);
    if (fflush(r->report) || fsync(fileno(r->report)))
        r->write_failed = 1;
    fclose(r->report);

    /* the same verdicts for a program, schema keep-report/1. No key is in this file. */
    if ((fd = create(r, "verdict.json", O_WRONLY, 0600)) < 0 || !(json = fdopen(fd, "w"))) {
        r->write_failed = 1;
    } else {
        fprintf(json, "{\n  \"schema\": \"keep-report/1\",\n  \"tool\": \"keep %s\",\n  \"host\": ", KEEP_VERSION);
        json_value(json, host);
        fputs(",\n  \"kernel\": ", json); json_value(json, un.release);
        fputs(",\n  \"os\": ", json); json_value(json, os);
        fputs(",\n  \"cryptsetup\": null,\n  \"other_filesystems\": ", json); json_value(json, other);
        fprintf(json, ",\n  \"started_utc\": \"%s\",\n  \"finished_utc\": \"%s\",\n  \"lockdown\": ", started, finished);
        json_value(json, r->lockdown);
        fputs(",\n  \"secure_boot\": ", json); json_value(json, secure_boot);
        fputs(",\n  \"source\": \"/proc/kcore\",\n  \"evidence_medium\": ", json); json_value(json, medium.s);
        fputs(",\n  \"memory\": null,\n  \"binaries\": [\n  ],\n  \"volumes\": [", json);
        for (i = 0; i < nvols; i++) {
            const struct volume *v = &vols[i];
            char header[PATH_MAX] = "";

            if (v->has_header)
                snprintf(header, sizeof header, "headers/%s.hdr", v->file);
            fputs(i ? ",\n    {\"name\": " : "\n    {\"name\": ", json); json_value(json, v->name);
            fputs(", \"type\": ", json); json_value(json, v->type);
            fputs(", \"cipher\": ", json); json_value(json, v->cipher);
            if (v->has_key_bits)
                fprintf(json, ", \"key_bits\": %u", v->key_bits);
            else
                fputs(", \"key_bits\": null", json);
            fputs(", \"key_location\": ", json); json_value(json, v->location);
            fputs(", \"device\": ", json); json_value(json, v->device);
            fputs(", \"in_use\": ", json); json_value(json, v->in_use);
            fputs(", \"header_backup\": ", json); json_value(json, header);
            fputs(", \"route\": ", json); json_value(json, v->route);
            fputs(", \"verdict\": ", json); json_value(json, v->verdict);
            fputs(", \"key_sha256_16\": ", json); json_value(json, v->keyhash);
            fputs(", \"note\": ", json); json_value(json, v->note);
            fputc('}', json);
        }
        fputs("\n  ]\n}\n", json);
        if (fflush(json) || fsync(fd))
            r->write_failed = 1;
        fclose(json);
    }
    write_manifest(r);

    /* Everything of this run to the destination: the folder by fsync, which reports a failure,
       and then the whole file system that holds it by syncfs. */
    if ((fd = open(r->out, O_RDONLY | O_CLOEXEC)) < 0 || fsync(fd) || syncfs(fd))
        r->write_failed = 1;
    if (fd >= 0)
        close(fd);
    for (i = 0; i < nvols; i++)
        free(vols[i].in_use);
    for (i = 0; i < r->nfiles; i++)
        free(r->files[i]);
    free(r->files);
    free(vols);
    free(other);
    str_free(&medium);
    if (r->write_failed) {
        fprintf(stderr, "keep: a write or a flush to the destination FAILED, the folder is not complete\n");
        return 1;
    }
    printf("keep: every file of this run is flushed to the destination\n");
    return 0;
}
