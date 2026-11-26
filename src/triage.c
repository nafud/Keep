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
 * With a format of a memory image in the options, the memory of the machine is taken after the
 * keys (memory.c).
 *
 * No key is printed. A key is written only below keys/ of the folder of the run, by this
 * process with umask 077, counts as captured only after it is flushed, and is named by the first
 * 16 digits of its SHA-256.
 */
#include "triage.h"
#include "dm.h"
#include "keyscan.h"
#include "luks.h"
#include "memory.h"
#include "run.h"
#include "snappy.h"
#include "sys.h"
#include "util.h"
#include "volume.h"

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
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#define XTS_DISTANCE 496        /* data schedule minus tweak schedule, struct aesni_xts_ctx */

static const char V_PROVEN[] = "captured and proven", V_IN_USE[] = "captured, in use",
                  V_NOT_PROVEN[] = "captured, not proven", V_MEMORY[] = "needs a memory read",
                  V_LIVE[] = "live copy only", V_NO_KEY[] = "no key needed";
static const char R_TABLE[] = "R1 table", R_MEMORY[] = "R3 memory";

struct key_result {                     /* one key of a volume, and what became of it */
    char cipher[VOL_CIPHER_LEN];
    char file[DM_NAME_LEN + 96];        /* its file in keys/, without the ending */
    char hash[17], note[320];
    const char *location, *route, *verdict;
    unsigned bits;
    int has_bits;
    size_t bytes;                       /* of the key in its file, 0 while no file is written */
};

struct volume {
    char name[DM_NAME_LEN];             /* as the kernel has it */
    char shown[DM_NAME_LEN];            /* for the screen */
    char file[DM_NAME_LEN + 64];        /* as part of a file name */
    char type[16], device[PATH_MAX], note[320];
    const char *verdict;
    int has_header;
    char *in_use;
    struct key_result *keys;            /* one, and two while the volume is re-encrypted */
    size_t nkeys;
};

/* What became of a key: its verdict, the route that gave it and a note. */
static void settle(struct key_result *k, const char *what, const char *route, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void settle(struct key_result *k, const char *what, const char *route, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(k->note, sizeof k->note, fmt, ap);
    va_end(ap);
    k->verdict = what;
    k->route = route;
}

/* How much of a key is held, for the verdict of a volume with more than one: the volume is as
   far as the key that is least far. */
static int held(const char *verdict)
{
    static const char *const order[] = { V_LIVE, V_MEMORY, V_NOT_PROVEN, V_IN_USE, V_PROVEN, V_NO_KEY };
    int i;

    for (i = 0; i < (int)(sizeof order / sizeof order[0]) && order[i] != verdict; i++)
        ;
    return i;
}

/* How far a key is, as the tone of its verdict on the screen. */
static enum run_tone tone_of(const char *verdict)
{
    return verdict == V_PROVEN ? RUN_REACHED : verdict == V_LIVE ? RUN_NOT : verdict == V_NO_KEY ? RUN_PLAIN : RUN_OPEN;
}

/* The size of a key as the table states it, for the screen. */
static void size_of_key(const struct key_result *k, char out[32])
{
    if (!k->has_bits)
        snprintf(out, 32, "key size unknown");
    else if (!k->bits)
        snprintf(out, 32, "key size 0");
    else
        snprintf(out, 32, "%u-bit key", k->bits);
}

/* Close a volume: print the verdict and keep it for the result and for verdict.json. */
static void verdict(struct run *r, struct volume *v, const char *what, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void verdict(struct run *r, struct volume *v, const char *what, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(v->note, sizeof v->note, fmt, ap);
    va_end(ap);
    v->verdict = what;
    run_mark(r, "verdict", tone_of(what), what, "%s", v->note);
}

/* Write a key to keys/ and flush it. Only then does it count as captured. */
static int keep_key(struct run *r, struct key_result *k, const uint8_t *key, size_t n)
{
    if (run_keep_key(r, k->file, key, n, k->hash))
        return -1;
    k->bytes = n;
    return 0;
}

/* The search of /proc/kcore, run once and used for every volume that needs it. */
static void scan_once(struct run *r)
{
    FILE *keys = NULL, *msg = NULL;
    const char *const *said;
    char held[BUFSIZ];
    int kfd, mfd, failed = 0, status, n;

    if (r->scanned) {
        if (!r->scan_ok)
            run_mark(r, "search", RUN_NOT, "FAILED", "the search of /proc/kcore, as above");
        return;
    }
    r->scanned = 1;
    run_progress(r, "search", "reading /proc/kcore for AES key schedules");
    kfd = run_create(r, "keys/kcore-candidates.txt", O_WRONLY, 0600);
    mfd = run_create(r, "log/kcore-keyscan.txt", O_WRONLY, 0600);
    if (kfd < 0 || mfd < 0 || !(keys = fdopen(kfd, "w")) || !(msg = fdopen(mfd, "w"))) {
        snprintf(r->scan_error, sizeof r->scan_error, "the list of the schedules cannot be written: %s", strerror(errno));
        run_mark(r, "search", RUN_NOT, "FAILED", "%s", r->scan_error);
        r->write_failed = 1;
        if (keys) fclose(keys); else if (kfd >= 0) close(kfd);
        if (msg) fclose(msg); else if (mfd >= 0) close(mfd);
        return;
    }
    setvbuf(keys, held, _IOFBF, sizeof held);   /* keys pass through it: it is wiped below */
    status = keyscan_run("/proc/kcore", 0, 1, keys, msg, &failed);
    if (written(keys) | written(msg))
        r->write_failed = 1;
    if (status == 0) {
        keyscan_hits(&n);
        r->scan_ok = 1;
        run_field(r, "search", "/proc/kcore, %d AES schedules in keys/kcore-candidates.txt", n);
        if (run_flush(r, kfd, "keys"))
            run_mark(r, "search", RUN_NOT, "FAILED", "the list could not be flushed to the destination");
    } else {
        r->scan_refused = failed == EPERM;
        said = keyscan_said(&n);
        snprintf(r->scan_error, sizeof r->scan_error, "%s", n ? said[0] : "no message");
        run_mark(r, "search", RUN_NOT, "FAILED", "%s", r->scan_error);
    }
    fclose(keys);
    fclose(msg);
    explicit_bzero(held, sizeof held);
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
 * "n/a". The device is read past the page cache where it takes such reads, which *direct
 * says. Returns the descriptor of the device, or -1 with what is to say of the header, and
 * with *failed where the backup failed and the device could well hold the header.
 */
static int find_header(struct volume *v, const char *uuid, unsigned major, unsigned minor,
                       struct luks_header *on_device, struct str *why, int *failed, int *direct)
{
    char err[LUKS_ERR_LEN];
    struct stat st;
    int dev, found;

    *failed = 1;
    if ((dev = luks_open(v->device, direct)) < 0) {
        str_addf(why, "the backup of %s: %s", v->device, strerror(errno));
        return -1;
    }
    if (fstat(dev, &st) || !S_ISBLK(st.st_mode) || st.st_rdev != makedev(major, minor)) {
        str_addf(why, "the backup of %s: it is not the block device %u:%u of the table", v->device, major, minor);
    } else if ((found = luks_read(dev, on_device, err)) < 0) {
        str_addf(why, "the backup of %s: %s", v->device, err);
    } else if (found > 0) {
        *failed = 0;
        str_addf(why, "none on %s: %s. The mapping is taken as one without a header", v->device, err);
        snprintf(v->type, sizeof v->type, "n/a");
    } else if (on_device->version != (v->type[4] == '1' ? 1 : 2) || !luks_uuid_matches(on_device, uuid)) {
        *failed = 0;
        str_addf(why, "the LUKS%d header on %s, UUID %s, is not that of this mapping. The mapping is taken as "
                 "one without a header", on_device->version, v->device, on_device->uuid);
        snprintf(v->type, sizeof v->type, "n/a");
    } else {
        return dev;
    }
    close(dev);
    return -1;
}

/*
 * Copy the header to headers/ and read the copy, which is what the proof is made against: a
 * key that is proven is proven against the file that is kept. The copy passes the page cache
 * as the read of the device does, where the file system of the destination has direct writes,
 * so that the header takes no free memory of the machine on its way. Where one of the two went
 * through the cache, the run says so.
 */
static void back_up_header(struct run *r, struct volume *v, int dev, int dev_direct, const struct luks_header *on_device,
                           struct luks_header *h)
{
    char err[LUKS_ERR_LEN], rel[PATH_MAX];
    struct luks_copy copy = { 0 };
    int out;

    if (on_device->secondary)
        run_field(r, "header", "the first copy of the LUKS2 header is damaged and the second one is in use, both are copied as they are");
    if (pathf(rel, "headers/%s.hdr", v->file) || (out = run_create_direct(r, rel, O_RDWR, 0400, &copy.direct)) < 0) {
        run_mark(r, "header", RUN_NOT, "FAILED", "the backup of %s: %s", v->device, strerror(errno));
        r->write_failed = 1;
        return;
    }
    if (luks_backup(dev, on_device, out, &copy, err)) {
        /* The part is no copy of the header, and it can hold the room that the keys need: a
           key is a few bytes, and the copy of a LUKS2 header as cryptsetup makes it 16 MiB. */
        run_mark(r, "header", RUN_NOT, "FAILED", "the backup of %s: %s. The part that was written is removed", v->device, err);
        if (copy.write_failed)
            r->write_failed = 1;
        close(out);
        run_remove(r, rel);
        return;
    }
    run_hashed(r, rel, copy.sha256);
    run_field(r, "header", "%s, %llu bytes", rel, (unsigned long long)copy.bytes);
    if (!dev_direct)
        run_field(r, "header", "read through the page cache: the device takes no direct reads");
    if (!copy.direct)
        run_field(r, "header", "its copy written through the page cache: the file system of the destination takes "
                  "no direct writes");
    if (run_flush(r, out, "headers"))
        run_mark(r, "header", RUN_NOT, "FAILED", "the backup could not be flushed to the destination");
    if (luks_read(out, h, err))
        run_mark(r, "header", RUN_NOT, "FAILED", "the backup cannot be read back: %s", err);
    else
        v->has_header = 1;
    /* what the cache holds of the copy is let go, as for an image (image_settle) */
    posix_fadvise(out, 0, 0, POSIX_FADV_DONTNEED);
    close(out);
}

/*
 * The memory route for a key whose header is backed up: pair or take the schedules, prove.
 * TAKEN names the digests of the header that other keys of the volume give, and OTHERS those
 * that are not the digest of this key, so that the two keys of a volume in re-encryption are
 * two keys and each is the key of its part.
 */
static void memory_route(struct run *r, struct key_result *k, const struct luks_header *h, int xts, unsigned *taken,
                         unsigned others)
{
    const struct keyscan_hit *hits;
    const char *hash = NULL;
    uint8_t key[64];
    unsigned bits = xts ? k->bits / 2 : k->bits, tried = 0;
    int n, i, j, nk = bits == 128 ? 4 : bits == 256 ? 8 : 0, count = 0, proven = 0, uncomputed = 0;

    hits = keyscan_hits(&n);
    for (i = 0; i < n; i++)
        count += hits[i].nk == nk;
    run_field(r, "candidates", "%d schedules of AES-%u", count, bits);
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
        if ((result = luks_proves(h, key, len, *taken | others, &hash)) < 0) {
            uncomputed = 1;
        } else if (result) {
            proven = 1;
            *taken |= 1u << (result - 1);
            if (keep_key(r, k, key, len)) {
                run_mark(r, "key file", RUN_NOT, "FAILED", "the key could not be written to the destination");
                settle(k, V_MEMORY, NULL, "the write of the key to the destination failed");
            } else {
                if (xts)
                    run_field(r, "found", "tweak schedule at 0x%llx, data schedule at 0x%llx",
                              (unsigned long long)hits[i].phys, (unsigned long long)hits[i].phys + XTS_DISTANCE);
                else
                    run_field(r, "found", "its schedule at 0x%llx", (unsigned long long)hits[i].phys);
                run_field(r, "key file", "keys/%s.vk, %zu bytes, sha256 %s", k->file, len, k->hash);
                settle(k, V_PROVEN, R_MEMORY, "opens the header");
            }
        }
    }
    explicit_bzero(key, sizeof key);
    if (uncomputed) {
        run_field(r, "proof", "none: the digest of the header uses %s, which this program does not compute",
                  hash ? hash : "no known function");
        settle(k, V_MEMORY, NULL, "no proof on scene, the candidate list is kept for the lab verifier");
    } else if (!proven) {
        run_field(r, "proof", "none in %u attempt%s, of at most %u (-b)", tried, tried == 1 ? "" : "s", r->budget);
        settle(k, V_MEMORY, NULL, "the candidate list is kept for the lab verifier");
    }
}

/* The tables of the volume, kept in log/: its own, and those of the devices that are part of it. */
static void log_tables(struct run *r, const struct volume *v, const struct vol *f)
{
    char rel[PATH_MAX];
    struct str text = { 0 };
    size_t i;
    int fd;

    vol_table_text(&text, f->top);
    for (i = 0; i < f->nparts; i++) {
        str_add(&text, "\n");
        vol_table_text(&text, f->parts[i]);
    }
    if (f->below) {
        str_add(&text, "\n");
        vol_table_text(&text, f->below);
    }
    if (text.failed || pathf(rel, "log/%s.table.txt", v->file) || (fd = run_create(r, rel, O_WRONLY, 0600)) < 0) {
        r->write_failed = 1;
    } else {
        if (write_all(fd, str_text(&text), text.len))
            r->write_failed = 1;
        close(fd);
    }
    str_free(&text);
}

/*
 * The digest of the header that a keyring reference names. cryptsetup gives the key of digest N
 * the description cryptsetup:<UUID of the header>-d<N> (get_key_description_by_digest), so the
 * reference says which of the two keys of a volume in re-encryption it stands for. Returns the
 * place of that digest in the header, or -1 where the reference is not of that form or the
 * header has no such digest.
 */
static int named_digest(const struct luks_header *h, const char *field, size_t len)
{
    static const char maker[] = ":cryptsetup:";
    char text[256], *p, *number;
    size_t i, uuid = strlen(h->uuid);

    if (len >= sizeof text)
        return -1;
    memcpy(text, field, len);
    text[len] = 0;
    if (!(p = strstr(text, maker)) || strncmp(p += sizeof maker - 1, h->uuid, uuid) || strncmp(p + uuid, "-d", 2))
        return -1;
    number = p + uuid + 2;
    if (!*number || strspn(number, "0123456789") != strlen(number) || strlen(number) > 9)
        return -1;
    for (i = 0; i < h->ndigests; i++)
        if (h->digests[i].number == (unsigned)strtoul(number, NULL, 10))
            return (int)i;
    return -1;
}

/* The ladder for one key: the table, then memory, and what remains where neither gives it. */
static void one_key(struct run *r, const struct volume *v, struct key_result *k, const struct vol_key *vk,
                    const struct luks_header *header, unsigned *taken)
{
    const char *field = vk->field;
    size_t keylen = vk->field_len;
    int luks = !strcmp(v->type, "LUKS1") || !strcmp(v->type, "LUKS2");
    int xts = !strncmp(k->cipher, "aes-xts-", 8) || !strncmp(k->cipher, "capi:xts(aes)-", 14);
    int aes = xts || !strncmp(k->cipher, "aes-", 4);

    if (keylen == 1 && field[0] == '-') {
        /* dm-crypt writes "-" for a key of size 0 (crypt_status), which is the null cipher */
        run_field(r, "key", "none: key size 0 in the table, the device holds the data as they are");
        settle(k, V_NO_KEY, R_TABLE, "key size 0 in the table, cipher %s", k->cipher);
    } else if (field[0] != ':') {
        uint8_t *key = malloc(keylen / 2 + 1);
        const char *hash = NULL;
        int result;

        if (!key) {
            run_mark(r, "key", RUN_NOT, "FAILED", "in the table, and no memory to take it");
            settle(k, V_MEMORY, NULL, "no memory for the key of the table");
        } else if (hex_decode(field, keylen, key)) {
            run_field(r, "key", "the key field of the table line is neither a key in hexadecimal nor a keyring reference");
            settle(k, V_MEMORY, NULL, "the key field of the table line is not understood");
        } else if (keep_key(r, k, key, keylen / 2)) {
            run_field(r, "key", "in the table");
            run_mark(r, "key file", RUN_NOT, "FAILED", "the key could not be written to the destination");
            settle(k, V_MEMORY, NULL, "the write of the key to the destination failed");
        } else {
            run_field(r, "key", "in the table");
            run_field(r, "key file", "keys/%s.vk, %zu bytes, sha256 %s", k->file, keylen / 2, k->hash);
            if (!v->has_header && luks) {
                settle(k, V_NOT_PROVEN, R_TABLE, "no header backup to prove against");
            } else if (!v->has_header) {
                settle(k, V_IN_USE, R_TABLE, "the key of the live mapping, no header digest exists, the lab open confirms");
            } else if ((result = luks_proves(header, key, keylen / 2, *taken, &hash)) > 0) {
                *taken |= 1u << (result - 1);
                settle(k, V_PROVEN, R_TABLE, "opens the header");
            } else if (result == 0) {
                settle(k, V_NOT_PROVEN, R_TABLE, "the header does not accept the key, unexpected");
            } else {
                settle(k, V_NOT_PROVEN, R_TABLE, "the digest of the header uses %s, which this program does not "
                       "compute, the lab verifier proves it", hash ? hash : "no known function");
            }
        }
        if (key) {
            explicit_bzero(key, keylen / 2);
            free(key);
        }
    } else {
        /* the reference itself stands in log/NAME.table.txt */
        run_field(r, "key", "in the kernel keyring, not in the table");
        if (!strncmp(k->cipher, "capi:authenc(", 13)) {
            /* crypt_copy_authenckey in dm-crypt.c: the key of the cipher and the key of the
               authentication, which is no AES key */
            run_field(r, "search", "none: the volume key holds a key of the authentication beside the key of the cipher, "
                      "and the search for AES schedules finds no such key");
            settle(k, V_LIVE, NULL, "a memory image keeps another method open");
        } else if (!aes) {
            run_field(r, "search", "none: the cipher is not AES, so the search for AES schedules does not apply");
            settle(k, V_LIVE, NULL, "a memory image keeps another method open");
        } else if (!strcmp(r->lockdown, "confidentiality")) {
            run_field(r, "search", "none: /proc/kcore is blocked under lockdown confidentiality");
            settle(k, V_LIVE, NULL, "lockdown confidentiality");
        } else {
            scan_once(r);
            if (!r->scan_ok && r->scan_refused) {
                settle(k, V_LIVE, NULL, "the kernel refused the read of /proc/kcore");
            } else if (!r->scan_ok) {
                settle(k, V_MEMORY, NULL, "the search of /proc/kcore failed");
            } else if (!v->has_header || !k->has_bits) {
                run_field(r, "proof", "none: no header backup or no key size to prove against");
                settle(k, V_MEMORY, NULL, "no proof on scene, the candidate list is kept for the lab verifier");
            } else {
                int named = named_digest(header, field, keylen);
                unsigned others = named < 0 ? 0 : ~(1u << named);

                /* the key that the reference names, and where it names none, one that no other
                   key of the volume has given */
                if (named >= 0 && v->nkeys > 1)
                    run_field(r, "key", "the keyring reference names digest %u of the header", header->digests[named].number);
                memory_route(r, k, header, xts, taken, others);
            }
        }
    }
}

static void one_volume(struct run *r, struct volume *v, const struct vol *f)
{
    struct luks_header header = { 0 }, on_device;
    struct str why = { 0 };
    char size_of[32], label[32];
    unsigned taken = 0;
    size_t i;
    int have_device, luks, dev = -1, dev_direct = 0, header_failed = 0;

    run_title(r, "%s", v->shown);
    log_tables(r, v, f);
    type_of_uuid(f->top->uuid, v->type);
    for (i = 0; i < f->nkeys; i++) {
        struct key_result *k = &v->keys[i];
        const char *field = f->keys[i].field;

        memcpy(k->cipher, f->keys[i].cipher, sizeof k->cipher);
        if (field[0] == ':') {
            k->location = "keyring";
            k->has_bits = sscanf(field + 1, "%u", &k->bits) == 1;
            k->bits *= 8;
        } else {
            k->location = "dm-crypt";
            k->has_bits = 1;
            k->bits = field[0] == '-' ? 0 : (unsigned)f->keys[i].field_len * 4;
        }
    }
    have_device = f->has_device && !sys_device_path("/sys", f->major, f->minor, v->device, sizeof v->device);
    /* the header decides with the UUID what the mapping is, so it is read before the type is named */
    luks = !strcmp(v->type, "LUKS1") || !strcmp(v->type, "LUKS2");
    if (luks && have_device)
        dev = find_header(v, f->top->uuid, f->major, f->minor, &on_device, &why, &header_failed, &dev_direct);
    else if (luks && f->has_device)
        str_addf(&why, "the backup: no device node for %u:%u", f->major, f->minor);
    else if (luks)
        str_addf(&why, "the backup: the table names no device");
    if (luks && !have_device)
        header_failed = 1;

    if (f->nkeys == 1) {
        size_of_key(&v->keys[0], size_of);
        run_field(r, "type", "%s, %s, %s", v->type, v->keys[0].cipher, size_of);
    } else {
        run_field(r, "type", "%s, %zu keys in its tables", v->type, f->nkeys);
    }
    run_field(r, "device", "%s", have_device ? v->device : "unknown");
    if (f->below)
        run_field(r, "integrity", "%s, tags of %u bytes, kept by the dm-integrity device %s below the volume",
                  f->auth, f->tag_size, f->below->name);
    else if (f->tag_size)
        run_field(r, "integrity", "%s, tags of %u bytes", f->auth, f->tag_size);
    if (f->nparts) {
        struct str names = { 0 };

        for (i = 0; i < f->nparts; i++)
            str_addf(&names, "%s%s", i ? ", " : "", f->parts[i]->name);
        if (names.s)
            name_clean(names.s);
        run_field(r, "re-encrypt", "in work, with the helper devices of cryptsetup");
        run_field(r, "helpers", "%s", str_text(&names));
        str_free(&names);
    } else if (!strncmp(f->top->uuid, "CRYPT-SUBDEV-", 13)) {
        run_field(r, "re-encrypt", "a helper device of cryptsetup, whose volume is not among the mapped devices");
    }
    v->in_use = sys_in_use("/sys", "/proc/self/mountinfo", "/proc/swaps", f->top->major, f->top->minor);
    if (v->in_use)
        name_clean(v->in_use);
    /* What is found in /sys and in the mount table is what a copy of the files has to cover.
       The kernel counts every open of the device, also one that leaves no trace there, as
       that of a program that reads the device itself. */
    if (!v->in_use)
        run_field(r, "in use", "unknown: what stands on the device could not be looked up in /sys and "
                  "/proc/self/mountinfo. The kernel counts %d open%s of it", f->top->open_count,
                  f->top->open_count == 1 ? "" : "s");
    else if (v->in_use[0])
        run_field(r, "in use", "%s", v->in_use);
    else if (f->top->open_count > 0)
        run_field(r, "in use", "open %d time%s, by what is not seen: not mounted, not swap, nothing stands on it",
                  f->top->open_count, f->top->open_count == 1 ? "" : "s");
    else
        run_field(r, "in use", "no: not mounted, not swap, nothing stands on it");

    /* a key is useless without the header, so the header comes first */
    if (why.len && header_failed)
        run_mark(r, "header", RUN_NOT, "FAILED", "%s", str_text(&why));
    else if (why.len)
        run_field(r, "header", "%s", str_text(&why));
    str_free(&why);
    if (dev >= 0) {
        back_up_header(r, v, dev, dev_direct, &on_device, &header);
        close(dev);
    }

    if (f->not_understood)
        run_field(r, "table", "%s", f->nkeys ? "a further line of a crypt target is not understood"
                                             : "no line of a crypt target is understood");
    for (i = 0; i < f->nkeys; i++) {
        struct key_result *k = &v->keys[i];

        if (f->nkeys > 1) {
            size_of_key(k, size_of);
            snprintf(label, sizeof label, "key %zu of %zu", i + 1, f->nkeys);
            run_field(r, label, "%s, %s, for %llu sectors of 512 bytes", k->cipher, size_of,
                      (unsigned long long)f->keys[i].sectors);
        }
        one_key(r, v, k, &f->keys[i], &header, &taken);
        if (f->nkeys > 1) {
            snprintf(label, sizeof label, "key %zu", i + 1);
            run_mark(r, label, tone_of(k->verdict), k->verdict, "%s", k->note);
        }
    }

    if (f->nkeys == 1 && !f->not_understood) {
        verdict(r, v, v->keys[0].verdict, "%s", v->keys[0].note);
    } else if (!f->nkeys) {
        verdict(r, v, V_MEMORY, "the table of the mapping is not understood");
    } else {
        /* the volume is as far as the key that is least far */
        const char *least = f->not_understood ? V_MEMORY : v->keys[0].verdict;
        struct str all = { 0 };

        for (i = 0; i < f->nkeys; i++) {
            if (held(v->keys[i].verdict) < held(least))
                least = v->keys[i].verdict;
            str_addf(&all, "%skey %zu %s", i ? ", " : "", i + 1, v->keys[i].verdict);
        }
        if (f->not_understood)
            str_addf(&all, ", and a table line that is not understood");
        verdict(r, v, least, "%zu keys: %s", f->nkeys, str_text(&all));
        str_free(&all);
    }
}

/* The fields of a key in verdict.json, in the three places where they stand in the line of a
   volume: the cipher, the size and the location, then the route, then the name of the key. */
/* One memory image as an object of the report, without its closing brace. The first of a run
   has the fields that keytriage.sh has for the image that AVML wrote, in their order. */
static void json_image(FILE *f, const struct memory_image *m, const struct memory_result *first)
{
    fputs("{\"status\": ", f); run_json(f, m->status);
    fputs(", \"file\": ", f); run_json(f, m->file);
    fputs(", \"format\": ", f);
    run_json(f, !m->file[0] ? "" : m->format == IMAGE_AVML ? "avml compressed" : image_name(m->format));
    if (m->file[0])
        fprintf(f, ", \"bytes\": %llu", (unsigned long long)m->bytes);
    else
        fputs(", \"bytes\": null", f);
    if (first && m->file[0])
        fprintf(f, ", \"seconds\": %u", first->seconds);
    else if (first)
        fputs(", \"seconds\": null", f);
    fputs(", \"sha256\": ", f); run_json(f, m->sha256);
    fprintf(f, ", \"direct_io\": %s", !m->file[0] ? "null" : m->direct ? "true" : "false");
    if (first) {
        fputs(", \"tool\": \"keep " KEEP_VERSION "\", \"system_map\": ", f);
        run_json(f, first->system_map);
    }
    fputs(", \"note\": ", f); run_json(f, m->note);
}

static void json_key(FILE *f, const struct key_result *k, int part)
{
    if (part == 0) {
        fputs(", \"cipher\": ", f); run_json(f, k->cipher);
        if (k->has_bits)
            fprintf(f, ", \"key_bits\": %u", k->bits);
        else
            fputs(", \"key_bits\": null", f);
        fputs(", \"key_location\": ", f); run_json(f, k->location);
    } else if (part == 1) {
        fputs(", \"route\": ", f); run_json(f, k->route);
    } else {
        fputs(", \"key_sha256_16\": ", f); run_json(f, k->hash);
    }
}

/*
 * The tables of all mapped devices, read once: they are what the volumes are found in. The
 * control device is opened only where the kernel has device-mapper: its node can exist without
 * it, and opening it would then load the module (the alias devname:mapper/control of dm-mod).
 * Returns 0, with *present 0 where the kernel has no device-mapper, or -1 with err. A device
 * that was removed since the list was read has no table and is none any more. A table that
 * cannot be read for another reason is named in UNREAD: a volume in it is not examined, which
 * the run has to say. The tables can hold keys: free_tables wipes them.
 */
static int load_tables(struct dm_table **tabs, size_t *ntabs, int *present, struct str *unread, char err[DM_ERR_LEN])
{
    struct dm_dev *devs = NULL;
    size_t ndevs = 0, i;
    int dm;

    *tabs = NULL;
    *ntabs = 0;
    *present = !access("/sys/class/misc/device-mapper", F_OK);
    if (!*present && access("/sys/class/misc", F_OK)) {
        snprintf(err, DM_ERR_LEN, "/sys/class/misc is not there to say whether this kernel has device-mapper: %s",
                 strerror(errno));
        return -1;
    }
    if (!*present)
        return 0;
    if ((dm = dm_open(err)) < 0)
        return -1;
    if (dm_list(dm, &devs, &ndevs, err)) {
        close(dm);
        return -1;
    }
    if (ndevs && !(*tabs = calloc(ndevs, sizeof **tabs))) {
        snprintf(err, DM_ERR_LEN, "the tables of the mapped devices: no memory");
        free(devs);
        close(dm);
        return -1;
    }
    for (i = 0; i < ndevs; i++) {
        int r = dm_table(dm, devs[i].name, &(*tabs)[*ntabs], err);

        if (!r)
            ++*ntabs;
        else if (r < 0)
            str_addf(unread, "%s%s (%s)", unread->len ? ", " : "", devs[i].name, err);
    }
    free(devs);
    close(dm);
    return 0;
}

static void free_tables(struct dm_table *tabs, size_t ntabs)
{
    size_t i;

    for (i = 0; i < ntabs; i++)
        dm_table_free(&tabs[i]);
    free(tabs);
}

int triage_run(const struct triage_options *o)
{
    char dest[PATH_MAX], path[PATH_MAX], host[256], hostfile[256], started[32], finished[32], stamp[32];
    char secure_boot[16], os[256], err[DM_ERR_LEN], *other;
    unsigned long long kib;
    struct run run = { .budget = o->budget }, *r = &run;
    struct volume *vols = NULL;
    struct dm_table *tabs = NULL;
    struct vol *found = NULL;
    struct sys_mount mount;
    struct statvfs vfs;
    struct utsname un;
    struct str medium = { 0 }, where = { 0 }, unread = { 0 };
    struct memory_result mem = { 0 };
    const char *bad;
    size_t ntabs = 0, nvols = 0, i, k;
    FILE *json;
    char unlocked[160] = "", size_of[32], label[32];
    int fd, present = 1, no_memory = 0, listed = 1, names = 0, words = 0, tables_unread, readonly = 0;

    /* Keys pass through the memory of this process. Locked memory is not written to the swap
       space of the examined system. */
    run_lock_memory(unlocked);
    umask(077);
    run_screen(r, o->plain);
    if ((bad = hash_selftest()) || (bad = snappy_selftest()))
        return run_die("%s does not compute the example of its standard, so a proof or an image would not be reliable", bad);
    if (geteuid() != 0)
        return run_die("must run as root (sudo)");
    if (!realpath(o->dest, dest))
        return run_die("the destination directory %s: %s", o->dest, strerror(errno));
    if (access(dest, W_OK))
        return run_die("%s is not writable", dest);
    /* The file system that holds the destination, for the report. Where the destination lies is
       the examiner's decision and is not tested. A destination that the mount table does not
       name, as in a root that is no mount point, is one all the same. */
    if (sys_mount_of("/proc/self/mountinfo", dest, &mount)) {
        str_add(&medium, "unknown: no mount in /proc/self/mountinfo holds it");
        str_add(&where, "a file system that /proc/self/mountinfo does not name");
    } else {
        str_addf(&medium, "%s (%s) mounted at %s", mount.source, mount.type, mount.point);
        str_addf(&where, "%s, %s, mounted at %s", mount.source, mount.type, mount.point);
        readonly = mount.readonly;
        sys_mount_free(&mount);
    }
    if (medium.failed || where.failed) {
        run_die("no memory");
        goto refused;
    }
    if (readonly) {
        run_die("%s is on a file system that is mounted read-only: %s", dest, medium.s);
        goto refused;
    }

    uname(&un);
    snprintf(host, sizeof host, "%s", un.nodename);
    name_clean(host);
    name_file(host, hostfile, sizeof hostfile);
    run_utc(stamp, 1);
    run_utc(started, 0);
    if (pathf(r->out, "%s/triage_%s_%s", dest, hostfile, stamp) || mkdir(r->out, 0700)) {
        run_die("cannot create %s/triage_%s_%s: %s", dest, hostfile, stamp, strerror(errno));
        goto refused;
    }
    for (i = 0; i < 3; i++)
        if (pathf(path, "%s/%s", r->out, i == 0 ? "headers" : i == 1 ? "keys" : "log") || mkdir(path, 0700)) {
            run_die("cannot create %s: %s", path, strerror(errno));
            goto refused;
        }
    if (run_report(r)) {
        run_die("cannot create %s/triage.txt: %s", r->out, strerror(errno));
        goto refused;
    }

    sys_lockdown("/sys/kernel/security/lockdown", r->lockdown, sizeof r->lockdown);
    sys_secure_boot("/sys/firmware/efi/efivars", secure_boot, sizeof secure_boot);
    sys_os_name("/etc/os-release", "/usr/lib/os-release", os, sizeof os);
    name_clean(os);

    run_title(r, "keep %s", KEEP_VERSION);
    run_say(r, "%s", "");
    run_field(r, "host", "%s", host);
    run_field(r, "system", "%s", os[0] ? os : "unknown");
    run_field(r, "kernel", "%s", un.release);
    run_field(r, "lockdown", "%s", r->lockdown[0] ? r->lockdown : "unknown");
    /* the value of the variable: 1 with Secure Boot in force, 0 without */
    run_field(r, "secure boot", "%s", !secure_boot[0] ? "no SecureBoot variable" : !strcmp(secure_boot, "1") ? "enabled"
              : !strcmp(secure_boot, "0") ? "disabled" : secure_boot);
    if (sys_memory("/proc/meminfo", &kib)) {
        run_field(r, "memory", "unknown");
    } else {
        size_text(kib * 1024, size_of);
        run_field(r, "memory", "%s", size_of);
    }
    run_field(r, "started", "%s", started);
    run_field(r, "output", "%s", r->out);
    if (statvfs(r->out, &vfs)) {
        run_field(r, "destination", "%s", where.s);
    } else {
        size_text((uint64_t)vfs.f_bavail * vfs.f_frsize, size_of);
        run_field(r, "destination", "%s, %s free", where.s, size_of);
    }
    str_free(&where);
    if (unlocked[0])
        run_field(r, "note", "%s", unlocked);

    /* The open crypt volumes: every mapped device with a crypt target in its table, which is
       what "dmsetup ls --target crypt" lists, and a device whose crypt targets cryptsetup has
       put into a helper device below it (volume.c). */
    if (load_tables(&tabs, &ntabs, &present, &unread, err)) {
        run_mark(r, "volumes", RUN_NOT, "FAILED", "the mapped devices cannot be listed: %s", err);
        r->write_failed = 1;
        listed = 0;
    } else if (!present) {
        run_field(r, "volumes", "none: this kernel has no device-mapper loaded");
        listed = 0;
    } else if (vol_find(tabs, ntabs, &found, &nvols, err)) {
        run_mark(r, "volumes", RUN_NOT, "FAILED", "%s", err);
        r->write_failed = 1;
        listed = 0;
    }
    tables_unread = unread.len || unread.failed;
    if (tables_unread) {
        if (unread.s)
            name_clean(unread.s);
        run_mark(r, "tables", RUN_NOT, "FAILED", "not read, so a volume in them is not examined: %s", str_text(&unread));
    }
    str_free(&unread);
    if (nvols && !(vols = calloc(nvols, sizeof *vols)))
        no_memory = 1;
    for (i = 0; vols && i < nvols; i++) {
        struct volume *v = &vols[i];

        memcpy(v->name, found[i].top->name, DM_NAME_LEN);
        memcpy(v->shown, v->name, DM_NAME_LEN);
        name_clean(v->shown);
        name_file(v->name, v->file, DM_NAME_LEN);
        run_stem(r, v->file, sizeof v->file);
        v->nkeys = found[i].nkeys;
        if (v->nkeys && !(v->keys = calloc(v->nkeys, sizeof *v->keys))) {
            no_memory = 1;
            break;
        }
        for (k = 0; k < v->nkeys; k++) {
            if (k == 0) {
                snprintf(v->keys[k].file, sizeof v->keys[k].file, "%s", v->file);
            } else {
                snprintf(v->keys[k].file, sizeof v->keys[k].file, "%s-%zu", v->file, k + 1);
                run_stem(r, v->keys[k].file, sizeof v->keys[k].file);
            }
        }
    }
    if (no_memory) {
        free_tables(tabs, ntabs);               /* they can hold keys, and this wipes them */
        vol_free(found, nvols);
        for (i = 0; vols && i < nvols; i++)
            free(vols[i].keys);
        free(vols);
        run_mark(r, "volumes", RUN_NOT, "FAILED", "no memory for the %zu volumes: none is examined", nvols);
        if (written(r->report) || fsync(fileno(r->report)))
            r->write_failed = 1;
        fclose(r->report);
        run_free(r);
        run_die("no memory");
        goto refused;
    }
    if (nvols) {
        struct str all = { 0 };

        for (i = 0; i < nvols; i++)
            str_addf(&all, "%s%s", i ? ", " : "", vols[i].shown);
        run_field(r, "volumes", "%zu open dm-crypt volume%s: %s", nvols, nvols == 1 ? "" : "s", str_text(&all));
        str_free(&all);
    } else if (listed) {
        run_field(r, "volumes", "no open dm-crypt volume");
    }
    /* mounted file systems that can carry their own encryption. They are not dm-crypt, so they
       are named, so that their absence from the verdicts is not read as "clear". */
    other = sys_other_filesystems("/proc/mounts");
    if (other && other[0])
        run_field(r, "unexamined", "%s (mounted file systems that can encrypt by themselves)", other);

    for (i = 0; i < nvols; i++)
        one_volume(r, &vols[i], &found[i]);
    vol_free(found, nvols);
    free_tables(tabs, ntabs);
    keyscan_wipe();

    /* The keys are done, so the image no longer competes with them for time. */
    if (o->nformats)
        memory_run(r, o->formats, o->nformats, &mem);

    /* Every verdict once more, which is what stays on the screen after a long image: a volume,
       how far its key is and the start of the SHA-256 of the key that is held. A volume with
       several keys has a row for each below it. */
    if (nvols || mem.nimages) {
        run_title(r, "result");
        names = mem.nimages ? (int)sizeof "memory.lime" - 1 : 0;
        for (i = 0; i < nvols; i++) {
            if ((int)strlen(vols[i].shown) > names)
                names = (int)strlen(vols[i].shown);
            if (vols[i].verdict && (int)strlen(vols[i].verdict) > words)
                words = (int)strlen(vols[i].verdict);
        }
        for (i = 0; i < mem.nimages; i++)
            if ((int)strlen(mem.images[i].status) > words)
                words = (int)strlen(mem.images[i].status);
    }
    for (i = 0; i < nvols; i++) {
        const struct volume *v = &vols[i];

        if (!v->verdict)
            run_row(r, v->shown, names, RUN_NOT, "unknown", words, "%s", "");
        else
            run_row(r, v->shown, names, tone_of(v->verdict), v->verdict, words, "%s", v->nkeys == 1 ? v->keys[0].hash : "");
        for (k = 0; v->nkeys > 1 && k < v->nkeys; k++) {
            snprintf(label, sizeof label, "  key %zu", k + 1);
            run_row(r, label, names, tone_of(v->keys[k].verdict), v->keys[k].verdict, words, "%s", v->keys[k].hash);
        }
    }
    for (i = 0; i < mem.nimages; i++) {
        const struct memory_image *m = &mem.images[i];

        snprintf(label, sizeof label, "memory.%s", image_name(m->format));
        run_row(r, label, names, memory_tone(m), m->status, words, "%s", m->file[0] ? m->file : m->note);
    }
    run_say(r, "%s", "");
    run_utc(finished, 0);
    run_say(r, "finished %s, %u s", finished, run_seconds(r));
    if (written(r->report) || fsync(fileno(r->report)))
        r->write_failed = 1;
    fclose(r->report);

    /* the same verdicts for a program, schema keep-report/1. No key is in this file. */
    if ((fd = run_create(r, "verdict.json", O_WRONLY, 0600)) < 0 || !(json = fdopen(fd, "w"))) {
        r->write_failed = 1;
        if (fd >= 0)
            close(fd);
    } else {
        fprintf(json, "{\n  \"schema\": \"keep-report/1\",\n  \"tool\": \"keep %s\",\n  \"host\": ", KEEP_VERSION);
        run_json(json, host);
        fputs(",\n  \"kernel\": ", json); run_json(json, un.release);
        fputs(",\n  \"os\": ", json); run_json(json, os);
        fputs(",\n  \"cryptsetup\": null,\n  \"other_filesystems\": ", json); run_json(json, other);
        fprintf(json, ",\n  \"started_utc\": \"%s\",\n  \"finished_utc\": \"%s\",\n  \"lockdown\": ", started, finished);
        run_json(json, r->lockdown);
        fputs(",\n  \"secure_boot\": ", json); run_json(json, secure_boot);
        fputs(",\n  \"source\": \"/proc/kcore\",\n  \"evidence_medium\": ", json); run_json(json, medium.s);
        fputs(",\n  \"memory\": ", json);
        if (!mem.nimages) {
            fputs("null", json);
        } else {
            /* The image, with the fields that keytriage.sh has for the one that AVML wrote.
               Of several from one read, the further ones follow in further_images. */
            json_image(json, &mem.images[0], &mem);
            for (i = 1; i < mem.nimages; i++) {
                fputs(i == 1 ? ", \"further_images\": [" : ", ", json);
                json_image(json, &mem.images[i], NULL);
                fputs(i + 1 == mem.nimages ? "}]" : "}", json);
            }
            fputc('}', json);
        }
        fputs(",\n  \"binaries\": [\n  ],\n  \"volumes\": [", json);
        for (i = 0; i < nvols; i++) {
            static const struct key_result none;
            const struct volume *v = &vols[i];
            char header[PATH_MAX] = "";

            if (v->has_header)
                snprintf(header, sizeof header, "headers/%s.hdr", v->file);
            fputs(i ? ",\n    {\"name\": " : "\n    {\"name\": ", json); run_json(json, v->name);
            fputs(", \"type\": ", json); run_json(json, v->type);
            json_key(json, v->nkeys ? &v->keys[0] : &none, 0);
            fputs(", \"device\": ", json); run_json(json, v->device);
            fputs(", \"in_use\": ", json); run_json(json, v->in_use);
            fputs(", \"header_backup\": ", json); run_json(json, header);
            json_key(json, v->nkeys ? &v->keys[0] : &none, 1);
            fputs(", \"verdict\": ", json); run_json(json, v->verdict);
            json_key(json, v->nkeys ? &v->keys[0] : &none, 2);
            fputs(", \"note\": ", json); run_json(json, v->note);
            /* the further keys of a volume that has more than one, each with what became of it */
            for (k = 1; k < v->nkeys; k++) {
                char file[PATH_MAX] = "";

                if (v->keys[k].hash[0])
                    snprintf(file, sizeof file, "keys/%s.vk", v->keys[k].file);
                fputs(k == 1 ? ", \"further_keys\": [{\"key_file\": " : ", {\"key_file\": ", json);
                run_json(json, file);
                json_key(json, &v->keys[k], 0);
                json_key(json, &v->keys[k], 1);
                fputs(", \"verdict\": ", json); run_json(json, v->keys[k].verdict);
                json_key(json, &v->keys[k], 2);
                fputs(", \"note\": ", json); run_json(json, v->keys[k].note);
                fputs(k + 1 == v->nkeys ? "}]" : "}", json);
            }
            fputc('}', json);
        }
        fputs("\n  ]\n}\n", json);
        if (written(json) || fsync(fd))
            r->write_failed = 1;
        fclose(json);
    }
    run_manifest(r);

    /* Everything of this run to the destination: the folder by fsync, which reports a failure,
       and then the whole file system that holds it by syncfs. */
    if ((fd = open(r->out, O_RDONLY | O_CLOEXEC)) < 0 || fsync(fd) || syncfs(fd))
        r->write_failed = 1;
    if (fd >= 0)
        close(fd);
    for (i = 0; i < nvols; i++) {
        free(vols[i].in_use);
        free(vols[i].keys);
    }
    run_free(r);
    free(vols);
    free(other);
    str_free(&medium);
    if (r->write_failed) {
        fprintf(stderr, "keep: a write or a flush to the destination FAILED, the folder is not complete\n");
        return 1;
    }
    if (r->line_lost) {
        fprintf(stderr, "keep: a line of the report could not be put together for lack of memory, triage.txt is not whole\n");
        return 1;
    }
    if (tables_unread) {
        fprintf(stderr, "keep: the table of a mapped device could not be read, so not every volume is examined\n");
        return 1;
    }
    run_tell(r, "keep: every file of this run is flushed to the destination");
    if (mem.captured < mem.nimages) {
        fprintf(stderr, "keep: a memory image that was asked for is not there\n");
        return 1;
    }
    return 0;
refused:
    str_free(&medium);
    str_free(&where);
    return 1;
}
