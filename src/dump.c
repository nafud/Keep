/*
 * dump.c: the search of a memory dump that exists, "keep -s DUMP [FILE...]", the work of
 * offline-keyscan.sh and vkverify.py for a raw disk image or a header backup.
 *
 * The dump is searched for AES key schedules with the search of kcore-keyscan.c, which reads a
 * raw dump, a LiME image, a compressed AVML image and an ELF core. A schedule is a key that
 * some part of the kernel used. Which of them is the key of a volume is decided by a proof and
 * by nothing else: a LUKS header stores a PBKDF2 digest of its volume key, and a key that gives
 * that digest is the volume key.
 *
 * So each FILE is searched for LUKS headers: at its start, where a header backup and the image
 * of a partition have theirs, and at every further sector, where the image of a whole disk has
 * those of its partitions. For each header the candidate keys are tried in this order, as
 * vkverify.py tries them: the pairs of two schedules that lie as the XTS code of the kernel
 * keeps the two keys of a volume (the tweak schedule first, the data schedule 496 bytes after
 * it, struct aesni_xts_ctx), then each key alone, then every other pair. The place only orders
 * the attempts. The digest decides.
 *
 * The first two kinds of attempt are as many as the dump has keys. The third is every pair of
 * two keys of one size, the square of their number, each with the iterations of the digest:
 * 90 keys of a machine with 16 GiB took 510 s for one digest. A digest whose key the dump
 * does not hold costs all of them, and what a dump holds of a header can be of a volume that
 * was closed. So every header has the attempts of the first two kinds before any header has
 * those of the third, which are counted on the screen before they begin.
 *
 * A header can also lie in the dump itself, and it proves a key like any other. The kernel
 * keeps what was read of a device in its cache, and the 592 bytes of a LUKS1 header are in the
 * first page of its device. A program that has read a LUKS2 header has the metadata in its
 * memory, with the digest in it: udisksd of udisks2 2.10.1, which runs on a desktop system,
 * kept them for an open volume, and they were still there after the free memory was written
 * over (seen on Ubuntu 24.04.5). So the memory is searched, while it is read for the
 * schedules, for a LUKS1 header at the start of a page and for the object "digests" of the
 * metadata of LUKS2, which fits a page. Such a digest stands for a header without its file.
 *
 * Where no header is found nothing can be proven. The pairs that lie as the XTS code keeps
 * them are then, as for a volume whose header is not at hand, written as candidates and named
 * as found in memory and not proven.
 *
 * The run writes a folder scan_<dump>_<time>/ into the destination: triage.txt (the screen),
 * scan.txt (what the search said about the dump), verdict.json, manifest.sha256, and keys/ with
 * candidates.txt, the schedules that were found, one NAME.vk for each proven volume key and one
 * memory-pair-N.vk for each pair that no header proves. The dump and the files are only read,
 * and no key is shown.
 */
#include "dump.h"
#include "hash.h"
#include "keyscan.h"
#include "luks.h"
#include "run.h"
#include "triage.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define XTS_DISTANCE 496        /* data schedule minus tweak schedule, struct aesni_xts_ctx */
#define SECTOR 512u
#define CHUNK (8u << 20)        /* of a file, searched for headers at once */
#define MAX_PAIRS 16            /* key files for pairs that no header proves */
#define WINDOW (2u << 20)       /* of the memory of the dump, searched for headers at once */
#define AHEAD 8192u             /* the most that a header in memory is read behind its first byte */
#define MAX_IN_MEMORY 32        /* headers and digests of the dump itself */
#define PAGE 4096u

static const char PROVEN[] = "proven", NOT_PROVEN[] = "not proven", UNREADABLE[] = "unreadable header",
                  IN_MEMORY[] = "found in memory";

struct proof {                          /* the key of one digest of a header */
    char stem[NAME_MAX + 56], hash[17];
    size_t bytes;
    unsigned attempt;                   /* the attempt that gave it */
    int has_places;                     /* it is a pair that lies as the XTS code keeps it */
    uint64_t tweak_at;
};

struct target {                         /* a LUKS header that was located, or a file without one */
    char name[NAME_MAX + 32];           /* for the screen and the report */
    char stem[NAME_MAX + 40];           /* of its key files */
    char file[PATH_MAX];
    uint64_t offset;
    int readable;
    int in_memory;                      /* found in the dump itself, at the address offset */
    struct luks_header h;
    unsigned taken;                     /* bit n: digest n + 1 has its key */
    struct proof proofs[LUKS_MAX_DIGESTS];
    unsigned attempts;
    size_t far;                         /* the pairs that the second round has to try */
    const char *uncomputed;             /* the hash of a digest that is not computed here */
    const char *verdict;
    char note[LUKS_ERR_LEN + 96];
};

struct place {                          /* two schedules that lie as the XTS code keeps a pair */
    int data, tweak;                    /* which of the keys, as first counts them */
    const struct keyscan_hit *at;       /* the tweak schedule */
};

struct keys {                           /* the schedules of the dump, and each key once */
    const struct keyscan_hit *hits;
    int nhits;
    int *first;                         /* the hit at which a key was found first */
    int nfirst, aes128, aes256;
    struct place *places;               /* each pair of keys that lies in place, once, where it was found first */
    size_t nplaces;
    uint8_t *in_place;                  /* nfirst * nfirst: the data key i and the tweak key j are such a pair */
};

static size_t key_len(const struct keyscan_hit *h)
{
    return (size_t)h->nk * 4;
}

static int same_key(const struct keyscan_hit *a, const struct keyscan_hit *b)
{
    return a->nk == b->nk && !memcmp(a->key, b->key, key_len(a));
}

static int distinct(struct keys *k)
{
    int i, j;

    if (k->nhits && !(k->first = malloc((size_t)k->nhits * sizeof *k->first)))
        return -1;
    for (i = 0; i < k->nhits; i++) {
        for (j = 0; j < k->nfirst && !same_key(&k->hits[k->first[j]], &k->hits[i]); j++)
            ;
        if (j < k->nfirst)
            continue;
        k->first[k->nfirst++] = i;
        k->aes128 += k->hits[i].nk == 4;
        k->aes256 += k->hits[i].nk == 8;
    }
    return 0;
}

/* The hit with the data schedule that lies behind this tweak schedule as the XTS code of the
   kernel keeps the two, or -1. */
static int data_behind(const struct keys *k, int tweak)
{
    int j;

    for (j = 0; j < k->nhits; j++)
        if (k->hits[j].nk == k->hits[tweak].nk && k->hits[j].phys == k->hits[tweak].phys + XTS_DISTANCE)
            return j;
    return -1;
}

/* The pairs of keys that lie in place. They are the same for every header. */
static int places(struct keys *k)
{
    size_t nd = (size_t)k->nfirst, i, j;
    int a, b;

    if (!nd)
        return 0;
    if (!(k->in_place = calloc(nd, nd)) || !(k->places = malloc((size_t)k->nhits * sizeof *k->places)))
        return -1;
    for (a = 0; a < k->nhits; a++) {
        if ((b = data_behind(k, a)) < 0)
            continue;
        for (i = 0; i < nd && !same_key(&k->hits[k->first[i]], &k->hits[b]); i++)
            ;
        for (j = 0; j < nd && !same_key(&k->hits[k->first[j]], &k->hits[a]); j++)
            ;
        if (k->in_place[i * nd + j])
            continue;                           /* the same pair at another place */
        k->in_place[i * nd + j] = 1;
        k->places[k->nplaces].data = (int)i;
        k->places[k->nplaces].tweak = (int)j;
        k->places[k->nplaces++].at = &k->hits[a];
    }
    return 0;
}

static void keys_free(struct keys *k)
{
    free(k->first);
    free(k->places);
    free(k->in_place);
}

/* ---- the headers in the memory of the dump ---------------------------------------------------- */

struct in_memory {
    uint64_t phys;
    struct luks_header h;
};

struct watch {                          /* the memory as the search hands it over */
    uint8_t *win;
    size_t have;
    uint64_t phys;                      /* the address of the first byte of the window */
    struct in_memory found[MAX_IN_MEMORY];
    size_t nfound, further;
};

static int same_digest(const struct luks_header *a, const struct luks_header *b)
{
    const struct luks_digest *x = &a->digests[0], *y = &b->digests[0];

    return x->iterations == y->iterations && x->saltlen == y->saltlen && x->digestlen == y->digestlen &&
           !memcmp(x->salt, y->salt, x->saltlen) && !memcmp(x->digest, y->digest, x->digestlen);
}

static void remember(struct watch *w, uint64_t phys, const struct luks_header *h)
{
    size_t i;

    for (i = 0; i < w->nfound; i++)
        if (same_digest(&w->found[i].h, h))
            return;                     /* a further copy of one that is known */
    if (w->nfound == MAX_IN_MEMORY) {
        w->further++;
        return;
    }
    w->found[w->nfound].phys = phys;
    w->found[w->nfound++].h = *h;
}

/* Search the window. Unless LAST, what begins in its final part waits for the bytes behind it. */
static void look(struct watch *w, int last)
{
    static const char needle[] = "\"digests\":{";
    size_t end = last ? w->have : (w->have > AHEAD ? w->have - AHEAD : 0), i;
    struct luks_header h;
    const uint8_t *p;

    /* a LUKS1 header at the start of a page, as the cache of its device holds it */
    for (i = (size_t)((PAGE - w->phys % PAGE) % PAGE); i < end; i += PAGE)
        if (w->win[i] == 'L' && !luks_header1(w->win + i, w->have - i, &h))
            remember(w, w->phys + i, &h);
    /* the digests of a LUKS2 header, as a program that read the metadata holds them */
    for (i = 0; i < end && (p = memmem(w->win + i, w->have - i, needle, sizeof needle - 1)); i = (size_t)(p - w->win) + 1) {
        size_t brace = (size_t)(p - w->win) + sizeof needle - 2, room = w->have - brace;

        if ((size_t)(p - w->win) >= end)
            break;                      /* it begins in the part that waits */
        if (!luks_digests((const char *)w->win + brace, room < AHEAD ? room : AHEAD, &h))
            remember(w, w->phys + brace, &h);
    }
    memmove(w->win, w->win + end, w->have - end);
    w->have -= end;
    w->phys += end;
}

static void watch(void *arg, const uint8_t *p, size_t n, uint64_t phys)
{
    struct watch *w = arg;

    if (w->have && phys != w->phys + w->have)
        look(w, 1);                     /* memory that does not follow what came before */
    if (!w->have)
        w->phys = phys;
    while (n) {
        size_t k = n < WINDOW - w->have ? n : WINDOW - w->have;

        memcpy(w->win + w->have, p, k);
        w->have += k;
        p += k;
        n -= k;
        look(w, 0);
    }
}

/* ---- the headers ------------------------------------------------------------------------------ */

static struct target *add_target(struct run *r, struct target **list, size_t *n, const char *path, uint64_t offset)
{
    struct target *grown = realloc(*list, (*n + 1) * sizeof *grown), *t;
    const char *base = strrchr(path, '/');

    if (!grown)
        return NULL;
    *list = grown;
    t = &grown[(*n)++];
    memset(t, 0, sizeof *t);
    base = base ? base + 1 : path;
    if (offset)
        snprintf(t->name, sizeof t->name, "%.*s@0x%llx", NAME_MAX, base, (unsigned long long)offset);
    else
        snprintf(t->name, sizeof t->name, "%.*s", NAME_MAX, base);
    name_file(t->name, t->stem, sizeof t->stem - 8);
    run_stem(r, t->stem, sizeof t->stem - 8);
    name_clean(t->name);
    snprintf(t->file, sizeof t->file, "%s", path);
    t->offset = offset;
    t->verdict = NOT_PROVEN;
    return t;
}

/*
 * The LUKS headers of one file. The start is read as a header whatever stands there, because a
 * LUKS2 header whose first copy is overwritten still has its second one. Behind it every
 * sector that begins with the magic of a first copy is tried, and counts where the header
 * holds as cryptsetup would have it. Returns the number of headers, or -1 without memory.
 */
static int locate(struct run *r, const char *path, struct target **list, size_t *n)
{
    static const uint8_t magic[6] = { 'L', 'U', 'K', 'S', 0xba, 0xbe };
    char err[LUKS_ERR_LEN];
    struct luks_header h;
    struct target *t;
    uint8_t *buf;
    uint64_t off = 0;
    int fd, found = 0, at_start;

    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0) {
        if (!(t = add_target(r, list, n, path, 0)))
            return -1;
        t->verdict = UNREADABLE;
        snprintf(t->note, sizeof t->note, "the file cannot be opened: %s", strerror(errno));
        return 0;
    }
    if (!(buf = malloc(CHUNK))) {
        close(fd);
        return -1;
    }
    at_start = luks_read_at(fd, 0, &h, err);
    if (at_start <= 0) {
        if (!(t = add_target(r, list, n, path, 0)))
            goto no_memory;
        if (at_start == 0) {
            t->readable = 1;
            t->h = h;
            off = (h.area + SECTOR - 1) / SECTOR * SECTOR;
        } else {
            t->verdict = UNREADABLE;
            snprintf(t->note, sizeof t->note, "%s", err);
            off = SECTOR;
        }
        found++;
    }
    for (;;) {
        ssize_t got = pread(fd, buf, CHUNK, (off_t)off);
        size_t i, len;
        uint64_t next = 0;

        if (got < 0 && errno == EINTR)
            continue;
        if (got < (ssize_t)sizeof magic)
            break;
        len = (size_t)got;
        for (i = 0; i + sizeof magic <= len && !next; i += SECTOR) {
            if (memcmp(buf + i, magic, sizeof magic) || luks_read_at(fd, off + i, &h, err))
                continue;
            if (!(t = add_target(r, list, n, path, off + i)))
                goto no_memory;
            t->readable = 1;
            t->h = h;
            found++;
            next = off + i + (h.area + SECTOR - 1) / SECTOR * SECTOR;
        }
        if (next)
            off = next;
        else if (len < CHUNK)
            break;
        else
            off += CHUNK;
    }
    free(buf);
    close(fd);
    return found;
no_memory:
    free(buf);
    close(fd);
    return -1;
}

/* ---- the proof -------------------------------------------------------------------------------- */

/* Whether a key of LEN bytes, a pair or one key alone, can be the key of a digest that has none
   yet: by the length that the header states, and by its cipher, which with XTS takes a pair. */
static int wanted(const struct target *t, size_t len, int pair)
{
    size_t i;

    for (i = 0; i < t->h.ndigests; i++) {
        const struct luks_digest *d = &t->h.digests[i];

        if (t->taken & 1u << i || (d->key_bytes && d->key_bytes != len))
            continue;
        if (!d->cipher[0] || (!strncmp(d->cipher, "aes", 3) && (strstr(d->cipher, "xts") ? pair : !pair)))
            return 1;
    }
    return 0;
}

static int all_proven(const struct target *t)
{
    return t->h.ndigests && t->taken == (1u << t->h.ndigests) - 1;
}

struct effort {                         /* one header's attempts, and when the screen last heard of them */
    struct run *r;
    struct target *t;
    time_t start, said;
    unsigned before;                    /* the attempts before this round */
    size_t of;                          /* how many this round makes at most, where that is said */
};

/* One candidate key against the digests that have no key yet. Returns 1 when the header needs
   no further attempt. */
static int attempt(struct effort *e, const uint8_t *key, size_t len, const struct keyscan_hit *tweak)
{
    struct target *t = e->t;
    struct proof *p;
    const char *hash = NULL;
    time_t now = time(NULL);
    int which;

    t->attempts++;
    if (now - e->said >= 15) {
        e->said = now;
        if (e->of)
            printf("  %u of %zu pairs tried, %lld s\n", t->attempts - e->before, e->of, (long long)(now - e->start));
        else
            printf("  %u keys tried, %lld s\n", t->attempts, (long long)(now - e->start));
        fflush(stdout);
    }
    if ((which = luks_proves(&t->h, key, len, t->taken, &hash)) < 0) {
        t->uncomputed = hash ? hash : "no known function";
        return 1;
    }
    if (!which)
        return 0;
    p = &t->proofs[which - 1];
    t->taken |= 1u << (which - 1);
    if (which == 1)
        snprintf(p->stem, sizeof p->stem, "%s", t->stem);
    else
        snprintf(p->stem, sizeof p->stem, "%s-%d", t->stem, which);
    if (which > 1)
        run_stem(e->r, p->stem, sizeof p->stem);
    p->attempt = t->attempts;
    if (run_keep_key(e->r, p->stem, key, len, p->hash)) {
        run_say(e->r, "  a key gives the digest, and could not be written to the destination");
        p->hash[0] = 0;
    } else {
        p->bytes = len;
        run_say(e->r, "  proven at attempt %u: a volume key of %zu bytes, sha256 %s, in keys/%s.vk", t->attempts, len,
                p->hash, p->stem);
    }
    if (tweak) {
        p->has_places = 1;
        p->tweak_at = tweak->phys;
        run_say(e->r, "  its tweak schedule lies at 0x%016llx and its data schedule 496 bytes after it",
                (unsigned long long)tweak->phys);
    }
    return all_proven(t);
}

/* Whether the second round has this pair of keys to try for a header. */
static int is_far(const struct target *t, const struct keys *k, size_t i, size_t j)
{
    const struct keyscan_hit *data = &k->hits[k->first[i]], *tweak = &k->hits[k->first[j]];

    return i != j && data->nk == tweak->nk && !k->in_place[i * (size_t)k->nfirst + j] && wanted(t, 2 * key_len(data), 1);
}

/*
 * The first round for one header, the attempts that cost little: the pairs of keys that lie
 * in place, and each key alone. They are as many as the dump has keys, and where a volume was
 * open on the machine of the dump, one of them is its key. Returns 1 when the header needs no
 * further attempt, and else counts what the second round has to try.
 */
static int first_round(struct run *r, struct target *t, const struct keys *k)
{
    struct effort e = { .r = r, .t = t };
    uint8_t key[64];
    size_t nd = (size_t)k->nfirst, i, j;
    int done = 0;

    e.start = e.said = time(NULL);
    for (i = 0; i < k->nplaces && !done; i++) {
        const struct keyscan_hit *data = &k->hits[k->first[k->places[i].data]], *tweak = &k->hits[k->first[k->places[i].tweak]];
        size_t len = key_len(data);

        if (!wanted(t, 2 * len, 1))
            continue;
        memcpy(key, data->key, len);                    /* the data key, then the tweak key */
        memcpy(key + len, tweak->key, len);
        done = attempt(&e, key, 2 * len, k->places[i].at);
    }
    for (i = 0; i < nd && !done; i++) {
        const struct keyscan_hit *h = &k->hits[k->first[i]];

        if (wanted(t, key_len(h), 0))
            done = attempt(&e, h->key, key_len(h), NULL);
    }
    explicit_bzero(key, sizeof key);
    for (i = 0; i < nd && !done; i++)
        for (j = 0; j < nd; j++)
            t->far += (size_t)is_far(t, k, i, j);
    return done || !t->far;
}

/* The second round for one header: every other pair of keys, in the order of vkverify.py.
   They are as many as the square of the keys of one size. */
static void second_round(struct run *r, struct target *t, const struct keys *k)
{
    struct effort e = { .r = r, .t = t, .before = t->attempts, .of = t->far };
    uint8_t key[64];
    size_t nd = (size_t)k->nfirst, i, j;
    int done = 0;

    e.start = e.said = time(NULL);
    for (i = 0; i < nd && !done; i++)
        for (j = 0; j < nd && !done; j++) {
            const struct keyscan_hit *data = &k->hits[k->first[i]], *tweak = &k->hits[k->first[j]];
            size_t len = key_len(data);

            if (!is_far(t, k, i, j))
                continue;
            memcpy(key, data->key, len);
            memcpy(key + len, tweak->key, len);
            done = attempt(&e, key, 2 * len, NULL);
        }
    explicit_bzero(key, sizeof key);
}

/* What the attempts on a header came to. */
static void conclude(struct target *t)
{
    size_t proven = 0, i;

    for (i = 0; i < t->h.ndigests; i++)
        proven += t->proofs[i].bytes > 0;
    if (t->uncomputed) {
        snprintf(t->note, sizeof t->note, "the digest of the header uses %s, which this program does not compute. vkverify.py does",
                 t->uncomputed);
    } else if (all_proven(t) && proven == t->h.ndigests) {
        t->verdict = PROVEN;
        snprintf(t->note, sizeof t->note, "%s", t->h.ndigests > 1 ? "each key gives its digest of the header" : "gives the digest of the header");
    } else if (t->taken) {
        snprintf(t->note, sizeof t->note, "%zu of %zu keys of the header proven, none of %u candidate keys gives the other digest",
                 proven, t->h.ndigests, t->attempts);
    } else if (!t->attempts && t->h.digests[0].cipher[0] && strncmp(t->h.digests[0].cipher, "aes", 3)) {
        snprintf(t->note, sizeof t->note, "the cipher is not AES, so the search for AES schedules does not apply");
    } else if (!t->attempts) {
        snprintf(t->note, sizeof t->note, "the dump holds no schedule of a key of the length that the header states");
    } else {
        snprintf(t->note, sizeof t->note, "none of %u candidate keys gives the digest", t->attempts);
    }
}

static void verdict(struct run *r, struct target *t)
{
    if (t->verdict != PROVEN)
        run_say(r, "  %s", t->note);
    run_say(r, "  VERDICT: %s", t->verdict);
    run_say(r, "%s", "");
}

/* A header on the screen, and its first round. */
static void one_target(struct run *r, struct target *t, const struct keys *k)
{
    const struct luks_digest *d = &t->h.digests[0];

    run_say(r, "==== %s", t->name);
    if (t->in_memory)
        run_say(r, "  from the dump itself, at the address 0x%llx: %s", (unsigned long long)t->offset,
                t->h.version == 1 ? "a LUKS1 header, as the kernel keeps what was read of a device"
                                  : "the digests of a LUKS2 header, as a program that read the header keeps them");
    else if (t->offset)
        run_say(r, "  from %s, at offset 0x%llx", t->file, (unsigned long long)t->offset);
    else
        run_say(r, "  from %s", t->file);
    if (!t->readable) {
        verdict(r, t);
        return;
    }
    if (!t->h.ndigests) {
        run_say(r, "  LUKS%d, UUID %s, with no digest of a volume key", t->h.version, t->h.uuid);
        snprintf(t->note, sizeof t->note, "the header has no digest of a volume key");
        verdict(r, t);
        return;
    }
    if (t->in_memory && t->h.version == 2)
        run_say(r, "  LUKS2, digest pbkdf2-%s with %u iterations. The cipher and the size of the key stand in other parts of "
                "the metadata, so keys of every size are tried", d->hash, d->iterations);
    else if (d->key_bytes)
        run_say(r, "  LUKS%d, cipher %s, key of %zu bits, UUID %s, digest pbkdf2-%s with %u iterations", t->h.version,
                d->cipher[0] ? d->cipher : "unknown", d->key_bytes * 8, t->h.uuid, d->hash, d->iterations);
    else
        run_say(r, "  LUKS%d, cipher %s, key size not stated, no keyslot is left, UUID %s, digest pbkdf2-%s with %u iterations",
                t->h.version, d->cipher[0] ? d->cipher : "unknown", t->h.uuid, d->hash, d->iterations);
    if (t->h.ndigests > 1)
        run_say(r, "  %zu keys: a volume in re-encryption has one for the part that is done and one for the rest",
                t->h.ndigests);
    if (first_round(r, t, k)) {
        conclude(t);
        verdict(r, t);
        return;
    }
    run_say(r, "  %u keys tried, the pairs of schedules that lie as the kernel keeps the two keys of a volume and each key "
            "alone:%s", t->attempts, t->taken ? " not every key of the header is among them" : " none gives the digest");
    run_say(r, "  every other pair of keys, %zu of them, is tried when every header has had these attempts", t->far);
    run_say(r, "%s", "");
}

/* The second round of a header on the screen. */
static void one_more(struct run *r, struct target *t, const struct keys *k)
{
    run_say(r, "==== %s: every other pair of keys", t->name);
    run_say(r, "  up to %zu pairs, each with the %u iterations of the digest", t->far, t->h.digests[0].iterations);
    second_round(r, t, k);
    conclude(t);
    verdict(r, t);
}

/* ---- the pairs that no header proves ---------------------------------------------------------- */

struct pair {
    char stem[32], hash[17];
    size_t bytes;
    uint64_t tweak_at;
};

/* Whether a proven key of a header is this pair. */
static int is_proven(const struct target *targets, size_t n, const char *hash16)
{
    size_t i, k;

    for (i = 0; i < n; i++)
        for (k = 0; k < targets[i].h.ndigests; k++)
            if (!strcmp(targets[i].proofs[k].hash, hash16))
                return 1;
    return 0;
}

static void memory_pairs(struct run *r, const struct keys *k, const struct target *targets, size_t ntargets,
                         struct pair *pairs, size_t *npairs, size_t *further)
{
    uint8_t key[64], digest[32];
    char hash[17];
    size_t i, len;
    int a, b;

    *npairs = *further = 0;
    for (a = 0; a < k->nhits; a++) {
        if ((b = data_behind(k, a)) < 0)
            continue;
        len = key_len(&k->hits[a]);
        memcpy(key, k->hits[b].key, len);
        memcpy(key + len, k->hits[a].key, len);
        sha256(key, 2 * len, digest);
        hex_encode(digest, 8, hash);
        for (i = 0; i < *npairs && strcmp(pairs[i].hash, hash); i++)
            ;
        if (i < *npairs || is_proven(targets, ntargets, hash))
            continue;                           /* the same pair at another place, or a proven key */
        if (*npairs == MAX_PAIRS) {
            ++*further;
            continue;
        }
        snprintf(pairs[*npairs].stem, sizeof pairs[*npairs].stem, "memory-pair-%zu", *npairs + 1);
        run_stem(r, pairs[*npairs].stem, sizeof pairs[*npairs].stem);
        pairs[*npairs].tweak_at = k->hits[a].phys;
        if (!run_keep_key(r, pairs[*npairs].stem, key, 2 * len, pairs[*npairs].hash)) {
            pairs[*npairs].bytes = 2 * len;
            ++*npairs;
        }
    }
    explicit_bzero(key, sizeof key);
    if (!*npairs)
        return;
    run_say(r, "==== pairs in memory that no header proves");
    run_say(r, "  %zu pair(s) of schedules lie as the XTS code of the kernel keeps the two keys of a volume: the tweak",
            *npairs + *further);
    run_say(r, "  schedule first and the data schedule 496 bytes after it. Such a pair can be the key of a volume");
    run_say(r, "  whose header is not at hand. It is a candidate until a header accepts it.");
    for (i = 0; i < *npairs; i++)
        run_say(r, "  keys/%s.vk, %zu bytes, sha256 %s, tweak schedule at 0x%016llx: %s, not proven", pairs[i].stem,
                pairs[i].bytes, pairs[i].hash, (unsigned long long)pairs[i].tweak_at, IN_MEMORY);
    if (*further)
        run_say(r, "  %zu further pairs are not written as files. Their keys are in keys/candidates.txt.", *further);
    run_say(r, "%s", "");
}

/* ---- the run ---------------------------------------------------------------------------------- */

/* The key of one digest as fields of the report. The first key stands in the line of its
   header, whose verdict is that of the header as a whole. */
static void json_proof(FILE *f, const struct target *t, size_t i)
{
    const struct luks_digest *d = &t->h.digests[i];
    const struct proof *p = &t->proofs[i];
    char digest[64];

    snprintf(digest, sizeof digest, "pbkdf2-%s", d->hash);
    fputs("\"cipher\": ", f); run_json(f, d->cipher);
    if (p->bytes)
        fprintf(f, ", \"key_bits\": %zu", p->bytes * 8);
    else if (d->key_bytes)
        fprintf(f, ", \"key_bits\": %zu", d->key_bytes * 8);
    else
        fputs(", \"key_bits\": null", f);
    fputs(", \"digest\": ", f); run_json(f, digest);
    fputs(", \"route\": ", f); run_json(f, p->bytes ? "memory search" : "");
    if (i) {
        fputs(", \"verdict\": ", f);
        run_json(f, p->bytes ? PROVEN : NOT_PROVEN);
    }
    fputs(", \"key_sha256_16\": ", f); run_json(f, p->hash);
    if (p->bytes)
        fprintf(f, ", \"attempts\": %u, \"adjacent_places\": %d", p->attempt, p->has_places);
}

int dump_run(const struct dump_options *o)
{
    char dump[PATH_MAX], dest[PATH_MAX], path[PATH_MAX], name[NAME_MAX + 1], stamp[32], started[32], finished[32];
    char real[PATH_MAX], *said, *line, *next;
    struct run run = { 0 }, *r = &run;
    struct target *targets = NULL;
    struct keys keys = { 0 };
    struct pair pairs[MAX_PAIRS];
    struct watch *w;
    const char *base, *bad;
    FILE *list, *msg, *json;
    struct stat st;
    size_t ntargets = 0, nfiles_targets, npairs = 0, further = 0, i, k, proven = 0, in_memory = 0, more_in_memory;
    char unlocked[160] = "";
    int kfd, mfd, fd, failed = 0, status, found = 0;

    /* Keys pass through the memory of this process. Locked memory is not written to the swap
       space, and the files of the run are for their owner alone. */
    run_lock_memory(unlocked);
    umask(077);
    if ((bad = hash_selftest()))
        return run_die("%s does not compute the example of its standard, so a proof would not be reliable", bad);
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
    for (i = 0; i < o->nfiles; i++)
        if (stat(o->files[i], &st) || (!S_ISREG(st.st_mode) && !S_ISBLK(st.st_mode)) || access(o->files[i], R_OK))
            return run_die("%s is not a file or a device that can be read", o->files[i]);

    base = strrchr(dump, '/');
    name_file(base ? base + 1 : dump, name, sizeof name);
    run_utc(stamp, 1);
    run_utc(started, 0);
    if (pathf(r->out, "%s/scan_%s_%s", dest, name, stamp) || strlen(r->out) + sizeof "/keys/memory-pair-00_.vk" > PATH_MAX)
        return run_die("the path of the folder of this run is too long: %s/scan_%s_%s", dest, name, stamp);
    if (mkdir(r->out, 0700) || pathf(path, "%s/keys", r->out) || mkdir(path, 0700))
        return run_die("cannot create %s: %s", r->out, strerror(errno));
    if ((fd = run_create(r, "triage.txt", O_WRONLY, 0600)) < 0 || !(r->report = fdopen(fd, "w")))
        return run_die("cannot create %s/triage.txt: %s", r->out, strerror(errno));

    run_say(r, "keep %s", KEEP_VERSION);
    run_say(r, "memory dump: %s", dump);
    run_say(r, "output: %s", r->out);
    if (unlocked[0])
        run_say(r, "%s", unlocked);
    run_say(r, "%s", "");

    /* the schedules of the dump: the list is key material, what the search says is not */
    kfd = run_create(r, "keys/candidates.txt", O_WRONLY, 0600);
    mfd = run_create(r, "scan.txt", O_WRONLY, 0600);
    list = kfd < 0 ? NULL : fdopen(kfd, "w");
    msg = mfd < 0 ? NULL : fdopen(mfd, "w");
    if (!list || !msg) {
        run_say(r, "the list of the schedules cannot be written: %s", strerror(errno));
        fclose(r->report);
        return 1;
    }
    /* while the memory is read for the schedules, it is searched for headers as well */
    if (!(w = calloc(1, sizeof *w)) || !(w->win = malloc(WINDOW))) {
        free(w);
        fclose(list);
        fclose(msg);
        fclose(r->report);
        return run_die("no memory");
    }
    keyscan_watch(watch, w);
    status = keyscan_run(dump, 0, 1, list, msg, &failed);
    keyscan_watch(NULL, NULL);
    look(w, 1);
    if (fflush(list) || fflush(msg) || run_flush(r, kfd, "keys") || fsync(mfd))
        r->write_failed = 1;
    fclose(list);
    fclose(msg);
    if (!pathf(path, "%s/scan.txt", r->out) && (said = read_text(path, 1 << 20, NULL))) {
        for (line = said; *line; line = next) {
            next = line + strcspn(line, "\n");
            if (*next)
                *next++ = 0;
            run_say(r, "%s", line);
        }
        free(said);
    }
    keys.hits = keyscan_hits(&keys.nhits);
    if (distinct(&keys) || places(&keys)) {
        keyscan_wipe();
        keys_free(&keys);
        return run_die("no memory");
    }
    run_say(r, "%d schedules in keys/candidates.txt, %d different keys: %d of AES-128, %d of AES-256", keys.nhits,
            keys.nfirst, keys.aes128, keys.aes256);
    run_say(r, "%s", "");

    /* the headers of the files, and the proof against each */
    for (i = 0; i < o->nfiles && found >= 0; i++) {
        int n;

        if (!realpath(o->files[i], real))
            snprintf(real, sizeof real, "%s", o->files[i]);
        if ((n = locate(r, real, &targets, &ntargets)) < 0)
            found = -1;
        else if (!n)
            run_say(r, "%s holds no LUKS header", real);
        else
            found += n;
    }
    /* what the dump itself holds of a header, unless that header is among the files */
    nfiles_targets = ntargets;
    for (i = 0; i < w->nfound && found >= 0; i++) {
        struct target *t;

        for (k = 0; k < nfiles_targets; k++)
            if (targets[k].readable && targets[k].h.ndigests && same_digest(&targets[k].h, &w->found[i].h))
                break;
        if (k < nfiles_targets)
            continue;
        if (!(t = add_target(r, &targets, &ntargets, "memory", w->found[i].phys))) {
            found = -1;
            break;
        }
        snprintf(t->file, sizeof t->file, "%s", dump);
        t->readable = t->in_memory = 1;
        t->h = w->found[i].h;
        in_memory++;
    }
    more_in_memory = w->further;
    free(w->win);
    free(w);
    if (found < 0) {
        keyscan_wipe();
        keys_free(&keys);
        free(targets);
        return run_die("no memory");
    }
    if (o->nfiles && nfiles_targets)
        run_say(r, "%zu LUKS header(s) in %zu file(s)", nfiles_targets, o->nfiles);
    if (in_memory)
        run_say(r, "%zu header(s) or digest(s) of a header in the memory of the dump itself%s", in_memory,
                more_in_memory ? ", and further ones that are not looked at" : "");
    else if (!o->nfiles)
        run_say(r, "No file with a LUKS header is given, and the dump itself holds none, so no key can be proven. A header\n"
                "backup or the image of the disk as a further argument gives the proof: keep -s DUMP FILE...");
    run_say(r, "%s", "");
    /* Every header has the attempts that cost little before any header has the others: a
       digest that the dump has no key for, as that of a volume that was closed, costs every
       pair of keys, and no header with a key waits for that. */
    for (i = 0; i < ntargets; i++)
        one_target(r, &targets[i], &keys);
    for (i = 0; i < ntargets; i++)
        if (targets[i].far)
            one_more(r, &targets[i], &keys);
    for (i = 0; i < ntargets; i++)
        proven += !targets[i].in_memory && targets[i].verdict == PROVEN;
    memory_pairs(r, &keys, targets, ntargets, pairs, &npairs, &further);
    keyscan_wipe();
    keys_free(&keys);

    run_say(r, "==== verdicts");
    for (i = 0; i < ntargets; i++) {
        run_say(r, "  %-24s  %s", targets[i].name, targets[i].verdict);
        for (k = 0; k < targets[i].h.ndigests; k++)
            if (targets[i].proofs[k].bytes)
                run_say(r, "  %-24s  keys/%s.vk, %zu bytes, sha256 %s", "", targets[i].proofs[k].stem,
                        targets[i].proofs[k].bytes, targets[i].proofs[k].hash);
    }
    for (i = 0; i < npairs; i++)
        run_say(r, "  %-24s  %s, not proven: keys/%s.vk, %zu bytes, sha256 %s", "a pair in memory", IN_MEMORY, pairs[i].stem,
                pairs[i].bytes, pairs[i].hash);
    if (!ntargets && !npairs)
        run_say(r, "  no header and no pair of schedules: the schedules are listed in keys/candidates.txt");
    run_say(r, "%s", "");
    run_utc(finished, 0);
    run_say(r, "finished %s", finished);
    if (fflush(r->report) || fsync(fileno(r->report)))
        r->write_failed = 1;
    fclose(r->report);

    /* the same for a program, schema keep-report/1, with the fields of vkverify.py. No key is
       in this file. */
    if ((fd = run_create(r, "verdict.json", O_WRONLY, 0600)) < 0 || !(json = fdopen(fd, "w"))) {
        r->write_failed = 1;
    } else {
        fprintf(json, "{\n  \"schema\": \"keep-report/1\",\n  \"tool\": \"keep %s\",\n  \"started_utc\": \"%s\",\n"
                "  \"finished_utc\": \"%s\",\n  \"source\": ", KEEP_VERSION, started, finished);
        run_json(json, base ? base + 1 : dump);
        fprintf(json, ",\n  \"candidates\": {\"schedules\": %d, \"keys\": %d, \"aes128\": %d, \"aes256\": %d},\n  \"volumes\": [",
                keys.nhits, keys.nfirst, keys.aes128, keys.aes256);
        for (i = 0; i < ntargets; i++) {
            const struct target *t = &targets[i];
            char type[16] = "";

            if (t->readable)
                snprintf(type, sizeof type, "LUKS%d", t->h.version);
            fputs(i ? ",\n    {\"name\": " : "\n    {\"name\": ", json); run_json(json, t->name);
            fputs(", \"type\": ", json); run_json(json, type);
            fputs(", \"device\": ", json); run_json(json, t->file);
            fprintf(json, ", \"offset\": %llu, \"in_memory\": %s, \"uuid\": ", (unsigned long long)t->offset,
                    t->in_memory ? "true" : "false");
            run_json(json, t->h.uuid);
            if (t->readable && t->h.ndigests) {
                fputs(", ", json);
                json_proof(json, t, 0);
            } else {
                fputs(", \"cipher\": null, \"key_bits\": null, \"digest\": null, \"route\": null, \"key_sha256_16\": null", json);
            }
            /* of the header as a whole: every key of it must be proven */
            fputs(", \"verdict\": ", json); run_json(json, t->verdict);
            fputs(", \"note\": ", json); run_json(json, t->note);
            for (k = 1; t->readable && k < t->h.ndigests; k++) {
                char file[NAME_MAX + 64] = "";

                if (t->proofs[k].bytes)
                    snprintf(file, sizeof file, "keys/%s.vk", t->proofs[k].stem);
                fputs(k == 1 ? ", \"further_keys\": [{\"key_file\": " : ", {\"key_file\": ", json);
                run_json(json, file);
                fputs(", ", json);
                json_proof(json, t, k);
                fputs(k + 1 == t->h.ndigests ? "}]" : "}", json);
            }
            fputc('}', json);
        }
        fputs("\n  ],\n  \"memory_pairs\": [", json);
        for (i = 0; i < npairs; i++) {
            fprintf(json, "%s\n    {\"key_file\": \"keys/%s.vk\", \"key_bits\": %zu, \"verdict\": \"%s\", \"key_sha256_16\": \"%s\", "
                    "\"tweak_schedule_at\": \"0x%016llx\"}", i ? "," : "", pairs[i].stem, pairs[i].bytes * 8, IN_MEMORY,
                    pairs[i].hash, (unsigned long long)pairs[i].tweak_at);
        }
        fprintf(json, "\n  ],\n  \"further_memory_pairs\": %zu\n}\n", further);
        if (fflush(json) || fsync(fd))
            r->write_failed = 1;
        fclose(json);
    }
    run_manifest(r);
    if ((fd = open(r->out, O_RDONLY | O_CLOEXEC)) < 0 || fsync(fd) || syncfs(fd))
        r->write_failed = 1;
    if (fd >= 0)
        close(fd);
    run_free(r);
    free(targets);
    if (r->write_failed) {
        fprintf(stderr, "keep: a write or a flush to the destination FAILED, the folder is not complete\n");
        return status ? status : 1;
    }
    printf("keep: every file of this run is flushed to the destination\n");
    /* with files to prove against, the run is in order where every header of them has its
       keys. What the dump itself holds of a header can be that of a volume that was closed. */
    if (status)
        return status;
    return o->nfiles && (!nfiles_targets || proven < nfiles_targets) ? 1 : 0;
}
