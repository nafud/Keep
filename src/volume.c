/*
 * volume.c: which mapped devices are encrypted volumes, which further devices are part of each,
 * which keys it has and where its header lies. See volume.h.
 */
#include "volume.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char SUBDEV[] = "CRYPT-SUBDEV-";   /* DM_UUID_PREFIX and CRYPT_SUBDEV of cryptsetup */
#define UUID_DIGITS 32                          /* a UUID without its hyphens */

/* The next field of a table line, which the kernel separates by one space. Returns 0 at the end
   of the line. An empty field has the length 0. */
static int next_field(const char **p, const char **start, size_t *len)
{
    if (!**p)
        return 0;
    *start = *p;
    *len = strcspn(*p, " ");
    *p += *len;
    if (**p)
        ++*p;
    return 1;
}

/* A device as a table names it, "major:minor" (the name of a dm_dev in dm-table.c). */
static int device_number(const char *s, size_t len, unsigned *major, unsigned *minor)
{
    char text[32], end;

    if (len >= sizeof text)
        return -1;
    memcpy(text, s, len);
    text[len] = 0;
    return sscanf(text, "%u:%u%c", major, minor, &end) == 2 && strspn(text, "0123456789:") == len ? 0 : -1;
}

int vol_crypt_line(const char *params, struct vol_crypt *c)
{
    const char *p = params, *f = NULL;
    size_t n = 0;
    int i;

    memset(c, 0, sizeof *c);
    /* <cipher> <key> <iv_offset> <device> <offset> */
    for (i = 0; i < 5; i++) {
        if (!next_field(&p, &f, &n) || !n)
            return -1;
        if (i == 0) {
            c->cipher = f;
            c->cipher_len = n;
        } else if (i == 1) {
            c->key = f;
            c->key_len = n;
        } else if (i == 3 && device_number(f, n, &c->major, &c->minor)) {
            return -1;
        }
    }
    /* and then the number of its options and the options */
    while (next_field(&p, &f, &n)) {
        char text[sizeof "integrity:4294967295:" + sizeof c->auth];
        unsigned tag;
        int at = 0;

        if (n >= sizeof text || strncmp(f, "integrity:", 10))
            continue;
        memcpy(text, f, n);
        text[n] = 0;
        if (sscanf(text, "integrity:%u:%n", &tag, &at) == 1 && at && strlen(text + at) < sizeof c->auth) {
            c->tag_size = tag;
            strcpy(c->auth, text + at);
        }
    }
    return 0;
}

/* The device of a line that begins with it: a linear target and an integrity target. */
static int first_device(const char *params, unsigned *major, unsigned *minor)
{
    const char *p = params, *f;
    size_t n;

    return next_field(&p, &f, &n) ? device_number(f, n, major, minor) : -1;
}

static int is_type(const struct dm_target *t, const char *type)
{
    return !strcmp(t->type, type);
}

static const struct dm_table *by_number(const struct dm_table *tabs, size_t ntabs, unsigned major, unsigned minor)
{
    size_t i;

    for (i = 0; i < ntabs; i++)
        if (tabs[i].major == major && tabs[i].minor == minor)
            return &tabs[i];
    return NULL;
}

static int is_helper(const struct dm_table *t)
{
    return !strncmp(t->uuid, SUBDEV, sizeof SUBDEV - 1);
}

/* Whether a helper device is one of the volume TOP: cryptsetup gives a helper the UUID of the
   volume behind CRYPT-SUBDEV- and finds it again by that (dm_device_deps with the prefix that
   _init_by_name_crypt builds from the 32 digits behind CRYPT-LUKS2-). */
static int helper_of(const struct dm_table *helper, const struct dm_table *top)
{
    const size_t type = sizeof "CRYPT-LUKS2-" - 1;

    return strlen(top->uuid) >= type + UUID_DIGITS && !strncmp(top->uuid, "CRYPT-", 6) && is_helper(helper) &&
           !strncmp(helper->uuid + sizeof SUBDEV - 1, top->uuid + type, UUID_DIGITS);
}

/* A crypt target of the table T, with its key. While cryptsetup sets its helpers up, the table
   of the volume and that of a helper hold the same targets, so what a key maps is counted for
   each table and the largest of the counts is taken. */
static int add_key(struct vol *v, const struct vol_crypt *c, const struct dm_table *t, uint64_t sectors)
{
    struct vol_key *grown, *k = NULL;
    size_t i, n = c->cipher_len < VOL_CIPHER_LEN ? c->cipher_len : VOL_CIPHER_LEN - 1;

    for (i = 0; i < v->nkeys && !k; i++)
        if (strlen(v->keys[i].cipher) == n && !memcmp(v->keys[i].cipher, c->cipher, n) &&
            v->keys[i].field_len == c->key_len && !memcmp(v->keys[i].field, c->key, c->key_len))
            k = &v->keys[i];
    if (!k) {
        if (!(grown = realloc(v->keys, (v->nkeys + 1) * sizeof *grown)))
            return -1;
        v->keys = grown;
        k = &v->keys[v->nkeys++];
        memset(k, 0, sizeof *k);
        memcpy(k->cipher, c->cipher, n);
        k->field = c->key;
        k->field_len = c->key_len;
    }
    if (k->counted != t) {
        k->counted = t;
        k->in_table = 0;
    }
    k->in_table += sectors;
    if (k->in_table > k->sectors)
        k->sectors = k->in_table;
    return 0;
}

static int is_part(const struct vol *v, const struct dm_table *t)
{
    size_t i;

    for (i = 0; i < v->nparts; i++)
        if (v->parts[i] == t)
            return 1;
    return 0;
}

static int add_part(struct vol *v, const struct dm_table *t)
{
    const struct dm_table **grown = realloc(v->parts, (v->nparts + 1) * sizeof *grown);

    if (!grown)
        return -1;
    v->parts = grown;
    v->parts[v->nparts++] = t;
    return 0;
}

/*
 * The volume whose name the device TOP carries: its keys, the helpers of a re-encryption below
 * it where WITH_HELPERS is set, and its device. Returns -1 where memory runs out.
 */
static int build(struct vol *v, const struct dm_table *top, const struct dm_table *tabs, size_t ntabs,
                 int with_helpers)
{
    const struct dm_table *t = top;
    struct vol_crypt c;
    unsigned major, minor;
    size_t walked = 0, i;

    memset(v, 0, sizeof *v);
    v->top = top;
    /* the tables of the volume in the order found: its own, then those of its helpers */
    for (;;) {
        for (i = 0; i < t->ntargets; i++) {
            const struct dm_target *g = &t->targets[i];
            const struct dm_table *d;

            if (is_type(g, "crypt")) {
                if (vol_crypt_line(g->params, &c)) {
                    v->not_understood++;
                    continue;
                }
                if (add_key(v, &c, t, g->length))
                    return -1;
                major = c.major;
                minor = c.minor;
            } else if (!is_type(g, "linear") || first_device(g->params, &major, &minor)) {
                continue;
            }
            if (with_helpers && (d = by_number(tabs, ntabs, major, minor)) && helper_of(d, top) && !is_part(v, d) &&
                add_part(v, d))
                return -1;
        }
        if (walked == v->nparts) {
            /* The helpers that none of these tables names: cryptsetup makes them before it puts
               them below the volume. They are the volume's by their UUID, in the order of their
               names. */
            const struct dm_table *next = NULL;

            for (i = 0; with_helpers && i < ntabs; i++)
                if (helper_of(&tabs[i], top) && !is_part(v, &tabs[i]) && (!next || strcmp(tabs[i].name, next->name) < 0))
                    next = &tabs[i];
            if (!next)
                break;
            if (add_part(v, next))
                return -1;
        }
        t = v->parts[walked++];
    }

    /* The device, as _init_by_name_crypt finds it. It begins with the device of the first
       target. Below a crypt target with integrity that is a dm-integrity device, and the device
       of the volume is the one below it. */
    if (top->ntargets && is_type(&top->targets[0], "crypt") && !vol_crypt_line(top->targets[0].params, &c)) {
        const struct dm_table *d = by_number(tabs, ntabs, c.major, c.minor);

        v->has_device = 1;
        v->major = c.major;
        v->minor = c.minor;
        if (c.tag_size) {
            v->tag_size = c.tag_size;
            memcpy(v->auth, c.auth, sizeof v->auth);
            if (d && d->ntargets == 1 && is_type(&d->targets[0], "integrity") &&
                !first_device(d->targets[0].params, &v->major, &v->minor))
                v->below = d;
        }
    } else if (top->ntargets && is_type(&top->targets[0], "linear")) {
        v->has_device = !first_device(top->targets[0].params, &v->major, &v->minor);
    } else {
        /* cryptsetup knows no such volume. The device of its first crypt target is named. */
        for (i = 0; i < top->ntargets && !v->has_device; i++)
            if (is_type(&top->targets[i], "crypt") && !vol_crypt_line(top->targets[i].params, &c)) {
                v->has_device = 1;
                v->major = c.major;
                v->minor = c.minor;
            }
    }
    /* With helpers it is the first device in their tables that is not a helper itself. */
    for (walked = 0; walked < v->nparts; walked++) {
        t = v->parts[walked];
        for (i = 0; i < t->ntargets; i++) {
            const struct dm_target *g = &t->targets[i];
            const struct dm_table *d;

            if (is_type(g, "crypt") && !vol_crypt_line(g->params, &c)) {
                major = c.major;
                minor = c.minor;
            } else if (!is_type(g, "linear") || first_device(g->params, &major, &minor)) {
                continue;
            }
            if ((d = by_number(tabs, ntabs, major, minor)) && is_part(v, d))
                continue;
            v->has_device = 1;
            v->major = major;
            v->minor = minor;
            return 0;
        }
    }
    return 0;
}

/* An optional key of a dm-integrity line, behind NAME and the name of an algorithm, replaced
   by zeros: hide_key in dmsetup.c of LVM2. */
static void hide_key(char *params, const char *name)
{
    char *c = strstr(params, name);

    if (!c || !(c = strpbrk(c + strlen(name), " :")) || *c++ != ':')
        return;
    while (*c && *c != ' ')
        *c++ = '0';
}

/* What the kernel said about a device of the volume, with each key replaced by zeros, as
   "dmsetup table" prints it: the key of a crypt target, and the keys that a dm-integrity
   target can have for its hash, for the encryption of its journal and for the journal's MAC. */
void vol_table_text(struct str *text, const struct dm_table *t)
{
    size_t i;

    str_addf(text, "name %s\nuuid %s\ndevice %u:%u\n", t->name, t->uuid[0] ? t->uuid : "-", t->major, t->minor);
    for (i = 0; i < t->ntargets; i++) {
        const char *p = t->targets[i].params, *key = strchr(p, ' ');

        str_addf(text, "%llu %llu %s ", (unsigned long long)t->targets[i].start,
                 (unsigned long long)t->targets[i].length, t->targets[i].type);
        if (!strcmp(t->targets[i].type, "crypt") && key && key[1] != ':') {
            size_t n = strcspn(++key, " ");

            str_addn(text, p, (size_t)(key - p));
            for (; n; n--)
                str_add(text, "0");
            str_add(text, key + strcspn(key, " "));
        } else if (!strcmp(t->targets[i].type, "integrity")) {
            char *copy = strdup(p);

            if (copy) {
                hide_key(copy, "internal_hash:");
                hide_key(copy, "journal_crypt:");
                hide_key(copy, "journal_mac:");
                str_add(text, copy);
                explicit_bzero(copy, strlen(copy));
                free(copy);
            } else {
                text->failed = 1;               /* and not the line as it is */
            }
        } else {
            str_add(text, p);
        }
        str_add(text, "\n");
    }
}

static void release(struct vol *v)
{
    free(v->parts);
    free(v->keys);
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct vol *)a)->top->name, ((const struct vol *)b)->top->name);
}

int vol_find(const struct dm_table *tabs, size_t ntabs, struct vol **vols, size_t *nvols, char err[VOL_ERR_LEN])
{
    struct vol *list = NULL, v;
    size_t count = 0, i, k;
    int pass;

    *vols = NULL;
    *nvols = 0;
    if (ntabs && !(list = calloc(ntabs, sizeof *list)))
        goto no_memory;
    /* First the devices that are no helpers, each with the helpers below it. Then the helpers
       that no volume took, each for itself, so that no crypt target is left out. */
    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < ntabs; i++) {
            int taken = 0;

            if (is_helper(&tabs[i]) != pass)
                continue;
            for (k = 0; pass && k < count && !taken; k++)
                taken = is_part(&list[k], &tabs[i]);
            if (taken)
                continue;
            if (build(&v, &tabs[i], tabs, ntabs, !pass)) {
                release(&v);
                goto no_memory;
            }
            if (v.nkeys || v.not_understood)
                list[count++] = v;
            else
                release(&v);
        }
    }
    if (count)
        qsort(list, count, sizeof *list, by_name);
    *vols = list;
    *nvols = count;
    return 0;
no_memory:
    snprintf(err, VOL_ERR_LEN, "the volumes among the mapped devices: no memory");
    vol_free(list, count);
    return -1;
}

void vol_free(struct vol *vols, size_t nvols)
{
    size_t i;

    for (i = 0; vols && i < nvols; i++)
        release(&vols[i]);
    free(vols);
}
