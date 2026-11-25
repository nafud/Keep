/*
 * keep-unit.c: the parts of the C program one at a time, for the checks.
 *
 *   keep-unit selftest                          the examples of the standards
 *   keep-unit plain COMMAND...                  a command of this list with every digest
 *                                               computed without the SHA instructions of the
 *                                               processor
 *   keep-unit cpu                               whether those instructions are in use
 *   keep-unit hash NAME                         the digest of standard input, in hexadecimal
 *   keep-unit pbkdf2 NAME KEY SALT ITERATIONS LENGTH    KEY and SALT in hexadecimal
 *   keep-unit json                              the JSON text of standard input, written anew
 *   keep-unit luks FILE                         what the LUKS header at the start of FILE says
 *   keep-unit luks-backup FILE OUT              the copy of that header, as luksHeaderBackup
 *   keep-unit luks-prove FILE KEYFILE           whether the key of KEYFILE gives its digest
 *   keep-unit mount-of MOUNTINFO PATH           the mount that holds PATH
 *   keep-unit in-use SYSFS MOUNTINFO SWAPS MAJOR MINOR    what that block device carries
 *   keep-unit other-fs MOUNTS                   the file systems that encrypt by themselves
 *   keep-unit lockdown FILE                     the lockdown mode of that file
 *   keep-unit secure-boot DIR                   the value of the variable SecureBoot in DIR
 *   keep-unit os-name FILE FILE                 PRETTY_NAME of the first file that can be read
 *   keep-unit names NAME                        NAME for the screen and as a file name
 *   keep-unit image-source IOMEM CORE           the ranges of memory that an image holds, from
 *                                               a text like /proc/iomem and a core like
 *                                               /proc/kcore
 *   keep-unit image IOMEM CORE FORMAT OUT [FORMAT OUT]...    that memory, read once and written
 *                                               to each file OUT in its format. OUT must not
 *                                               exist, or be a device, which is written as it
 *                                               is. Says for each file whether it was written
 *                                               with direct writes, and how many of its pages
 *                                               lay in the page cache after its writes, before
 *                                               it is flushed and its pages are let go
 *   keep-unit cached FILE                       how many pages of FILE lie in the page cache
 *   keep-unit snappy                            standard input as a framed Snappy stream
 *   keep-unit dm-answer list|table FILE         FILE as an answer of the kernel to one of the two
 *                                               requests, printed like the two lines below
 *   keep-unit dm-list                           the mapped devices, as "dmsetup ls" prints them
 *   keep-unit dm-table NAME                     the table, as "dmsetup table NAME" prints it,
 *                                               and for a crypt target the length of its key
 *                                               and the first 16 digits of the key's SHA-256
 *
 * The device-mapper requests need root and change nothing. No key is printed: like dmsetup
 * without --showkeys, the key of a crypt target is replaced by zeros.
 * Exit status: 0, 1 when something failed, 2 for a wrong use.
 */
#include "../src/dm.h"
#include "../src/hash.h"
#include "../src/image.h"
#include "../src/json.h"
#include "../src/luks.h"
#include "../src/snappy.h"
#include "../src/sys.h"
#include "../src/util.h"
#include "../src/volume.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void print_hex(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int unhex(const char *s, uint8_t **out, size_t *n)
{
    size_t len = strlen(s), i;
    unsigned v;

    *out = NULL;
    if (len % 2 || !(*out = malloc(len / 2 + 1)))
        return -1;
    for (i = 0; i < len / 2; i++) {
        if (sscanf(s + 2 * i, "%2x", &v) != 1) {
            free(*out);
            *out = NULL;
            return -1;
        }
        (*out)[i] = (uint8_t)v;
    }
    *n = len / 2;
    return 0;
}

static int cmd_hash(const char *name)
{
    const struct hash_alg *alg = hash_by_name(name);
    struct hash_ctx c;
    uint8_t buf[65536], out[HASH_MAX_DIGEST];
    size_t n;

    if (!alg) {
        fprintf(stderr, "keep-unit: no hash function %s\n", name);
        return 1;
    }
    hash_init(&c, alg);
    while ((n = fread(buf, 1, sizeof buf, stdin)) > 0)
        hash_update(&c, buf, n);
    hash_final(&c, out);
    print_hex(out, hash_len(alg));
    return 0;
}

static int cmd_pbkdf2(char **a)
{
    const struct hash_alg *alg = hash_by_name(a[0]);
    uint8_t *key = NULL, *salt = NULL, *out = NULL;
    size_t keylen, saltlen, outlen = (size_t)atol(a[4]);
    int r = 1;

    if (!alg || unhex(a[1], &key, &keylen) || unhex(a[2], &salt, &saltlen) || !(out = malloc(outlen + 1))) {
        fprintf(stderr, "keep-unit: pbkdf2: an argument is not understood\n");
    } else {
        pbkdf2(alg, key, keylen, salt, saltlen, (uint32_t)atol(a[3]), out, outlen);
        print_hex(out, outlen);
        r = 0;
    }
    free(key);
    free(salt);
    free(out);
    return r;
}

/* The tree as text that Python's json.loads reads: strings and names as \uXXXX escapes of their
   bytes, numbers as they were written. */
static void dump_string(const char *s, size_t n)
{
    size_t i;

    putchar('"');
    for (i = 0; i < n; i++)
        printf("\\u%04x", (unsigned)(unsigned char)s[i]);
    putchar('"');
}

static void dump(const struct json *j)
{
    const struct json *m;

    switch (j->type) {
    case JSON_NULL:   printf("null"); break;
    case JSON_FALSE:  printf("false"); break;
    case JSON_TRUE:   printf("true"); break;
    case JSON_NUMBER: printf("%s", j->text); break;
    case JSON_STRING: dump_string(j->text, j->len); break;
    case JSON_ARRAY:
    case JSON_OBJECT:
        putchar(j->type == JSON_ARRAY ? '[' : '{');
        for (m = j->first; m; m = m->next) {
            if (j->type == JSON_OBJECT) {
                dump_string(m->name, strlen(m->name));
                putchar(':');
            }
            dump(m);
            if (m->next)
                putchar(',');
        }
        putchar(j->type == JSON_ARRAY ? ']' : '}');
        break;
    }
}

static int cmd_json(void)
{
    size_t room = 1 << 16, n = 0, got;
    char *text = malloc(room);
    const char *why;
    struct json *j;

    while (text && (got = fread(text + n, 1, room - n, stdin)) > 0)
        if ((n += got) == room)
            text = realloc(text, room *= 2);
    if (!text)
        return 1;
    j = json_parse(text, n, &why);
    free(text);
    if (!j) {
        printf("refused: %s\n", why);
        return 1;
    }
    dump(j);
    putchar('\n');
    json_free(j);
    return 0;
}

static int open_header(const char *path, struct luks_header *h)
{
    char err[LUKS_ERR_LEN];
    int fd = open(path, O_RDONLY | O_CLOEXEC), r;

    if (fd < 0) {
        perror(path);
        return -1;
    }
    if ((r = luks_read(fd, h, err))) {
        printf("%s: %s\n", r > 0 ? "none" : "damaged", err);
        close(fd);
        return -1;
    }
    return fd;
}

static int cmd_luks(const char *path)
{
    struct luks_header h;
    size_t i;
    int fd = open_header(path, &h);

    if (fd < 0)
        return 1;
    printf("LUKS%d uuid %s area %llu%s\n", h.version, h.uuid, (unsigned long long)h.area,
           h.secondary ? " second copy in use" : "");
    for (i = 0; i < h.ndigests; i++) {
        printf("digest %u %s%s iterations %u salt %zu bytes digest ", h.digests[i].number, h.digests[i].hash,
               h.digests[i].alg ? "" : " (not computed here)", h.digests[i].iterations, h.digests[i].saltlen);
        print_hex(h.digests[i].digest, h.digests[i].digestlen);
    }
    for (i = 0; i < h.ndigests; i++)
        printf("the key of digest %u: %zu bytes, cipher %s\n", h.digests[i].number, h.digests[i].key_bytes,
               h.digests[i].cipher[0] ? h.digests[i].cipher : "unknown");
    close(fd);
    return 0;
}

static int cmd_luks_backup(const char *path, const char *outpath)
{
    char err[LUKS_ERR_LEN];
    struct luks_header h;
    uint64_t written;
    int fd = open_header(path, &h), out, r;

    if (fd < 0)
        return 1;
    if ((out = open(outpath, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600)) < 0) {
        perror(outpath);
        close(fd);
        return 1;
    }
    if ((r = luks_backup(fd, &h, out, &written, err)))
        printf("failed: %s\n", err);
    else
        printf("%llu bytes\n", (unsigned long long)written);
    close(out);
    close(fd);
    return r ? 1 : 0;
}

static int cmd_luks_prove(const char *path, const char *keypath)
{
    struct luks_header h;
    uint8_t key[1024];
    const char *hash;
    FILE *kf;
    size_t n;
    int fd = open_header(path, &h), r;

    if (fd < 0)
        return 1;
    close(fd);
    if (!(kf = fopen(keypath, "rb"))) {
        perror(keypath);
        return 1;
    }
    n = fread(key, 1, sizeof key, kf);
    fclose(kf);
    r = luks_proves(&h, key, n, 0, &hash);
    if (r > 0 && h.ndigests > 1)
        printf("proven by digest %d of %zu, ", r, h.ndigests);
    /* with the digest that it gives taken, the key gives no other */
    if (r > 0 && luks_proves(&h, key, n, 1u << (r - 1), &hash) > 0)
        printf("and by a second digest, ");
    explicit_bzero(key, sizeof key);
    printf("%s%s\n", r > 0 ? "proven" : r == 0 ? "not proven" : "no digest that is computed here",
           r < 0 && hash ? hash : "");
    return r > 0 ? 0 : 1;
}

static int cmd_mount_of(const char *mountinfo, const char *path)
{
    struct sys_mount m;

    if (sys_mount_of(mountinfo, path, &m)) {
        printf("none\n");
        return 1;
    }
    printf("%s (%s) mounted at %s%s\n", m.source, m.type, m.point, m.readonly ? ", read-only" : "");
    sys_mount_free(&m);
    return 0;
}

static int cmd_text(char *text)
{
    if (!text)
        return 1;
    printf("[%s]\n", text);
    free(text);
    return 0;
}

static int cmd_names(const char *name)
{
    char shown[256], file[256];

    snprintf(shown, sizeof shown, "%s", name);
    name_clean(shown);
    name_file(name, file, sizeof file);
    printf("[%s] [%s]\n", shown, file);
    return 0;
}

static int by_name(const void *a, const void *b)
{
    return strcmp(((const struct dm_dev *)a)->name, ((const struct dm_dev *)b)->name);
}

static void print_devs(struct dm_dev *devs, size_t n)
{
    size_t i;

    if (n)
        qsort(devs, n, sizeof *devs, by_name);
    for (i = 0; i < n; i++)
        printf("%s\t(%u:%u)\n", devs[i].name, devs[i].major, devs[i].minor);
    if (!n)
        printf("No devices found\n");
    free(devs);
}

static int cmd_dm_list(void)
{
    char err[DM_ERR_LEN];
    struct dm_dev *devs;
    size_t n;
    int fd = dm_open(err);

    if (fd < 0 || dm_list(fd, &devs, &n, err)) {
        fprintf(stderr, "keep-unit: %s\n", err);
        return 1;
    }
    print_devs(devs, n);
    close(fd);
    return 0;
}

static void print_table(struct dm_table *tp)
{
    struct dm_table t = *tp;
    size_t i;

    fprintf(stderr, "name %s, uuid %s, device %u:%u, %zu target(s)\n", t.name, t.uuid, t.major, t.minor, t.ntargets);
    for (i = 0; i < t.ntargets; i++) {
        char *p = t.targets[i].params, *key, *end;

        if (!strcmp(t.targets[i].type, "crypt") && (key = strchr(p, ' ')) && *++key != ':') {
            uint8_t *raw, digest[32];
            size_t rawlen;
            char saved;

            end = key + strcspn(key, " ");
            saved = *end;
            *end = 0;
            if (!unhex(key, &raw, &rawlen)) {
                sha256(raw, rawlen, digest);
                fprintf(stderr, "key of %zu bytes, sha256 ", rawlen);
                explicit_bzero(raw, rawlen);
                free(raw);
                for (rawlen = 0; rawlen < 8; rawlen++)
                    fprintf(stderr, "%02x", digest[rawlen]);
                fprintf(stderr, "\n");
            }
            *end = saved;
            memset(key, '0', (size_t)(end - key));
        }
        printf("%llu %llu %s %s\n", (unsigned long long)t.targets[i].start,
               (unsigned long long)t.targets[i].length, t.targets[i].type, p);
    }
    dm_table_free(tp);
}

static int cmd_dm_table(const char *name)
{
    char err[DM_ERR_LEN];
    struct dm_table t;
    int fd = dm_open(err);

    if (fd < 0 || dm_table(fd, name, &t, err)) {
        fprintf(stderr, "keep-unit: %s\n", err);
        return 1;
    }
    print_table(&t);
    close(fd);
    return 0;
}

/* A file as the answer of the kernel, in a buffer of exactly its size, so that a read beyond
   it is a read beyond an allocation. */
static void *read_answer(const char *path, size_t *len)
{
    struct stat st;
    void *buf = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0 || fstat(fd, &st) || !(buf = malloc((size_t)st.st_size + !st.st_size)) ||
        read(fd, buf, (size_t)st.st_size) != st.st_size) {
        perror(path);
        free(buf);
        buf = NULL;
    }
    if (fd >= 0)
        close(fd);
    *len = buf ? (size_t)st.st_size : 0;
    return buf;
}

static int cmd_dm_answer(const char *kind, const char *path)
{
    char err[DM_ERR_LEN];
    struct dm_table t;
    struct dm_dev *devs;
    size_t n, len;
    void *buf = read_answer(path, &len);
    int r;

    if (!buf)
        return 2;
    if (!strcmp(kind, "list")) {
        r = dm_list_answer(buf, len, &devs, &n, err);
        free(buf);
        if (!r)
            print_devs(devs, n);
    } else {
        r = dm_table_answer(buf, len, &t, err);
        if (!r)
            print_table(&t);
    }
    if (r)
        printf("refused: %s\n", err);
    return r ? 1 : 0;
}

/* The volumes among some tables: one line for each and one for each of its keys. A key in a
   table is named by its length. */
static int print_volumes(struct dm_table *tabs, size_t ntabs)
{
    char err[VOL_ERR_LEN];
    struct vol *vols;
    size_t nvols, i, k;
    int r = vol_find(tabs, ntabs, &vols, &nvols, err);

    if (r)
        printf("refused: %s\n", err);
    for (i = 0; !r && i < nvols; i++) {
        const struct vol *v = &vols[i];

        printf("%s:", v->top->name);
        if (v->has_device)
            printf(" device %u:%u,", v->major, v->minor);
        else
            printf(" no device,");
        printf(" %zu key(s)", v->nkeys);
        if (v->tag_size)
            printf(", integrity %u %s", v->tag_size, v->auth);
        if (v->below)
            printf(", below it %s", v->below->name);
        for (k = 0; k < v->nparts; k++)
            printf("%s %s", k ? "" : ", parts", v->parts[k]->name);
        if (v->not_understood)
            printf(", %zu crypt line(s) not understood", v->not_understood);
        printf("\n");
        for (k = 0; k < v->nkeys; k++) {
            const struct vol_key *key = &v->keys[k];

            printf("  key %zu: %s, ", k + 1, key->cipher);
            if (key->field[0] == ':' || key->field[0] == '-')
                printf("%.*s", (int)key->field_len, key->field);
            else
                printf("%zu characters", key->field_len);
            printf(", %llu sectors\n", (unsigned long long)key->sectors);
        }
    }
    if (!r)
        vol_free(vols, nvols);
    for (i = 0; i < ntabs; i++)
        dm_table_free(&tabs[i]);
    free(tabs);
    return r ? 1 : 0;
}

/* The volumes among tables that files hold, each file one answer of the kernel. */
static int cmd_volumes(int count, char **paths)
{
    char err[DM_ERR_LEN];
    struct dm_table *tabs = calloc((size_t)count, sizeof *tabs);
    size_t n = 0, len;
    int i;

    for (i = 0; tabs && i < count; i++) {
        void *buf = read_answer(paths[i], &len);

        if (!buf)
            return 2;
        if (dm_table_answer(buf, len, &tabs[n], err))
            printf("refused: %s: %s\n", paths[i], err);
        else
            n++;
    }
    return tabs ? print_volumes(tabs, n) : 2;
}

/* The volumes of the running kernel. */
static int cmd_dm_volumes(void)
{
    char err[DM_ERR_LEN];
    struct dm_dev *devs;
    struct dm_table *tabs;
    size_t ndevs, n = 0, i;
    int fd = dm_open(err);

    if (fd < 0 || dm_list(fd, &devs, &ndevs, err)) {
        fprintf(stderr, "keep-unit: %s\n", err);
        return 1;
    }
    if (!(tabs = calloc(ndevs + 1, sizeof *tabs)))
        return 2;
    for (i = 0; i < ndevs; i++)
        n += !dm_table(fd, devs[i].name, &tabs[n], err);
    free(devs);
    close(fd);
    return print_volumes(tabs, n);
}

/* The source of an image from two files of the checks. Returns the descriptor of the core. */
static int open_source(const char *iomem_path, const char *core_path, struct image_source *src)
{
    char err[IMAGE_ERR_LEN], *iomem = read_text(iomem_path, 1 << 20, NULL);
    int core = open(core_path, O_RDONLY);

    if (!iomem || core < 0) {
        fprintf(stderr, "keep-unit: %s or %s cannot be read\n", iomem_path, core_path);
    } else if (image_source(iomem, core, src, err)) {
        printf("refused: %s\n", err);
    } else {
        free(iomem);
        return core;
    }
    free(iomem);
    if (core >= 0)
        close(core);
    return -1;
}

/* Standard input as a framed Snappy stream, in chunks of the most that a chunk holds. */
static int cmd_snappy(void)
{
    static uint8_t in[SNAPPY_CHUNK], out[SNAPPY_CHUNK_MAX];
    size_t n;

    fwrite(snappy_stream_start, 1, sizeof snappy_stream_start, stdout);
    while ((n = fread(in, 1, sizeof in, stdin)) > 0)
        fwrite(out, 1, snappy_chunk(in, n, out), stdout);
    return ferror(stdin) || fflush(stdout) ? 1 : 0;
}

static int cmd_image_source(const char *iomem_path, const char *core_path)
{
    struct image_source src;
    size_t i;
    int exact, core = open_source(iomem_path, core_path, &src);

    if (core < 0)
        return 1;
    for (i = 0; i < src.nranges; i++)
        printf("0x%llx-0x%llx at 0x%llx\n", (unsigned long long)src.ranges[i].start,
               (unsigned long long)src.ranges[i].end, (unsigned long long)src.ranges[i].offset);
    printf("%llu bytes of %llu, lime %llu, raw %llu, avml at most %llu\n", (unsigned long long)src.bytes,
           (unsigned long long)src.ram, (unsigned long long)image_size(IMAGE_LIME, &src, &exact),
           (unsigned long long)image_size(IMAGE_RAW, &src, &exact), (unsigned long long)image_size(IMAGE_AVML, &src, &exact));
    image_source_free(&src);
    close(core);
    return 0;
}

/* The pages of a file that lie in the page cache, as the kernel says with mincore. Returns 0,
   or -1 with errno. */
static int cached(const char *path, size_t *in, size_t *pages)
{
    unsigned char *vec = NULL;
    void *map = MAP_FAILED;
    struct stat st;
    size_t i;
    int fd, r = -1;

    *in = *pages = 0;
    if ((fd = open(path, O_RDONLY)) < 0)
        return -1;
    if (fstat(fd, &st))
        goto out;
    *pages = ((size_t)st.st_size + 4095) / 4096;
    if (!*pages) {
        r = 0;
        goto out;
    }
    map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    vec = malloc(*pages);
    if (map == MAP_FAILED || !vec || mincore(map, (size_t)st.st_size, vec))
        goto out;
    for (i = 0; i < *pages; i++)
        *in += vec[i] & 1;
    r = 0;
out:
    free(vec);
    if (map != MAP_FAILED)
        munmap(map, (size_t)st.st_size);
    close(fd);
    return r;
}

static int cmd_cached(const char *path)
{
    size_t in, pages;

    if (cached(path, &in, &pages)) {
        fprintf(stderr, "keep-unit: %s: %s\n", path, strerror(errno));
        return 1;
    }
    printf("%zu of %zu pages in the page cache\n", in, pages);
    return 0;
}

static int cmd_image(int argc, char **argv)
{
    struct image_file files[8];
    struct image_source src;
    char err[IMAGE_ERR_LEN];
    uint64_t unread;
    size_t n = (size_t)(argc - 2) / 2, i, in, pages;
    int core, r;

    if (n > sizeof files / sizeof files[0])
        return 2;
    memset(files, 0, sizeof files);
    for (i = 0; i < n; i++)
        if (image_by_name(argv[2 + 2 * i], &files[i].format))
            return 2;
    if ((core = open_source(argv[0], argv[1], &src)) < 0)
        return 1;
    for (i = 0; i < n; i++) {
        struct stat st;

        /* a device stands for a medium that takes no byte, /dev/full */
        if (!stat(argv[3 + 2 * i], &st) && S_ISCHR(st.st_mode)) {
            files[i].direct = 0;
            files[i].fd = open(argv[3 + 2 * i], O_WRONLY);
        } else if (image_open(&files[i], argv[3 + 2 * i])) {
            files[i].fd = -1;
        }
        if (files[i].fd < 0) {
            fprintf(stderr, "keep-unit: %s cannot be made: %s\n", argv[3 + 2 * i], strerror(errno));
            return 1;
        }
    }
    r = image_write(core, &src, files, n, NULL, NULL, &unread, err);
    for (i = 0; i < n; i++) {
        if (files[i].failed) {
            printf("%s failed: %s\n", image_name(files[i].format), strerror(files[i].failed));
        } else {
            printf("%s %llu bytes, sha256 ", image_name(files[i].format), (unsigned long long)files[i].bytes);
            print_hex(files[i].sha256, 32);
            printf("%s %s\n", image_name(files[i].format), files[i].direct ? "direct writes" : "through the page cache");
            /* what the writes left in the cache, before the file is flushed and its pages let go */
            if (!cached(argv[3 + 2 * i], &in, &pages))
                printf("%s %zu of %zu pages in the page cache after its writes\n", image_name(files[i].format), in, pages);
            if (image_settle(&files[i]))
                printf("%s is not flushed: %s\n", image_name(files[i].format), strerror(errno));
        }
        close(files[i].fd);
    }
    printf("%llu bytes not read\n", (unsigned long long)unread);
    if (r)
        printf("failed: %s\n", err);
    image_source_free(&src);
    close(core);
    return r ? 1 : 0;
}

int main(int argc, char **argv)
{
    const char *bad;

    if (argc >= 3 && !strcmp(argv[1], "plain")) {
        hash_plain(1);
        argc--;
        argv++;
    }
    if (argc == 2 && !strcmp(argv[1], "cpu")) {
        printf("%s\n", hash_with_cpu() ? "SHA instructions" : "no SHA instructions");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "selftest")) {
        if ((bad = hash_selftest()) || (bad = snappy_selftest())) {
            fprintf(stderr, "keep-unit: %s does not compute the example of its standard\n", bad);
            return 1;
        }
        printf("the examples of the standards compute\n");
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "hash"))
        return cmd_hash(argv[2]);
    if (argc == 7 && !strcmp(argv[1], "pbkdf2"))
        return cmd_pbkdf2(argv + 2);
    if (argc == 2 && !strcmp(argv[1], "json"))
        return cmd_json();
    if (argc == 3 && !strcmp(argv[1], "luks"))
        return cmd_luks(argv[2]);
    if (argc == 4 && !strcmp(argv[1], "luks-backup"))
        return cmd_luks_backup(argv[2], argv[3]);
    if (argc == 4 && !strcmp(argv[1], "luks-prove"))
        return cmd_luks_prove(argv[2], argv[3]);
    if (argc == 4 && !strcmp(argv[1], "mount-of"))
        return cmd_mount_of(argv[2], argv[3]);
    if (argc == 7 && !strcmp(argv[1], "in-use"))
        return cmd_text(sys_in_use(argv[2], argv[3], argv[4], (unsigned)atoi(argv[5]), (unsigned)atoi(argv[6])));
    if (argc == 3 && !strcmp(argv[1], "other-fs"))
        return cmd_text(sys_other_filesystems(argv[2]));
    if (argc == 3 && !strcmp(argv[1], "lockdown")) {
        char mode[64];

        sys_lockdown(argv[2], mode, sizeof mode);
        return cmd_text(strdup(mode));
    }
    if (argc == 3 && !strcmp(argv[1], "secure-boot")) {
        char value[16];

        sys_secure_boot(argv[2], value, sizeof value);
        return cmd_text(strdup(value));
    }
    if (argc == 4 && !strcmp(argv[1], "os-name")) {
        char name[256];

        sys_os_name(argv[2], argv[3], name, sizeof name);
        return cmd_text(strdup(name));
    }
    if (argc == 3 && !strcmp(argv[1], "memory")) {
        unsigned long long kib;

        if (sys_memory(argv[2], &kib))
            return cmd_text(strdup("unknown"));
        printf("[%llu]\n", kib);
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "snappy"))
        return cmd_snappy();
    if (argc == 4 && !strcmp(argv[1], "image-source"))
        return cmd_image_source(argv[2], argv[3]);
    if (argc >= 6 && argc % 2 == 0 && !strcmp(argv[1], "image"))
        return cmd_image(argc - 2, argv + 2);
    if (argc == 3 && !strcmp(argv[1], "cached"))
        return cmd_cached(argv[2]);
    if (argc == 3 && !strcmp(argv[1], "names"))
        return cmd_names(argv[2]);
    if (argc == 4 && !strcmp(argv[1], "dm-answer") && (!strcmp(argv[2], "list") || !strcmp(argv[2], "table")))
        return cmd_dm_answer(argv[2], argv[3]);
    if (argc >= 3 && !strcmp(argv[1], "volumes"))
        return cmd_volumes(argc - 2, argv + 2);
    if (argc == 2 && !strcmp(argv[1], "dm-volumes"))
        return cmd_dm_volumes();
    if (argc == 2 && !strcmp(argv[1], "dm-list"))
        return cmd_dm_list();
    if (argc == 3 && !strcmp(argv[1], "dm-table"))
        return cmd_dm_table(argv[2]);
    fprintf(stderr, "usage: keep-unit [plain] selftest | cpu | hash NAME | pbkdf2 NAME KEY SALT ITERATIONS LENGTH | json | luks FILE | "
            "luks-backup FILE OUT | luks-prove FILE KEYFILE | mount-of MOUNTINFO PATH | in-use SYSFS MOUNTINFO SWAPS MAJOR MINOR | other-fs MOUNTS | "
            "lockdown FILE | secure-boot DIR | os-name FILE FILE | memory FILE | names NAME | image-source IOMEM CORE | "
            "image IOMEM CORE FORMAT OUT... | cached FILE | snappy | dm-answer list|table FILE | volumes FILE... | "
            "dm-list | dm-table NAME | dm-volumes\n");
    return 2;
}
