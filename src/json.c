/*
 * json.c: a reader of JSON as RFC 8259 defines it, and nothing beyond: no comments, no single
 * quotes, no trailing comma. cryptsetup writes the metadata of LUKS2 with json-c, which keeps
 * to the RFC, so a text that this reader refuses was not written by cryptsetup.
 */
#include "json.h"

#include <stdlib.h>
#include <string.h>

#define MAX_DEPTH 32            /* the metadata of LUKS2 nests five deep */

struct reader {
    const char *p, *end;
    const char *err;
};

static struct json *value(struct reader *r, int depth);

static void blank(struct reader *r)
{
    while (r->p < r->end && (*r->p == ' ' || *r->p == '\t' || *r->p == '\n' || *r->p == '\r'))
        r->p++;
}

static struct json *fail(struct reader *r, const char *why, struct json *j)
{
    if (!r->err)
        r->err = why;
    json_free(j);
    return NULL;
}

static struct json *node(struct reader *r, enum json_type type)
{
    struct json *j = calloc(1, sizeof *j);

    if (!j)
        return fail(r, "no memory", NULL);
    j->type = type;
    return j;
}

static int hex4(struct reader *r, unsigned *v)
{
    int i;

    if (r->end - r->p < 4)
        return -1;
    for (*v = 0, i = 0; i < 4; i++, r->p++) {
        char c = *r->p;

        if (c >= '0' && c <= '9')      *v = *v << 4 | (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') *v = *v << 4 | (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') *v = *v << 4 | (unsigned)(c - 'A' + 10);
        else return -1;
    }
    return 0;
}

/* A string, from behind its opening quote. An escape never grows, so the text fits the bytes
   of its source. */
static char *string(struct reader *r, size_t *len)
{
    char *out = malloc((size_t)(r->end - r->p) + 1), *o = out;

    if (!out) {
        fail(r, "no memory", NULL);
        return NULL;
    }
    for (;;) {
        unsigned char c;

        if (r->p == r->end)
            goto bad;
        c = (unsigned char)*r->p++;
        if (c == '"')
            break;
        if (c < 0x20)
            goto bad;
        if (c != '\\') {
            *o++ = (char)c;
            continue;
        }
        if (r->p == r->end)
            goto bad;
        switch (*r->p++) {
        case '"': *o++ = '"'; break;
        case '\\': *o++ = '\\'; break;
        case '/': *o++ = '/'; break;
        case 'b': *o++ = '\b'; break;
        case 'f': *o++ = '\f'; break;
        case 'n': *o++ = '\n'; break;
        case 'r': *o++ = '\r'; break;
        case 't': *o++ = '\t'; break;
        case 'u': {
            unsigned u, low;

            if (hex4(r, &u))
                goto bad;
            if (u >= 0xd800 && u <= 0xdbff) {           /* the first half of a pair */
                if (r->end - r->p < 6 || r->p[0] != '\\' || r->p[1] != 'u')
                    goto bad;
                r->p += 2;
                if (hex4(r, &low) || low < 0xdc00 || low > 0xdfff)
                    goto bad;
                u = 0x10000 + ((u - 0xd800) << 10) + (low - 0xdc00);
            } else if (u >= 0xdc00 && u <= 0xdfff) {
                goto bad;
            }
            if (u < 0x80) {
                *o++ = (char)u;
            } else if (u < 0x800) {
                *o++ = (char)(0xc0 | u >> 6);
                *o++ = (char)(0x80 | (u & 0x3f));
            } else if (u < 0x10000) {
                *o++ = (char)(0xe0 | u >> 12);
                *o++ = (char)(0x80 | (u >> 6 & 0x3f));
                *o++ = (char)(0x80 | (u & 0x3f));
            } else {
                *o++ = (char)(0xf0 | u >> 18);
                *o++ = (char)(0x80 | (u >> 12 & 0x3f));
                *o++ = (char)(0x80 | (u >> 6 & 0x3f));
                *o++ = (char)(0x80 | (u & 0x3f));
            }
            break;
        }
        default:
            goto bad;
        }
    }
    *o = 0;
    *len = (size_t)(o - out);
    return out;
bad:
    free(out);
    fail(r, "a string that does not end or has a character it must not have", NULL);
    return NULL;
}

static struct json *number(struct reader *r)
{
    const char *start = r->p;
    struct json *j;

    if (r->p < r->end && *r->p == '-')
        r->p++;
    if (r->p == r->end || *r->p < '0' || *r->p > '9')
        return fail(r, "a number without digits", NULL);
    if (*r->p == '0')
        r->p++;
    else
        while (r->p < r->end && *r->p >= '0' && *r->p <= '9')
            r->p++;
    if (r->p < r->end && *r->p == '.') {
        r->p++;
        if (r->p == r->end || *r->p < '0' || *r->p > '9')
            return fail(r, "a number that ends at its point", NULL);
        while (r->p < r->end && *r->p >= '0' && *r->p <= '9')
            r->p++;
    }
    if (r->p < r->end && (*r->p == 'e' || *r->p == 'E')) {
        r->p++;
        if (r->p < r->end && (*r->p == '+' || *r->p == '-'))
            r->p++;
        if (r->p == r->end || *r->p < '0' || *r->p > '9')
            return fail(r, "a number that ends at its exponent", NULL);
        while (r->p < r->end && *r->p >= '0' && *r->p <= '9')
            r->p++;
    }
    if (!(j = node(r, JSON_NUMBER)))
        return NULL;
    j->len = (size_t)(r->p - start);
    if (!(j->text = strndup(start, j->len)))
        return fail(r, "no memory", j);
    return j;
}

static struct json *word(struct reader *r, const char *w, enum json_type type)
{
    size_t n = strlen(w);

    if ((size_t)(r->end - r->p) < n || memcmp(r->p, w, n))
        return fail(r, "a word that is none of true, false and null", NULL);
    r->p += n;
    return node(r, type);
}

/* An array or an object, from behind its opening bracket. */
static struct json *members(struct reader *r, int depth, enum json_type type)
{
    struct json *j = node(r, type), **link, *m;
    char close = type == JSON_ARRAY ? ']' : '}';

    if (!j)
        return NULL;
    link = &j->first;
    blank(r);
    if (r->p < r->end && *r->p == close) {
        r->p++;
        return j;
    }
    for (;;) {
        char *name = NULL;
        size_t namelen;

        blank(r);
        if (type == JSON_OBJECT) {
            if (r->p == r->end || *r->p++ != '"')
                return fail(r, "a member without a name", j);
            if (!(name = string(r, &namelen)))
                return fail(r, NULL, j);
            blank(r);
            if (strlen(name) != namelen || r->p == r->end || *r->p++ != ':') {
                free(name);
                return fail(r, "a name without a value", j);
            }
        }
        if (!(m = value(r, depth + 1))) {
            free(name);
            return fail(r, NULL, j);
        }
        m->name = name;
        *link = m;
        link = &m->next;
        blank(r);
        if (r->p < r->end && *r->p == ',') {
            r->p++;
            continue;
        }
        if (r->p < r->end && *r->p == close) {
            r->p++;
            return j;
        }
        return fail(r, "an array or an object that does not end", j);
    }
}

static struct json *value(struct reader *r, int depth)
{
    struct json *j;

    if (depth > MAX_DEPTH)
        return fail(r, "nested deeper than any metadata of LUKS2", NULL);
    blank(r);
    if (r->p == r->end)
        return fail(r, "the text ends where a value is expected", NULL);
    switch (*r->p) {
    case '{': r->p++; return members(r, depth, JSON_OBJECT);
    case '[': r->p++; return members(r, depth, JSON_ARRAY);
    case '"':
        r->p++;
        if (!(j = node(r, JSON_STRING)))
            return NULL;
        if (!(j->text = string(r, &j->len)))
            return fail(r, NULL, j);
        return j;
    case 't': return word(r, "true", JSON_TRUE);
    case 'f': return word(r, "false", JSON_FALSE);
    case 'n': return word(r, "null", JSON_NULL);
    default:  return number(r);
    }
}

struct json *json_parse(const char *text, size_t len, const char **err)
{
    struct reader r = { text, text + len, NULL };
    struct json *j = value(&r, 0);

    if (j) {
        blank(&r);
        if (r.p != r.end)
            j = fail(&r, "something follows the value", j);
    }
    *err = r.err;
    return j;
}

/* Elements are freed in a loop, so only the depth of the nesting uses the stack. */
void json_free(struct json *j)
{
    while (j) {
        struct json *next = j->next;

        json_free(j->first);
        free(j->name);
        free(j->text);
        free(j);
        j = next;
    }
}

const struct json *json_member(const struct json *object, const char *name)
{
    const struct json *m, *found = NULL;

    if (!object || object->type != JSON_OBJECT)
        return NULL;
    for (m = object->first; m; m = m->next)
        if (!strcmp(m->name, name))
            found = m;
    return found;
}

const char *json_string(const struct json *j)
{
    return j && j->type == JSON_STRING && strlen(j->text) == j->len ? j->text : NULL;
}

int json_u64(const struct json *j, uint64_t *value)
{
    uint64_t v = 0;
    size_t i;

    if (!j || (j->type != JSON_NUMBER && j->type != JSON_STRING) || !j->len)
        return -1;
    for (i = 0; i < j->len; i++) {
        unsigned d = (unsigned)(j->text[i] - '0');

        if (j->text[i] < '0' || j->text[i] > '9' || v > (UINT64_MAX - d) / 10)
            return -1;
        v = v * 10 + d;
    }
    *value = v;
    return 0;
}
