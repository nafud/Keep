/*
 * json.h: a reader of JSON (RFC 8259), for the metadata of a LUKS2 header.
 *
 * The text becomes a tree. A value of an object is found by its name, and of two members with
 * one name the later counts, as in json-c, which cryptsetup reads the metadata with.
 */
#ifndef KEEP_JSON_H
#define KEEP_JSON_H

#include <stddef.h>
#include <stdint.h>

enum json_type { JSON_NULL, JSON_FALSE, JSON_TRUE, JSON_NUMBER, JSON_STRING, JSON_ARRAY, JSON_OBJECT };

struct json {
    enum json_type type;
    char *name;                 /* of a member of an object, else NULL */
    char *text;                 /* a string without its escapes, or a number as it is written */
    size_t len;                 /* bytes of text: a string may hold a zero byte */
    struct json *first;         /* the first member or element */
    struct json *next;          /* the one after this in its object or array */
};

/* The tree of the text, or NULL with *err set to what is wrong with it. */
struct json *json_parse(const char *text, size_t len, const char **err);
void json_free(struct json *j);

const struct json *json_member(const struct json *object, const char *name);
/* The text of a string without a zero byte inside, or NULL for anything else. */
const char *json_string(const struct json *j);
/* A number without sign, fraction or exponent, or a string of decimal digits, which is how
   cryptsetup writes a 64-bit number. Returns 0, or -1 for anything else. */
int json_u64(const struct json *j, uint64_t *value);

#endif
