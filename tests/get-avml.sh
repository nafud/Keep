#!/bin/bash
# get-avml.sh FILE : fetch the release binary of Microsoft AVML for the checks of Keep.
#
#   tests/get-avml.sh work/avml
#
# Keep takes its memory image by itself. The checks hold its images against AVML, the tool that
# an examiner would otherwise use: unit-check.sh has AVML convert the compressed image of Keep,
# and compat-check.sh compares the image of Keep with the one that AVML takes of the same
# machine. AVML is no part of Keep and is passed on with nothing.
#
# The binary is the one of release 0.21.0. It is written to FILE only when its SHA-256 equals
# the value below, and a FILE that has that value already is not fetched again.
# Exit status 0 when FILE is that binary, 2 for a wrong call, else 1. Needs curl and sha256sum.
set -u
AVML_URL=https://github.com/microsoft/avml/releases/download/v0.21.0/avml
AVML_SHA=e75597dcdcaaa8475fdc61643effb050f72aaa9cff677c7271386a9781bf4460
[ $# -eq 1 ] && [ -n "$1" ] || { printf 'usage: get-avml.sh FILE\n' >&2; exit 2; }
F=$1
is_pinned() { [ -f "$1" ] && [ "$(sha256sum < "$1" | cut -d' ' -f1)" = "$AVML_SHA" ]; }
if ! is_pinned "$F"; then
    # a transfer that the server ends in the middle is begun again as well (curl 7.71 and later)
    curl -s -S -L --fail --retry 3 --retry-all-errors -o "$F.part" "$AVML_URL" || { rm -f "$F.part"; printf 'get-avml.sh: cannot fetch %s\n' "$AVML_URL" >&2; exit 1; }
    is_pinned "$F.part" || { rm -f "$F.part"; printf 'get-avml.sh: what %s gave has not the pinned SHA-256, and is not used\n' "$AVML_URL" >&2; exit 1; }
    mv "$F.part" "$F" || exit 1
fi
chmod 755 "$F" || exit 1
printf 'avml: SHA-256 equals the pinned value, %s\n' "$("$F" --version 2>/dev/null | head -n 1)"
