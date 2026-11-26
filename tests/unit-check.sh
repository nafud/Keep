#!/bin/bash
# unit-check.sh [-a] : the parts of the C program of Keep, each against an independent source.
#
#   tests/unit-check.sh        run what this machine can run, a missing program is a SKIP
#   tests/unit-check.sh -a     as the pipeline runs it: a SKIP counts as a failure
#
# It builds tests/keep-unit twice, statically against musl and against the system's C library
# with the address and undefined-behaviour sanitizers, and runs every check with both.
#
#   build      both builds with -Werror
#   hashes     the examples of the standards, then SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512
#              and PBKDF2 against Python's hashlib, on messages of every length up to 300 bytes
#              and some longer ones: with the SHA instructions of the processor where it has
#              them, and without them
#   json       texts that RFC 8259 allows and texts that it does not, and a LUKS2 metadata text
#              with one byte changed at a time, against Python's json module
#   scanner    the search of memory with the sanitizers, on a fixture with the schedules of
#              known keys in its four formats, cut short and damaged: the same schedules,
#              messages and status as the scanner gives that is built as the program links it
#   options    the command line of "keep", with both builds of the program: a wrong option, an
#              option without its value, a command of an earlier version and options that do
#              not go together end with status 2 and the usage, -h names every option, and
#              "keep -s DUMP" writes the list of the scanner into keys/ of its folder, shows
#              no key and ends with the status of the search. Without a header it proves
#              nothing and keeps the pairs of schedules that lie as the kernel keeps the two
#              keys of a volume, as candidates
#   screen     what a run prints: on a pseudo-terminal the titles bold, the labels cyan and
#              the verdicts in their colours, with no other escape sequence, and a line of
#              progress that is written over. None of it with -n, without TERM or with
#              TERM=dumb, and no colour with NO_COLOR. Through a pipe no escape byte and no
#              carriage return, in triage.txt the lines of the screen, no line of more than 80
#              columns but for a word that is longer, and a control character in the name of
#              a file as a space. A line that is broken parts no number from the word behind
#              it and leaves no word alone in its last line
#   kernel     the two answers of device-mapper, laid out as the kernel lays them out, before
#              and from Linux 4.13, and then with bytes changed and ends cut off 1600 times:
#              read or refused, never a fault. Then the volumes among tables as cryptsetup
#              builds them: one device, LUKS2 with integrity on its dm-integrity device, a
#              volume in re-encryption with its helper devices, one interrupted in it, and
#              the same with bytes changed
#   image      the memory image, from texts like /proc/iomem and cores like /proc/kcore that
#              are written here with the memory they stand for: the LiME and the raw image
#              must be the files that Python writes from the definitions of the two formats,
#              with the SHA-256 of hashlib. An image is written with direct writes, which
#              pass the page cache: ranges that begin and end inside a block of the file are
#              cases, the file of an image must have no page in the cache but its last, and
#              on a ramfs, which has no such writes, the files must be the same (root, or
#              sudo without a password). The compressed image is read back by a decoder
#              that is written here from the two documents of Snappy: its blocks must be
#              those of AVML, each chunk must have its checksum, and the memory must be the
#              same. With AVML=/path/to/avml that program converts the compressed image to a
#              LiME image and the LiME image to a raw one, which must be the files that
#              Python writes. Streams of zeros, of random bytes and of text that repeats at
#              every distance are decoded as well. RAM that a driver added, a range that two segments
#              offer, memory that the core offers twice, a range that reaches beyond its
#              segment, a stretch that cannot be read and a file that cannot be written. What
#              cannot be placed is refused, and cores with changed bytes give no fault. The
#              image of the fixture of the scanner gives the schedules of that fixture
#   system     the mount that holds a path, what a volume carries by a tree like /sys with
#              logical volumes on it, the file systems that encrypt by themselves, the
#              lockdown mode, the variable SecureBoot, the name of the system and the names of
#              a host or a mapping for the screen and for a file, each on files written here
#   headers    LUKS1 and LUKS2 headers that cryptsetup makes from keys drawn here: the copy of
#              the header must equal the file of "cryptsetup luksHeaderBackup" byte for byte,
#              and a key must be proven exactly where "cryptsetup open --test-passphrase"
#              accepts it. Also with erased keyslots, with a hash that is not computed here,
#              with a damaged first copy, which must be read from the second and left as it
#              is, with files that end early, and with a header in re-encryption, whose two
#              keys must each give their own digest, as hashlib computes it
#   dump       "keep -s DUMP FILE..." on an image with the schedules of the keys of those
#              headers: each key must be proven and written as it is, also for a header with
#              erased keyslots, for one in re-encryption with its two keys, for a cipher with
#              one key, for headers inside the image of a disk, and for two schedules that do
#              not lie as the kernel keeps them. A header of another key, a file without a
#              header and a damaged header must be named as such. The verdicts and the names
#              of the keys must be those of vkverify.py on the same schedules and headers.
#              A dump that holds a LUKS1 header at the start of a page and the digests of a
#              LUKS2 header inside other bytes, as the memory of a machine can, must give
#              both keys with no file at all, each copy once, and not for a header that is
#              among the files
#
# It needs neither root nor device-mapper, and writes only below a temporary directory, which
# is removed at the end. The test keys are drawn from /dev/urandom there and are never printed.
# Programs: make, musl-gcc, cc with the sanitizer libraries, python3 and cryptsetup, and for the
# check against AVML its release binary, named in AVML.
# Ends with "RESULT: PASS" and status 0, or with "RESULT: FAIL" and status 1.
set -u
umask 077
export LC_ALL=C
usage() {
    local line
    while IFS= read -r line; do
        case $line in '#!'*) ;; '#'*) printf '%s\n' "$line" ;; *) break ;; esac
    done < "$0"
}
ALL=0
case ${1:-} in
    -a) ALL=1 ;;
    -h|--help) usage; exit 0 ;;
    '') ;;
    *) printf 'usage: unit-check.sh [-a]\n' >&2; exit 2 ;;
esac
R=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d) || exit 1
trap '[ -z "${RAMFS:-}" ] || ${SUDO:-} umount "$RAMFS"; [ -z "${LOOPDEV:-}" ] || ${SUDO:-} losetup -d "$LOOPDEV"; rm -rf "$T"' EXIT
cd "$R" || exit 1

FAILED=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILED=1; }
skip() { printf 'SKIP  %s\n' "$1"; [ "$ALL" = 0 ] || FAILED=1; }
# check NAME COMMAND... : the output of the command is shown only when it fails
check() {
    local name=$1; shift
    if "$@" > "$T/out.txt" 2>&1; then pass "$name"; else fail "$name"; sed 's/^/      /' "$T/out.txt"; fi
}
finish() {
    if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; exit 0; fi
    echo "RESULT: FAIL"; exit 1
}
have() { command -v "$1" > /dev/null; }

# ---- build ---------------------------------------------------------------------------------------
UNITS=()
if have make && have musl-gcc; then
    check "build: tests/keep-unit, static against musl, -Werror" make -s tests/keep-unit
    [ -x tests/keep-unit ] && UNITS+=(tests/keep-unit)
else
    skip "build: tests/keep-unit (make and musl-gcc, the package musl-tools)"
fi
if have make && have cc; then
    check "build: tests/keep-unit-san, with the sanitizers, -Werror" make -s tests/keep-unit-san
    [ -x tests/keep-unit-san ] && UNITS+=(tests/keep-unit-san)
else
    skip "build: tests/keep-unit-san (make and cc)"
fi
[ "${#UNITS[@]}" -gt 0 ] || finish
have python3 || { skip "everything else (python3)"; finish; }

# ---- scanner -------------------------------------------------------------------------------------
# keep links the search of kcore-keyscan.c. In keep-san it is built without the sanitizers,
# because that program reads the whole memory of a machine, so the search runs with them here,
# beside tests/keyscan, which is the scanner as keep links it: static, against musl.
scanner_same() {
    local f opt a b r=0
    head -c 64 /dev/urandom > "$T/scan.vk"
    for f in raw elf lime avml; do
        python3 -I tests/make-schedule-fixture.py --format "$f" --size 8 "$T/fx.$f" "$T/scan.vk" > /dev/null || return 1
    done
    head -c 3000000 "$T/fx.avml" > "$T/fx.cut"
    cp "$T/fx.avml" "$T/fx.bad" && printf 'XXXX' | dd of="$T/fx.bad" bs=1 seek=100000 conv=notrunc status=none
    for f in raw elf lime avml cut bad missing; do
        for opt in "" "-r" "-s 16"; do
            # shellcheck disable=SC2086
            a=$(tests/keyscan $opt "$T/fx.$f" 2> "$T/e1" | sha256sum; echo "status ${PIPESTATUS[0]}")
            # shellcheck disable=SC2086
            b=$(tests/keyscan-san $opt "$T/fx.$f" 2> "$T/e2" | sha256sum; echo "status ${PIPESTATUS[0]}")
            [ "$a" = "$b" ] && diff <(sed 's/[0-9.]* seconds//' "$T/e1") <(sed 's/[0-9.]* seconds//' "$T/e2") > /dev/null ||
                { echo "$f $opt: the scanner and the scanner with the sanitizers differ"; tail -n 5 "$T/e2"; r=1; }
        done
    done
    # both halves of the key are among the schedules of the image
    tests/keyscan "$T/fx.lime" 2> /dev/null > "$T/scan.txt"
    for f in 0 32; do
        grep -q " key $(od -An -v -tx1 -j "$f" -N 32 "$T/scan.vk" | tr -d ' \n')\$" "$T/scan.txt" || { echo "a half of the key is not found"; r=1; }
    done
    rm -f "$T/scan.txt" "$T/scan.vk"
    return $r
}

# An image that ends inside a range or a segment, a range that states more memory than the
# file holds, and an ELF header that is cut: each is named with status 1, and none is searched
# without end. Before 1.3 the first two ended with status 0, what was missing counted as zeros,
# and the third ran for as long as its range was. A compressed image that is cut in its first
# range is still named as one. A list that cannot be written ends with status 1 too. Two
# segments of a core that state no physical address, each with another key at the same
# place, give both keys.
scanner_ends() {
    local s=$1 f rc r=0
    head -c 3000000 "$T/fx.lime" > "$T/fx.cutl"; head -c 3000000 "$T/fx.elf" > "$T/fx.cute"; head -c 6 "$T/fx.elf" > "$T/fx.six"
    head -c 300000 "$T/fx.avml" > "$T/fx.cuta"
    python3 -I - "$T" <<'EOF' || return 1
import struct, sys
t = sys.argv[1]
open(t + "/fx.huge", "wb").write(struct.pack("<IIQQQ", 0x4C694D45, 1, 0, (1 << 62) - 1, 0) + bytes(4096))
# two schedules of AES-256 of the fixture, each in a segment of its own at 0x100, both without an address
raw = open(t + "/fx.raw", "rb").read()
places = []
for line in open(t + "/fx.list"):
    w = line.split()
    if w[0] == "AES-256" and w[-1] not in [k for _, k in places]:
        places.append((int(w[2], 16), w[-1]))
assert len(places) >= 2, places
segs = [bytes(0x100) + raw[at:at + 240] + bytes(4096 - 0x100 - 240) for at, _ in places[:2]]
ehdr = b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HHIQQQIHHHHHH", 4, 62, 1, 0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
phdrs = b"".join(struct.pack("<IIQQQQQQ", 1, 4, 4096 * (i + 1), 0xffff800000000000 + (i << 20), 0, 4096, 4096, 4096) for i in range(2))
open(t + "/fx.zero", "wb").write((ehdr + phdrs).ljust(4096, b"\0") + segs[0] + segs[1])
open(t + "/fx.zero.want", "w").write("".join(sorted(k + "\n" for _, k in places[:2])))
EOF
    for f in cutl cute huge six cuta; do
        timeout 60 "$s" "$T/fx.$f" > /dev/null 2> "$T/e.$f"; rc=$?
        [ "$rc" = 1 ] || { echo "fx.$f: status $rc"; tail -n 2 "$T/e.$f"; r=1; }
    done
    grep -q 'ends early at file offset 3000000: the file ends inside a range\.' "$T/e.cutl" || { echo "a LiME image that is cut:"; cat "$T/e.cutl"; r=1; }
    grep -q 'ends early at file offset 3000000: the file ends inside a segment\.' "$T/e.cute" || { echo "an ELF core that is cut:"; cat "$T/e.cute"; r=1; }
    grep -q 'the file ends inside a range\.' "$T/e.huge" || { echo "a range of 2^62 bytes:"; cat "$T/e.huge"; r=1; }
    grep -q 'ends inside its ELF header$' "$T/e.six" || { echo "an ELF header that is cut:"; cat "$T/e.six"; r=1; }
    grep -q ', AVML compressed, 0 segments, ' "$T/e.cuta" || { echo "a compressed image that is cut in its first range:"; cat "$T/e.cuta"; r=1; }
    "$s" "$T/fx.raw" > /dev/full 2> "$T/e.full"; rc=$?
    [ "$rc" = 1 ] && grep -q 'the list of the schedules could not be written to its end$' "$T/e.full" ||
        { echo "a list that cannot be written: status $rc"; cat "$T/e.full"; r=1; }
    "$s" "$T/fx.zero" 2> "$T/e.zero" | sed 's/.* key //' | sort | cmp -s - "$T/fx.zero.want" ||
        { echo "two keys at one place of two segments without an address:"; "$s" "$T/fx.zero" 2>&1 | sed 's/ key .*//'; r=1; }
    return $r
}
# A page of /proc/kcore that cannot be read. The kernel then fails the whole read that holds
# the page (read_kcore_iter), so the pages before it in that read are asked for one by one,
# and only the page itself is zeros. Here a library that stands before the C library makes a
# read fail in that way for one page of the raw fixture: the schedules must be those of the
# fixture all the same, with 4096 bytes named as not read. Before 1.3 every page of that read
# up to the unreadable one was zeros.
scanner_page() {
    local bad
    cat > "$T/shim.c" <<'EOF'
/* pread fails as a whole where it holds the byte KEEP_SHIM_BAD of the file KEEP_SHIM_FILE */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
static ssize_t shim(int fd, void *buf, size_t n, off_t off)
{
    static ssize_t (*real)(int, void *, size_t, off_t);
    const char *file = getenv("KEEP_SHIM_FILE"), *at = getenv("KEEP_SHIM_BAD");
    struct stat a, b;

    if (!real)
        real = (ssize_t (*)(int, void *, size_t, off_t))dlsym(RTLD_NEXT, "pread64");
    if (file && at && !fstat(fd, &a) && !stat(file, &b) && a.st_ino == b.st_ino && a.st_dev == b.st_dev) {
        off_t bad = (off_t)strtoull(at, NULL, 10);

        if (off <= bad && bad < off + (off_t)n) {
            errno = EFAULT;
            return -1;
        }
    }
    return real(fd, buf, n, off);
}
ssize_t pread(int fd, void *buf, size_t n, off_t off) { return shim(fd, buf, n, off); }
ssize_t pread64(int fd, void *buf, size_t n, off_t off) { return shim(fd, buf, n, off); }
/* the names that a C library with fortified reads gives the call */
ssize_t __pread_chk(int fd, void *buf, size_t n, off_t off, size_t room) { (void)room; return shim(fd, buf, n, off); }
ssize_t __pread64_chk(int fd, void *buf, size_t n, off_t off, size_t room) { (void)room; return shim(fd, buf, n, off); }
EOF
    cc -shared -fPIC -O1 -o "$T/shim.so" "$T/shim.c" -ldl && cc -O2 -o "$T/keyscan-dyn" kcore-keyscan.c || { echo "the library or the scanner is not built"; return 1; }
    # a page late in a read of 1 MiB that holds schedules, and that holds none itself
    bad=$(python3 -I -c 'import sys
hits = [int(l.split()[2], 16) for l in open(sys.argv[1])]
for chunk in sorted({h >> 20 for h in hits}, reverse=True):
    for page in range((chunk << 20) + (1 << 20) - 4096, chunk << 20, -4096):
        if all(h + 240 <= page - 4096 or h >= page + 8192 for h in hits) and any(chunk << 20 <= h < page for h in hits):
            print(page + 100); sys.exit(0)
sys.exit(1)' "$T/fx.list") || { echo "the fixture has no page for this"; return 1; }
    LD_PRELOAD="$T/shim.so" KEEP_SHIM_FILE="$T/fx.raw" KEEP_SHIM_BAD="$bad" "$T/keyscan-dyn" "$T/fx.raw" > "$T/fx.shim" 2> "$T/e.shim" ||
        { echo "the search with a page that cannot be read: status $?"; cat "$T/e.shim"; return 1; }
    cmp -s "$T/fx.shim" "$T/fx.list" || { echo "a page that cannot be read at $bad costs schedules:"; diff "$T/fx.list" "$T/fx.shim" | sed 's/ key .*//'; cat "$T/e.shim"; return 1; }
    grep -q '^kcore-keyscan: 4096 bytes could not be read and count as zeros$' "$T/e.shim" || { echo "the page is not named:"; cat "$T/e.shim"; return 1; }
}

# A search that the program ends before the end of the image, as a run that was asked to end
# ends it: after the first read, in the middle and near the end, for each format.
# The schedules must be those of the whole search that lie before the place where it ended, in
# their order, the search must name that place, and its status must be 1. A search that is
# not ended gives the list of the scanner alone.
scanner_ended() {
    local u=$1 f r=0
    for f in raw elf lime avml; do
        tests/keyscan "$T/fx.$f" > "$T/whole.$f" 2> /dev/null || { echo "the scanner on fx.$f: status $?"; return 1; }
        "$u" scan-until "$T/fx.$f" 0 > "$T/until.$f" 2> "$T/until.err" && cmp -s "$T/until.$f" "$T/whole.$f" ||
            { echo "fx.$f, a search that is not ended: another list than that of the scanner"; cat "$T/until.err"; r=1; }
    done
    python3 -I - "$u" "$T" <<'EOF' || r=1
import re, subprocess, sys
unit, t = sys.argv[1:3]
bad = 0
for fmt in ("raw", "elf", "lime", "avml"):
    whole = open("%s/whole.%s" % (t, fmt)).read().splitlines()
    for after in (1, 3 << 20, (6 << 20) + 5):
        p = subprocess.run([unit, "scan-until", "%s/fx.%s" % (t, fmt), str(after)], capture_output=True, text=True)
        said = p.stderr.splitlines()
        m = [re.fullmatch(r"kcore-keyscan: the search was interrupted, at file offset (\d+): what lies behind that place is not searched\.", l) for l in said]
        read = [re.fullmatch(r"read (\d+) bytes of memory, up to 0x([0-9a-f]+)", l) for l in said]
        if p.returncode != 1 or not any(m) or not any(read):
            bad += 1; print(fmt, "ended after", after, ": status", p.returncode, said); continue
        n, end = [(int(x.group(1)), int(x.group(2), 16)) for x in read if x][0]
        got = p.stdout.splitlines()
        # every schedule that lies whole in the memory that was read, and no other
        want = [l for l in whole if int(l.split()[2], 16) + (176 if l.startswith("AES-128") else 240) <= end]
        if got != want or not after <= n < after + (2 << 20):
            bad += 1; print(fmt, "ended after", after, ":", len(got), "schedules,", len(want), "lie in the", n, "bytes that were read up to", hex(end))
sys.exit(1 if bad else 0)
EOF
    return $r
}

# ---- options -------------------------------------------------------------------------------------
# "keep" takes what a run does as options and asks nothing. The search of a dump needs no root.
# start PROGRAM [ARGUMENT...] : one start in $T/opt, with the umask of an ordinary shell and no
# input, the screen to $T/opt.txt.
start() {
    local k=$1; shift
    ( cd "$T/opt" && umask 022 && "$k" "$@" > "$T/opt.txt" 2>&1 < /dev/null )
}
options() {
    local k=$1 r=0 rc d open key o
    case $k in /*) ;; *) k=$R/$k ;; esac
    rm -rf "$T/opt"; mkdir "$T/opt" "$T/opt/out" && cp "$T/fx.lime" "$T/fx.cut" "$T/opt/" || return 1
    said() { grep -q -- "$1" "$T/opt.txt" || { echo "$2: the screen lacks: $1"; r=1; }; }
    refused() {  # refused WHAT ARGUMENT... : status 2, the usage, and nothing written
        local what=$1; shift
        start "$k" "$@"; rc=$?
        [ "$rc" = 2 ] || { echo "$what: status $rc, expected 2"; r=1; }
        said '^usage: keep ' "$what"
        [ -z "$(ls "$T/opt/out")" ] && ! ls -d "$T"/opt/triage_* "$T"/opt/scan_* > /dev/null 2>&1 || { echo "$what: something was written"; r=1; }
    }
    refused "an option that does not exist" -x
    refused "an argument without an option" fx.lime
    refused "-s without a dump" -s
    refused "-d without a directory" -s fx.lime -d
    refused "-b without a number" -b
    refused "-b that is no number" -b many
    refused "-b 0" -b 0
    refused "-b with -s" -s fx.lime -b 3
    refused "-f without -m" -f raw
    refused "-f without a format" -m -f
    refused "a format that does not exist" -m -f elf
    refused "-m with -s" -s fx.lime -m
    refused "-F without -m" -F
    refused "-F with -f" -m -f lime -F
    refused "-F with -s" -s fx.lime -F
    refused "the command triage of an earlier version" triage
    refused "the command scan of an earlier version" scan fx.lime

    start "$k" -h; rc=$?
    [ "$rc" = 0 ] || { echo "-h: status $rc"; r=1; }
    for o in '-m ' '-f FORMAT' '-F ' '-s DUMP' '-d DIR' '-b N' '-n ' '-h ' '-V '; do said "^ *$o" "-h"; done
    said 'No key is printed' "-h"
    [ -z "$(awk 'length($0) > 80' "$T/opt.txt")" ] || { echo "-h: a line of more than 80 columns"; r=1; }
    for o in 'captured and proven' 'captured, in use' 'captured, not proven' 'needs a memory read' 'live copy only' 'no key needed'; do said "^    $o  " "-h"; done
    start "$k" -V; rc=$?
    [ "$rc" = 0 ] && grep -q '^keep [0-9][^ ]* ([0-9-]*)$' "$T/opt.txt" || { echo "-V: status $rc, $(cat "$T/opt.txt")"; r=1; }

    # the search of a dump: the list in keys/, what the scanner said on the screen, no key there
    start "$k" -s fx.lime -d out; rc=$?
    d=$(ls -d "$T"/opt/out/scan_fx.lime_* 2>/dev/null | head -n 1)
    [ "$rc" = 0 ] && [ -d "$d" ] || { echo "the search of a dump ended with status $rc"; cat "$T/opt.txt"; return 1; }
    said "^  dump         $T/opt/fx.lime\$" "dump"
    said "^  output       $d\$" "dump"
    said '^  format       LiME, [0-9]* ranges of memory, [0-9.]* MiB$' "dump"
    said '^  search       [0-9]* AES schedules, [0-9]* different keys, [0-9]* s$' "dump"
    said '^  keys         2 of AES-128, [0-9]* of AES-256, in keys/candidates.txt$' "dump"
    said '^  headers      none: no file with a LUKS header is given and the dump itself' "dump"
    # the fixture has one key with its two schedules as the kernel keeps them, and no header
    said '^  pair 1       keys/memory-pair-1.vk, 64 bytes, sha256 [0-9a-f]*$' "dump"
    said '^  schedules    tweak at 0x[0-9a-f]*, data at 0x[0-9a-f]*$' "dump"
    said '^  memory-pair-1  found in memory, not proven  [0-9a-f]*$' "dump"
    [ "$(stat -c %s "$d/keys/memory-pair-1.vk" 2> /dev/null)" = 64 ] || { echo "the pair in memory is not kept as a key file of 64 bytes"; r=1; }
    grep -q '"memory_pairs": \[$' "$d/verdict.json" && grep -q '"verdict": "found in memory"' "$d/verdict.json" || { echo "the report does not name the pair in memory"; r=1; }
    ( cd "$d" && sha256sum -c --quiet manifest.sha256 ) > /dev/null 2>&1 || { echo "the manifest of the search does not verify"; r=1; }
    said '^keep: every file of this run is flushed to the destination$' "dump"
    tests/keyscan-san "$T/fx.lime" 2> /dev/null | cmp -s - "$d/keys/candidates.txt" || { echo "the candidate list is not that of the scanner"; r=1; }
    [ "$(wc -l < "$d/keys/candidates.txt")" = "$(sed -n 's/^  search  *\([0-9]*\) AES schedules.*/\1/p' "$T/opt.txt")" ] || { echo "the number of the schedules is not that of the list"; r=1; }
    # what the scanner said is in scan.txt, and the screen says it in its own lines
    grep -q '^kcore-keyscan [0-9.]*: .*/fx.lime, LiME, 2 segments, ' "$d/scan.txt" && grep -q '^kcore-keyscan: AES-128 schedules: 2 ' "$d/scan.txt" &&
        ! grep -q 'kcore-keyscan' "$T/opt.txt" || { echo "scan.txt lacks what the scanner said, or the screen has it"; r=1; }
    open=$(find "$d" -perm /077)
    [ -z "$open" ] || { echo "open to the group or to others: $open"; r=1; }
    while read -r key; do
        ! grep -q "$key" "$T/opt.txt" || { echo "a key is on the screen"; r=1; }
    done < <(sed 's/.* key //' "$d/keys/candidates.txt")
    ! grep -q -f <(sed 's/.* key //' "$d/keys/candidates.txt") "$d/triage.txt" "$d/verdict.json" "$d/scan.txt" "$d/manifest.sha256" || { echo "a key is in a file outside keys/"; r=1; }

    # without -d the folder is made in the directory of the start. An image that is cut: what
    # was found is kept, and the run ends with the status of the scanner.
    start "$k" -s fx.cut; rc=$?
    d=$(ls -d "$T"/opt/scan_fx.cut_* 2>/dev/null | head -n 1)
    [ "$rc" = 1 ] && [ -s "$d/keys/candidates.txt" ] || { echo "a cut image: status $rc, expected 1 and a list"; r=1; }

    # what cannot start writes nothing and ends with status 1
    start "$k" -s no-such-file -d out; rc=$?
    [ "$rc" = 1 ] || { echo "a dump that does not exist: status $rc"; r=1; }
    said '^keep: the memory dump no-such-file: ' "a dump that does not exist"
    start "$k" -s out -d out; rc=$?
    [ "$rc" = 1 ] || { echo "a directory as the dump: status $rc"; r=1; }
    said ' is not a file that can be read$' "a directory as the dump"
    start "$k" -s fx.lime -d no-such-dir; rc=$?
    [ "$rc" = 1 ] || { echo "a destination that does not exist: status $rc"; r=1; }
    start "$k" -s fx.lime -d fx.cut; rc=$?
    [ "$rc" = 1 ] || { echo "a file as the destination: status $rc"; r=1; }
    said ' is not a directory$' "a file as the destination"
    [ "$(ls "$T/opt/out" | wc -l)" = 1 ] || { echo "a run that could not start wrote something"; r=1; }
    if [ "$(id -u)" != 0 ]; then
        start "$k"; rc=$?
        [ "$rc" = 1 ] || { echo "the running system without root: status $rc"; r=1; }
        said '^keep: must run as root (sudo)$' "the running system without root"
        start "$k" -m -f raw -d out; rc=$?
        [ "$rc" = 1 ] || { echo "a memory image without root: status $rc"; r=1; }
        said '^keep: must run as root (sudo)$' "a memory image without root"
        chmod 500 "$T/opt/out"
        start "$k" -s fx.lime -d out; rc=$?
        chmod 700 "$T/opt/out"
        [ "$rc" = 1 ] || { echo "a destination that cannot be written to: status $rc"; r=1; }
        said "^keep: $T/opt/out is not writable\$" "a destination that cannot be written to"
    fi
    return $r
}
if have make && have musl-gcc && have cc; then
    check "build: keep, the program, static against musl, the same with the sanitizers, and the scanner alone both ways" make -s keep keep-san tests/keyscan tests/keyscan-san
    check "scanner: static and with the sanitizers it gives the same on four formats, a cut and a damaged image" scanner_same
    tests/keyscan "$T/fx.raw" > "$T/fx.list" 2> /dev/null
    for s in tests/keyscan tests/keyscan-san; do
        check "scanner: ${s##*/} names an image that ends early, a range beyond the file and a list that cannot be written with status 1, and keeps two keys at one place" scanner_ends "$s"
    done
    check "scanner: a page that cannot be read costs that page alone, and not the pages that were read with it" scanner_page
    for u in "${UNITS[@]}"; do
        check "scanner: a search that ${u##*/} ends gives the schedules up to that place in four formats, names the place and has status 1" scanner_ended "$u"
    done
    for k in keep keep-san; do
        check "options: $k refuses what does not go together, names its options with -h, searches a dump into keys/ and ends with the status of the search" options "$k"
    done
else
    skip "scanner and options: with the sanitizers (make, musl-gcc and cc)"
fi

# ---- hashes --------------------------------------------------------------------------------------
cat > "$T/hashes.py" <<'EOF'
import hashlib, os, subprocess, sys
unit, how, bad = sys.argv[1], sys.argv[2:], 0
def run(*a, data=None):
    return subprocess.run([unit, *how, *a], input=data, capture_output=True).stdout.decode().strip()
for name in ("sha1", "sha224", "sha256", "sha384", "sha512"):
    for n in list(range(0, 300)) + [1000, 4096, 65535, 65536, 65537, 1 << 20]:
        m = os.urandom(n)
        if run("hash", name, data=m) != hashlib.new(name, m).hexdigest():
            bad += 1; print("hash", name, "of", n, "bytes differs")
    # key and salt lengths around the block sizes, and the lengths of a LUKS digest
    for keylen, saltlen, it, outlen in ((1, 1, 1, 1), (32, 32, 1000, 20), (64, 32, 2000, 32), (64, 32, 777, 64),
                                        (200, 64, 300, 100), (129, 7, 50, 200), (0, 0, 3, 16), (64, 32, 60000, 32)):
        k, s = os.urandom(keylen), os.urandom(saltlen)
        if run("pbkdf2", name, k.hex(), s.hex(), str(it), str(outlen)) != hashlib.pbkdf2_hmac(name, k, s, it, outlen).hex():
            bad += 1; print("pbkdf2", name, keylen, saltlen, it, outlen, "differs")
sys.exit(1 if bad else 0)
EOF
for u in "${UNITS[@]}"; do
    check "hashes: ${u##*/} computes the examples of FIPS 180-4, RFC 4231 and RFC 6070" "$u" selftest
    check "hashes: ${u##*/} equals hashlib for five functions and PBKDF2 ($("$u" cpu))" python3 -I "$T/hashes.py" "$u"
    check "hashes: ${u##*/} equals hashlib for five functions and PBKDF2, computed without the SHA instructions" python3 -I "$T/hashes.py" "$u" plain
done

# ---- json ----------------------------------------------------------------------------------------
# Python's module reads more than the RFC allows in three places, which are left out of the
# comparison and tested by themselves: the words NaN and Infinity, a half of a surrogate pair
# alone, and any depth of nesting.
cat > "$T/json.py" <<'EOF'
import json, random, subprocess, sys
unit, bad = sys.argv[1], 0
REFUSED = object()
class Crash(Exception): pass
# Every string as its bytes, so that both sides compare whatever the bytes of the text are: the
# program writes a string as one \u00XX per byte, and Python reads the text as UTF-8 where
# bytes that are none stay what they are.
def as_bytes(v, enc):
    if isinstance(v, str): return v.encode(*enc)
    if isinstance(v, list): return [as_bytes(x, enc) for x in v]
    if isinstance(v, dict): return {as_bytes(k, enc): as_bytes(x, enc) for k, x in v.items()}
    return v
def ours(text):
    p = subprocess.run([unit, "json"], input=text, capture_output=True)
    if p.returncode not in (0, 1):
        raise Crash("status %d %s" % (p.returncode, p.stderr.decode(errors="replace")[-300:]))
    return REFUSED if p.returncode else as_bytes(json.loads(p.stdout.decode()), ("latin-1",))
def theirs(text):
    def no(_): raise ValueError
    try: return as_bytes(json.loads(text.decode("utf-8", "surrogateescape"), parse_constant=no), ("utf-8", "surrogateescape"))
    except (ValueError, RecursionError): return REFUSED
def same(text):
    global bad
    try:
        if ours(text) != theirs(text):
            bad += 1; print("differs on", text[:120])
    except Crash as e:
        bad += 1; print("crash on", text[:80], e)
def must(text, accepted):
    global bad
    try:
        if (ours(text) is not REFUSED) != accepted:
            bad += 1; print("must be", "read" if accepted else "refused", ":", text[:80])
    except Crash as e:
        bad += 1; print("crash on", text[:80], e)
valid = [b'{}', b'[]', b'""', b'0', b'-0', b'1.5e+10', b'-12.25E-3', b'true', b'false', b'null',
         b' [1, 2 ,3]\n', b'{"a":{"b":[{"c":null}]}}', b'"\\"\\\\\\/\\b\\f\\n\\r\\t"', b'"\\u00e9\\u20ac"',
         b'"\\ud83d\\ude00"', b'{"a":1,"a":2}', b'"\xc3\xa9 raw bytes"', b'[[[[[[[[[[1]]]]]]]]]]',
         b'{"keyslots":{"0":{"type":"luks2","key_size":64}},"config":{"json_size":"12288"}}']
invalid = [b'', b' ', b'{', b'}', b'[1,]', b'{"a":1,}', b'{a:1}', b"{'a':1}", b'[1 2]', b'01', b'1.', b'.5',
           b'+1', b'1e', b'"abc', b'"\n"', b'"\\x41"', b'"\\u12"', b'tru', b'nul', b'[1] 2', b'{"a"}',
           b'{"a":}', b'{"a" 1}', b'/* c */ 1', b'[1] // c', b'"a" "b"', b'\x00', b'{"a":1}\x00']
for t in valid: must(t, True)
for t in invalid: must(t, False)
for t in valid + invalid: same(t)
for t in (b'NaN', b'Infinity', b'-Infinity', b'[NaN]', b'"\\ud800"', b'"\\udc00"', b'"\\ud800\\u0041"'):
    must(t, False)
must(b'[' * 32 + b']' * 32, True)
must(b'[' * 34 + b']' * 34, False)
must(b'[' * 100000, False)
# the metadata of a LUKS2 header as cryptsetup lays them out, with one byte changed at a time
meta = json.dumps({"keyslots": {"0": {"type": "luks2", "key_size": 64, "af": {"type": "luks1", "stripes": 4000, "hash": "sha256"},
        "area": {"type": "raw", "offset": "32768", "size": "258048", "encryption": "aes-xts-plain64", "key_size": 64},
        "kdf": {"type": "argon2id", "time": 4, "memory": 1048576, "cpus": 4, "salt": "c2FsdA=="}}},
    "tokens": {}, "segments": {"0": {"type": "crypt", "offset": "16777216", "size": "dynamic", "iv_tweak": "0",
        "encryption": "aes-xts-plain64", "sector_size": 512}},
    "digests": {"0": {"type": "pbkdf2", "keyslots": ["0"], "segments": ["0"], "hash": "sha256", "iterations": 123456,
        "salt": "c2FsdA==", "digest": "ZGlnZXN0"}},
    "config": {"json_size": "12288", "keyslots_size": "16744448"}}, separators=(",", ":")).encode()
same(meta)
rnd = random.Random(1)
for _ in range(1500):
    b = bytearray(meta)
    for _ in range(rnd.choice((1, 1, 1, 2, 3))):
        i = rnd.randrange(len(b))
        how = rnd.randrange(4)
        if how == 0: b[i] = rnd.choice(b'{}[]",:\\ 0e.-tfn\x00\x1f\x7f\xff')
        elif how == 1: del b[i]
        elif how == 2: b.insert(i, rnd.choice(b'{}[]",:\\ 0e.-u'))
        else: del b[i:]
    t = bytes(b)
    if b"NaN" in t or b"Infinity" in t or b"\\ud" in t or b"\\uD" in t: continue
    same(t)
sys.exit(1 if bad else 0)
EOF
for u in "${UNITS[@]}"; do
    check "json: ${u##*/} reads and refuses what RFC 8259 says, as Python's json does" python3 -I "$T/json.py" "$u"
done

# ---- kernel --------------------------------------------------------------------------------------
# The two answers of device-mapper, laid out here as list_devices and retrieve_status of
# dm-ioctl.c lay them out, and then with bytes changed and with their ends cut off.
cat > "$T/kernel.py" <<'EOF'
import os, random, struct, subprocess, sys
unit, tmp, part, bad = sys.argv[1], sys.argv[2], sys.argv[3], 0
HEAD = 312                                      # sizeof(struct dm_ioctl)
def align(n): return (n + 7) & ~7
def encode(major, minor): return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)
def head(size, count=0, dev=0, name=b"", uuid=b""):
    return struct.pack("<3I7IQ128s129s7s", 4, 48, 0, size, HEAD, count, 0, 0, 0, 0, dev, name, uuid, b"")
def listing(devs, new=True):
    """devs: (name, major, minor). new: an event number and flags follow a name (Linux 4.13
    and later, two words), else one word, as before."""
    body = b""
    for i, (name, major, minor) in enumerate(devs):
        rec = struct.pack("<QI", encode(major, minor), 0) + name + b"\0"
        rec += b"\0" * (align(len(rec)) - len(rec)) + (b"\0" * 8 if new else b"\0" * 4)
        rec += b"\0" * (align(len(rec)) - len(rec))
        if i + 1 < len(devs): rec = rec[:8] + struct.pack("<I", len(rec)) + rec[12:]
        body += rec
    return head(HEAD + len(body)) + body if devs else head(305)
def table(name, uuid, major, minor, targets):
    body = b""
    for start, length, kind, params in targets:
        spec = struct.pack("<QQiI16s", start, length, 0, 0, kind) + params + b"\0"
        used = len(body) + len(spec)
        nxt = align(used)
        spec = spec[:20] + struct.pack("<I", nxt) + spec[24:]
        body += spec + b"\0" * (nxt - used)
    size = HEAD + len(body) if targets else 305
    return head(size, len(targets), encode(major, minor), name, uuid) + body
def run(kind, data):
    path = os.path.join(tmp, "answer.bin")
    open(path, "wb").write(data)
    p = subprocess.run([unit, "dm-answer", kind, path], capture_output=True)
    return p.returncode, p.stdout.decode("latin-1"), p.stderr.decode("latin-1")
def expect(what, kind, data, out, err=None):
    global bad
    rc, got, goterr = run(kind, data)
    if rc != 0 or got != out or (err is not None and err not in goterr):
        bad += 1; print(what, ": status", rc, "output", repr(got), repr(goterr[-200:]))
def refused(what, kind, data):
    global bad
    rc, got, goterr = run(kind, data)
    if rc != 1 or not got.startswith("refused: "):
        bad += 1; print(what, ": status", rc, "output", repr(got[:200]), repr(goterr[-300:]))

# ---- the volumes among tables, as cryptsetup builds them (volume.c)
def volumes(what, tables, want):
    """tables: answers of the kernel, one for each mapped device. want: the lines of keep-unit."""
    global bad
    paths = []
    for i, t in enumerate(tables):
        paths.append(os.path.join(tmp, "table%d.bin" % i))
        open(paths[-1], "wb").write(t)
    p = subprocess.run([unit, "volumes"] + paths, capture_output=True)
    got = p.stdout.decode("latin-1")
    if p.returncode != 0 or got != want:
        bad += 1; print(what, ": status", p.returncode, "\n got:", repr(got), "\nwant:", repr(want), p.stderr.decode("latin-1")[-300:])
    return paths

def volume_checks():
    global bad
    U, V = b"0123456789abcdef0123456789abcdef", b"fedcba9876543210fedcba9876543210"
    hexkey = b"ab" * 64
    dashed = lambda u: b"-".join((u[:8], u[8:12], u[12:16], u[16:20], u[20:]))
    ring = lambda u, d, size=b"64": b":" + size + b":logon:cryptsetup:" + dashed(u) + b"-d" + d    # get_key_description_by_digest
    def crypt(start, length, cipher, key, dev, offset, options=b""):
        return (start, length, b"crypt", cipher + b" " + key + b" 0 " + dev + b" " + offset + options)
    xts = b"aes-xts-plain64"

    # one device, one crypt target: LUKS1 with its key in the table
    plain = table(b"kc_l1", b"CRYPT-LUKS1-" + U + b"-kc_l1", 252, 1, [crypt(0, 126976, xts, hexkey, b"7:0", b"4096")])
    volumes("a volume of one device", [plain], "kc_l1: device 7:0, 1 key(s)\n  key 1: aes-xts-plain64, 128 characters, 126976 sectors\n")

    # LUKS2 with integrity, as cryptsetup 2.7.0 sets up --integrity hmac-sha256 on Linux 6.8: the
    # crypt target on NAME_dif, and the header on the device below that
    auth = b"capi:authenc(hmac(sha256),xts(aes))-plain64"
    integ = [table(b"kc_i", b"CRYPT-LUKS2-" + U + b"-kc_i", 252, 5,
                   [crypt(0, 60728, auth, ring(U, b"0", b"96"), b"252:4", b"0", b" 1 integrity:32:aead")]),
             table(b"kc_i_dif", b"CRYPT-INTEGRITY-" + U + b"-kc_i_dif", 252, 4,
                   [(0, 60728, b"integrity", b"7:3 32768 32 J 6 journal_sectors:704 interleave_sectors:32768 buffer_sectors:128 journal_watermark:50 commit_time:10000 fix_padding")])]
    want_i = ("kc_i: device 7:3, 1 key(s), integrity 32 aead, below it kc_i_dif\n"
              "  key 1: capi:authenc(hmac(sha256),xts(aes))-plain64, :96:logon:cryptsetup:01234567-89ab-cdef-0123-456789abcdef-d0, 60728 sectors\n")
    volumes("LUKS2 with integrity", integ, want_i)
    volumes("the same, the devices in the other order", integ[::-1], want_i)

    # a LUKS2 volume on a dm-integrity device that stands alone: its header is on that device
    alone = [table(b"kc_is", b"CRYPT-LUKS2-" + U + b"-kc_is", 252, 7, [crypt(0, 50000, xts, ring(U, b"0"), b"252:6", b"32768")]),
             table(b"kc_isdev", b"CRYPT-INTEGRITY-kc_isdev", 252, 6,
                   [(0, 96824, b"integrity", b"7:4 0 4 J 8 journal_sectors:704 interleave_sectors:32768 buffer_sectors:128 journal_watermark:50 commit_time:10000 fix_padding fix_hmac internal_hash:crc32c")])]
    want_a = "kc_is: device 252:6, 1 key(s)\n  key 1: aes-xts-plain64, :64:logon:cryptsetup:01234567-89ab-cdef-0123-456789abcdef-d0, 50000 sectors\n"
    volumes("a volume on a dm-integrity device", alone, want_a)

    # re-encryption that runs, as cryptsetup 2.7.0 had set it up on Linux 6.8 at one moment: NAME
    # is linear on NAME-overlay, the crypt targets are there, the one of the new key on
    # NAME-hotzone-forward
    def helpers(overlay):
        return [table(b"kc_r", b"CRYPT-LUKS2-" + V + b"-kc_r", 252, 8, [(0, 1540096, b"linear", b"252:10 0")]),
                table(b"kc_r-hotzone-forward", b"CRYPT-SUBDEV-" + V + b"-kc_r-hotzone-forward", 252, 9, [(0, 1540096, b"linear", b"7:5 32768")]),
                table(b"kc_r-overlay", b"CRYPT-SUBDEV-" + V + b"-kc_r-overlay", 252, 10, overlay)]
    def want_helpers(new, old):
        return ("kc_r: device 7:5, 2 key(s), parts kc_r-overlay kc_r-hotzone-forward\n"
                "  key 1: aes-xts-plain64, :64:logon:cryptsetup:fedcba98-7654-3210-fedc-ba9876543210-d1, %d sectors\n"
                "  key 2: aes-xts-plain64, :64:logon:cryptsetup:fedcba98-7654-3210-fedc-ba9876543210-d0, %d sectors\n" % (new, old))
    running = helpers([crypt(0, 507136, xts, ring(V, b"1"), b"252:9", b"0"),
                       crypt(507136, 1032960, xts, ring(V, b"0"), b"7:5", b"539904", b"")])
    want_r = want_helpers(507136, 1032960)
    paths = volumes("a volume in re-encryption with its helper devices", running, want_r)
    volumes("the same, the devices in the other order", running[::-1], want_r)
    # and as reencrypt_make_targets lays it out with a part that is done before the part in work
    volumes("the same with three crypt targets", helpers([crypt(0, 300000, xts, ring(V, b"1"), b"7:5", b"32768"),
                                                          crypt(300000, 100000, xts, ring(V, b"1"), b"252:9", b"300000"),
                                                          crypt(400000, 1140096, xts, ring(V, b"0"), b"7:5", b"432768")]),
            want_helpers(400000, 1140096))
    # the moment in which cryptsetup has made the helpers and not yet put them below the volume,
    # as it was seen with cryptsetup 2.7.0: the volume has its crypt target still, the overlay a
    # copy of it. The helpers are the volume's by their UUID, and the key maps the volume once.
    early = [table(b"kc_t", b"CRYPT-LUKS2-" + U + b"-kc_t", 252, 20, [crypt(0, 4161536, xts, ring(U, b"0"), b"7:9", b"32768")]),
             table(b"kc_t-overlay", b"CRYPT-SUBDEV-" + U + b"-kc_t-overlay", 252, 22, [crypt(0, 4161536, xts, ring(U, b"0"), b"7:9", b"32768")]),
             table(b"kc_t-hotzone-forward", b"CRYPT-SUBDEV-" + U + b"-kc_t-hotzone-forward", 252, 21, [(0, 4161536, b"linear", b"7:9 32768")])]
    volumes("helper devices that are not yet below their volume", early,
            "kc_t: device 7:9, 1 key(s), parts kc_t-hotzone-forward kc_t-overlay\n"
            "  key 1: aes-xts-plain64, :64:logon:cryptsetup:01234567-89ab-cdef-0123-456789abcdef-d0, 4161536 sectors\n")
    # the helpers of a volume are not those of another one, and are then listed for themselves
    other = [table(b"kc_r", b"CRYPT-LUKS2-" + U + b"-kc_r", 252, 8, [(0, 1540096, b"linear", b"252:10 0")])] + running[1:]
    volumes("helper devices with the UUID of another volume", other,
            want_r.replace("kc_r: device 7:5, 2 key(s), parts kc_r-overlay kc_r-hotzone-forward", "kc_r-overlay: device 252:9, 2 key(s)"))

    # re-encryption that was interrupted, or a volume opened in that state: both in NAME itself
    stopped = table(b"kc_s", b"CRYPT-LUKS2-" + U + b"-kc_s", 252, 11,
                    [crypt(0, 300000, xts, hexkey, b"7:6", b"32768"), crypt(300000, 700000, xts, b"cd" * 64, b"7:6", b"332768")])
    volumes("a volume with the crypt targets of two keys", [stopped],
            "kc_s: device 7:6, 2 key(s)\n  key 1: aes-xts-plain64, 128 characters, 300000 sectors\n"
            "  key 2: aes-xts-plain64, 128 characters, 700000 sectors\n")
    # encryption of a device in place: the part that is done and the rest as it is
    partly = table(b"kc_e", b"CRYPT-LUKS2-" + U + b"-kc_e", 252, 12,
                   [crypt(0, 300000, xts, ring(U, b"0"), b"7:7", b"65536"), (300000, 700000, b"linear", b"7:7 300000")])
    want_e = "kc_e: device 7:7, 1 key(s)\n  key 1: aes-xts-plain64, :64:logon:cryptsetup:01234567-89ab-cdef-0123-456789abcdef-d0, 300000 sectors\n"
    volumes("a volume that is encrypted in part", [partly], want_e)
    # no crypt target, and one whose line is not that of a crypt target
    lvm = table(b"vg-root", b"LVM-abc", 253, 0, [(0, 100, b"linear", b"8:3 2048")])
    short = table(b"kc_x", b"", 252, 13, [(0, 100, b"crypt", b"aes-xts-plain64 " + hexkey + b" 0")])
    null = table(b"kc_null", b"CRYPT-PLAIN-kc_null", 252, 14, [crypt(0, 100, b"cipher_null-ecb", b"-", b"7:8", b"0")])
    volumes("a device without a crypt target, a crypt line that is cut, a crypt target without a key", [lvm, short, null],
            "kc_null: device 7:8, 1 key(s)\n  key 1: cipher_null-ecb, -, 100 sectors\n"
            "kc_x: no device, 0 key(s), 1 crypt line(s) not understood\n")

    # all of them together are the same volumes, by name
    volumes("all of these devices at once", [plain] + integ + alone + running + [stopped, partly, lvm, short, null],
            want_e + want_i + want_a +
            "kc_l1: device 7:0, 1 key(s)\n  key 1: aes-xts-plain64, 128 characters, 126976 sectors\n"
            "kc_null: device 7:8, 1 key(s)\n  key 1: cipher_null-ecb, -, 100 sectors\n" + want_r +
            "kc_s: device 7:6, 2 key(s)\n  key 1: aes-xts-plain64, 128 characters, 300000 sectors\n"
            "  key 2: aes-xts-plain64, 128 characters, 700000 sectors\n"
            "kc_x: no device, 0 key(s), 1 crypt line(s) not understood\n")

    # the same tables with bytes of their lines changed: read or refused, never a fault
    rnd = random.Random(3)
    base = integ + running + [stopped, partly]
    for _ in range(300):
        changed = []
        for t in base:
            b = bytearray(t)
            for _ in range(rnd.randrange(0, 3)):
                at = rnd.randrange(HEAD, len(b))
                b[at] = rnd.choice((0x20, 0x3a, 0x30, 0x39, 0x2d, rnd.randrange(1, 256)))
            if rnd.randrange(8) == 0:
                at = rnd.choice((40, 176 + rnd.randrange(50)))        # the device number, the UUID
                b[at] = rnd.randrange(1, 256)
            changed.append(bytes(b))
        for i, t in enumerate(changed):
            open(paths[0].replace("table0", "changed%d" % i), "wb").write(t)
        p = subprocess.run([unit, "volumes"] + [paths[0].replace("table0", "changed%d" % i) for i in range(len(changed))],
                           capture_output=True)
        if p.returncode not in (0, 1):
            bad += 1; print("changed tables ended with status", p.returncode, ":", p.stderr.decode("latin-1")[-400:])

if part == "volumes":
    volume_checks()
    sys.exit(1 if bad else 0)

devs = [(b"kc_l2", 252, 0), (b"No", 252, 2), (b"name\\x20with\\x20space", 252, 4), (b"vg-root", 253, 1048575),
        (b"n" * 127, 4095, 300)]
want = "".join("%s\t(%d:%d)\n" % (n.decode(), ma, mi) for n, ma, mi in sorted(devs))
expect("a list as Linux 4.13 and later write it", "list", listing(devs), want)
expect("a list as Linux before 4.13 wrote it", "list", listing(devs, new=False), want)
expect("a list of one", "list", listing(devs[:1]), "kc_l2\t(252:0)\n")
expect("no mapped device", "list", listing([]), "No devices found\n")
expect("a buffer with room behind the list", "list", listing(devs) + b"\0" * 4096, want)
refused("a name of 128 bytes", "list", listing([(b"n" * 128, 1, 1)]))
refused("an empty name", "list", listing([(b"", 1, 1)]))
refused("a list shorter than its header", "list", listing(devs)[:200])

key = b"ab" * 64
crypt = b"aes-xts-plain64 " + key + b" 0 7:0 32768 1 allow_discards"
t = table(b"kc_l1", b"CRYPT-LUKS1-0123456789abcdef0123456789abcdef-kc_l1", 252, 1, [(0, 126976, b"crypt", crypt)])
expect("a crypt table with its key", "table", t,
       "0 126976 crypt aes-xts-plain64 " + "0" * 128 + " 0 7:0 32768 1 allow_discards\n",
       "name kc_l1, uuid CRYPT-LUKS1-0123456789abcdef0123456789abcdef-kc_l1, device 252:1, 1 target(s)\nkey of 64 bytes, sha256 ")
t2 = table(b"kc_l2", b"CRYPT-LUKS2-x", 252, 0, [(0, 98304, b"crypt", b"aes-xts-plain64 :64:logon:cryptsetup:u-d0 0 7:1 32768")])
expect("a keyring reference stays as it is", "table", t2, "0 98304 crypt aes-xts-plain64 :64:logon:cryptsetup:u-d0 0 7:1 32768\n")
t3 = table(b"lv", b"", 253, 3, [(0, 100, b"linear", b"8:3 2048"), (100, 50, b"striped_sixteen_", b"2 128 8:3 0 8:4 0"),
                                (150, 10, b"error", b"")])
expect("three targets, one type of 16 bytes, one without a line", "table", t3,
       "0 100 linear 8:3 2048\n100 50 striped_sixteen_ 2 128 8:3 0 8:4 0\n150 10 error \n", "3 target(s)")
expect("a device without a table", "table", table(b"empty", b"", 253, 9, []), "", "0 target(s)")
# The table as it is kept in log/: the key of a crypt target and the three keys that a
# dm-integrity target can have are zeros, as "dmsetup table" prints them, and a keyring
# reference stays.
def kept(what, data, out):
    global bad
    path = os.path.join(tmp, "answer.bin")
    open(path, "wb").write(data)
    p = subprocess.run([unit, "table-text", path], capture_output=True)
    if p.returncode != 0 or p.stdout.decode("latin-1") != out:
        bad += 1; print(what, ": status", p.returncode, "output", repr(p.stdout), repr(p.stderr[-200:]))
kept("the keys of a crypt and of an integrity target",
     table(b"vol", b"CRYPT-LUKS2-x", 253, 4, [
         (0, 100, b"crypt", b"aes-xts-plain64 00112233aabbccdd 0 7:1 32768 1 allow_discards"),
         (100, 50, b"integrity", b"7:2 0 32 J 4 journal_crypt:ctr(aes):0123456789abcdef internal_hash:hmac(sha256):feedface "
                                  b"journal_mac:hmac(sha256):c0ffee00 journal_sectors:1024"),
         (150, 10, b"integrity", b"7:3 0 32 J 1 internal_hash:crc32c"),
         (160, 10, b"crypt", b"aes-xts-plain64 :64:logon:cryptsetup:abc-d0 0 7:1 0")]),
     "name vol\nuuid CRYPT-LUKS2-x\ndevice 253:4\n"
     "0 100 crypt aes-xts-plain64 0000000000000000 0 7:1 32768 1 allow_discards\n"
     "100 50 integrity 7:2 0 32 J 4 journal_crypt:ctr(aes):0000000000000000 internal_hash:hmac(sha256):00000000 "
     "journal_mac:hmac(sha256):00000000 journal_sectors:1024\n"
     "150 10 integrity 7:3 0 32 J 1 internal_hash:crc32c\n"
     "160 10 crypt aes-xts-plain64 :64:logon:cryptsetup:abc-d0 0 7:1 0\n")
refused("a table shorter than its header", "table", t[:311])
refused("more targets stated than the answer holds", "table", t[:20] + struct.pack("<I", 100000) + t[24:])
refused("two targets stated and one held", "table", t[:20] + struct.pack("<I", 2) + t[24:])
refused("a line without its end", "table", t.rstrip(b"\0")[:-1] + b"x")

# changed and cut answers: read or refused, with status 0 or 1. Any other status is a fault,
# which the build with the sanitizers reports for a read outside the buffer.
rnd = random.Random(2)
for kind, base in (("list", listing(devs)), ("list", listing(devs, new=False)), ("table", t), ("table", t3)):
    for _ in range(400):
        b = bytearray(base)
        how = rnd.randrange(5)
        if how == 0: del b[rnd.randrange(len(b)):]
        elif how == 1:
            for _ in range(rnd.randrange(1, 4)): b[rnd.randrange(len(b))] = rnd.randrange(256)
        elif how == 2:                          # the words that say where things lie
            off = rnd.choice((12, 16, 20, 24, HEAD + 8, HEAD + 20))
            b[off:off + 4] = struct.pack("<I", rnd.choice((0, 1, 7, 8, 12, 40, 311, 312, 313, len(b) - 1, len(b), len(b) + 1, 0x7fffffff, 0xffffffff)))
        elif how == 3: b[rnd.randrange(HEAD, len(b))] = rnd.choice((0, 0, 0x20, 0xff))
        else: b += bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 64)))
        rc, got, goterr = run(kind, bytes(b))
        if rc not in (0, 1):
            bad += 1; print("a changed", kind, "answer ended with status", rc, ":", goterr[-400:])
sys.exit(1 if bad else 0)
EOF
# A table that the kernel does not give. A device that was removed since the list was read is
# none any more (the kernel says ENXIO, which needs a kernel with device-mapper and is looked
# at by compat-check.sh). Any other refusal is a table that could not be read, and a run with
# one is not whole: here the request goes to a device that knows no such request.
table_refused() {
    local u=$1 rc
    "$u" dm-table kc_x /dev/null > "$T/dmt.txt" 2>&1; rc=$?
    [ "$rc" = 1 ] && ! grep -q 'no such device' "$T/dmt.txt" && grep -q '^keep-unit: the table of a mapped device: ' "$T/dmt.txt" ||
        { echo "status $rc:"; cat "$T/dmt.txt"; return 1; }
}
for u in "${UNITS[@]}"; do
    check "kernel: ${u##*/} takes a request that is refused as a table that cannot be read, and not as a device that is gone" table_refused "$u"
    check "kernel: ${u##*/} reads the answers of device-mapper and refuses damaged ones without a fault" python3 -I "$T/kernel.py" "$u" "$T" answers
    check "kernel: ${u##*/} finds the volumes among tables: one device, with integrity, in re-encryption, with changed bytes" python3 -I "$T/kernel.py" "$u" "$T" volumes
done

# ---- image ---------------------------------------------------------------------------------------
# The memory image. A case is a text like /proc/iomem, a core like /proc/kcore, the memory
# that the core stands for, and the records that the image must have, which are written down
# here by hand. Python writes the two image files from the definitions of the formats: a LiME
# record is a header of 32 bytes (magic, version 1, first and last address, 8 zeros) and the
# memory, and a raw image has each byte at the offset that is its address.
cat > "$T/image.py" <<'EOF'
import hashlib, os, random, re, struct, subprocess, sys
unit, tmp, part, bad = sys.argv[1], sys.argv[2], sys.argv[3], 0
avml = sys.argv[4] if len(sys.argv) > 4 else ""
rnd = random.Random(3)
NONE = 2**64 - 1
os.makedirs(tmp + "/image", exist_ok=True)

def core(segments, memory, size=None, ident=b"\x7fELF\x02\x01\x01", phentsize=56):
    """An ELF64 core: a note, then the segments (address, bytes, offset or None for the next
    free one, with the virtual address a kernel would state). memory maps address to bytes."""
    phnum = 1 + len(segments)
    data_at = 64 + 56 * phnum + 16
    out = bytearray(ident + bytes(16 - len(ident)) + struct.pack("<HHIQQQIHHHHHH", 4, 62, 1, 0, 64, 0, 0, 64, phentsize, phnum, 0, 0, 0))
    out += struct.pack("<IIQQQQQQ", 4, 0, 64 + 56 * phnum, 0, 0, 16, 16, 0)
    body, at = bytearray(), data_at
    for addr, length, offset in segments:
        if offset is None:
            offset = at
            if addr != NONE:
                body += content(memory, addr, length)
                at += length
        out += struct.pack("<IIQQQQQQ", 1, 7, offset, 0xffff888000000000 + (addr & 0xffffffffff), addr, length, length, 0)
    out += bytes(16) + body
    return bytes(out if size is None else out[:size])

def content(memory, addr, length):
    """The bytes of a stretch of memory, zeros where the case has none."""
    out = bytearray(length)
    for start, data in memory.items():
        a, b = max(start, addr), min(start + len(data), addr + length)
        if a < b:
            out[a - addr:b - addr] = data[a - start:b - start]
    return bytes(out)

def lime(memory, records):
    return b"".join(struct.pack("<IIQQ8x", 0x4C694D45, 1, a, b - 1) + content(memory, a, b - a) for a, b in records)

def raw(memory, records):
    out = bytearray(records[-1][1])
    for a, b in records:
        out[a:b] = content(memory, a, b - a)
    return bytes(out)

def run(*args, data=None):
    r = subprocess.run([unit] + list(args), capture_output=True, input=data)
    return r.returncode, (r.stdout if data is not None else r.stdout.decode("latin-1")), r.stderr.decode("latin-1")

# A reader of the framed Snappy format, from format_description.txt and framing_format.txt.
CRC = []
for i in range(256):
    c = i
    for _ in range(8):
        c = c >> 1 ^ 0x82F63B78 if c & 1 else c >> 1
    CRC.append(c)

def masked_crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c = c >> 8 ^ CRC[(c ^ b) & 0xFF]
    c ^= 0xFFFFFFFF
    return ((c >> 15 | c << 17) + 0xA282EAD8) & 0xFFFFFFFF

def unsnappy(data):
    """Compressed data as its literals and copies say."""
    want, shift, i = 0, 0, 0
    while True:
        want |= (data[i] & 0x7F) << shift; shift += 7; i += 1
        if not data[i - 1] & 0x80: break
    out = bytearray()
    while i < len(data):
        tag = data[i]; i += 1
        if tag & 3 == 0:
            n = tag >> 2
            if n >= 60:
                size = n - 59
                n = int.from_bytes(data[i:i + size], "little"); i += size
            n += 1
            assert i + n <= len(data), "a literal reaches beyond the data"
            out += data[i:i + n]; i += n
            continue
        if tag & 3 == 1:
            n, back = 4 + (tag >> 2 & 7), (tag >> 5) << 8 | data[i]; i += 1
        elif tag & 3 == 2:
            n, back = 1 + (tag >> 2), int.from_bytes(data[i:i + 2], "little"); i += 2
        else:
            n, back = 1 + (tag >> 2), int.from_bytes(data[i:i + 4], "little"); i += 4
        assert 0 < back <= len(out), "a copy from before the data"
        while n:                                # a copy can reach into what it writes
            piece = out[len(out) - back:len(out) - back + n]
            out += piece; n -= len(piece)
    assert len(out) == want, "the data is not as long as its length says"
    return bytes(out)

def unframe(data, at, length=None):
    """The chunks of a stream from AT: until LENGTH bytes are decoded, or to the end of the
    data. Returns the decoded bytes and the place behind the last chunk."""
    assert data[at:at + 10] == b"\xff\x06\x00\x00sNaPpY", "no stream identifier"
    at += 10
    out = bytearray()
    while at < len(data) and (length is None or len(out) < length):
        kind, size = data[at], int.from_bytes(data[at + 1:at + 4], "little")
        body = data[at + 8:at + 4 + size]
        assert kind in (0, 1) and size >= 4 and at + 4 + size <= len(data), "a chunk of type %d and length %d" % (kind, size)
        plain = unsnappy(body) if kind == 0 else body
        assert kind == 1 or len(body) < len(plain), "a compressed chunk that is not shorter than its data"
        assert 0 < len(plain) <= 65536, "a chunk of %d bytes" % len(plain)
        assert int.from_bytes(data[at + 4:at + 8], "little") == masked_crc32c(plain), "a chunk with a wrong checksum"
        out += plain; at += 4 + size
    return bytes(out), at

BLOCK = 16 << 20
def blocks(memory, records):
    """What the compressed format of AVML holds: blocks of 16 MiB, without those of zeros."""
    out = []
    for a, b in records:
        for start in range(a, b, BLOCK):
            data = content(memory, start, min(b, start + BLOCK) - start)
            if any(data):
                out.append((start, data))
    return out

def read_avml(data):
    """The blocks of a compressed image of AVML, version 2."""
    out, at = [], 0
    while at < len(data):
        magic, version, start, last, pad = struct.unpack("<IIQQQ", data[at:at + 32])
        assert (magic, version, pad) == (0x4C4D5641, 2, 0), "a header %x %d %d" % (magic, version, pad)
        plain, end = unframe(data, at + 32, last + 1 - start)
        assert len(plain) == last + 1 - start, "a block shorter than its header says"
        assert int.from_bytes(data[end:end + 8], "little") == end - at - 32, "the length behind the stream is not its length"
        out.append((start, plain)); at = end + 8
    return out

def write(name, data):
    path = tmp + "/image/" + name
    with open(path, "wb") as f:
        f.write(data)
    return path

OUT = ("out.lime", "out.raw", "out.avml")
def fresh():
    """The file of an image must not exist when it is made."""
    for name in OUT:
        try: os.unlink(tmp + "/image/" + name)
        except FileNotFoundError: pass

WAYS = ("direct writes", "through the page cache")
way = os.environ.get("KEEP_WAY", "")    # the way that the file system of tmp must give, or any
def ways(out):
    """The lines of an image run without those that say how a file was written, and those."""
    lines, said = [], []
    for l in out.splitlines():
        w = l.split(" ", 1)
        if len(w) == 2 and w[0] in ("lime", "raw", "avml") and w[1].endswith(" pages in the page cache after its writes"):
            continue                    # counted by a check of its own
        (said if len(w) == 2 and w[0] in ("lime", "raw", "avml") and w[1] in WAYS else lines).append(l)
    return lines, said

def case(what, iomem, segments, memory, records, unread=0, size=None):
    """The source and the images of one case, against the records written down for it."""
    global bad
    io, co = write("iomem", iomem.encode()), write("core", core(segments, memory, size))
    want_lime, want_raw = lime(memory, records), raw(memory, records)
    ram = sum(int(l.split("-")[1].split()[0], 16) + 1 - int(l.split("-")[0], 16)
              for l in iomem.splitlines() if re.match(r"[0-9a-f]+-[0-9a-f]+ : System RAM($| \()", l))
    rc, out, err = run("image-source", io, co)
    lines = out.splitlines()
    want = ["0x%x-0x%x" % r for r in records]
    got = [l.split(" at ")[0] for l in lines[:-1]]
    total = "%d bytes of %d, lime %d, raw %d, avml at most " % (sum(b - a for a, b in records), ram, len(want_lime), len(want_raw))
    if rc != 0 or got != want or not lines[-1].startswith(total):
        bad += 1; print(what, ": the source is", rc, lines, err[-300:], "expected", want, total)
        return
    most = int(lines[-1][len(total):])
    fresh()
    rc, out, err = run("image", io, co, "lime", tmp + "/image/out.lime", "raw", tmp + "/image/out.raw", "avml", tmp + "/image/out.avml")
    packed = open(tmp + "/image/out.avml", "rb").read() if os.path.exists(tmp + "/image/out.avml") else b""
    said = ["lime %d bytes, sha256 %s" % (len(want_lime), hashlib.sha256(want_lime).hexdigest()),
            "raw %d bytes, sha256 %s" % (len(want_raw), hashlib.sha256(want_raw).hexdigest()),
            "avml %d bytes, sha256 %s" % (len(packed), hashlib.sha256(packed).hexdigest()),
            "%d bytes not read" % unread]
    lines, how = ways(out)
    if rc != 0 or lines != said:
        bad += 1; print(what, ": status", rc, out, err[-300:], "expected", said)
        return
    if [h.split(" ", 1)[0] for h in how] != ["lime", "raw", "avml"] or any(h.split(" ", 1)[1] != (way or WAYS[0]) for h in how) and way:
        bad += 1; print(what, ": the files were written", how, "expected each", way or "in one of the two ways")
    if open(tmp + "/image/out.lime", "rb").read() != want_lime or open(tmp + "/image/out.raw", "rb").read() != want_raw:
        bad += 1; print(what, ": an image is not the file that its format defines")
    want_blocks = blocks(memory, records)
    try:
        if read_avml(packed) != want_blocks:
            bad += 1; print(what, ": the compressed image does not hold the blocks of the memory")
        if len(packed) > most:
            bad += 1; print(what, ": the compressed image has", len(packed), "bytes, more than the", most, "it can take at most")
    except (AssertionError, IndexError, struct.error) as e:
        bad += 1; print(what, ": the compressed image is not read:", e)
    if avml:
        # AVML itself: its reader of the compressed format, and its writer of the raw one
        as_lime = b"".join(struct.pack("<IIQQ8x", 0x4C694D45, 1, a, a + len(d) - 1) + d for a, d in want_blocks)
        for src, fmt, dst, want_file in (("out.avml", "lime_compressed", "lime", as_lime), ("out.lime", "lime", "raw", want_raw)):
            r = subprocess.run([avml, "convert", "--source-format", fmt, "--format", dst, tmp + "/image/" + src, tmp + "/image/conv"], capture_output=True)
            if r.returncode != 0 or open(tmp + "/image/conv", "rb").read() != want_file:
                bad += 1; print(what, ": avml convert of", src, "to", dst, "ends with status", r.returncode, "or gives another file", r.stderr[-300:])
            os.unlink(tmp + "/image/conv")

def refused(what, iomem, core_bytes, word):
    global bad
    rc, out, err = run("image-source", write("iomem", iomem.encode()), write("core", core_bytes))
    if rc != 1 or not out.startswith("refused: ") or word not in out:
        bad += 1; print(what, ": status", rc, out, err[-300:], "expected a refusal that says:", word)

MiB = 1 << 20
low, high = rnd.randbytes(0x9e000), rnd.randbytes(3 * MiB + 0x3000)
mem = {0x1000: low, 0x100000: high}
IOMEM = """00000000-00000fff : Reserved
00001000-0009efff : System RAM
0009f000-000fffff : Reserved
  000a0000-000bffff : PCI Bus 0000:00
00100000-00402fff : System RAM
  00200000-002fffff : Kernel code
  00300000-0033ffff : Kernel data
fec00000-fec003ff : IOAPIC 0
"""
segs = [(NONE, 1 << 30, 1 << 40), (0x1000, 0x9e000, None), (0x100000, 3 * MiB + 0x3000, None)]

if part == "formats":
    case("two ranges with a gap, a segment that is not physical memory", IOMEM, segs, mem, [(0x1000, 0x9f000), (0x100000, 0x403000)])
    # the text of the kernel is a second view of memory that a RAM segment offers as well
    text = [(0x200000, MiB, None)]
    case("memory that two segments offer is taken once", IOMEM, segs + text, mem, [(0x1000, 0x9f000), (0x100000, 0x403000)])
    case("the second view first among the segments", IOMEM, [segs[0]] + text + segs[1:], mem, [(0x1000, 0x9f000), (0x100000, 0x403000)])
    # a firmware ends a RAM range inside a page, and the kernel offers whole pages
    case("a RAM range that reaches beyond its segment",
         IOMEM.replace("00001000-0009efff : System RAM", "00001000-0009fbff : System RAM"), segs, mem, [(0x1000, 0x9f000), (0x100000, 0x403000)])
    case("a RAM range that begins before its segment",
         IOMEM.replace("00100000-00402fff", "000ff000-00402fff").replace("0009f000-000fffff", "0009f000-000fefff"), segs, mem,
         [(0x1000, 0x9f000), (0x100000, 0x403000)])
    # one range in two segments: one record where the second goes on in the core, else two
    two = [segs[1], (0x100000, MiB, None), (0x200000, 2 * MiB + 0x3000, None)]
    case("a RAM range in two segments that follow each other in the core", IOMEM, two, mem, [(0x1000, 0x9f000), (0x100000, 0x403000)])
    apart = [(0x200000, 2 * MiB + 0x3000, None), segs[1], (0x100000, MiB, None)]
    case("a RAM range in two segments that lie apart in the core", IOMEM, apart, mem,
         [(0x1000, 0x9f000), (0x100000, 0x200000), (0x200000, 0x403000)])
    case("a RAM range with a stretch that no segment offers", IOMEM, [segs[1], (0x100000, MiB, None), (0x300000, MiB + 0x3000, None)], mem,
         [(0x1000, 0x9f000), (0x100000, 0x200000), (0x300000, 0x403000)])
    # RAM that a driver added has its name behind "System RAM", and a part of a range is no range
    added = rnd.randbytes(MiB)
    case("RAM that a driver added",
         IOMEM + "08000000-080fffff : System RAM (virtio_mem)\n  08000000-080fffff : virtio0\n0c000000-0c0fffff : System RAMDISK\n",
         segs + [(0x8000000, MiB, None), (0xc000000, MiB, None)], {**mem, 0x8000000: added},
         [(0x1000, 0x9f000), (0x100000, 0x403000), (0x8000000, 0x8100000)])
    case("ranges that touch are one, in any order of the lines",
         "00200000-00402fff : System RAM\n00001000-0009efff : System RAM\n00100000-001fffff : System RAM\n", segs, mem,
         [(0x1000, 0x9f000), (0x100000, 0x403000)])
    # more than one block of 16 MiB, and a length that is no multiple of anything
    big = rnd.randbytes(33 * MiB + 0x1234)
    case("a range of more than two blocks", "00100000-%08x : System RAM\n" % (0x100000 + len(big) - 1),
         [(0x100000, len(big), None)], {0x100000: big}, [(0x100000, 0x100000 + len(big))])
    # A read that is ended before the end of the memory, as a run that was asked to end ends
    # it, after one block of 16 MiB and after two: each file is whole as far as it goes. The
    # LiME and the raw image are the start of the files of the whole read, to the last byte
    # that was read, the compressed image is the blocks up to there, and each has the SHA-256
    # that is stated for it.
    io, co = write("iomem", ("00100000-%08x : System RAM\n" % (0x100000 + len(big) - 1)).encode()), write("core", core([(0x100000, len(big), None)], {0x100000: big}))
    whole_lime, whole_raw = lime({0x100000: big}, [(0x100000, 0x100000 + len(big))]), raw({0x100000: big}, [(0x100000, 0x100000 + len(big))])
    for after, read in ((1, BLOCK), (BLOCK, BLOCK), (BLOCK + 1, 2 * BLOCK)):
        fresh()
        r = subprocess.run([unit, "image", io, co, "lime", tmp + "/image/out.lime", "raw", tmp + "/image/out.raw", "avml", tmp + "/image/out.avml"],
                           capture_output=True, env={**os.environ, "KEEP_UNIT_STOP": str(after)})
        got = {n: open(tmp + "/image/" + n, "rb").read() for n in OUT}
        lines, how = ways(r.stdout.decode("latin-1"))
        said = ["%s %d bytes, sha256 %s" % (n[4:], len(got[n]), hashlib.sha256(got[n]).hexdigest()) for n in OUT]
        said += ["0 bytes not read", "ended after %d bytes of memory" % read]
        if r.returncode != 0 or lines != said:
            bad += 1; print("a read that is ended after", after, "bytes: status", r.returncode, lines, r.stderr[-300:], "expected", said)
        if got["out.lime"] != whole_lime[:32 + read] or got["out.raw"] != whole_raw[:0x100000 + read]:
            bad += 1; print("a read that is ended after", after, "bytes: the LiME or the raw image is not the start of the whole one, to the last byte read")
        try:
            if read_avml(got["out.avml"]) != blocks({0x100000: big}, [(0x100000, 0x100000 + read)]):
                bad += 1; print("a read that is ended after", after, "bytes: the compressed image does not hold the blocks that were read")
        except (AssertionError, IndexError, struct.error) as e:
            bad += 1; print("a read that is ended after", after, "bytes: the compressed image is not read:", e)
    # a block of zeros is left out of the compressed image, and memory with zeros in it is not
    holes = bytearray(rnd.randbytes(40 * MiB)); holes[16 * MiB:32 * MiB] = bytes(16 * MiB); holes[33 * MiB:35 * MiB] = bytes(2 * MiB)
    case("a block of zeros between two blocks", "00100000-%08x : System RAM\n" % (0x100000 + len(holes) - 1),
         [(0x100000, len(holes), None)], {0x100000: bytes(holes)}, [(0x100000, 0x100000 + len(holes))])
    case("memory that is all zeros", "00100000-002fffff : System RAM\n", [(0x100000, 2 * MiB, None)], {}, [(0x100000, 0x300000)])
    # A direct write is whole blocks of 4096 bytes. Ranges that end and begin inside one
    # block of the file, one that begins and ends inside its blocks, and an image that ends
    # inside a block.
    edges = {0x1000: rnd.randbytes(0x800), 0x1a00: rnd.randbytes(0x1600), 0x100200: rnd.randbytes(0xc00)}
    case("ranges that begin and end inside a block of the file",
         "00001000-000017ff : System RAM\n00001a00-00002fff : System RAM\n00100200-00100dff : System RAM\n",
         [(0x1000, 0x800, None), (0x1a00, 0x1600, None), (0x100200, 0xc00, None)], edges,
         [(0x1000, 0x1800), (0x1a00, 0x3000), (0x100200, 0x100e00)])
    # a range that fills what is written at once to its last byte, and a gap of less than a block behind it
    full = {0x100000: rnd.randbytes(15 * MiB), 0x1000800: rnd.randbytes(0x1000)}
    case("a range that ends where a write ends, and the next inside the block behind it",
         "00100000-00ffffff : System RAM\n01000800-010017ff : System RAM\n",
         [(0x100000, 15 * MiB, None), (0x1000800, 0x1000, None)], full, [(0x100000, 0x1000000), (0x1000800, 0x1001800)])
    case("an image of less than a block", "00001000-000011ff : System RAM\n", [(0x1000, 0x200, None)],
         {0x1000: rnd.randbytes(0x200)}, [(0x1000, 0x1200)])
    # a core that ends inside a segment: what is missing is zeros and is counted
    cut = dict(mem); cut[0x100000] = high[:2 * MiB + 0x800]
    case("a stretch that cannot be read", IOMEM, segs, cut, [(0x1000, 0x9f000), (0x100000, 0x403000)],
         unread=len(high) - 2 * MiB - 0x800, size=64 + 56 * 4 + 16 + len(low) + 2 * MiB + 0x800)

    # a file that cannot be written: the other image is complete all the same
    io, co = write("iomem", IOMEM.encode()), write("core", core(segs, mem))
    want = raw(mem, [(0x1000, 0x9f000), (0x100000, 0x403000)])
    fresh()
    rc, out, err = run("image", io, co, "lime", "/dev/full", "raw", tmp + "/image/out.raw")
    if rc != 0 or out.splitlines()[:2] != ["lime failed: No space left on device", "raw %d bytes, sha256 %s" % (len(want), hashlib.sha256(want).hexdigest())]:
        bad += 1; print("one file that cannot be written: status", rc, out, err[-300:])
    fresh()
    rc, out, err = run("image", io, co, "avml", "/dev/full", "raw", tmp + "/image/out.raw")
    if rc != 0 or out.splitlines()[0] != "avml failed: No space left on device":
        bad += 1; print("a compressed image that cannot be written: status", rc, out, err[-300:])
    # the file of an image is made, and one that is there is not written over
    rc, out, err = run("image", io, co, "raw", tmp + "/image/out.raw")
    if rc != 1 or "cannot be made: File exists" not in err or open(tmp + "/image/out.raw", "rb").read() != want:
        bad += 1; print("a file that is there: status", rc, out, err[-300:])
    rc, out, err = run("image", io, co, "raw", "/dev/full", "lime", "/dev/full")
    if rc != 1 or "failed: no image could be written to its end" not in out:
        bad += 1; print("no file that can be written: status", rc, out, err[-300:])
    rc, out, err = run("image", io, co, "elf", tmp + "/image/out.elf")
    if rc != 2:
        bad += 1; print("a format that does not exist: status", rc, out)

elif part == "streams":
    # the compressor alone: every stream must decode to its data
    def stream(what, data, most=None):
        global bad
        rc, out, err = run("snappy", data=data)
        try:
            plain, end = unframe(out, 0)
            if rc != 0 or plain != data or end != len(out):
                bad += 1; print(what, ": status", rc, "or the stream does not decode to its data")
            elif len(out) > (most if most is not None else 10 + len(data) + 8 * ((len(data) + 65535) // 65536)):
                bad += 1; print(what, ":", len(out), "bytes for", len(data))
        except (AssertionError, IndexError) as e:
            bad += 1; print(what, ": the stream is not read:", e)
    for n in (1, 2, 3, 4, 5, 59, 60, 61, 62, 255, 256, 257, 65535, 65536, 65537, 300000):
        stream("%d random bytes" % n, rnd.randbytes(n))
        stream("%d zeros" % n, bytes(n), most=10 + 8 * ((n + 65535) // 65536) + n // 16 + 12)
        stream("%d bytes of one text" % n, (b"the quick brown fox jumps over the lazy dog. " * (n // 45 + 1))[:n])
    for period in (1, 2, 3, 4, 5, 7, 11, 12, 63, 64, 65, 67, 68, 100, 2047, 2048, 2049, 3000, 32768, 65531, 65532, 65535):
        unit_text = rnd.randbytes(period)
        stream("a period of %d" % period, (unit_text * (200000 // period + 1))[:200000], most=200000 // 2 if period <= 3000 else None)
    for n in range(200):
        # literals and copies of every length next to each other
        parts, text = [], rnd.randbytes(3000)
        while sum(map(len, parts)) < 70000:
            a = rnd.randrange(len(text) - 80)
            parts.append(text[a:a + rnd.randrange(1, 80)] if rnd.randrange(3) else rnd.randbytes(rnd.randrange(1, 70)))
        stream("a mix of pieces", b"".join(parts))

elif part == "refused":
    good = core(segs, mem)
    refused("a reader that is not root sees no addresses", "00000000-00000000 : System RAM\n00000000-00000000 : Reserved\n", good, "not root")
    refused("no RAM range", "00000000-00000fff : Reserved\n  00001000-0009efff : System RAM\n", good, "no RAM range")
    refused("an empty text", "", good, "no RAM range")
    refused("a range that ends before it begins", "00100000-000fffff : System RAM\n", good, "ends before it begins")
    refused("a range to the last address", "00100000-ffffffffffffffff : System RAM\n", good, "last address")
    refused("RAM that no segment offers", "200000000-2000fffff : System RAM\n", good, "offers none")
    refused("no segment with an address", IOMEM, core([segs[0]], mem), "no segment with a physical address")
    # before Linux 4.12 every segment of /proc/kcore states the address 0
    old = bytearray(good)
    for i in (2, 3):
        old[64 + 56 * i + 24:64 + 56 * i + 32] = bytes(8)
    refused("a kernel that states no physical addresses", IOMEM, bytes(old), "states no physical addresses")
    refused("a file that is no core", IOMEM, rnd.randbytes(4096), "not an ELF64 core")
    refused("an empty core", IOMEM, b"", "header")
    refused("a core of 32 bits", IOMEM, core(segs, mem, ident=b"\x7fELF\x01\x01\x01"), "not an ELF64 core")
    refused("a core in the other byte order", IOMEM, core(segs, mem, ident=b"\x7fELF\x02\x02\x01"), "not an ELF64 core")
    refused("segments of another size", IOMEM, core(segs, mem, phentsize=32), "not an ELF64 core")
    refused("a core that ends inside its segments", IOMEM, good[:64 + 56 * 2 + 10], "cannot be read")
    far = bytearray(good); far[64 + 56 * 2 + 32:64 + 56 * 2 + 40] = struct.pack("<Q", NONE - 0x10)
    refused("a segment that reaches beyond the last address", IOMEM, bytes(far), "beyond the last address")

elif part == "changed":
    # cores with bytes of their headers changed, and texts with bytes changed: read or
    # refused, with status 0 or 1. The memory that such a core can stand for is that of the
    # text, so the images stay small.
    good = core(segs, mem)
    heads = 64 + 56 * 4 + 16
    io = write("iomem", IOMEM.encode())
    for n in range(300):
        b = bytearray(good)
        how = rnd.randrange(4)
        if how == 0: del b[rnd.randrange(heads + 4096):]
        elif how == 1:
            for _ in range(rnd.randrange(1, 4)): b[rnd.randrange(heads)] = rnd.randrange(256)
        elif how == 2:                          # the words that say where things lie and how long they are
            i = 64 + 56 * rnd.randrange(4) + rnd.choice((8, 24, 32))
            b[i:i + 8] = struct.pack("<Q", rnd.choice((0, 1, 0xfff, 0x1000, 0x100000, len(b), len(b) + 1, 2**47, 2**63, NONE - 1, NONE)))
        else:
            off = rnd.choice((32, 54, 56))
            b[off:off + 2] = struct.pack("<H", rnd.choice((0, 1, 4, 5, 56, 64, 0xffff)))
        fresh()
        rc, out, err = run("image", io, write("core", bytes(b)), "lime", tmp + "/image/out.lime", "raw", tmp + "/image/out.raw", "avml", tmp + "/image/out.avml")
        if rc not in (0, 1):
            bad += 1; print("a changed core ended with status", rc, ":", err[-400:])
    co = write("core", good)
    for n in range(300):
        t = bytearray(IOMEM.encode())
        for _ in range(rnd.randrange(1, 4)):
            how = rnd.randrange(3)
            if len(t) < 2: break
            if how == 0: t[rnd.randrange(len(t))] = rnd.choice(b"0123456789abcdef- :\nS")
            elif how == 1: del t[rnd.randrange(len(t)):]
            else: t[rnd.randrange(len(t)):rnd.randrange(len(t))] = bytes(rnd.choice(b"0f- :\n") for _ in range(rnd.randrange(20)))
        rc, out, err = run("image-source", write("iomem", bytes(t)), co)
        if rc not in (0, 1):
            bad += 1; print("a changed text ended with status", rc, ":", err[-400:])
sys.exit(1 if bad else 0)
EOF
# The fixture of the scanner as a core: the scanner must find in the image of it the schedules
# that it finds in the core itself, at the same addresses. The core offers a part of its
# memory twice, as /proc/kcore offers the text of the kernel, so each schedule counts once.
image_fixture() {
    local u=$1
    rm -f "$T/fx.out.lime"
    "$u" image "$T/fx.iomem" "$T/fx.elf" lime "$T/fx.out.lime" > "$T/fx.out.txt" || { cat "$T/fx.out.txt"; return 1; }
    cmp <(tests/keyscan "$T/fx.elf" 2> /dev/null | sed 's/ virt .* key / key /' | sort -u) <(tests/keyscan "$T/fx.out.lime" 2> /dev/null | sed 's/ virt .* key / key /' | sort -u) ||
        { echo "the LiME image of the fixture gives other schedules than the fixture"; return 1; }
    [ "$(tests/keyscan "$T/fx.out.lime" 2> /dev/null | wc -l)" -ge 6 ] || { echo "too few schedules"; return 1; }
}
# The way an image is written. A file system with direct writes must get them: these are the
# ones of the machines that run this check. Elsewhere either way is taken.
case $(stat -f -c %T "$T") in
ext2/ext3|xfs|btrfs) export KEEP_WAY="direct writes" ;;
ramfs) export KEEP_WAY="through the page cache" ;;
*) export KEEP_WAY="" ;;
esac
# The pages of an image file that lie in the page cache. After its direct writes: none but
# the last, which is the end of the file that is no whole block. After the file is flushed
# and its pages are let go: none. The raw image of the fixture is as long as its highest
# address, 4 GiB and 8 MiB, most of it a hole.
image_cached() {
    local u=$1 f n
    rm -f "$T/fx.c.lime" "$T/fx.c.raw" "$T/fx.c.avml"
    "$u" image "$T/fx.iomem" "$T/fx.elf" lime "$T/fx.c.lime" raw "$T/fx.c.raw" avml "$T/fx.c.avml" > "$T/fx.c.txt" || { cat "$T/fx.c.txt"; return 1; }
    [ "$(grep -c ' direct writes$' "$T/fx.c.txt")" = 3 ] || { echo "not every file was written with direct writes:"; cat "$T/fx.c.txt"; return 1; }
    [ "$(grep -c '^[a-z]* [01] of [0-9]* pages in the page cache after its writes$' "$T/fx.c.txt")" = 3 ] ||
        { echo "pages of an image in the page cache after its direct writes:"; cat "$T/fx.c.txt"; return 1; }
    for f in lime raw avml; do
        n=$("$u" cached "$T/fx.c.$f") || return 1
        case $n in
        "0 of "*) ;;
        *) echo "memory.$f after its pages were let go: $n"; return 1 ;;
        esac
    done
    # the measure itself: a file that was written in the usual way lies in the cache
    cat "$T/fx.c.lime" > "$T/fx.c.copy"
    n=$("$u" cached "$T/fx.c.copy")
    [ "${n%% *}" -gt 1 ] || { echo "a file written in the usual way: $n"; return 1; }
    rm -f "$T/fx.c.lime" "$T/fx.c.raw" "$T/fx.c.avml" "$T/fx.c.copy"
}
# A file system without direct writes: the images are the same files, written through the cache.
RAMFS=
image_ramfs() {
    local u=$1 r=0
    mkdir -p "$T/ram" && $SUDO mount -t ramfs none "$T/ram" && RAMFS=$T/ram || { echo "a ramfs cannot be mounted"; return 1; }
    $SUDO chmod 1777 "$T/ram"
    KEEP_WAY="through the page cache" python3 -I "$T/image.py" "$u" "$T/ram" formats || r=1
    $SUDO umount "$T/ram" && RAMFS=
    return $r
}
printf '100000000-1007fffff : System RAM\n' > "$T/fx.iomem"
if [ "$(id -u)" = 0 ]; then SUDO=; ROOT=1; elif sudo -n true 2> /dev/null; then SUDO="sudo -n"; ROOT=1; else SUDO=; ROOT=0; fi
for u in "${UNITS[@]}"; do
    check "image: ${u##*/} writes the LiME and the raw image that the formats define, each byte of RAM once, and a compressed image that reads as the same memory" python3 -I "$T/image.py" "$u" "$T" formats
    if [ "$KEEP_WAY" = "direct writes" ] && [ -f "$T/fx.elf" ]; then
        check "image: ${u##*/} leaves no page of an image in the page cache but its last: direct writes" image_cached "$u"
    else
        skip "image: the page cache after an image (the temporary directory is on $(stat -f -c %T "$T"), not on ext4, xfs or btrfs)"
    fi
    if [ "$ROOT" = 1 ]; then
        check "image: ${u##*/} writes the same files on a ramfs, which has no direct writes, through the page cache" image_ramfs "$u"
    else
        skip "image: on a file system without direct writes (root, or sudo without a password, to mount a ramfs)"
    fi
    check "image: ${u##*/} writes Snappy streams that decode to their data, of zeros, random bytes and text that repeats" python3 -I "$T/image.py" "$u" "$T" streams
    if [ -n "${AVML:-}" ] && [ -x "$AVML" ]; then
        check "image: AVML converts what ${u##*/} wrote: the compressed image to the LiME image of its blocks, the LiME image to the raw one" python3 -I "$T/image.py" "$u" "$T" formats "$AVML"
    else
        skip "image: against AVML itself (AVML=/path/to/avml, the release binary that tests/get-avml.sh fetches)"
    fi
    check "image: ${u##*/} refuses what it cannot place: no addresses, no RAM, no core, a kernel before 4.12" python3 -I "$T/image.py" "$u" "$T" refused
    check "image: ${u##*/} reads cores and texts with changed bytes without a fault" python3 -I "$T/image.py" "$u" "$T" changed
    if [ -x tests/keyscan ] && [ -f "$T/fx.elf" ]; then
        check "image: ${u##*/} writes a LiME image of the fixture that holds its schedules at their addresses" image_fixture "$u"
    else
        skip "image: the fixture of the scanner (make, musl-gcc and cc)"
    fi
done

# ---- system --------------------------------------------------------------------------------------
# Lines as the kernel writes them (Documentation/filesystems/proc.rst, 3.5): optional fields
# before the hyphen, a space in a mount point as \040, two mounts at one place.
mkdir -p "$T/sys/efi" "$T/sys/noefi"
cat > "$T/sys/mountinfo" <<'EOF'
22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro
30 22 0:26 / /run rw,nosuid shared:5 - tmpfs tmpfs rw,size=800000k
40 22 8:17 / /mnt/usb rw,relatime shared:9 master:3 - vfat /dev/sdb1 rw,fmask=0022
41 22 8:18 / /mnt/usb\040two ro,relatime - exfat /dev/sdb2 rw
42 22 8:19 / /mnt/usbstick rw - ext4 /dev/sdb3 rw
43 22 8:33 / /mnt/usb rw,relatime - ext4 /dev/sdc1 rw
44 22 253:3 / /home rw - btrfs /dev/mapper/name\040with\040space rw,subvol=/home
EOF
cat > "$T/sys/mounts" <<'EOF'
/dev/sda2 / ext4 rw 0 0
tank /tank zfs rw 0 0
/home/u/.Private /home/u ecryptfs rw 0 0
gocryptfs /mnt/a fuse.gocryptfs rw 0 0
tank/b /tank/b zfs rw 0 0
sshfs /mnt/s fuse.sshfs rw 0 0
EOF
printf '/dev/sda2 / ext4 rw 0 0\n' > "$T/sys/mounts-plain"
printf 'none [integrity] confidentiality\n' > "$T/sys/lockdown"
printf 'MemFree:         1000 kB\nMemTotal:       16473800 kB\nMemAvailable:   15000000 kB\n' > "$T/sys/meminfo"
# a variable of efivarfs: four bytes of attributes, then the value
printf '\006\000\000\000\001' > "$T/sys/efi/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
printf 'NAME="Test"\nPRETTY_NAME="Test Linux 1 (One)"\nID=test\n' > "$T/sys/os-release"
# /sys as the kernel lays it out for a LUKS volume that carries three logical volumes: each
# device has its directory, a link to it by its number, and the devices that stand on it in
# holders/. They are made in an order that is not the order of their names.
blockdev() {    # blockdev KERNELNAME MAJOR:MINOR MAPPINGNAME [BELOW]
    mkdir -p "$T/sys/tree/devices/virtual/block/$1/dm" "$T/sys/tree/devices/virtual/block/$1/holders" "$T/sys/tree/dev/block"
    printf '%s\n' "$2" > "$T/sys/tree/devices/virtual/block/$1/dev"
    printf '%s\n' "$3" > "$T/sys/tree/devices/virtual/block/$1/dm/name"
    ln -s "../../devices/virtual/block/$1" "$T/sys/tree/dev/block/$2"
    [ -z "${4:-}" ] || ln -s "../../$1" "$T/sys/tree/devices/virtual/block/$4/holders/$1"
}
blockdev dm-0 253:0 kc_pv
blockdev dm-9 253:9 vg-home dm-0
blockdev dm-2 253:2 vg-root dm-0
blockdev dm-10 253:10 vg-data dm-0
blockdev dm-11 253:11 on-data dm-10
cat > "$T/sys/mountinfo-lvm" <<'EOF'
22 1 253:2 / / rw - ext4 /dev/mapper/vg-root rw
23 22 253:9 / /home rw - ext4 /dev/mapper/vg-home rw
24 22 253:10 / /data rw - xfs /dev/mapper/vg-data rw
25 22 253:11 / /data/inner\040one rw - ext4 /dev/mapper/on-data rw
26 22 8:1 / /boot rw - ext4 /dev/sda1 rw
EOF
system_parts() {
    local u=$1 r=0
    # expect WHAT WANTED COMMAND... : the output of the command must be the wanted line
    expect() { local what=$1 want=$2 got; shift 2; got=$("$@" 2>&1); [ "$got" = "$want" ] || { echo "$what: got '$got', expected '$want'"; r=1; }; }
    expect "the root"                       "/dev/sda2 (ext4) mounted at /"                 "$u" mount-of "$T/sys/mountinfo" /
    expect "a path below the root"          "/dev/sda2 (ext4) mounted at /"                 "$u" mount-of "$T/sys/mountinfo" /var/tmp
    expect "optional fields are passed"     "tmpfs (tmpfs) mounted at /run"                 "$u" mount-of "$T/sys/mountinfo" /run/x
    expect "the later of two mounts at one place" "/dev/sdc1 (ext4) mounted at /mnt/usb"    "$u" mount-of "$T/sys/mountinfo" /mnt/usb/case
    expect "a mount point with a space"     "/dev/sdb2 (exfat) mounted at /mnt/usb two, read-only" "$u" mount-of "$T/sys/mountinfo" "/mnt/usb two/x"
    expect "a name that only begins alike"  "/dev/sdb3 (ext4) mounted at /mnt/usbstick"     "$u" mount-of "$T/sys/mountinfo" /mnt/usbstick
    expect "a sibling of a mount point"     "/dev/sda2 (ext4) mounted at /"                 "$u" mount-of "$T/sys/mountinfo" /mnt/usbother
    expect "a source with a space"          "/dev/mapper/name with space (btrfs) mounted at /home" "$u" mount-of "$T/sys/mountinfo" /home/u
    expect "no mount table"                 "none"                                          "$u" mount-of "$T/sys/missing" /
    # in the order of the names in holders/, as a shell lists them: dm-10, what stands on it, dm-2, dm-9
    expect "what a volume carries"          "[vg-data at /data, on-data at /data/inner one, vg-root at /, vg-home at /home]" \
        "$u" in-use "$T/sys/tree" "$T/sys/mountinfo-lvm" /dev/null 253 0
    expect "what a logical volume carries"  "[vg-home at /home]"                            "$u" in-use "$T/sys/tree" "$T/sys/mountinfo-lvm" /dev/null 253 9
    expect "a device that /sys does not know" "[unknown]"                                   "$u" in-use "$T/sys/tree" "$T/sys/mountinfo-lvm" /dev/null 8 1
    expect "a mount table that is not there" "[unknown]"                                    "$u" in-use "$T/sys/tree" "$T/sys/missing" /dev/null 253 9
    expect "no file of the swap spaces"     "[vg-home at /home]"                            "$u" in-use "$T/sys/tree" "$T/sys/mountinfo-lvm" "$T/sys/missing" 253 9
    expect "file systems that encrypt"      "[ecryptfs fuse.gocryptfs zfs]"                 "$u" other-fs "$T/sys/mounts"
    expect "none that encrypts"             "[]"                                            "$u" other-fs "$T/sys/mounts-plain"
    expect "the lockdown mode"              "[integrity]"                                   "$u" lockdown "$T/sys/lockdown"
    expect "no lockdown file"               "[]"                                            "$u" lockdown "$T/sys/missing"
    expect "SecureBoot enabled"             "[1]"                                           "$u" secure-boot "$T/sys/efi"
    expect "no SecureBoot variable"         "[]"                                            "$u" secure-boot "$T/sys/noefi"
    expect "no efivars"                     "[]"                                            "$u" secure-boot "$T/sys/missing"
    expect "the name of the system"         "[Test Linux 1 (One)]"                          "$u" os-name "$T/sys/os-release" "$T/sys/missing"
    expect "the second os-release"          "[Test Linux 1 (One)]"                          "$u" os-name "$T/sys/missing" "$T/sys/os-release"
    expect "no os-release"                  "[]"                                            "$u" os-name "$T/sys/missing" "$T/sys/missing"
    expect "the memory of the machine"      "[16473800]"                                    "$u" memory "$T/sys/meminfo"
    expect "no line MemTotal"               "[unknown]"                                     "$u" memory "$T/sys/os-release"
    expect "no meminfo"                     "[unknown]"                                     "$u" memory "$T/sys/missing"
    expect "a plain name"                   "[kc_l2] [kc_l2]"                               "$u" names kc_l2
    expect "a name that leaves the folder"  "[../../etc/x] [_._.._etc_x]"                   "$u" names ../../etc/x
    expect "a name of two points"           "[..] [_.]"                                     "$u" names ..
    expect "a name that begins with a point" "[.hidden] [_hidden]"                          "$u" names .hidden
    expect "a name with an escape sequence" "[a [31m b] [a__31m_b]"                         "$u" names "$(printf 'a\033[31m b')"
    expect "the characters that are kept"   "[A.z_0+=@,-] [A.z_0+=@,-]"                     "$u" names "A.z_0+=@,-"
    expect "an empty name"                  "[] [_]"                                        "$u" names ""
    return $r
}
# The memory of a run is locked, so what is allocated is taken from the free memory of the
# machine at once. A text file is read into memory that grows with it, and a string of JSON
# has the memory of its own bytes: under a limit of the address space of 64 MiB a file of
# 4 MiB must be read with a maximum of 256 MiB, and under one of 200 MiB metadata of 20000
# members in 269 KiB. Before 2.0-pre12 the first allocated its maximum and the second the rest
# of the text for each string, which needed 5.4 GiB for those metadata. The build with the sanitizers
# needs more address space than such a limit leaves, and is given the same without one.
frugal() {
    local u=$1 r=0 out limit=1
    case $u in *-san) limit=0 ;; esac
    head -c 3000000 /dev/urandom | base64 > "$T/big.txt"
    python3 -I -c 'import json, sys; open(sys.argv[1], "w").write(json.dumps({str(i): "v" for i in range(20000)}))' "$T/many.json"
    out=$( [ "$limit" = 0 ] || ulimit -v 65536; "$u" text "$T/big.txt" 268435456 )
    [ "$out" = "$(wc -c < "$T/big.txt") bytes, sha256 $(sha256sum < "$T/big.txt" | cut -d' ' -f1)" ] || { echo "a text of 4 MiB: $out"; r=1; }
    out=$("$u" text "$T/big.txt" 1000)
    [ "$out" = "1000 bytes, sha256 $(head -c 1000 "$T/big.txt" | sha256sum | cut -d' ' -f1)" ] || { echo "the first 1000 bytes of it: $out"; r=1; }
    ( [ "$limit" = 0 ] || ulimit -v 200000; "$u" json < "$T/many.json" > "$T/many.out" ) || { echo "metadata of 20000 members are not read"; r=1; }
    python3 -I -c 'import json, sys; sys.exit(0 if json.load(open(sys.argv[1])) == json.load(open(sys.argv[2])) else 1)' "$T/many.json" "$T/many.out" ||
        { echo "metadata of 20000 members are read as something else"; r=1; }
    # a write that failed inside a stream, and a flush of what came after it that succeeds
    out=$("$u" written "$T/written.txt")
    [ "$out" = "fflush 0, ferror 1, written -1" ] || { echo "a write that failed and a flush that did not: $out"; r=1; }
    return $r
}
for u in "${UNITS[@]}"; do
    check "system: ${u##*/} reads mounts, lockdown, SecureBoot and os-release, and makes names safe" system_parts "$u"
    check "system: ${u##*/} reads a text and metadata into the memory they need, and takes a write that failed for one after a flush that did not" frugal "$u"
done

# Where a line of the screen is broken. The two first cases are lines of runs by hand on
# installed guests, which 2.0-pre9 broke between a number and its unit and before a last word.
line_breaks() {
    local u=$1 r=0
    # broken LABEL TEXT: the lines of standard input are what the screen must give
    broken() {
        "$u" line "$1" "$2" > "$T/line.txt" 2>&1 && cmp -s - "$T/line.txt" ||
            { echo "the line of '$1': not broken as expected"; cat "$T/line.txt"; r=1; }
    }
    broken destination "/dev/mapper/ubuntu--vg-ubuntu--lv, ext4, mounted at /, 6.65 GiB free" <<'EOF'
  destination  /dev/mapper/ubuntu--vg-ubuntu--lv, ext4, mounted at /,
               6.65 GiB free
EOF
    broken header "headers/a-mapping-with-a-name-of-some-length-on-this-system.hdr, 16777216 bytes" <<'EOF'
  header       headers/a-mapping-with-a-name-of-some-length-on-this-system.hdr,
               16777216 bytes
EOF
    # a number in the last column stays with its unit, and one before the break is left alone
    broken note "every pair of the 90 keys of the image was tried, which were 5108 attempts in 510 s" <<'EOF'
  note         every pair of the 90 keys of the image was tried, which were
               5108 attempts in 510 s
EOF
    # a line that 2.0-pre9 broke well is broken as before
    broken headers "none: no file with a LUKS header is given and the dump itself holds none, so nothing can be proven here" <<'EOF'
  headers      none: no file with a LUKS header is given and the dump itself
               holds none, so nothing can be proven here
EOF
    # numbers alone: there is no other place, so the last space in the width is taken
    broken note "1234567890 1234567890 1234567890 1234567890 1234567890 1234567890 1234567890 words" <<'EOF'
  note         1234567890 1234567890 1234567890 1234567890 1234567890 1234567890
               1234567890 words
EOF
    # a last word that fits no line with the one before it stands alone, as long as it is
    broken image "the image of the memory was written into the folder of this run, as /a/path/that/is/longer/than/a/line/of/the/screen/can/hold/memory.lime" <<'EOF'
  image        the image of the memory was written into the folder of this run,
               as
               /a/path/that/is/longer/than/a/line/of/the/screen/can/hold/memory.lime
EOF
    # a text that fits is one line, and spaces at its end are not printed
    broken key "keys/dm_crypt-0.vk, 64 bytes  " <<'EOF'
  key          keys/dm_crypt-0.vk, 64 bytes
EOF
    # 400 texts of words, numbers and paths, broken here by the rule as it is said and not as
    # the program computes it: the same lines
    python3 -I - "$u" <<'EOF' || r=1
import random, subprocess, sys

WIDTH, HANG = 80, 15
def number(w):
    return any(c.isdigit() for c in w) and all(c in "0123456789." for c in w)
def before_no_number(words, k):                 # the most words up to K that do not end with a number
    while k and number(words[k - 1]):
        k -= 1
    return k
def lines(words):
    out, room = [], WIDTH - HANG
    while words:
        if len(" ".join(words)) <= room:
            out.append(words)
            break
        k = 0
        while len(" ".join(words[:k + 1])) <= room:
            k += 1
        if k == 0:                              # a word that fits no line stands alone
            k = 1
        else:
            j = before_no_number(words, k)
            if j == 0:
                j = k                           # numbers only: no other place
            elif j == k and k == len(words) - 1:
                p = before_no_number(words, k - 1)
                if p and len(" ".join(words[p:])) <= room:
                    j = p                       # the last word is not left alone
            k = j
        out.append(words[:k])
        words = words[k:]
    return out

rnd = random.Random(20261126)
plain = ["a", "of", "the", "key", "image", "schedules", "bytes", "GiB", "free", "s", "written,", "proven,",
         "/proc/kcore,", "headers/name.hdr,", "0x10b695830", "sha256", "attempt", "in", "at", "mounted"]
figures = ["1", "64", "510", "6.65", "16777216", "4274352352", "3.30"]
long_word = "/a/path/that/is/longer/than/a/line/of/the/screen/can/hold/in/its/width/memory.lime"
for n in range(400):
    words = [rnd.choice(figures) if rnd.random() < 0.3 else long_word if rnd.random() < 0.03 else rnd.choice(plain)
             for i in range(rnd.randint(1, 45))]
    want = "".join(("  note         " if i == 0 else " " * HANG) + " ".join(l) + "\n" for i, l in enumerate(lines(words)))
    got = subprocess.run([sys.argv[1], "line", "note", " ".join(words)], capture_output=True, text=True)
    if got.returncode or got.stdout != want:
        sys.exit("text %d is not broken by the rule:\n%s\nwanted:\n%s" % (n, got.stdout + got.stderr, want))
EOF
    return $r
}
for u in "${UNITS[@]}"; do
    check "screen: ${u##*/} breaks a long line at a space, parts no number from its unit and leaves no word alone at the end" line_breaks "$u"
done

# ---- headers -------------------------------------------------------------------------------------
if ! have cryptsetup; then
    skip "headers: against cryptsetup (cryptsetup)"
    finish
fi
# the option that hands a volume key to cryptsetup: renamed in release 2.5.0
if cryptsetup --help 2>&1 | grep -q -e '--volume-key-file'; then VK=--volume-key-file; else VK=--master-key-file; fi
head -c 64 /dev/urandom > "$T/k64"; head -c 32 /dev/urandom > "$T/k32"; head -c 64 /dev/urandom > "$T/other"
printf 'unit-check\n' > "$T/pass"
# container NAME KEYFILE OPTIONS... : a container of 32 MiB with that volume key
container() {
    local name=$1 key=$2; shift 2
    truncate -s 32M "$T/$name.img" &&
        cryptsetup luksFormat -q "$@" "$VK" "$T/$key" --pbkdf-force-iterations 1000 "$T/$name.img" "$T/pass" 2> "$T/$name.err"
}
HEADERS=()
made() { if container "$@"; then HEADERS+=("$1:$2"); else fail "headers: cryptsetup could not make $1"; sed 's/^/      /' "$T/$1.err"; fi; }
made l1      k64 --type luks1 --cipher aes-xts-plain64 --key-size 512
made l1sha1  k32 --type luks1 --cipher aes-cbc-essiv:sha256 --key-size 256 --hash sha1
made l1s512  k64 --type luks1 --cipher aes-xts-plain64 --key-size 512 --hash sha512
made l2      k64 --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf pbkdf2
made l2s512  k64 --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf pbkdf2 --hash sha512
made l2k256  k32 --type luks2 --cipher aes-xts-plain64 --key-size 256 --pbkdf pbkdf2
made l2big   k64 --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf pbkdf2 --luks2-metadata-size 64k --luks2-keyslots-size 4m
# both erased: the keyslots are gone and the digest stays
for n in l1 l2; do
    cp "$T/$n.img" "$T/${n}e.img" && cryptsetup erase -q "$T/${n}e.img" 2> /dev/null && HEADERS+=("${n}e:k64") ||
        fail "headers: cryptsetup could not erase the keyslots of $n"
done

# one_header UNIT NAME KEYFILE : the copy and the proof of one header against cryptsetup
one_header() {
    local u=$1 n=$2 key=$3 r=0 bits
    rm -f "$T/ours.hdr" "$T/theirs.hdr"
    cryptsetup luksHeaderBackup "$T/$n.img" --header-backup-file "$T/theirs.hdr" || { echo "cryptsetup made no backup"; return 1; }
    "$u" luks "$T/$n.img" || r=1
    "$u" luks-backup "$T/$n.img" "$T/ours.hdr" || r=1
    cmp "$T/ours.hdr" "$T/theirs.hdr" || { echo "the copy differs from the file of luksHeaderBackup"; r=1; }
    # cryptsetup and this program must agree on the right key and on another one
    # a header without keyslots does not state the size of its key, so cryptsetup is told
    bits=$(( $(wc -c < "$T/$key") * 8 ))
    cryptsetup open --test-passphrase --key-size "$bits" "$VK" "$T/$key" "$T/theirs.hdr" || { echo "cryptsetup refuses the key"; r=1; }
    "$u" luks-prove "$T/$n.img" "$T/$key" || { echo "the key is not proven"; r=1; }
    "$u" luks-prove "$T/ours.hdr" "$T/$key" || { echo "the key is not proven against the copy"; r=1; }
    if cryptsetup open --test-passphrase --key-size 512 "$VK" "$T/other" "$T/theirs.hdr" 2> /dev/null; then echo "cryptsetup accepts another key"; r=1; fi
    if "$u" luks-prove "$T/$n.img" "$T/other"; then echo "another key is proven"; r=1; fi
    return $r
}
# Every check of a header is run twice: past the page cache, as the program reads a device and
# writes its copy where they take direct reads and writes, and through it (KEEP_UNIT_CACHE), as
# it does elsewhere. The temporary directory decides whether the first way is the direct one.
header_ways() {         # header_ways NAME FUNCTION ARGUMENT... : a check, once for each way
    local name=$1; shift
    unset KEEP_UNIT_CACHE
    check "$name, past the page cache" "$@"
    export KEEP_UNIT_CACHE=1
    check "$name, through the page cache" "$@"
    unset KEEP_UNIT_CACHE
}
for u in "${UNITS[@]}"; do
    for h in "${HEADERS[@]}"; do
        header_ways "headers: ${u##*/}, ${h%%:*}: the copy equals luksHeaderBackup, the key is proven and another is not" \
            one_header "$u" "${h%%:*}" "${h##*:}"
    done
done

# A hash function that is not computed here: the copy is made, and the proof says which function.
other_hash() {
    local u=$1
    rm -f "$T/ours.hdr" "$T/theirs.hdr"
    cryptsetup luksHeaderBackup "$T/l1rmd.img" --header-backup-file "$T/theirs.hdr" || return 1
    "$u" luks-backup "$T/l1rmd.img" "$T/ours.hdr" && cmp "$T/ours.hdr" "$T/theirs.hdr" || return 1
    "$u" luks-prove "$T/l1rmd.img" "$T/k64" | tee "$T/prove.txt"
    grep -q 'no digest that is computed here.*ripemd160' "$T/prove.txt"
}
# A header can state up to 4294967295 iterations for its digest, and one attempt with that many
# takes from minutes to hours. Such a digest is named as one that is not computed here, at
# once, and the copy of the header is made all the same.
costly() {
    local u=$1 out rc
    python3 -I -c 'import sys
d = bytearray(open(sys.argv[1], "rb").read()); d[164:168] = b"\xff\xff\xff\xff"; open(sys.argv[2], "wb").write(d)' "$T/l1.img" "$T/l1huge.img" || return 1
    rm -f "$T/ours.hdr"
    "$u" luks-backup "$T/l1huge.img" "$T/ours.hdr" > /dev/null && cmp -s <(head -c 2066432 "$T/l1huge.img") <(head -c 2066432 "$T/ours.hdr") ||
        { echo "the copy of the header is not made"; return 1; }
    out=$(timeout 20 "$u" luks-prove "$T/l1huge.img" "$T/k64"); rc=$?
    [ "$rc" = 1 ] && [ "$out" = "no digest that is computed heresha256 with 4294967295 iterations" ] || { echo "status $rc: $out"; return 1; }
}
for u in "${UNITS[@]}"; do header_ways "headers: ${u##*/}, a digest of 4294967295 iterations is named as not computed, and not begun" costly "$u"; done
if container l1rmd k64 --type luks1 --cipher aes-xts-plain64 --key-size 512 --hash ripemd160; then
    for u in "${UNITS[@]}"; do header_ways "headers: ${u##*/}, a LUKS1 header with ripemd160 is copied, and its proof is named as not computed" other_hash "$u"; done
else
    skip "headers: a LUKS1 header with ripemd160 (this cryptsetup makes none)"
fi

# The first copy of a LUKS2 header damaged in three ways. cryptsetup would write it anew from
# the second copy. Here the file must be read from the second copy and stay as it is.
damaged() {
    local u=$1 how=$2 before after
    cp "$T/l2.img" "$T/dmg.img" || return 1
    case $how in
        magic)    printf 'XXXXXX' | dd of="$T/dmg.img" conv=notrunc status=none ;;
        zeros)    dd if=/dev/zero of="$T/dmg.img" bs=4096 count=1 conv=notrunc status=none ;;
        metadata) printf 'X' | dd of="$T/dmg.img" bs=1 seek=5000 conv=notrunc status=none ;;
    esac
    before=$(sha256sum < "$T/dmg.img")
    "$u" luks "$T/dmg.img" | tee "$T/luks.txt"
    grep -q '^LUKS2 .*second copy in use' "$T/luks.txt" || { echo "the second copy is not the one in use"; return 1; }
    "$u" luks-prove "$T/dmg.img" "$T/k64" || { echo "the key is not proven from the second copy"; return 1; }
    if "$u" luks-prove "$T/dmg.img" "$T/other"; then echo "another key is proven"; return 1; fi
    after=$(sha256sum < "$T/dmg.img")
    [ "$before" = "$after" ] || { echo "the file was changed"; return 1; }
}
# Both copies damaged, and files that end early: named, never read as a header, and no crash.
unusable() {
    local u=$1 r=0 n f out rc want whole
    cp "$T/l2.img" "$T/both.img" && printf 'X' | dd of="$T/both.img" bs=1 seek=5000 conv=notrunc status=none &&
        printf 'X' | dd of="$T/both.img" bs=1 seek=$(( 16384 + 5000 )) conv=notrunc status=none || return 1
    out=$("$u" luks "$T/both.img"); [ $? = 1 ] && [ "${out%%:*}" = damaged ] || { echo "both copies damaged: $out"; r=1; }
    for n in 0 5 6 100 591 592 1023 1024 4095 4096 5000 16383 16384 20000 32767 32768 40000; do
        for f in l1 l2; do
            head -c "$n" "$T/$f.img" > "$T/cut.img"
            out=$("$u" luks "$T/cut.img" 2>&1); rc=$?
            # a LUKS1 header is whole after 1024 bytes and a copy of this LUKS2 header after 16384
            case $f in l1) whole=1024 ;; *) whole=16384 ;; esac
            if [ "$n" -ge "$whole" ]; then want=0; else want=1; fi
            [ "$rc" = "$want" ] || { echo "$f cut to $n bytes: status $rc, expected $want: $out"; r=1; }
            rm -f "$T/cut.hdr"
            "$u" luks-backup "$T/cut.img" "$T/cut.hdr" > "$T/cutb.txt" 2>&1; rc=$?
            [ "$rc" = 1 ] || { echo "$f cut to $n bytes: a copy was made, status $rc"; r=1; }
        done
    done
    head -c 4096 /dev/urandom > "$T/noise.img"
    out=$("$u" luks "$T/noise.img"); [ $? = 1 ] && [ "${out%%:*}" = none ] || { echo "random bytes: $out"; r=1; }
    return $r
}
uuid_rule() {   # the UUID of a mapping against the header, as crypt_uuid_cmp of cryptsetup
    "$1" luks "$T/l2.img" | grep -q '^LUKS2 uuid ........-....-....-....-............ area 16777216$'
}
# The page cache after a header was read and copied. With direct reads and writes no page of
# the container and none of the copy may lie in it, also after the copy was read back for the
# proof. Through the cache the count must find the pages of both, so that a count of none says
# something.
header_cached() {
    local u=$1 n
    rm -f "$T/ours.hdr"
    "$u" forget "$T/l2.img" || return 1
    n=$("$u" cached "$T/l2.img"); [ "${n%% *}" = 0 ] || { echo "the container is not let go from the page cache: $n"; return 1; }
    "$u" luks-backup "$T/l2.img" "$T/ours.hdr" > "$T/way.txt" || { cat "$T/way.txt"; return 1; }
    grep -qx 'read with direct reads' "$T/way.txt" &&
        grep -qx 'written with direct writes, 0 of 4096 pages in the page cache after its writes' "$T/way.txt" ||
        { echo "the header was not read and copied past the page cache:"; cat "$T/way.txt"; return 1; }
    "$u" luks-prove "$T/ours.hdr" "$T/k64" || return 1
    n=$("$u" cached "$T/l2.img"); [ "${n%% *}" = 0 ] || { echo "the container after the direct reads: $n"; return 1; }
    n=$("$u" cached "$T/ours.hdr"); [ "${n%% *}" = 0 ] || { echo "the copy after its direct writes and the direct reads of the proof: $n"; return 1; }
    rm -f "$T/ours.hdr"
    KEEP_UNIT_CACHE=1 "$u" luks-backup "$T/l2.img" "$T/ours.hdr" > "$T/way.txt" || { cat "$T/way.txt"; return 1; }
    grep -qx 'read through the page cache' "$T/way.txt" &&
        grep -qx 'written through the page cache, 4096 of 4096 pages in the page cache after its writes' "$T/way.txt" ||
        { echo "the count of the copy that was written in the usual way:"; cat "$T/way.txt"; return 1; }
    n=$("$u" cached "$T/l2.img"); [ "${n%% *}" -ge 4096 ] || { echo "the container after a read in the usual way: $n"; return 1; }
}
# A file system without direct reads and writes: the same copy, through the cache, and said so.
header_ramfs() {
    local u=$1 r=0 f
    mkdir -p "$T/ram" && $SUDO mount -t ramfs none "$T/ram" && RAMFS=$T/ram || { echo "a ramfs cannot be mounted"; return 1; }
    $SUDO chmod 1777 "$T/ram"
    for f in l1 l2; do
        cp "$T/$f.img" "$T/ram/$f.img" && cryptsetup luksHeaderBackup "$T/$f.img" --header-backup-file "$T/ram/$f.theirs" || r=1
        "$u" luks-backup "$T/ram/$f.img" "$T/ram/$f.ours" > "$T/way.txt" || r=1
        cmp "$T/ram/$f.ours" "$T/ram/$f.theirs" || { echo "$f: the copy differs from the file of luksHeaderBackup"; r=1; }
        grep -qx 'read through the page cache' "$T/way.txt" && grep -q '^written through the page cache, ' "$T/way.txt" ||
            { echo "$f: not named as read and written through the page cache:"; cat "$T/way.txt"; r=1; }
        "$u" luks-prove "$T/ram/$f.ours" "$T/k64" || { echo "$f: the key is not proven against the copy"; r=1; }
    done
    $SUDO umount "$T/ram" && RAMFS=
    return $r
}
# A block device, which is what the program reads the header of a volume from. The kernel
# drops the cache of a device when its last opener closes it (blkdev_flush_mapping in
# block/bdev.c of Linux 6.12, __blkdev_put in fs/block_dev.c of 4.18), and dm-crypt holds the
# device of an open volume. So this shell holds a loop device on the container open: direct
# reads add no page of it to the cache, and reads in the usual way the pages of the header.
# A device that is new is read by the system itself, which looks at what it holds (udev), and
# a page that is in use at that moment stays: on a runner of the pipeline one page of 8192
# did. So the system is given time to end that, and the pages are counted before and after.
LOOPDEV=
header_device() {
    local u=$1 r=0 n before
    rm -f "$T/ours.hdr" "$T/theirs.hdr"
    cryptsetup luksHeaderBackup "$T/l2.img" --header-backup-file "$T/theirs.hdr" || return 1
    LOOPDEV=$($SUDO losetup -f --show "$T/l2.img") && $SUDO chmod 666 "$LOOPDEV" && exec 9< "$LOOPDEV" ||
        { echo "no loop device on the container"; return 1; }
    if have udevadm; then $SUDO udevadm settle 2> /dev/null; fi
    "$u" forget "$LOOPDEV" || r=1
    n=$("$u" cached "$LOOPDEV"); before=${n%% *}
    [ "$before" -le 16 ] || { echo "the device is not let go from the page cache: $n"; r=1; }
    "$u" luks-backup "$LOOPDEV" "$T/ours.hdr" > "$T/way.txt" || r=1
    grep -qx 'read with direct reads' "$T/way.txt" || { echo "the device was not read with direct reads:"; cat "$T/way.txt"; r=1; }
    "$u" luks-prove "$LOOPDEV" "$T/k64" || r=1
    n=$("$u" cached "$LOOPDEV"); [ "${n%% *}" -le "$before" ] || { echo "the device after the direct reads: $n, and $before pages before them"; r=1; }
    cmp "$T/ours.hdr" "$T/theirs.hdr" || { echo "the copy differs from the file of luksHeaderBackup"; r=1; }
    rm -f "$T/ours.hdr"
    KEEP_UNIT_CACHE=1 "$u" luks-backup "$LOOPDEV" "$T/ours.hdr" > "$T/way.txt" || r=1
    n=$("$u" cached "$LOOPDEV"); [ "${n%% *}" -ge 4096 ] || { echo "the device after reads in the usual way: $n"; r=1; }
    cmp "$T/ours.hdr" "$T/theirs.hdr" || { echo "the copy through the page cache differs from the file of luksHeaderBackup"; r=1; }
    exec 9<&-
    $SUDO losetup -d "$LOOPDEV" && LOOPDEV=
    return $r
}
# A file system without room for the copy: the write fails, and it is named as a write that
# failed, which is what makes a run end with status 1 and take the part away again.
header_full() {
    local u=$1 r=0
    mkdir -p "$T/ram" && $SUDO mount -t tmpfs -o size=1m,mode=1777 none "$T/ram" && RAMFS=$T/ram || { echo "a tmpfs cannot be mounted"; return 1; }
    "$u" luks-backup "$T/l2.img" "$T/ram/ours.hdr" > "$T/way.txt" 2>&1 && { echo "a copy of 16 MiB was made in 1 MiB"; r=1; }
    grep -q '^failed at a write: write of the copy of the header: No space left on device$' "$T/way.txt" ||
        { echo "not named as a write that failed for lack of room:"; cat "$T/way.txt"; r=1; }
    $SUDO umount "$T/ram" && RAMFS=
    return $r
}
for u in "${UNITS[@]}"; do
    for how in magic zeros metadata; do
        header_ways "headers: ${u##*/}, first copy damaged ($how): read from the second copy, proven, the file unchanged" damaged "$u" "$how"
    done
    header_ways "headers: ${u##*/}, both copies damaged, files that end early and random bytes are named and not read" unusable "$u"
    check "headers: ${u##*/}, a default LUKS2 header has an area of 16 MiB" uuid_rule "$u"
    if [ "$KEEP_WAY" = "direct writes" ]; then
        check "headers: ${u##*/} leaves no page of a header or of its copy in the page cache: direct reads and writes" header_cached "$u"
    else
        skip "headers: the page cache after a header was copied (the temporary directory is on $(stat -f -c %T "$T"), not on ext4, xfs or btrfs)"
    fi
    if [ "$ROOT" = 1 ]; then
        check "headers: ${u##*/} makes the same copy on a ramfs, which has no direct reads and writes, through the page cache" header_ramfs "$u"
    else
        skip "headers: on a file system without direct reads and writes (root, or sudo without a password, to mount a ramfs)"
    fi
    if [ "$ROOT" = 1 ]; then
        check "headers: ${u##*/} names a copy that the file system has no room for as a write that failed" header_full "$u"
    else
        skip "headers: on a file system without room for the copy (root, or sudo without a password, to mount a tmpfs)"
    fi
    if [ "$ROOT" = 1 ] && have losetup; then
        check "headers: ${u##*/} reads the header of a block device that is held open past the page cache, and leaves no page of it there" header_device "$u"
    else
        skip "headers: on a block device (root, or sudo without a password, and losetup, for a loop device)"
    fi
done

# A header in re-encryption has two volume keys and a digest for each, and a third digest that
# belongs to no data segment. cryptsetup accepts neither key alone for such a header, so the
# digests are computed here once more by hashlib, from the metadata of the header.
cat > "$T/digests.py" <<'EOF'
import base64, hashlib, json, struct, sys
head = open(sys.argv[1], "rb").read()
size = struct.unpack(">Q", head[8:16])[0]
meta = json.loads(head[4096:size].split(b"\0")[0])
for path in sys.argv[2:]:
    key, gives = open(path, "rb").read(), []
    for number, name in enumerate(d for d in sorted(meta["digests"], key=int) if meta["digests"][d]["segments"]):
        d = meta["digests"][name]
        want = base64.b64decode(d["digest"])
        if hashlib.pbkdf2_hmac(d["hash"], key, base64.b64decode(d["salt"]), d["iterations"], len(want)) == want:
            gives.append(str(number + 1))
    print(" ".join(gives) or "none")
EOF
reencrypted() {
    local u=$1 r=0 out
    rm -f "$T/ours.hdr" "$T/theirs.hdr"
    cryptsetup luksHeaderBackup "$T/re.img" --header-backup-file "$T/theirs.hdr" || { echo "cryptsetup made no backup"; return 1; }
    "$u" luks "$T/re.img" > "$T/re.txt" || r=1
    [ "$(grep -c '^digest ' "$T/re.txt")" = 2 ] || { echo "not two digests of data segments:"; cat "$T/re.txt"; r=1; }
    "$u" luks-backup "$T/re.img" "$T/ours.hdr" || r=1
    cmp "$T/ours.hdr" "$T/theirs.hdr" || { echo "the copy differs from the file of luksHeaderBackup"; r=1; }
    [ "$(python3 -I "$T/digests.py" "$T/re.img" "$T/k64" "$T/knew" "$T/other" | tr '\n' ' ')" = "1 2 none " ] ||
        { echo "hashlib does not give digest 1 for the old key, digest 2 for the new one and none for another"; r=1; }
    out=$("$u" luks-prove "$T/ours.hdr" "$T/k64"); [ "$out" = "proven by digest 1 of 2, proven" ] || { echo "the old key: $out"; r=1; }
    out=$("$u" luks-prove "$T/ours.hdr" "$T/knew"); [ "$out" = "proven by digest 2 of 2, proven" ] || { echo "the new key: $out"; r=1; }
    if "$u" luks-prove "$T/ours.hdr" "$T/other"; then echo "another key is proven"; r=1; fi
    return $r
}
head -c 64 /dev/urandom > "$T/knew"
if cp "$T/l2.img" "$T/re.img" && cryptsetup reencrypt --init-only -q --key-file "$T/pass" "$VK" "$T/knew" \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$T/re.img" 2> "$T/re.err"; then
    for u in "${UNITS[@]}"; do
        header_ways "headers: ${u##*/}, a header in re-encryption: the copy equals luksHeaderBackup, the old and the new key each give their digest" reencrypted "$u"
    done
else
    skip "headers: a header in re-encryption (this cryptsetup starts none on a file: $(head -n 1 "$T/re.err"))"
fi
# ---- dump ----------------------------------------------------------------------------------------
# The search of a dump with the proof. The image holds the schedules of the keys of the headers
# above, as the kernel keeps the two keys of an XTS volume: k64, k32 as two keys of AES-128,
# knew, and k32 once more as one key of AES-256, which is the key of the header with CBC.
{ cat "$T/k32"; head -c 32 /dev/urandom; } > "$T/kcbc"
python3 -I tests/make-schedule-fixture.py --format lime --size 8 "$T/dump.lime" "$T/k64" "$T/k32" "$T/knew" "$T/kcbc" > /dev/null
truncate -s 80M "$T/disk.dd"
dd if="$T/l2.img" of="$T/disk.dd" bs=1M seek=1 conv=notrunc status=none
dd if="$T/l1.img" of="$T/disk.dd" bs=1M seek=36 conv=notrunc status=none
container ot other --type luks2 --cipher aes-xts-plain64 --key-size 512 --pbkdf pbkdf2 2> /dev/null
head -c 4096 /dev/urandom > "$T/noise.bin"
# random bytes with the magic of LUKS at the start of some sectors, as in data that is no header
head -c 1048576 /dev/urandom > "$T/magic.bin"
for at in 3 10 700 2047; do
    printf 'LUKS\272\276\000\00%d' $(( at % 2 + 1 )) | dd of="$T/magic.bin" bs=512 seek="$at" conv=notrunc status=none
done
head -c 3000 "$T/l2.img" > "$T/short.img"
# two schedules of the key k64 that lie apart, as another XTS code than that of AES-NI keeps them
python3 -I - "$T/k64" "$T/apart.raw" <<'EOF'
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("fixture", "tests/make-schedule-fixture.py")
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
key = open(sys.argv[1], "rb").read()
img = bytearray(os.urandom(1 << 20))
img[0x40000:0x40000 + 240] = fixture.expand(key[:32])       # the data key
img[0x90000:0x90000 + 240] = fixture.expand(key[32:])       # the tweak key
open(sys.argv[2], "wb").write(img)
EOF
# A dump with what the memory of a machine can hold of two headers: the first page of the device
# of the LUKS1 header, the metadata of the LUKS2 header with the key of 32 bytes inside other
# bytes, its digests once more across the place where the search of the memory takes its next
# stretch, and text that begins like the digests and is none.
python3 -I tests/make-schedule-fixture.py --format raw --size 8 "$T/mem.raw" "$T/k64" "$T/k32" > /dev/null
cp "$T/mem.raw" "$T/mem-plain.raw"
python3 -I - "$T" > "$T/mem2.at" <<'EOF'
import sys
t = sys.argv[1]
img = bytearray(open(t + "/mem.raw", "rb").read())
meta = open(t + "/l2k256.img", "rb").read(32768)[4096:].split(b"\0", 1)[0]
at = meta.index(b'"digests":{')
img[0x300000:0x301000] = open(t + "/l1.img", "rb").read(4096)
img[0x41f123:0x41f123 + len(meta)] = meta
img[0x1fff00:0x1fff00 + len(meta) - at] = meta[at:]
img[0x500010:0x500010 + 30] = b'"digests":{"0":{"type":"pbkdf2'
img[0x600000:0x600008] = b"LUKS\xba\xbe\x00\x01"
open(t + "/mem.raw", "wb").write(img)
# A dump with the digests of two headers: at the lower address those of a header whose key the
# dump does not hold, as of a volume that was closed, behind them those of a header with a key.
img = bytearray(open(t + "/mem-plain.raw", "rb").read())
gone = open(t + "/ot.img", "rb").read(32768)[4096:].split(b"\0", 1)[0]
img[0x100100:0x100100 + len(gone)] = gone
img[0x41f123:0x41f123 + len(meta)] = meta
open(t + "/mem2.raw", "wb").write(img)
print("0x%x 0x%x" % (0x100100 + gone.index(b'"digests":{') + 10, 0x41f123 + at + 10))
EOF
# verdicts REPORT : "name verdict key..." for each header of a report, by name
verdicts() {
    python3 -I -c 'import json, sys
for v in sorted(json.load(open(sys.argv[1]))["volumes"], key=lambda v: v["name"]):
    print(v["name"], v["verdict"].replace(" ", "-"), v["key_sha256_16"], *[k["key_sha256_16"] for k in v.get("further_keys", [])])' "$1"
}
key16() { sha256sum < "$1" | cut -c1-16; }
dump_proof() {
    local k=$R/$1 r=0 rc d h n key want got
    local -a re=()
    rm -rf "$T/dp"; mkdir "$T/dp" "$T/dp/2" "$T/dp/3" "$T/dp/4" "$T/dp/5" "$T/dp/6" "$T/dp/7"
    # the header in re-encryption, where this cryptsetup made one
    [ -s "$T/re.img" ] && [ ! -s "$T/re.err" ] && re=(re.img)
    # every header, the image of a disk with two of them, one of another key
    ( cd "$T" && umask 022 && "$k" -s dump.lime -d dp l1.img l1sha1.img l1s512.img l2.img l2s512.img l2k256.img l2big.img l1e.img l2e.img \
        "${re[@]}" disk.dd ot.img > "$T/dp.txt" 2>&1 ); rc=$?
    d=$(ls -d "$T"/dp/scan_dump.lime_* 2> /dev/null | head -n 1)
    [ "$rc" = 1 ] && [ -f "$d/verdict.json" ] || { echo "status $rc, expected 1 for the header of another key"; cat "$T/dp.txt"; return 1; }
    for h in "${HEADERS[@]}"; do
        n=${h%%:*}; key=$T/${h##*:}
        cmp -s "$d/keys/$n.img.vk" "$key" || { echo "$n: the key in keys/ is not the key of the header"; r=1; }
        grep -q "^  $n.img  *proven  *[0-9a-f]\{16\}\$" "$d/triage.txt" || { echo "$n: not named as proven, with the start of the SHA-256 of its key"; r=1; }
    done
    cmp -s "$d/keys/disk.dd@0x100000.vk" "$T/k64" && cmp -s "$d/keys/disk.dd@0x2400000.vk" "$T/k64" || { echo "the headers inside the image of a disk are not proven at their offsets"; r=1; }
    grep -q '^  ot.img  *not proven$' "$d/triage.txt" && [ ! -e "$d/keys/ot.img.vk" ] || { echo "the header of another key is not named as not proven"; r=1; }
    if [ "${#re[@]}" = 1 ]; then
        cmp -s "$d/keys/re.img.vk" "$T/k64" && cmp -s "$d/keys/re.img-2.vk" "$T/knew" || { echo "a header in re-encryption: not both keys, each for its digest"; r=1; }
        grep -q '^  keys         2, as a volume in re-encryption has them$' "$d/triage.txt" || { echo "a header in re-encryption is not named as one"; r=1; }
    fi
    # the erased LUKS2 header states no key size
    grep -A 3 '^l2e.img$' "$d/triage.txt" | grep -q 'key size not stated, no keyslot is left' || { echo "an erased header is not named as one without a key size"; r=1; }
    ( cd "$d" && sha256sum -c --quiet manifest.sha256 ) > /dev/null 2>&1 || { echo "the manifest does not verify"; r=1; }
    [ -z "$(find "$d" -perm /077)" ] || { echo "a file of the run is open to the group or to others"; r=1; }
    for key in k64 k32 knew other; do
        ! grep -q "$(od -An -v -tx1 -N 16 "$T/$key" | tr -d ' \n')" "$T/dp.txt" "$d/triage.txt" "$d/verdict.json" "$d/scan.txt" "$d/manifest.sha256" ||
            { echo "key material outside keys/"; r=1; }
    done
    # the verifier of the lab on the same schedules and headers: the same verdicts and keys.
    # It names a header by its file without the ending, and takes the first digest of a header
    # in re-encryption.
    ( cd "$T" && python3 -I "$R/vkverify.py" "$d/keys/candidates.txt" l1.img l1sha1.img l1s512.img l2.img l2s512.img l2k256.img l2big.img l1e.img l2e.img ot.img \
        --image disk.dd --json "$T/dp-lab.json" > "$T/dp-lab.txt" 2>&1 )
    want=$(verdicts "$T/dp-lab.json")
    got=$(verdicts "$d/verdict.json" | grep -v '^re\.img ' | sed 's/^\([^ @]*\)\.img /\1 /' | sort)
    [ "$got" = "$(printf '%s\n' "$want" | sort)" ] || { echo "the verdicts are not those of vkverify.py:"; diff <(printf '%s\n' "$want" | sort) <(printf '%s\n' "$got"); r=1; }

    # every header proven: status 0. Two schedules that lie apart: proven as a pair all the same.
    ( cd "$T" && "$k" -s dump.lime -d dp/2 l2.img l1.img > "$T/dp2.txt" 2>&1 ); rc=$?
    [ "$rc" = 0 ] || { echo "two headers, both proven: status $rc"; r=1; }
    ( cd "$T" && "$k" -s apart.raw -d dp/3 l2.img > "$T/dp3.txt" 2>&1 ); rc=$?
    d=$(ls -d "$T"/dp/3/scan_apart.raw_* 2> /dev/null | head -n 1)
    [ "$rc" = 0 ] && cmp -s "$d/keys/l2.img.vk" "$T/k64" || { echo "two schedules that lie apart: status $rc"; cat "$T/dp3.txt"; r=1; }
    grep -q '^  proof        attempt [0-9]*$' "$T/dp3.txt" && grep -q '^  key file     keys/l2.img.vk, 64 bytes, sha256 ' "$T/dp3.txt" &&
        ! grep -q 'a pair of schedules in place' "$T/dp3.txt" && ! grep -q 'memory-pair' "$T/dp3.txt" ||
        { echo "two schedules that lie apart are named as lying in place"; r=1; }
    # a file without a header, and a header that ends early
    ( cd "$T" && "$k" -s dump.lime -d dp/4 noise.bin magic.bin short.img > "$T/dp4.txt" 2>&1 ); rc=$?
    [ "$rc" = 1 ] || { echo "no header that can be read: status $rc"; r=1; }
    grep -q '^  headers      none in .*/noise.bin$' "$T/dp4.txt" || { echo "a file without a header is not named"; r=1; }
    grep -q '^  headers      none in .*/magic.bin$' "$T/dp4.txt" || { echo "the magic of LUKS in data that is no header is taken for one"; r=1; }
    grep -q '^  short.img  *unreadable header$' "$T/dp4.txt" || { echo "a header that ends early is not named as unreadable"; cat "$T/dp4.txt"; r=1; }
    # A user who is not root may lock little memory. The program then takes no lock, says so, and
    # goes on: with a lock on what it allocates later, the search of the files had no memory.
    if [ "$(id -u)" != 0 ]; then
        mkdir "$T/dp/8"
        ( cd "$T" && ulimit -l 64 && "$k" -s dump.lime -d dp/8 l2.img disk.dd > "$T/dp8.txt" 2>&1 ); rc=$?
        [ "$rc" = 0 ] && grep -q '^  note         the memory of this program is not locked' "$T/dp8.txt" || { echo "with little memory to lock: status $rc"; cat "$T/dp8.txt"; r=1; }
    fi
    # the dump alone: what it holds of the two headers proves their keys, each copy once
    ( cd "$T" && "$k" -s mem.raw -d dp/6 > "$T/dp6.txt" 2>&1 ); rc=$?
    d=$(ls -d "$T"/dp/6/scan_mem.raw_* 2> /dev/null | head -n 1)
    [ "$rc" = 0 ] || { echo "the dump alone: status $rc"; cat "$T/dp6.txt"; r=1; }
    grep -q '^  headers      2 in the dump itself$' "$T/dp6.txt" || { echo "the dump alone: not two headers in its memory"; cat "$T/dp6.txt"; r=1; }
    cmp -s "$d/keys/memory@0x300000.vk" "$T/k64" || { echo "the LUKS1 header in memory does not prove its key"; r=1; }
    cmp -s "$d/keys/memory@0x1fff0a.vk" "$T/k32" || { echo "the digests of the LUKS2 header in memory do not prove their key"; r=1; }
    [ "$(ls "$d/keys" | wc -l)" = 3 ] || { echo "the dump alone: other files in keys/ than the list and two keys: $(ls "$d/keys" | tr '\n' ' ')"; r=1; }
    grep -q '"in_memory": true' "$d/verdict.json" && ( cd "$d" && sha256sum -c --quiet manifest.sha256 ) > /dev/null 2>&1 || { echo "the dump alone: the report or the manifest"; r=1; }
    # a header that is among the files is not taken from the memory as well
    ( cd "$T" && "$k" -s mem.raw -d dp/7 l1.img > "$T/dp7.txt" 2>&1 ); rc=$?
    [ "$rc" = 0 ] && grep -q '^l1.img$' "$T/dp7.txt" && grep -q '^memory@0x1fff0a$' "$T/dp7.txt" && ! grep -q '^memory@0x300000$' "$T/dp7.txt" ||
        { echo "a header among the files is taken from the memory as well, or status $rc"; r=1; }
    # Two digests in the dump, the first without a key. Every header has the attempts that cost
    # little before any header has every other pair of keys: the key of the second is proven
    # before the first costs those, and the first is then not proven after them.
    read -r gone held < "$T/mem2.at"
    mkdir "$T/dp/9"
    ( cd "$T" && "$k" -s mem2.raw -d dp/9 > "$T/dp9.txt" 2>&1 ); rc=$?
    d=$(ls -d "$T"/dp/9/scan_mem2.raw_* 2> /dev/null | head -n 1)
    [ "$rc" = 0 ] && cmp -s "$d/keys/memory@$held.vk" "$T/k32" || { echo "two digests, the first without a key: status $rc, or the key of the second is not proven"; cat "$T/dp9.txt"; r=1; }
    n=$(grep -n "^memory@$gone, round 2\$" "$T/dp9.txt" | cut -d: -f1)
    want=$(grep -n "^  key file     keys/memory@$held.vk, 32 bytes, sha256 " "$T/dp9.txt" | cut -d: -f1)
    [ -n "$n" ] && [ -n "$want" ] && [ "$want" -lt "$n" ] || { echo "the key of the second digest is not proven before every pair is tried for the first"; cat "$T/dp9.txt"; r=1; }
    [ "$(grep -n '^  round 2      [0-9]* other pairs, when every header has had round 1$' "$T/dp9.txt" | cut -d: -f1)" -lt "${n:-0}" ] &&
        grep -q '^  round 2      [0-9]* of [0-9]* pairs tried, [0-9]* s$' "$T/dp9.txt" ||
        { echo "the pairs that are left are not counted before they are tried"; r=1; }
    grep -q "^  memory@$gone  *not proven\$" "$d/triage.txt" && [ ! -e "$d/keys/memory@$gone.vk" ] || { echo "the digest without a key is not named as not proven"; r=1; }
    # the pairs that are left are every pair of two keys of one size but those that lie in place
    python3 -I -c 'import json, re, sys
c = json.load(open(sys.argv[1]))["candidates"]; text = open(sys.argv[2]).read()
left = int(re.search(r"\n  round 2      (\d+) other pairs", text).group(1))
first = int(re.search(r"\n  round 1      (\d+) keys?, pairs in place and each key alone", text).group(1))
tried, of = map(int, re.search(r"\n  round 2      (\d+) of (\d+) pairs tried", text).groups())
total = int(re.search(r"not proven, none of (\d+) candidate keys gives the digest", text).group(1))
if (tried, of) != (left, left):
    sys.exit("the second round: %d of %d pairs tried, and %d were counted before" % (tried, of, left))
# The first round: each pair in place, and each key alone. The second: of each size every
# pair of two keys, but those of the first round.
want = c["aes128"] * (c["aes128"] - 1) + c["aes256"] * (c["aes256"] - 1) - (first - c["keys"])
sys.exit(0 if first > c["keys"] and left == want and total == first + left else "the attempts: %d first, %d left and %d expected, %d in all" % (first, left, want, total))' \
        "$d/verdict.json" "$T/dp9.txt" || r=1
    ( cd "$T" && "$k" -s dump.lime -d dp/5 no-such-file > "$T/dp5.txt" 2>&1 ); rc=$?
    [ "$rc" = 1 ] && grep -q 'no-such-file is not a file or a device that can be read$' "$T/dp5.txt" || { echo "a file that does not exist: status $rc"; r=1; }
    return $r
}
# ---- screen --------------------------------------------------------------------------------------
# What a run prints, with the files that the checks of the search have made: dump.lime with the
# schedules of the key of l2.img and not of that of ot.img, and fx.lime with a pair of
# schedules that no header proves. The bytes are looked at by Python, which is given a
# pseudo-terminal by its own module pty.
screen_look() {
    local k=$1 r=0
    case $k in /*) ;; *) k=$R/$k ;; esac
    rm -rf "$T/scr"; mkdir "$T/scr" "$T"/scr/{1,2,3,4,5,6,7,8,9} || return 1
    cat > "$T/scr/pty.py" <<'EOF'
# pty.py OUT COMMAND... : the command with a pseudo-terminal as its screen, what it wrote there to OUT
import os, pty, sys
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[2], sys.argv[2:])
out = b""
while True:
    try:
        b = os.read(fd, 65536)
    except OSError:
        break
    if not b:
        break
    out += b
os.waitpid(pid, 0)
open(sys.argv[1], "wb").write(out)
EOF
    cat > "$T/scr/look.py" <<'EOF'
# look.py WHAT FILE... : the bytes of a screen
import re, sys
what, files = sys.argv[1], sys.argv[2:]
E = b"\x1b"
for f in files:
    s = open(f, "rb").read()
    def need(*parts):
        for p in parts:
            if p not in s:
                sys.exit("%s, %s: lacks %r" % (f, what, p))
    def none(*parts):
        for p in parts:
            if p in s:
                sys.exit("%s, %s: has %r" % (f, what, p))
    over = re.findall(rb"\r(?!\n)", s)         # a terminal ends a line with both
    if what in ("colour", "colour-pair"):
        known = {b"\x1b[1m", b"\x1b[36m", b"\x1b[1;32m", b"\x1b[1;34m", b"\x1b[0m"}
        if set(re.findall(rb"\x1b\[[0-9;]*m", s)) - known or s.count(E) != len(re.findall(rb"\x1b\[[0-9;]*m", s)):
            sys.exit("%s: an escape sequence that is none of bold, cyan, green, blue and their end" % f)
        need(E + b"[1mkeep ", b"\r  " + E + b"[36msearch" + E + b"[0m       reading the dump")
        if what == "colour":
            need(b"  " + E + b"[36mverdict" + E + b"[0m      " + E + b"[1;32mproven" + E + b"[0m\r\n",
                 b"  " + E + b"[36mverdict" + E + b"[0m      " + E + b"[1mnot proven" + E + b"[0m, none of ",
                 E + b"[1ml2.img" + E + b"[0m\r\n", E + b"[1mresult" + E + b"[0m\r\n")
            # the rows of the result: a name, the verdict in its colour, the start of the SHA-256 of the key
            for row in (rb"\n  l2\.img +\x1b\[1;32mproven\x1b\[0m +[0-9a-f]{16}\r\n", rb"\n  ot\.img +\x1b\[1mnot proven\x1b\[0m\r\n"):
                if not re.search(row, s):
                    sys.exit("%s: the result lacks a row like %r" % (f, row))
        else:
            need(b"  memory-pair-1  " + E + b"[1;34mfound in memory, not proven" + E + b"[0m  ")
        # the line of progress is taken away: spaces over all of it, and the next line from its start
        if not re.search(rb"reading the dump[^\r]*\r {60,}\r  ", s):
            sys.exit("%s: the line of progress is not taken away" % f)
    elif what == "no-colour":
        none(E)
        need(b"\r  search       reading the dump")
        if not over:
            sys.exit("%s: no line is written over" % f)
    elif what == "plain":
        none(E)
        if over:
            sys.exit("%s: a carriage return that ends no line" % f)
        need(b"  search       reading the dump for AES key schedules and LUKS headers\r\n")
    elif what == "pipe":
        none(E, b"\r")
    elif what == "width":
        for line in s.decode("utf-8", "replace").split("\n"):
            if len(line) > 80 and not any(len(w) > 40 for w in line.split()):
                sys.exit("%s: a line of %d columns with no word that needs them: %s" % (f, len(line), line))
            if line != line.rstrip():
                sys.exit("%s: a line that ends with spaces: %r" % (f, line))
EOF
    # under OUT [ARGUMENT OF env]... -- COMMAND... : the command on a pseudo-terminal, its screen to scr/OUT
    under() {
        local out=$1; shift
        local -a e=()
        while [ "$1" != -- ]; do e+=("$1"); shift; done
        shift
        ( cd "$T" && env "${e[@]}" python3 -I "$T/scr/pty.py" "$T/scr/$out" "$@" )
    }
    look() { python3 -I "$T/scr/look.py" "$@" || r=1; }

    # a terminal: colour and a line of progress that is written over
    under 1.txt -u NO_COLOR TERM=xterm -- "$k" -s dump.lime -d scr/1 l2.img ot.img
    look colour "$T/scr/1.txt"
    under 2.txt -u NO_COLOR TERM=linux -- "$k" -s fx.lime -d scr/2
    look colour-pair "$T/scr/2.txt"
    under 3.txt NO_COLOR= TERM=xterm -- "$k" -s fx.lime -d scr/3
    look colour-pair "$T/scr/3.txt"
    # NO_COLOR takes the colour and leaves the line that is written over
    under 4.txt NO_COLOR=1 TERM=xterm -- "$k" -s fx.lime -d scr/4
    look no-colour "$T/scr/4.txt"
    # -n, no TERM and TERM=dumb: a terminal gets what a pipe gets
    under 5.txt -u NO_COLOR TERM=xterm -- "$k" -n -s fx.lime -d scr/5
    under 6.txt -u NO_COLOR TERM=dumb -- "$k" -s fx.lime -d scr/6
    under 7.txt -u NO_COLOR -u TERM -- "$k" -s fx.lime -d scr/7
    look plain "$T/scr/5.txt" "$T/scr/6.txt" "$T/scr/7.txt"

    # a pipe: no escape byte and no carriage return, also with a terminal's variables, and the
    # report holds the lines of the screen but the line of progress and the last word
    ( cd "$T" && env -u NO_COLOR TERM=xterm "$k" -s dump.lime -d scr/8 l2.img ot.img > "$T/scr/8.txt" 2>&1 )
    look pipe "$T/scr/8.txt" "$T"/scr/[1-8]/scan_*/triage.txt
    cmp -s <(grep -v -e '^  search       reading the dump' -e '^keep: every file of this run is flushed' "$T/scr/8.txt") "$T"/scr/8/scan_*/triage.txt ||
        { echo "triage.txt does not hold the lines of the screen"; r=1; }
    grep -q '^  search       reading the dump for AES key schedules and LUKS headers$' "$T/scr/8.txt" &&
        [ "$(tail -n 1 "$T/scr/8.txt")" = "keep: every file of this run is flushed to the destination" ] || { echo "the screen of a pipe lacks its two lines"; r=1; }

    # a control character in the name of a file is a space on the screen and in the report
    cp "$T/l2.img" "$T/scr/a"$'\033'"[31mb.img"
    ( cd "$T" && "$k" -s dump.lime -d scr/9 "scr/a"$'\033'"[31mb.img" > "$T/scr/9.txt" 2>&1 ) || { echo "a file with a control character in its name: not proven"; r=1; }
    look pipe "$T/scr/9.txt" "$T"/scr/9/scan_*/triage.txt
    grep -q '^a \[31mb.img$' "$T/scr/9.txt" && cmp -s "$T"/scr/9/scan_*/keys/a__31mb.img.vk "$T/k64" || { echo "the name with a control character, or its key file"; cat "$T/scr/9.txt"; r=1; }

    # no line of more than 80 columns but for a word that is longer, and a long text goes on
    # below its value
    look width "$T/scr/8.txt" "$T/scr/9.txt" "$T/dp.txt" "$T/dp4.txt" "$T/dp6.txt" "$T/dp9.txt" "$T"/scr/2/scan_*/triage.txt "$T"/dp/scan_*/triage.txt
    grep -A 2 '^  headers      none: no file with a LUKS header is given and the dump itself$' "$T"/scr/2/scan_*/triage.txt |
        grep -c '^               [a-z]' | grep -q -x 2 || { echo "a long line does not go on below its value"; cat "$T"/scr/2/scan_*/triage.txt; r=1; }
    return $r
}
if [ -x keep ] && [ -x keep-san ]; then
    for k in keep keep-san; do
        check "dump: $k proves the keys of an image against header files, a disk image and what the image itself holds of a header, as vkverify.py does, and names what it cannot prove" dump_proof "$k"
    done
    for k in keep keep-san; do
        check "screen: $k gives colour and a line that is written over to a terminal alone, and lines of at most 80 columns that triage.txt holds as they are" screen_look "$k"
    done
else
    skip "dump: the program (make, musl-gcc and cc)"
fi
# ---- a run that is disturbed ---------------------------------------------------------------------
# A run that has begun is brought to its end and to its status, whatever becomes of its screen
# and whatever limit its shell had. Each of these ended the program in the middle before
# 2.0-pre11, by a signal: a reader of the screen that goes away (SIGPIPE), a terminal that
# hangs up (SIGHUP), and a limit of the size of a file (SIGXFSZ). The screen is a pipe that
# holds one page, so the run waits for its reader and is alive when the two happen.
cat > "$T/gone.py" <<'EOF'
# gone.py KEEP DUMP DEST FILE... : the search of a dump with a screen that hangs up and goes away
import fcntl, glob, os, signal, struct, subprocess, sys, termios, time
keep, dump, dest, files = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]
r, w = os.pipe()
fcntl.fcntl(w, 1031, 4096)                              # F_SETPIPE_SZ
p = subprocess.Popen([keep, "-n", "-s", dump, "-d", dest] + files, stdout=w, stderr=subprocess.DEVNULL)
os.close(w)
first = os.read(r, 16)
def report():
    found = glob.glob(dest + "/scan_*/triage.txt")
    return open(found[0], "rb").read() if found else b""
# It waits for its reader when the pipe is full: a line is written whole or not at all, so
# the pipe then lacks less than a line, and what it holds stays as it is.
def queued():
    return struct.unpack("i", fcntl.ioctl(r, termios.FIONREAD, b"\0\0\0\0"))[0]
full, held = 0, -1
for _ in range(6000):
    now = queued()
    full = full + 1 if now == held and now >= 3600 else 0
    held = now
    if full >= 10 or p.poll() is not None:
        break
    time.sleep(0.02)
before = report()
if p.poll() is not None:
    sys.exit("the run ended with status %d before its screen was read: it did not wait" % p.returncode)
# the report holds the lines that the screen has had, each whole, before the run is over
if not first.startswith(b"keep ") or len(before) < 3500 or not before.endswith(b"\n"):
    sys.exit("while the run waits, triage.txt holds %d bytes and ends with %r" % (len(before), before[-20:]))
os.kill(p.pid, signal.SIGHUP)
time.sleep(0.3)
if p.poll() is not None:
    sys.exit("the run ended with status %d when its terminal hung up" % p.returncode)
os.close(r)                                             # the reader of the screen is gone
try:
    rc = p.wait(timeout=120)
except subprocess.TimeoutExpired:
    p.kill()
    sys.exit("the run did not end after its screen was gone")
if rc != 0:
    sys.exit("the run ended with status %d after its screen was gone" % rc)
if not report().rstrip().endswith(b" s") or b"\nresult\n" not in report():
    sys.exit("triage.txt does not hold the run to its end")
EOF
disturbed() {
    local k=$1 r=0 d rc i f caps
    local -a files=()
    case $k in /*) ;; *) k=$R/$k ;; esac
    rm -rf "$T/gone"; mkdir "$T/gone" "$T/gone/1" "$T/gone/2" || return 1
    # sixteen headers, so that the screen is longer than the pipe holds
    for _ in 1 2 3 4 5 6 7 8; do files+=("$T/l2.img" "$T/l1.img"); done
    python3 -I "$T/gone.py" "$k" "$T/dump.lime" "$T/gone/1" "${files[@]}" || r=1
    d=$(ls -d "$T"/gone/1/scan_* 2> /dev/null | head -n 1)
    i=0
    for f in "$d"/keys/*.vk; do cmp -s "$f" "$T/k64" && i=$(( i + 1 )); done
    [ "$i" = 16 ] || { echo "of the 16 keys of a run whose screen went away, $i are kept"; ls "$d/keys" 2>&1; r=1; }
    ( cd "$d" 2> /dev/null && sha256sum -c --quiet manifest.sha256 > /dev/null 2>&1 ) || { echo "the manifest of a run whose screen went away"; r=1; }
    python3 -I -c 'import json, sys; sys.exit(0 if len(json.load(open(sys.argv[1]))["volumes"]) == 16 else 1)' "$d/verdict.json" ||
        { echo "the report of a run whose screen went away"; r=1; }

    # A limit of the size of a file, as a shell of the examined system can have it. A process
    # that may raise its limits (CAP_SYS_RESOURCE, bit 24 of its capabilities), as root on a
    # machine, takes it off, and the run is whole. Another cannot: a write then fails, which
    # the run says with its status, and no signal ends it.
    ( ulimit -f 1 && "$k" -n -s "$T/dump.lime" -d "$T/gone/2" "$T/l2.img" > "$T/gone/2.txt" 2> "$T/gone/2.err" ); rc=$?
    d=$(ls -d "$T"/gone/2/scan_* 2> /dev/null | head -n 1)
    caps=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
    if [ $(( 0x${caps:-0} >> 24 & 1 )) = 1 ]; then
        [ "$rc" = 0 ] && cmp -s "$d/keys/l2.img.vk" "$T/k64" && ( cd "$d" && sha256sum -c --quiet manifest.sha256 > /dev/null 2>&1 ) ||
            { echo "a limit of the size of a file that the process may take off: status $rc"; cat "$T/gone/2.err"; r=1; }
    else
        [ "$rc" = 1 ] && grep -q 'a write or a flush to the destination FAILED' "$T/gone/2.err" ||
            { echo "a limit of the size of a file: status $rc"; cat "$T/gone/2.err"; r=1; }
    fi
    return $r
}
# A run that is asked to end, by an interrupt from the keyboard or by SIGTERM, ends in order:
# it makes no further attempt, says which header it left, writes its report and its manifest
# and has status 1. Before 2.0-rc1 the signal ended it at once, with no verdict.json and no
# manifest. The header here has a digest of 2000000 iterations, which no key of the dump
# gives, so the run is inside its first attempt when the signal comes. A second signal of the
# same kind ends it at once, by the signal.
cat > "$T/asked.py" <<'EOF'
# asked.py KEEP DUMP DEST SIGNALS FILE... : the search of a dump that is sent SIGNALS (i for
# SIGINT, t for SIGTERM) when it begins the attempts on its first header
import glob, json, os, re, signal, subprocess, sys, time
keep, dump, dest, sigs, files = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
# a shell that started this check in the background has SIGINT ignored, which the program
# would leave as it is: it is given the signal as a terminal gives it
p = subprocess.Popen([keep, "-n", "-s", dump, "-d", dest] + files, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                     preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
screen = b""
while True:
    line = p.stdout.readline()
    if not line:
        sys.exit("the run ended before the attempts on its first header: " + screen.decode("latin-1")[-300:])
    screen += line
    if line.startswith(b"  digest "):
        break
for c in sigs:
    os.kill(p.pid, signal.SIGINT if c == "i" else signal.SIGTERM)
    time.sleep(0.2)
try:
    out, err = p.communicate(timeout=300)
except subprocess.TimeoutExpired:
    p.kill()
    sys.exit("the run did not end after the signal")
folder = glob.glob(dest + "/scan_*")[0]
report = open(folder + "/triage.txt").read()
if len(sigs) > 1:
    # the second signal: the process is ended by it, and the report holds the lines up to there
    if p.returncode != -signal.SIGINT or os.path.exists(folder + "/verdict.json") or "  digest " not in report:
        sys.exit("after a second signal: status %d, verdict.json %s" % (p.returncode, os.path.exists(folder + "/verdict.json")))
    sys.exit(0)
name = "from the keyboard (SIGINT)" if sigs == "i" else "by SIGTERM"
if p.returncode != 1 or b"keep: the run was ended by a signal" not in err:
    sys.exit("status %d, and it says: %s" % (p.returncode, err.decode("latin-1")[-300:]))
if "\ninterrupted %s: " % name not in report or not report.rstrip().split("\n")[-1].startswith("finished "):
    sys.exit("triage.txt does not say that the run was interrupted %s, or does not go to its end:\n%s" % (name, report[-400:]))
v = json.load(open(folder + "/verdict.json"))
notes = [(x["verdict"], x["note"]) for x in v["volumes"]]
if v.get("interrupted") is not True or len(notes) != len(files) or any(
        w != "not proven" or not re.match(r"the attempts were ended by a signal after [01], ", n) for w, n in notes):
    sys.exit("verdict.json: interrupted %r, %r" % (v.get("interrupted"), notes))
EOF
asked() {
    local k=$1 r=0 n d
    case $k in /*) ;; *) k=$R/$k ;; esac
    rm -rf "$T/asked"; mkdir "$T/asked" "$T/asked/i" "$T/asked/t" "$T/asked/ii" || return 1
    python3 -I -c 'import struct, sys
d = bytearray(open(sys.argv[1], "rb").read()); d[164:168] = struct.pack(">I", 2000000); open(sys.argv[2], "wb").write(d)' "$T/l1.img" "$T/asked/slow.img" || return 1
    for n in i t ii; do
        python3 -I "$T/asked.py" "$k" "$T/dump.lime" "$T/asked/$n" "$n" "$T/asked/slow.img" "$T/l2.img" || { echo "sent $n"; r=1; continue; }
        [ "$n" != ii ] || continue
        d=$(ls -d "$T/asked/$n"/scan_* 2> /dev/null | head -n 1)
        ( cd "$d" && sha256sum -c --quiet manifest.sha256 > /dev/null 2>&1 ) || { echo "sent $n: the manifest does not verify"; r=1; }
        [ -s "$d/keys/candidates.txt" ] || { echo "sent $n: the list of the schedules is not kept"; r=1; }
    done
    # a run that is not asked to end says that it was not
    d=$(ls -d "$T"/says/3/scan_* 2> /dev/null | head -n 1)
    grep -q '^  "interrupted": false,$' "$d/verdict.json" || { echo "a run that was not interrupted does not say so in verdict.json"; r=1; }
    return $r
}
# What the search of a dump must say and not pass over. A file that cannot be read: the place
# is named and the run ends with status 1. Such a file is one of /sys that every system has:
# the speed of the loopback interface, a regular file that any user may open and whose read
# the kernel refuses (speed_show in net/core/net-sysfs.c). A key that gives the digest and whose file cannot be
# written, here for a name that is too long: named as such, and not as a key that was not
# found. A name that is no UTF-8, with a longer form of "/" in it: verdict.json must be JSON
# that Python reads.
dump_says() {
    local k=$1 r=0 rc d long
    case $k in /*) ;; *) k=$R/$k ;; esac
    rm -rf "$T/says"; mkdir "$T/says" "$T/says/1" "$T/says/2" "$T/says/3" || return 1
    if head -c 1 /sys/class/net/lo/speed > /dev/null 2>&1 || [ ! -f /sys/class/net/lo/speed ]; then
        echo "no file here whose read fails: /sys/class/net/lo/speed is not one"; r=1
    fi
    "$k" -n -s "$T/dump.lime" -d "$T/says/1" /sys/class/net/lo/speed > "$T/says/1.txt" 2>&1; rc=$?
    [ "$rc" = 1 ] && tr -s '\n ' '  ' < "$T/says/1.txt" | grep -q 'headers FAILED, /sys/[^ ]*/lo/speed cannot be read at offset 512 (.*): what lies behind that place is not searched for headers' ||
        { echo "a file that cannot be read: status $rc"; cat "$T/says/1.txt"; r=1; }
    long=$(printf 'n%.0s' $(seq 1 253))
    cp "$T/l2.img" "$T/says/$long" && "$k" -n -s "$T/dump.lime" -d "$T/says/2" "$T/says/$long" > "$T/says/2.txt" 2>&1; rc=$?
    [ "$rc" = 1 ] && tr -s '\n ' '  ' < "$T/says/2.txt" | grep -q 'verdict not proven, a key gives the digest of the header, and its file could not be written to the destination' ||
        { echo "a key whose file cannot be written: status $rc"; cat "$T/says/2.txt"; r=1; }
    cp "$T/l2.img" "$T/says/over"$'\xe0\x80\xaf'"long"$'\xed\xa0\x80\xf4\x90\x80\x80'".img" &&
        "$k" -n -s "$T/dump.lime" -d "$T/says/3" "$T/says/over"$'\xe0\x80\xaf'"long"$'\xed\xa0\x80\xf4\x90\x80\x80'".img" > "$T/says/3.txt" 2>&1; rc=$?
    d=$(ls -d "$T"/says/3/scan_* 2> /dev/null | head -n 1)
    [ "$rc" = 0 ] && python3 -I -c 'import json, sys
v = json.load(open(sys.argv[1], encoding="utf-8", errors="strict"))["volumes"]
sys.exit(0 if len(v) == 1 and v[0]["verdict"] == "proven" and "\ufffd" in v[0]["name"] else 1)' "$d/verdict.json" ||
        { echo "a name that is no UTF-8: status $rc"; cat "$T/says/3.txt"; r=1; }
    return $r
}
if [ -x keep ] && [ -x keep-san ] && [ -f "$T/dump.lime" ]; then
    for k in keep keep-san; do
        check "dump: $k names a file that cannot be read and a key whose file cannot be written, and writes a report that is JSON for a name that is no UTF-8" dump_says "$k"
    done
    for k in keep keep-san; do
        check "asked to end: $k ends its attempts at SIGINT and at SIGTERM, writes its report and its manifest with status 1, and is ended at once by a second signal" asked "$k"
    done
    for k in keep keep-san; do
        check "disturbed: $k ends its run and keeps every key when its terminal hangs up and its screen goes away, and under a limit of the size of a file" disturbed "$k"
    done
else
    skip "disturbed: the program and the image of the search (make, musl-gcc and cc)"
fi
finish
