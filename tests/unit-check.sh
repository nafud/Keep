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
#              and some longer ones
#   json       texts that RFC 8259 allows and texts that it does not, and a LUKS2 metadata text
#              with one byte changed at a time, against Python's json module
#   scanner    the search of memory with the sanitizers, on a fixture with the schedules of
#              known keys in its four formats, cut short and damaged: the same schedules,
#              messages and status as the scanner gives that is built as the program links it
#   options    the command line of "keep", with both builds of the program: a wrong option, an
#              option without its value, a command of an earlier version and options that do
#              not go together end with status 2 and the usage, -h names every option, and
#              "keep -s DUMP" writes the list of the scanner into keys/ of its folder, shows
#              no key and ends with the status of the search
#   kernel     the two answers of device-mapper, laid out as the kernel lays them out, before
#              and from Linux 4.13, and then with bytes changed and ends cut off 1600 times:
#              read or refused, never a fault. Then the volumes among tables as cryptsetup
#              builds them: one device, LUKS2 with integrity on its dm-integrity device, a
#              volume in re-encryption with its helper devices, one interrupted in it, and
#              the same with bytes changed
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
#
# It needs neither root nor device-mapper, and writes only below a temporary directory, which
# is removed at the end. The test keys are drawn from /dev/urandom there and are never printed.
# Programs: make, musl-gcc, cc with the sanitizer libraries, python3 and cryptsetup.
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
trap 'rm -rf "$T"' EXIT
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
    refused "the command triage of an earlier version" triage
    refused "the command scan of an earlier version" scan fx.lime
    refused "the option -n of an earlier version" -n

    start "$k" -h; rc=$?
    [ "$rc" = 0 ] || { echo "-h: status $rc"; r=1; }
    for o in '-s DUMP' '-d DIR' '-b N' '-h ' '-V '; do said "^ *$o" "-h"; done
    said 'No key is printed' "-h"
    start "$k" -V; rc=$?
    [ "$rc" = 0 ] && grep -q '^keep [0-9][^ ]* ([0-9-]*)$' "$T/opt.txt" || { echo "-V: status $rc, $(cat "$T/opt.txt")"; r=1; }

    # the search of a dump: the list in keys/, what the scanner said on the screen, no key there
    start "$k" -s fx.lime -d out; rc=$?
    d=$(ls -d "$T"/opt/out/scan_fx.lime_* 2>/dev/null | head -n 1)
    [ "$rc" = 0 ] && [ -d "$d" ] || { echo "the search of a dump ended with status $rc"; cat "$T/opt.txt"; return 1; }
    said "^memory dump: $T/opt/fx.lime\$" "dump"
    said "^output: $d\$" "dump"
    said '^kcore-keyscan: AES-128 schedules: 2 ' "dump"
    said '^[0-9]* schedules are listed in keys/candidates.txt' "dump"
    said '^keep: every file of this run is flushed to the destination$' "dump"
    tests/keyscan-san "$T/fx.lime" 2> /dev/null | cmp -s - "$d/keys/candidates.txt" || { echo "the candidate list is not that of the scanner"; r=1; }
    [ "$(wc -l < "$d/keys/candidates.txt")" = "$(sed -n 's/^\([0-9]*\) schedules are listed.*/\1/p' "$T/opt.txt")" ] || { echo "the number of the schedules is not that of the list"; r=1; }
    cmp -s <(sed -n '/^kcore-keyscan/p' "$T/opt.txt" | sed 's/[0-9.]* seconds//') <(sed 's/[0-9.]* seconds//' "$d/scan.txt") || { echo "scan.txt is not what the screen shows"; r=1; }
    open=$(find "$d" -perm /077)
    [ -z "$open" ] || { echo "open to the group or to others: $open"; r=1; }
    while read -r key; do
        ! grep -q "$key" "$T/opt.txt" || { echo "a key is on the screen"; r=1; }
    done < <(sed 's/.* key //' "$d/keys/candidates.txt")

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
    for k in keep keep-san; do
        check "options: $k refuses what does not go together, names its options with -h, searches a dump into keys/ and ends with the status of the search" options "$k"
    done
else
    skip "scanner and options: with the sanitizers (make, musl-gcc and cc)"
fi

# ---- hashes --------------------------------------------------------------------------------------
cat > "$T/hashes.py" <<'EOF'
import hashlib, os, subprocess, sys
unit, bad = sys.argv[1], 0
def run(*a, data=None):
    return subprocess.run([unit, *a], input=data, capture_output=True).stdout.decode().strip()
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
    check "hashes: ${u##*/} equals hashlib for five functions and PBKDF2" python3 -I "$T/hashes.py" "$u"
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
for u in "${UNITS[@]}"; do
    check "kernel: ${u##*/} reads the answers of device-mapper and refuses damaged ones without a fault" python3 -I "$T/kernel.py" "$u" "$T" answers
    check "kernel: ${u##*/} finds the volumes among tables: one device, with integrity, in re-encryption, with changed bytes" python3 -I "$T/kernel.py" "$u" "$T" volumes
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
    expect "a device that /sys does not know" "[]"                                          "$u" in-use "$T/sys/tree" "$T/sys/mountinfo-lvm" /dev/null 8 1
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
    expect "a name that leaves the folder"  "[../../etc/x] [.._.._etc_x]"                   "$u" names ../../etc/x
    expect "a name with an escape sequence" "[a [31m b] [a__31m_b]"                         "$u" names "$(printf 'a\033[31m b')"
    expect "the characters that are kept"   "[A.z_0+=@,-] [A.z_0+=@,-]"                     "$u" names "A.z_0+=@,-"
    expect "an empty name"                  "[] [_]"                                        "$u" names ""
    return $r
}
for u in "${UNITS[@]}"; do
    check "system: ${u##*/} reads mounts, lockdown, SecureBoot and os-release, and makes names safe" system_parts "$u"
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
for u in "${UNITS[@]}"; do
    for h in "${HEADERS[@]}"; do
        check "headers: ${u##*/}, ${h%%:*}: the copy equals luksHeaderBackup, the key is proven and another is not" \
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
if container l1rmd k64 --type luks1 --cipher aes-xts-plain64 --key-size 512 --hash ripemd160; then
    for u in "${UNITS[@]}"; do check "headers: ${u##*/}, a LUKS1 header with ripemd160 is copied, and its proof is named as not computed" other_hash "$u"; done
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
for u in "${UNITS[@]}"; do
    for how in magic zeros metadata; do
        check "headers: ${u##*/}, first copy damaged ($how): read from the second copy, proven, the file unchanged" damaged "$u" "$how"
    done
    check "headers: ${u##*/}, both copies damaged, files that end early and random bytes are named and not read" unusable "$u"
    check "headers: ${u##*/}, a default LUKS2 header has an area of 16 MiB" uuid_rule "$u"
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
        check "headers: ${u##*/}, a header in re-encryption: the copy equals luksHeaderBackup, the old and the new key each give their digest" reencrypted "$u"
    done
else
    skip "headers: a header in re-encryption (this cryptsetup starts none on a file: $(head -n 1 "$T/re.err"))"
fi
finish
