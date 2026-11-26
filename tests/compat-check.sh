#!/bin/bash
# compat-check.sh [-m] [-c] : check Keep on one distribution, against that system's own tools.
#
#   sudo bash tests/compat-check.sh            the keys
#   sudo bash tests/compat-check.sh -m         also the memory images
#   sudo bash tests/compat-check.sh -c         the same, with the image of AVML compressed
#
# For a throwaway test guest only, never for a system under examination: it makes small
# encrypted containers with keys it has just drawn, opens them, runs keep on them and removes
# everything again. Each container is formatted with a volume key from a file, so the ground
# truth is known without any dump. No key is printed.
#
# The programs are taken from beside this script, as "make all tests/keyscan" builds them in
# the repository: ../keep, the program, keep-unit, which counts the pages of a file in the
# page cache, and keyscan, the scanner alone. With -m or -c the variable AVML names the binary
# of AVML (tests/get-avml.sh fetches it).
#
# What keep writes is held against what this system says of the same mappings:
#   the volumes        the mapped devices of "dmsetup ls --target crypt"
#   type, key size, key location, device    the lines of "cryptsetup status"
#   the cipher         the table of "dmsetup table", which names it as the kernel does
#   the table in log/  the UUID and the device number of "dmsetup info" and the lines of
#                      "dmsetup table", in which a key is zeros
#   a header backup    the file of "cryptsetup luksHeaderBackup", byte for byte
#   a key              the key file the container was made from, and where the table holds
#                      the key, what "dmsetup table --showkeys" shows
#   the proof          "cryptsetup open --test-passphrase" with the key file that keep wrote,
#                      against the header: it accepts the key exactly where keep says proven
#   a memory image     the image that AVML takes of the same machine
#
# The mappings and the runs:
#   kc_l2     LUKS2 as cryptsetup opens it by default, the key in the kernel keyring: found
#             in memory, "captured and proven"
#   kc_l1     LUKS1, the key in the device-mapper table: "captured and proven"
#   No        a mapping of that name, made with dmsetup from a known key: "captured, in use"
#   kc_null   a mapping with the null cipher and no key: "no key needed"
#   before any mapping is made, keep is run once on the guest as it is, which on a guest
#             without encrypted volumes is the run with none. Its shell has a limit of the
#             size of a file of one block, which the program must take off
#   the main run names no destination and is started in a directory on the guest's own
#             disk, which must take the folder of the run. keep reads a header past the page
#             cache and writes its copy past it: with the cache of each device let go before
#             a run, keep-unit may count no page of such a device there after it, and none
#             of a copy
#   asked to end: keep is sent SIGTERM while it searches the memory. It must end the search,
#             keep the keys of the table all the same, say which key it did not reach, and
#             write its report and a manifest that verifies, with status 1
#   the memory images, with -m or -c: AVML takes an image while the two containers are open,
#             and the scanner must read it to its end and find the schedules of both volume
#             keys in it. Then keep takes its own, once for each word of KEEP_IMAGES
#             (default "lime raw avml all"). A word is a format, or "all" for every format
#             from one read (-F). An image is written with direct writes and its pages are
#             let go from the page cache: after the run keep-unit may count one page of its
#             file there at most. The report must name each file with its size and its
#             SHA-256, the scanner must read each image to its end, and the schedule of each
#             half of both volume keys must lie in it at an address at which it lies in the
#             image of AVML. A compressed image is also converted by AVML itself, and the
#             scanner must find in the result what it finds in the image. The images of one
#             read must give the same list of schedules. The first image of a run is then
#             searched as a dump that exists, "keep -s IMAGE", with the images of the two
#             containers as the files that hold the headers: both volume keys must be proven
#             and written as they are. It is searched once more with no file, and what it
#             holds of a header by itself is told and not judged. One more image is begun
#             and keep is sent SIGTERM while it reads: the part must be kept and named as
#             interrupted, with its size and its SHA-256
#   a destination on FAT, named with -d: every name must be taken by FAT, and the screen
#             must name each key that is held by its file, its length and the start of its
#             SHA-256 (where the guest has mkfs.vfat and can mount FAT)
#   a destination of 1 MiB, which has no room for the copy of a header: the part of each
#             copy must be gone and the keys kept all the same, with status 1
#   kc_pv     a LUKS2 volume that carries an LVM volume group, as an installer lays out an
#             encrypted system, with a logical volume that is mounted and one that is swap:
#             the mapping below them is the one that is listed and proven, both are named as
#             what it carries, and the logical volume is the destination of that run (where
#             the guest has lvm2 and mkfs.ext4)
#   kc_it, kc_ik   LUKS2 with integrity (--integrity hmac-sha256), one with its key in the
#             table and one with its key in the keyring. The crypt target lies on a
#             dm-integrity device and the header on the device below that. The first must be
#             captured and proven with the key of 96 bytes it was made from, the second
#             "live copy only", because its volume key holds a key of HMAC that the search
#             for AES key schedules does not find (where the kernel has dm-integrity)
#   kc_re     a LUKS2 volume in re-encryption. The re-encryption is started and interrupted,
#             so that the volume has the crypt targets of two keys, then resumed and paused,
#             so that they lie in the helper devices that cryptsetup puts below the volume.
#             In each state keep must list the volume once, prove both keys against the
#             header and name each key with its part: the keys are compared with those that
#             the table shows where the volume is opened with --disable-keyring, and the key
#             of the part not yet done with the key the volume was made from. cryptsetup
#             itself accepts neither key alone for such a header
#   every screen and every report of the check: none may hold an escape byte, or a line of
#             more than 80 columns without a word that needs them
# With KEEP_SAN=/path/to/keep-san in the environment, that build of the program with the
# sanitizers of the compiler is run at the same places as well and must end with status 0,
# which it does not where a sanitizer finds a fault.
# A part that the guest cannot run is reported as SKIP and does not fail the check.
#
# Needs root, cryptsetup, dmsetup and losetup on the guest (package cryptsetup on Debian, Ubuntu,
# Fedora, the RHEL family, openSUSE and Arch). dosfstools and lvm2 are needed for the parts with
# FAT and LVM.
set -u
export LC_ALL=C
MEM=""; IMAGE=memory.lime
while :; do
    case ${1:-} in
        -m) MEM=-m; IMAGE=memory.lime; shift ;;
        -c) MEM=-c; IMAGE=memory.avml; shift ;;
        *) break ;;
    esac
done
HERE=$(cd "$(dirname "$0")" && pwd)
KEEP=$HERE/../keep; UNIT=$HERE/keep-unit; SCAN=$HERE/keyscan
W=/root/kc-compat
fail() { echo "compat-check: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
[ $# -eq 0 ] || fail "usage: compat-check.sh [-m] [-c]"
for f in "$KEEP" "$UNIT" "$SCAN"; do [ -x "$f" ] || fail "no $f (make all tests/keyscan builds it)"; done
if [ -n "$MEM" ]; then
    [ -n "${AVML:-}" ] && [ -x "$AVML" ] || fail "-m and -c need AVML=/path/to/avml (tests/get-avml.sh fetches it)"
    AVML=$(cd "$(dirname "$AVML")" && pwd)/${AVML##*/}
fi
for c in cryptsetup dmsetup losetup sha256sum; do command -v "$c" >/dev/null || fail "$c is not installed on this guest"; done
for n in kc_l2 kc_l1 kc_null No kc_pv kc_vg-data kc_vg-swap kc_it kc_ik kc_re; do [ ! -e "/dev/mapper/$n" ] || fail "the mapping $n is already open, close it first"; done

LOOPS=()
RP=""
close_lvm() {   # the volume group on kc_pv with what is mounted from it, and kc_pv
    local b
    for b in "$W"/bind*; do [ -d "$b" ] && umount "$b" 2>/dev/null; done
    umount "$W/lvm" 2>/dev/null
    swapoff /dev/mapper/kc_vg-swap 2>/dev/null
    vgchange -an kc_vg >/dev/null 2>&1
    vgremove -ff kc_vg >/dev/null 2>&1
    cryptsetup close kc_pv 2>/dev/null
}
cleanup() {
    # a re-encryption that is still paused: let it go on and end it
    [ -z "$RP" ] || { kill -CONT "$RP" 2>/dev/null; kill -INT "$RP" 2>/dev/null; wait "$RP" 2>/dev/null; }
    cryptsetup close kc_re 2>/dev/null
    cryptsetup close kc_it 2>/dev/null
    cryptsetup close kc_ik 2>/dev/null
    umount "$W/fat" 2>/dev/null
    umount "$W/small" 2>/dev/null
    close_lvm
    cryptsetup close kc_l2 2>/dev/null
    cryptsetup close kc_l1 2>/dev/null
    dmsetup remove kc_null 2>/dev/null
    dmsetup remove No 2>/dev/null
    for l in "${LOOPS[@]}"; do losetup -d "$l" 2>/dev/null; done
    rm -rf "$W"
}
trap cleanup EXIT
rm -rf "$W"; mkdir -p "$W/dest" || fail "cannot create $W"
chmod 700 "$W"; cd "$W" && W=$(pwd -P) || exit 1

# keep on the guest as it is, before a mapping is made: on a guest without encrypted
# volumes this is the run with none, which must end in order like any other. Its shell has a
# limit of the size of a file of one block, as a shell of an examined system can have one: the
# program takes the limit off, which root may, and no file of the run is cut.
mkdir "$W/empty"
( cd "$W/empty" && ulimit -f 1 && "$KEEP" ) > "$W/empty/screen.txt" 2>&1; RCE=$?
E=$(ls -d "$W"/empty/triage_* 2>/dev/null | tail -n 1)
EMPTY=FAIL
[ "$RCE" = 0 ] && grep -q '"volumes": \[' "$E/verdict.json" 2>/dev/null && (cd "$E" && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) && EMPTY=PASS
if [ -n "${KEEP_SAN:-}" ]; then
    mkdir "$W/empty-san"
    "$KEEP_SAN" -d "$W/empty-san" > "$W/empty-san/screen.txt" 2>&1 || { EMPTY=FAIL; cat "$W/empty-san/screen.txt" >> "$W/empty/screen.txt"; }
fi

# the key file option was renamed in cryptsetup 2.5.0
if cryptsetup --help 2>&1 | grep -q -e '--volume-key-file'; then VK=--volume-key-file; else VK=--master-key-file; fi
printf 'compat-check-passphrase' > pw
mk() {  # mk NAME TYPE [options], the size of the container in SIZE
    local n=$1 t=$2; shift 2
    head -c 64 /dev/urandom > "$n.vk"
    truncate -s "${SIZE:-64M}" "$n.img"
    cryptsetup luksFormat -q --type "$t" --cipher aes-xts-plain64 --key-size 512 "$VK" "$n.vk" "$@" --key-file pw "$n.img" \
        || fail "luksFormat $n failed"
    cryptsetup open --key-file pw "$n.img" "$n" || fail "open $n failed"
}
mk kc_l2 luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000
mk kc_l1 luks1 --pbkdf pbkdf2 --pbkdf-force-iterations 1000
# two mappings straight from a table line, as the kernel takes it: one with a key that is known
# here and a name that reads like the first word of "No devices found", one without a key
dm() {  # dm NAME CIPHER KEYFIELD
    local l
    truncate -s 16M "$1.img"; l=$(losetup --find --show "$1.img") || fail "losetup $1 failed"
    LOOPS+=("$l")
    dmsetup create "$1" --table "0 32768 crypt $2 $3 0 $l 0" || fail "dmsetup create $1 failed"
}
head -c 64 /dev/urandom > No.vk
dm No aes-xts-plain64 "$(od -An -v -tx1 No.vk | tr -d ' \n')"
dm kc_null cipher_null-ecb -

sha() { sha256sum < "$1" | cut -c1-16; }
# cfield FOLDER VOLUME FIELD : a field of a volume in a report, not one of its further keys
cfield() { grep "\"name\": \"$2\"" "$1/verdict.json" | sed -n "s/.*\"name\": \"$2\"[^[]*\"$3\": \"\\([^\"]*\\)\".*/\\1/p"; }
# the first 16 digits of the SHA-256 of a key that is read in hexadecimal, as a table shows it
hexsha() { printf '%b' "$(sed 's/../\\x&/g')" | sha256sum | cut -c1-16; }
# one field of "cryptsetup status" in status.txt: everything after the label
sfield() { awk -v k="$1" '$0 ~ "^[[:space:]]*" k ":" {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}' "$W/status.txt"; }
crypts() { dmsetup ls --target crypt | cut -f1 | sort; }

# against FOLDER : the report and the files that keep wrote into FOLDER, against what the
# tools of this system say of the same mappings (see the head of this script). What differs
# is written to against.txt, and the status is 1 where something does. TABLES, HEADERS, PROVEN
# and TABLEKEYS count what was compared.
against() {
    local c=$1 n typ ksz loc dev tcip tkey want v
    TABLES=0; HEADERS=0; PROVEN=0; TABLEKEYS=0
    : > "$W/against.txt"
    diff <(crypts) <(sed -n 's/^    {"name": "\([^"]*\)", "type": .*/\1/p' "$c/verdict.json" | sort) >> "$W/against.txt" 2>&1 ||
        echo "the volumes of the report are not the mapped devices of \"dmsetup ls --target crypt\"" >> "$W/against.txt"
    for n in $(crypts); do
        cryptsetup status "$n" > "$W/status.txt" 2>&1
        typ=$(sfield type); loc=$(sfield "key location"); dev=$(sfield device)
        # the line "keysize:" and not "integrity keysize:", which a volume with integrity has as well
        ksz=$(awk '$1 == "keysize:" {print $2; exit}' "$W/status.txt")
        tcip=$(dmsetup table "$n" | awk '$3 == "crypt" {print $4; exit}')
        tkey=$(dmsetup table --showkeys "$n" | awk '$3 == "crypt" {print $5; exit}')
        want="    {\"name\": \"$n\", \"type\": \"$typ\", \"cipher\": \"$tcip\", \"key_bits\": $ksz, \"key_location\": \"$loc\", \"device\": \"$dev\", "
        grep -q -F "$want" "$c/verdict.json" ||
            { echo "$n is not named as cryptsetup status and the table of dmsetup name it:"; echo "$want"; grep -F "\"name\": \"$n\"" "$c/verdict.json" | cut -c1-240; } >> "$W/against.txt"
        # log/NAME.table.txt begins with what the kernel said about the mapping, each key as
        # zeros: its UUID, its device number and its table, as dmsetup prints them
        awk -v RS= 'NR == 1' "$c/log/$n.table.txt" > "$W/ours.table" 2> /dev/null
        { echo "name $n"; echo "uuid $(dmsetup info -c --noheadings -o uuid "$n" | tr -d ' ' | sed 's/^$/-/')"
          echo "device $(dmsetup info -c --noheadings -o major,minor "$n" | tr -d ' ')"; dmsetup table "$n"; } > "$W/theirs.table"
        if cmp -s "$W/ours.table" "$W/theirs.table"; then
            TABLES=$((TABLES + 1))
        else
            { echo "$n: log/$n.table.txt does not begin with what dmsetup says of the mapping:"; diff "$W/theirs.table" "$W/ours.table"; } >> "$W/against.txt"
        fi
        v=$(cfield "$c" "$n" verdict)
        case $typ in
        LUKS1|LUKS2)
            rm -f "$W/theirs.hdr"
            if cryptsetup luksHeaderBackup "$dev" --header-backup-file "$W/theirs.hdr" > /dev/null 2>&1 && cmp -s "$c/headers/$n.hdr" "$W/theirs.hdr"; then
                HEADERS=$((HEADERS + 1))
            else
                echo "$n: headers/$n.hdr is not the file of cryptsetup luksHeaderBackup" >> "$W/against.txt"
            fi
            if [ -f "$c/keys/$n.vk" ] && cryptsetup open --test-passphrase "$VK" "$c/keys/$n.vk" "$W/theirs.hdr" > /dev/null 2>&1; then
                PROVEN=$((PROVEN + 1))
                [ "$v" = "captured and proven" ] || echo "$n: cryptsetup accepts keys/$n.vk for the header, and the verdict is \"$v\"" >> "$W/against.txt"
            else
                [ "$v" != "captured and proven" ] || echo "$n: the verdict is \"$v\", and cryptsetup does not accept keys/$n.vk for the header, or there is no such file" >> "$W/against.txt"
            fi ;;
        esac
        case $tkey in
        :*|-|'') ;;
        *)  # the key that the table shows is the key that is kept
            if [ -f "$c/keys/$n.vk" ] && [ "$(od -An -v -tx1 "$c/keys/$n.vk" | tr -d ' \n')" = "$tkey" ]; then
                TABLEKEYS=$((TABLEKEYS + 1))
            else
                echo "$n: keys/$n.vk is not the key that dmsetup table --showkeys shows" >> "$W/against.txt"
            fi ;;
        esac
    done
    [ ! -s "$W/against.txt" ]
}

# examine DEST LABEL : keep on the mappings as they are now, started in the directory DEST with
# no destination named, and what it wrote against the tools of this system. Its folder is left
# in C.
examine() {
    local dest=$1 label=$2 rc ok=1 f n devs pages=0
    # keep reads a header past the page cache and writes its copy past it. So the cache of
    # each device with a header is let go before the run, and after it, before anything else
    # reads them, no page of such a device and none of a copy may lie there.
    devs=$(for n in $(crypts); do cryptsetup status "$n" 2> /dev/null | awk '$1 == "type:" && $2 ~ /^LUKS/ {l = 1} l && $1 == "device:" {print $2}'; done | sort -u)
    for f in $devs; do "$UNIT" forget "$f" || ok=0; done
    ( cd "$dest" && "$KEEP" ) > "$dest/screen.txt" 2>&1; rc=$?
    C=$(ls -d "$dest"/triage_* 2>/dev/null | tail -n 1)
    [ "$rc" = 0 ] && [ -f "$C/verdict.json" ] || ok=0
    : > "$dest/diff.txt"
    for f in $devs "$C"/headers/*.hdr; do
        [ -e "$f" ] || continue
        n=$("$UNIT" cached "$f" 2>&1)
        case $n in
        "0 of "*) pages=$(( pages + $(printf '%s' "$n" | sed 's/^0 of \([0-9]*\) .*/\1/') )) ;;
        *) ok=0; echo "in the page cache after the run, $f: $n" >> "$dest/diff.txt" ;;
        esac
    done
    [ -n "$devs" ] || { ok=0; echo "no device with a header among the mappings" >> "$dest/diff.txt"; }
    if grep -q 'through the page cache' "$dest/screen.txt"; then
        ok=0; echo "a header went through the page cache" >> "$dest/diff.txt"
    fi
    against "$C" || { ok=0; cat "$W/against.txt" >> "$dest/diff.txt"; }
    (cd "$C" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || { ok=0; echo "the manifest does not verify" >> "$dest/diff.txt"; }
    if [ -n "${KEEP_SAN:-}" ]; then
        mkdir "$dest/san"
        "$KEEP_SAN" -d "$dest/san" > "$dest/san/screen.txt" 2>&1 || { ok=0; echo "the build with the sanitizers:" >> "$dest/diff.txt"; cat "$dest/san/screen.txt" >> "$dest/diff.txt"; }
    fi
    if [ "$ok" = 1 ]; then
        echo "PASS   $label: $(crypts | wc -l) volumes as dmsetup lists them, each with the type, key size, key location and device of cryptsetup status and the cipher of its table, $TABLES tables in log/ as dmsetup prints them, $HEADERS header backups byte for byte the files of cryptsetup luksHeaderBackup, $PROVEN keys that cryptsetup accepts for their headers, $TABLEKEYS keys as dmsetup table --showkeys shows them, manifest${KEEP_SAN:+, also with the sanitizers}"
        echo "       of the $pages pages of the devices with a header and of the copies, none in the page cache after the run"
    else
        echo "FAIL   $label, status $rc"; sed 's/^/       /' "$dest/diff.txt" "$dest/screen.txt"; PASS=0
    fi
}

echo "==== Keep compatibility check"
echo "system:      $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')"
echo "kernel:      $(uname -r)"
echo "cryptsetup:  $(cryptsetup --version | head -n 1)"
echo "dmsetup:     $(dmsetup --version 2>/dev/null | head -n 1 | tr -s ' ')"
echo "key option:  $VK"
echo "lockdown:    $(cat /sys/kernel/security/lockdown 2>/dev/null || echo 'no lockdown file')"
echo "AES-NI:      $(grep -q -w aes /proc/cpuinfo && echo yes || echo no)"
echo "XTS driver:  $(awk '$1=="name" && $3=="xts(aes)" {f=1} f && $1=="driver" {print $3; exit}' /proc/crypto)"
echo "tool:        $("$KEEP" -V)"
echo

PASS=1
if [ "$EMPTY" = PASS ]; then
    echo "PASS   before any mapping is made: $(grep -c '^    {"name": .*, "type": ' "$E/verdict.json") volume(s) of the guest itself, status 0, manifest, under a limit of the size of a file${KEEP_SAN:+, also with the sanitizers}"
else
    echo "FAIL   before any mapping is made, status $RCE"; sed 's/^/       /' "$W/empty/screen.txt"; PASS=0
fi
# No destination is named: it is the directory of the start, which lies on the disk of this
# guest. Where the destination lies is the examiner's decision, and no place is refused.
examine "$W/dest" "the four mappings"
O=$C
for n in kc_l2:"R3 memory" kc_l1:"R1 table"; do
    r=${n#*:}; n=${n%%:*}
    if [ "$(cfield "$O" "$n" verdict)" = "captured and proven" ] && [ "$(cfield "$O" "$n" route)" = "$r" ] && cmp -s "$O/keys/$n.vk" "$n.vk" &&
        [ "$(cfield "$O" "$n" key_sha256_16)" = "$(sha "$n.vk")" ]; then
        printf 'PASS   %-5s verdict "captured and proven", route "%s", key equals the ground truth\n' "$n" "$r"
    else
        printf 'FAIL   %-5s verdict "%s", route "%s", the key differs from the ground truth or is missing\n' "$n" "$(cfield "$O" "$n" verdict)" "$(cfield "$O" "$n" route)"; PASS=0
    fi
done
if [ "$(cfield "$O" No verdict)" = "captured, in use" ] && cmp -s "$O/keys/No.vk" No.vk && [ "$(cfield "$O" No key_sha256_16)" = "$(sha No.vk)" ]; then
    echo "PASS   No    verdict \"captured, in use\", key equals the ground truth"
else
    echo "FAIL   No    verdict \"$(cfield "$O" No verdict)\", the mapping is missing or its key differs"; PASS=0
fi
if [ "$(cfield "$O" kc_null verdict)" = "no key needed" ] && [ ! -e "$O/keys/kc_null.vk" ]; then
    echo "PASS   kc_null verdict \"no key needed\""
else
    echo "FAIL   kc_null verdict \"$(cfield "$O" kc_null verdict)\""; PASS=0
fi
if [ -n "$O" ] && grep -q "^  output       $O\$" "$W/dest/screen.txt" && grep -q '^  destination  .*, mounted at ' "$W/dest/screen.txt"; then
    echo "PASS   no destination named: the folder of the run is in the directory of the start, on the guest's own disk"
else
    echo "FAIL   no destination named: the folder of the run is not in the directory of the start: $(sed -n '/^  output/p' "$W/dest/screen.txt")"; PASS=0
fi
# A mapped device that was removed since the list was read has no table, and the kernel says
# so with an error of its own, which the program tells apart from a table that cannot be read.
"$UNIT" dm-table kc_no_such_device > /dev/null 2> "$W/gone.txt"; rcg=$?
if [ "$rcg" = 3 ]; then
    echo "PASS   a mapped device that is not there is named as such by the kernel, and not as a table that cannot be read"
else
    echo "FAIL   the table of a mapped device that is not there: status $rcg, $(cat "$W/gone.txt")"; PASS=0
fi

# A run that is asked to end while it searches the memory. The list of the schedules is made
# when the search begins, and the search of a machine takes a second at least, so the signal
# meets it there. SIGTERM, because a shell without job control starts a command in the
# background with SIGINT ignored, which the program leaves as it is. The keys of the table
# must be kept all the same, also the one of a volume that comes after the search, the key
# of the keyring must be named as not reached, and the report and the manifest be written.
asked() {
    local d=$W/asked pid rc i c
    mkdir "$d"
    "$KEEP" -d "$d" > "$d/screen.txt" 2>&1 &
    pid=$!
    for i in $(seq 1 6000); do
        ls "$d"/triage_*/keys/kcore-candidates.txt > /dev/null 2>&1 && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.01
    done
    kill -TERM "$pid" 2>/dev/null
    wait "$pid"; rc=$?
    c=$(ls -d "$d"/triage_* 2>/dev/null | tail -n 1)
    [ "$rc" = 1 ] || echo "status $rc, not 1"
    grep -q '^  "interrupted": true,$' "$c/verdict.json" 2>/dev/null || echo "verdict.json does not say that the run was interrupted"
    grep -q '^interrupted by SIGTERM: ' "$d/screen.txt" && grep -q '^interrupted by SIGTERM: ' "$c/triage.txt" || echo "the screen and triage.txt do not say that the run was interrupted"
    grep -q '^keep: the run was ended by a signal' "$d/screen.txt" || echo "the last line does not say that the run was ended by a signal"
    [ "$(cfield "$c" kc_l2 verdict)" = "needs a memory read" ] && [ "$(cfield "$c" kc_l2 note)" = "the search of /proc/kcore was ended by a signal" ] ||
        echo "kc_l2: \"$(cfield "$c" kc_l2 verdict)\", $(cfield "$c" kc_l2 note)"
    [ "$(cfield "$c" kc_l1 verdict)" = "captured and proven" ] && cmp -s "$c/keys/kc_l1.vk" kc_l1.vk || echo "the key of kc_l1 is not kept and proven"
    [ "$(cfield "$c" No verdict)" = "captured, in use" ] && cmp -s "$c/keys/No.vk" No.vk || echo "the key of No is not kept"
    [ "$(cfield "$c" kc_null verdict)" = "no key needed" ] || echo "kc_null, which comes after the search, has no verdict"
    [ -f "$c/keys/kcore-candidates.txt" ] && [ ! -e "$c/keys/kc_l2.vk" ] || echo "no list of the schedules, or a key of kc_l2"
    cmp -s "$c/headers/kc_l2.hdr" "$O/headers/kc_l2.hdr" || echo "the copy of the header of kc_l2 is not that of the main run"
    (cd "$c" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || echo "the manifest does not verify"
}
if asked > "$W/asked.txt" 2>&1 && [ ! -s "$W/asked.txt" ]; then
    echo "PASS   asked to end while it searches the memory: the search ends, the keys of kc_l1 and No are kept, kc_l2 needs a memory read, report and manifest are written, status 1"
else
    echo "FAIL   asked to end while it searches the memory"; sed 's/^/       /' "$W/asked.txt" "$W/asked/screen.txt"; PASS=0
fi

# The image that AVML takes of this machine, while the two containers are open. The scanner
# must read it to its end and find in it the schedules of both halves of both volume keys:
# image-candidates.txt is then what the images of keep are held against.
if [ -n "$MEM" ]; then
    mkdir "$W/avml"; img=$W/avml/$IMAGE
    case $MEM in -c) "$AVML" acquire --compress "$img" > "$W/avml/avml.txt" 2>&1 ;; *) "$AVML" acquire "$img" > "$W/avml/avml.txt" 2>&1 ;; esac; rca=$?
    if [ "$rca" = 0 ] && [ -s "$img" ]; then
        "$SCAN" "$img" > "$W/image-candidates.txt" 2> "$W/image-scan.txt"; rcs=$?
        inimg=1
        for n in kc_l2 kc_l1; do
            for o in 0 32; do
                grep -q " key $(od -An -v -tx1 -j "$o" -N 32 "$n.vk" | tr -d ' \n')\$" "$W/image-candidates.txt" || inimg=0
            done
        done
        if [ "$rcs" = 0 ] && [ "$inimg" = 1 ]; then res=PASS; else res=FAIL; PASS=0; : > "$W/image-candidates.txt"; fi
        echo "$res   the image of $("$AVML" --version 2>/dev/null | head -n 1), $IMAGE: $(stat -c%s "$img") bytes, $(sed -n 's/^kcore-keyscan [^,]*, \(.*\), [0-9]* segments*, \([0-9]* bytes\).*/\1, \2 of memory/p' "$W/image-scan.txt"), $(wc -l < "$W/image-candidates.txt") key schedules, $([ "$inimg" = 1 ] && echo "the keys of both containers among them" || echo "the keys of the containers are not all among them"), scanner status $rcs"
    else
        PASS=0
        echo "FAIL   AVML took no image, status $rca: $(grep -v '^[[:space:]]*$' "$W/avml/avml.txt" | head -n 3 | tr -s ' \t\n' ' ')"
    fi
    rm -f "$img"
fi

# The memory image of keep. AVML took its image of the same machine just before, with the
# same containers open, and the scanner listed what it holds in image-candidates.txt.
# The kernel keeps the schedules of an open volume where they are, so each must lie in the new
# image at an address at which it lies in that one. Memory that a program gave back can hold
# further copies in one image and not in the other, which is why one common address counts.
# cimage PROGRAM WORD LABEL : one run with -m and the format WORD, or with -m -F for the word
# "all". Its images are examined and then removed.
cimage() {
    local k=$1 word=$2 label=$3 d c img rc rcs n o key f formats said="" sd sa alone="" cached=""
    d=$W/cimage-$(printf '%s' "$3" | tr -c 'a-z0-9' '_')        # a comma in a path would end the name in what the scanner says
    local -a how
    case $word in all) formats="lime raw avml"; how=(-F) ;; *) formats=$word; how=(-f "$word") ;; esac
    mkdir "$d"
    "$k" -m "${how[@]}" -d "$d" > "$d/screen.txt" 2>&1; rc=$?
    c=$(ls -d "$d"/triage_* 2>/dev/null | tail -n 1)
    : > "$d/why.txt"
    [ "$rc" = 0 ] || echo "status $rc" >> "$d/why.txt"
    # The image is written with direct writes and its pages are let go from the page cache:
    # before anything reads a file, none of its pages may lie in the cache, but one that the
    # kernel could not let go. A file system of the guest without such writes would be named
    # by the run, and is none that this check knows.
    for f in $formats; do
        [ -s "$c/memory/memory.$f" ] || continue
        n=$("$UNIT" cached "$c/memory/memory.$f" 2>&1)
        case $n in
        "0 of "*|"1 of "*) cached="$cached, memory.$f ${n%% pages*}" ;;
        *) echo "memory.$f after the run: $n" >> "$d/why.txt" ;;
        esac
    done
    [ "$(grep -c '^  written      direct (O_DIRECT), pages released from the page cache$' "$d/screen.txt")" = "$(set -- $formats; echo $#)" ] ||
        echo "not every image is named as written with direct writes" >> "$d/why.txt"
    (cd "$c" 2>/dev/null && sha256sum -c --quiet manifest.sha256 > "$d/manifest.txt" 2>&1) || echo "the manifest does not verify" >> "$d/why.txt"
    for f in $formats; do
        img=$c/memory/memory.$f
        [ -s "$img" ] || { echo "no image memory.$f" >> "$d/why.txt"; continue; }
        # the report names the file with its size and with the SHA-256 that the manifest verifies
        grep -q "{\"status\": \"captured\", \"file\": \"memory/memory.$f\", \"format\": \"${f}[a-z ]*\", \"bytes\": $(stat -c%s "$img"), [^}]*\"sha256\": \"$(sed -n "s|  memory/memory.$f\$||p" "$c/manifest.sha256")\"" "$c/verdict.json" ||
            echo "verdict.json does not name memory.$f with its size and its SHA-256" >> "$d/why.txt"
        "$SCAN" "$img" > "$d/candidates-$f.txt" 2> "$d/scan-$f.txt"; rcs=$?
        [ "$rcs" = 0 ] || echo "the scanner ended with status $rcs on memory.$f" >> "$d/why.txt"
        for n in kc_l2 kc_l1; do
            for o in 0 32; do
                key=$(od -An -v -tx1 -j "$o" -N 32 "$n.vk" | tr -d ' \n')
                grep " key $key\$" "$W/image-candidates.txt" | grep -q -x -F -f - "$d/candidates-$f.txt" ||
                    echo "a schedule of $n lies in memory.$f at no address at which it lies in the image of AVML" >> "$d/why.txt"
            done
        done
        # what one read wrote is the same memory in every file
        cmp -s "$d/candidates-$f.txt" "$d/candidates-${formats%% *}.txt" || echo "memory.$f gives other schedules than memory.${formats%% *} of the same read" >> "$d/why.txt"
        if [ "$f" = "${formats%% *}" ]; then
            # the image as a dump that exists: the search of it must prove the keys of both
            # containers against the headers in their images, which are files of this folder
            "$k" -s "$img" -d "$d" kc_l2.img kc_l1.img > "$d/screen-s.txt" 2>&1; rcs=$?
            sd=$(ls -d "$d"/scan_* 2>/dev/null | tail -n 1)
            [ "$rcs" = 0 ] && cmp -s "$sd/keys/kc_l2.img.vk" kc_l2.vk && cmp -s "$sd/keys/kc_l1.img.vk" kc_l1.vk &&
                (cd "$sd" && sha256sum -c --quiet manifest.sha256 > /dev/null 2>&1) ||
                { echo "keep -s does not prove the keys of both containers from memory.$f against their images, status $rcs" >> "$d/why.txt"; cat "$d/screen-s.txt" >> "$d/why.txt"; }
            # The image alone, with no file: what it holds of a header by itself. This is told
            # and not judged, because it depends on what runs on the system: the containers of
            # this check lie in files, whose cache holds their headers.
            if [ "$k" = "$KEEP" ]; then
                mkdir "$d/alone"
                "$k" -s "$img" -d "$d/alone" > "$d/screen-alone.txt" 2>&1
                sa=$(ls -d "$d"/alone/scan_* 2>/dev/null | tail -n 1)
                alone="$(grep -c '^memory@0x[0-9a-f]*$' "$d/screen-alone.txt") header(s) or digest(s) of a header in its memory"
                for n in kc_l2 kc_l1; do
                    for key in "$sa"/keys/memory@*.vk; do
                        if cmp -s "$key" "$n.vk"; then alone="$alone, the key of $n proven from one"; break; fi
                    done
                done
            fi
        fi
        if [ "$f" = avml ]; then
            # AVML reads the compressed image: its LiME image of it must hold the same
            "$AVML" convert "$img" "$d/converted.lime" > "$d/convert.txt" 2>&1 && "$SCAN" "$d/converted.lime" 2> /dev/null | cmp -s - "$d/candidates-$f.txt" ||
                echo "AVML does not convert memory.avml, or its LiME image of it gives other schedules" >> "$d/why.txt"
            rm -f "$d/converted.lime"
        fi
        said="$said, memory.$f $(stat -c%s "$img") bytes"
    done
    if [ ! -s "$d/why.txt" ]; then
        echo "PASS   the memory image, $label:${said#,}, $(sed -n 's/^kcore-keyscan [^,]*, [^,]*, [0-9]* segments*, \([0-9]* bytes\).*/\1 of memory/p' "$d/scan-${formats%% *}.txt"), read in $(sed -n 's/.*"seconds": \([0-9]*\),.*/\1/p' "$c/verdict.json") s. The report names each size and SHA-256, the scanner reads each to its end, and the schedules of both containers lie where they lie in the image of AVML. \"keep -s\" proves the keys of both containers from memory.${formats%% *} against their images$(case " $formats " in *" avml "*) echo ". AVML converts the compressed image to the same memory" ;; esac)"
        echo "       $(grep -m 1 '^  source ' "$d/screen.txt" | sed 's/^ *source  */source: /')"
        # with what a long line goes on with below its value
        echo "       $(awk '/^  symbols / { on = 1; sub(/^ *symbols */, "symbols: "); printf "%s", $0; next }
                            on && /^               [^ ]/ { sub(/^ */, " "); printf "%s", $0; next }
                            on { exit }' "$d/screen.txt")"
        echo "       pages in the page cache after the run:${cached#,}"
        [ -z "$alone" ] || echo "       \"keep -s\" with memory.${formats%% *} and no file: $alone"
    else
        echo "FAIL   the memory image, $label"; sed 's/^/       /' "$d/why.txt" "$d/screen.txt"; PASS=0
    fi
    rm -f "$c"/memory/memory.lime "$c"/memory/memory.raw "$c"/memory/memory.avml
}
# An image whose read is ended: keep is sent SIGTERM when the file of the image has its first
# bytes. The keys were taken before, so the run has them. The part of the image must be kept
# and named as interrupted, with its size and with the SHA-256 that the manifest verifies,
# and the scanner must read it as the run says it is: a LiME image whose last range ends
# before the end that its header states, which it names with status 1.
cut_image() {
    local d=$W/cut pid rc i c img inside
    mkdir "$d"
    "$KEEP" -m -d "$d" > "$d/screen.txt" 2>&1 &
    pid=$!
    for i in $(seq 1 60000); do
        [ -s "$(ls "$d"/triage_*/memory/memory.lime 2>/dev/null | head -n 1)" ] && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.01
    done
    kill -TERM "$pid" 2>/dev/null
    wait "$pid"; rc=$?
    c=$(ls -d "$d"/triage_* 2>/dev/null | tail -n 1); img=$c/memory/memory.lime
    [ "$rc" = 1 ] || echo "status $rc, not 1"
    grep -q '^  "interrupted": true,$' "$c/verdict.json" 2>/dev/null || echo "verdict.json does not say that the run was interrupted"
    grep -q "\"memory\": {\"status\": \"interrupted\", \"file\": \"memory/memory.lime\", \"format\": \"lime\", \"bytes\": $(stat -c%s "$img" 2>/dev/null), [^}]*\"sha256\": \"$(sha256sum < "$img" | cut -d' ' -f1)\"" "$c/verdict.json" ||
        echo "verdict.json does not name the part of the image as interrupted, with its size and its SHA-256"
    grep -q '^  memory.lime  interrupted, ' "$d/screen.txt" && grep -q '^  holds        the first [0-9]* of [0-9]* bytes of the memory' "$d/screen.txt" ||
        echo "the screen does not name the image as interrupted and what it holds"
    [ "$(cfield "$c" kc_l2 verdict)" = "captured and proven" ] && cmp -s "$c/keys/kc_l2.vk" kc_l2.vk && cmp -s "$c/keys/kc_l1.vk" kc_l1.vk || echo "the keys, which were taken before the image, are not kept"
    (cd "$c" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || echo "the manifest does not verify"
    "$SCAN" "$img" > /dev/null 2> "$d/scan.txt"; rc=$?
    if tr -s '\n ' '  ' < "$d/screen.txt" | grep -q 'Its last range ends before the end that its header states'; then inside=1; else inside=0; fi
    if [ "$inside" = 1 ]; then
        [ "$rc" = 1 ] && grep -q 'the file ends inside a range' "$d/scan.txt" || { echo "the scanner on the part, status $rc:"; cat "$d/scan.txt"; }
    else
        [ "$rc" = 0 ] || { echo "the scanner on a part of whole ranges, status $rc:"; cat "$d/scan.txt"; }
    fi
    CUT="$(sed -n 's/^  holds  *\(the first [0-9]* of [0-9]* bytes\).*/\1/p' "$d/screen.txt") of the memory, $(stat -c%s "$img" 2>/dev/null) bytes"
    rm -f "$img"
}
if [ -n "$MEM" ] && [ -s "$W/image-candidates.txt" ]; then
    first=1
    for f in ${KEEP_IMAGES:-lime raw avml all}; do
        cimage "$KEEP" "$f" "$f"
        # the build with the sanitizers takes the image once: the formats are its unit checks
        if [ -n "${KEEP_SAN:-}" ] && [ "$first" = 1 ]; then cimage "$KEEP_SAN" "$f" "$f, with the sanitizers"; fi
        first=0
    done
    CUT=""
    cut_image > "$W/cut.txt" 2>&1
    if [ ! -s "$W/cut.txt" ]; then
        echo "PASS   asked to end while it reads the memory image: the part is kept and named as interrupted, $CUT, with the SHA-256 that the manifest verifies, the scanner reads it as that, the keys are kept, status 1"
    else
        echo "FAIL   asked to end while it reads the memory image"; sed 's/^/       /' "$W/cut.txt" "$W/cut/screen.txt"; PASS=0
    fi
fi
# A destination with FAT, named with -d. Every name must be taken by FAT.
mkdir "$W/fat"; truncate -s 96M fat.img
if command -v mkfs.vfat >/dev/null && mkfs.vfat fat.img >/dev/null 2>&1 && mount -o loop fat.img "$W/fat" 2>/dev/null; then
    # -d, the names on FAT, and what the screen says about the system and about the keys that
    # are held
    "$KEEP" -d "$W/fat" > "$W/screen-cfat.txt" 2>&1; rcm=$?
    M=$(ls -d "$W"/fat/triage_* 2>/dev/null | tail -n 1)
    ok=1
    # FAT takes a direct write that makes a file longer through the page cache by itself, and
    # the kernel drops those pages (fat_direct_IO, direct_write_fallback): none may be left
    fatpages=""
    for f in "$M"/headers/*.hdr; do
        [ -e "$f" ] || continue
        n=$("$UNIT" cached "$f" 2>&1)
        fatpages="$fatpages ${f##*/} $n,"
        case $n in "0 of "*) ;; *) ok=0 ;; esac
    done
    grep -q 'through the page cache' "$W/screen-cfat.txt" && ok=0
    [ "$rcm" = 0 ] && grep -q '^  destination  .*, vfat, mounted at .*, [0-9.]* [GMiBbytes]* free$' "$W/screen-cfat.txt" &&
        grep -q '^  memory       [0-9.]* [GM]iB$' "$W/screen-cfat.txt" && grep -q '^  kernel       [^ ]' "$W/screen-cfat.txt" || ok=0
    grep -q '^  volumes      [0-9]* open dm-crypt volumes: .*kc_l1.*kc_l2' "$W/screen-cfat.txt" || ok=0
    for n in kc_l2 kc_l1 No; do
        cmp -s "$M/keys/$n.vk" "$n.vk" || ok=0
        grep -q "^  key file     keys/$n.vk, $(stat -c%s "$n.vk") bytes, sha256 $(sha256sum < "$n.vk" | cut -c1-16)\$" "$W/screen-cfat.txt" || ok=0
        # and once more in the result, by the start of its SHA-256
        grep -q "^  $n  *captured[a-z, ]*  $(sha256sum < "$n.vk" | cut -c1-16)\$" "$W/screen-cfat.txt" || ok=0
    done
    (cd "$M" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || ok=0
    if [ "$ok" = 1 ]; then
        echo "PASS   a destination on FAT, named with -d: the system and the open volumes are named, three keys equal the ground truth and are named by file, length and SHA-256, manifest"
        echo "       the copies of the headers on FAT, before anything read them:$fatpages"
    else
        echo "FAIL   a destination on FAT, named with -d, status $rcm, pages of the copies in the page cache:$fatpages"; sed 's/^/       /' "$W/screen-cfat.txt"; PASS=0
    fi
else
    echo "SKIP   no mkfs.vfat or no FAT in this kernel, the destination with FAT is not run"
fi
# A destination without room for the copy of a header: a megabyte, where the copy of the
# LUKS1 header takes two and that of the LUKS2 header sixteen. A part of a copy that stayed
# would take the room of the keys, which are what cannot be had again. So each part must be
# gone, the key of the table and the list of the schedules must be kept all the same, the
# run must say that a write failed, with status 1, and its manifest must verify.
mkdir "$W/small"
if mount -t tmpfs -o size=1m,mode=700 none "$W/small" 2>/dev/null; then
    "$KEEP" -d "$W/small" > "$W/screen-small.txt" 2>&1; rcs=$?
    M=$(ls -d "$W"/small/triage_* 2>/dev/null | tail -n 1)
    : > "$W/small.txt"
    [ "$rcs" = 1 ] || echo "status $rcs, not 1" >> "$W/small.txt"
    [ "$(tr -s '\n ' '  ' < "$W/screen-small.txt" | grep -o 'write of the copy of the header: No space left on device. The part that was written is removed' | wc -l)" = 2 ] ||
        echo "not two copies that failed at a write and were removed" >> "$W/small.txt"
    [ -z "$(ls "$M"/headers 2>/dev/null)" ] || echo "a part of a copy stayed: $(ls -l "$M"/headers | tail -n +2 | tr '\n' ' ')" >> "$W/small.txt"
    for n in kc_l1 No; do
        cmp -s "$M/keys/$n.vk" "$n.vk" || echo "the key of $n is not kept" >> "$W/small.txt"
    done
    [ -s "$M/keys/kcore-candidates.txt" ] || echo "the list of the schedules is not kept" >> "$W/small.txt"
    grep -q '^    {"name": "kc_l1", .*"header_backup": null, .*"verdict": "captured, not proven"' "$M/verdict.json" 2>/dev/null ||
        echo "kc_l1 is not captured, not proven, without a header backup" >> "$W/small.txt"
    grep -q '^    {"name": "kc_l2", .*"header_backup": null, .*"verdict": "needs a memory read"' "$M/verdict.json" 2>/dev/null ||
        echo "kc_l2 does not need a memory read, without a header backup" >> "$W/small.txt"
    (cd "$M" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || echo "the manifest does not verify" >> "$W/small.txt"
    grep -q '^keep: a write or a flush to the destination FAILED' "$W/screen-small.txt" || echo "the run does not say that a write failed" >> "$W/small.txt"
    if [ ! -s "$W/small.txt" ]; then
        echo "PASS   a destination of 1 MiB: the parts of two header copies are removed, the key of the table, the key of the plain mapping and the list of the schedules are kept, status 1, manifest"
    else
        echo "FAIL   a destination of 1 MiB"; sed 's/^/       /' "$W/small.txt" "$W/screen-small.txt"; PASS=0
    fi
    umount "$W/small"
else
    echo "FAIL   a tmpfs of 1 MiB cannot be mounted"; PASS=0
fi
# LVM on LUKS: the stack of an encrypted installation
mkdir "$W/lvm"
if command -v vgcreate >/dev/null && command -v mkfs.ext4 >/dev/null; then
    SIZE=256M mk kc_pv luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000
    if vgcreate -q kc_vg /dev/mapper/kc_pv >/dev/null 2>"$W/lvm.txt" && lvcreate -q -y -n swap -L 32M kc_vg >/dev/null 2>>"$W/lvm.txt" \
        && lvcreate -q -y -n data -l 100%FREE kc_vg >/dev/null 2>>"$W/lvm.txt" \
        && mkfs.ext4 -q /dev/mapper/kc_vg-data 2>>"$W/lvm.txt" && mount /dev/mapper/kc_vg-data "$W/lvm" 2>>"$W/lvm.txt" \
        && mkswap /dev/mapper/kc_vg-swap >/dev/null 2>>"$W/lvm.txt" && swapon /dev/mapper/kc_vg-swap 2>>"$W/lvm.txt"; then
        # the file system is mounted at ten places, of which the line names eight
        for i in 1 2 3 4 5 6 7 8 9; do mkdir "$W/bind$i" && mount --bind "$W/lvm" "$W/bind$i"; done
        # the logical volume is the destination of this run
        mkdir "$W/lvm/c" && examine "$W/lvm/c" "LVM on LUKS"
        L=$C
        ok=1
        [ "$(cfield "$L" kc_pv verdict)" = "captured and proven" ] && cmp -s "$L/keys/kc_pv.vk" kc_pv.vk || ok=0
        grep -q '"name": "kc_vg-data"' "$L/verdict.json" 2>/dev/null && ok=0
        # what the volume carries is named: the logical volume and where it is mounted
        use=$(cfield "$L" kc_pv in_use)
        case $use in *"kc_vg-data at $W/lvm,"*) ;; *) ok=0 ;; esac
        [ "$(grep -o 'kc_vg-data at ' <<<"$use" | wc -l)" = 8 ] || ok=0
        case $use in *"kc_vg-swap as swap"*) ;; *) ok=0 ;; esac
        case $use in *" and 2 more mounts") ;; *) ok=0 ;; esac
        grep '"name": "kc_l1"' "$L/verdict.json" | grep -q '"in_use": null, ' || ok=0
        tr -s '\n ' '  ' < "$W/lvm/c/screen.txt" | grep -q -F " in use ${use} " || ok=0
        if [ "$ok" = 1 ]; then
            echo "PASS   LVM on LUKS: kc_pv is captured and proven, the logical volumes are not listed as volumes and are named as what kc_pv carries, one mounted at ten places and one as swap"
        else
            echo "FAIL   LVM on LUKS: in use \"$use\""; sed 's/^/       /' "$W/lvm/c/screen.txt"; PASS=0
        fi
    else
        echo "FAIL   LVM on LUKS: the volume group, a logical volume, the file system or the swap area could not be made: $(head -n 1 "$W/lvm.txt")"; PASS=0
    fi
else
    echo "SKIP   no lvm2 or no mkfs.ext4, LVM on LUKS is not run"
fi
# The two volumes with their keys in the keyring are closed here. The parts that follow are not
# about them, and every run with one of them open searches the whole memory once more.
close_lvm
cryptsetup close kc_l2 2>/dev/null

# LUKS2 with integrity: the volume key is the key of the cipher and then the key of HMAC, 96
# bytes, and the kernel names the cipher in the form of its crypto API.
CAPI='capi:authenc(hmac(sha256),xts(aes))-plain64'
integ() {  # integ NAME [option of open] : a container with integrity, made from a key drawn here, and opened
    local n=$1; shift
    head -c 96 /dev/urandom > "$n.vk"
    truncate -s 48M "$n.img"
    cryptsetup luksFormat -q --type luks2 --cipher aes-xts-plain64 --key-size 512 --integrity hmac-sha256 "$VK" "$n.vk" \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file pw "$n.img" >> "$W/int.txt" 2>&1 &&
        cryptsetup open --key-file pw "$@" "$n.img" "$n" >> "$W/int.txt" 2>&1
}
mkdir "$W/int"
if integ kc_it --disable-keyring && integ kc_ik; then
    examine "$W/int" "LUKS2 with integrity"
    I=$C
    ok=1
    [ "$(cfield "$I" kc_it verdict)" = "captured and proven" ] && cmp -s "$I/keys/kc_it.vk" kc_it.vk || ok=0
    [ "$(cfield "$I" kc_ik verdict)" = "live copy only" ] && [ ! -e "$I/keys/kc_ik.vk" ] || ok=0
    # the cipher as the kernel names it, where cryptsetup status says aes-xts-plain64
    grep '"name": "kc_it"' "$I/verdict.json" 2>/dev/null | grep -q -F "\"cipher\": \"$CAPI\", \"key_bits\": 768, \"key_location\": \"dm-crypt\"" || ok=0
    grep -q '"name": "kc_it_dif"' "$I/verdict.json" 2>/dev/null && ok=0
    if [ "$ok" = 1 ]; then
        echo "PASS   LUKS2 with integrity: kc_it is captured and proven with its key of 96 bytes and the cipher $CAPI, kc_ik with its key in the keyring is \"live copy only\", the dm-integrity devices are not listed"
    else
        echo "FAIL   LUKS2 with integrity"; sed 's/^/       /' "$W/int/screen.txt"; PASS=0
    fi
else
    echo "SKIP   LUKS2 with integrity is not run, the container could not be made or opened: $(grep -v '^$' "$W/int.txt" | head -n 1)"
fi

# A volume in re-encryption.
# ctriage NAME : keep on the mappings as they are now, into $W/re/NAME. Its folder is left in
# C, and the build with the sanitizers is run as well where it is given.
ctriage() {
    local d=$W/re/$1 rc
    mkdir "$d"
    ( cd "$d" && "$KEEP" ) > "$d/screen.txt" 2>&1; rc=$?
    C=$(ls -d "$d"/triage_* 2>/dev/null | tail -n 1)
    [ "$rc" = 0 ] && (cd "$C" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || return 1
    if [ -n "${KEEP_SAN:-}" ]; then
        mkdir "$d/san"
        "$KEEP_SAN" -d "$d/san" > "$d/san/screen.txt" 2>&1 || { cat "$d/san/screen.txt" >> "$d/screen.txt"; return 1; }
    fi
}
# reencrypt OPTION... : cryptsetup re-encrypts kc_re in the background, in steps of 1 MiB, each
# of which it writes down, so that it works for seconds. Returns when cryptsetup is in its first
# step: it has put its helper devices below the volume, and a crypt target of kc_re-overlay
# lies on kc_re-hotzone-forward. Returns 1 where cryptsetup ended before that.
reencrypt() {
    local i hz
    cryptsetup reencrypt -q --key-file pw --hotzone-size 1M --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$@" "$RL" >> "$W/re.txt" 2>&1 &
    RP=$!
    for i in $(seq 1 3000); do
        hz=$(dmsetup info -c --noheadings -o major,minor kc_re-hotzone-forward 2>/dev/null | tr -d ' ')
        [ -n "$hz" ] && dmsetup table kc_re-overlay 2>/dev/null | grep -q " crypt .* $hz " && return 0
        kill -0 "$RP" 2>/dev/null || break
        sleep 0.02
    done
    wait "$RP"; RP=""
    return 1
}
mkdir "$W/re"
re_part() {
    local t1 t2 use
    # on a loop device of its own, which stays while the volume is closed and opened again
    head -c 64 /dev/urandom > kc_re.vk
    truncate -s 2G kc_re.img
    RL=$(losetup --find --show kc_re.img) || { echo "no loop device for kc_re.img"; return 1; }
    LOOPS+=("$RL")
    cryptsetup luksFormat -q --type luks2 --cipher aes-xts-plain64 --key-size 512 "$VK" kc_re.vk --pbkdf pbkdf2 \
        --pbkdf-force-iterations 1000 --key-file pw "$RL" && cryptsetup open --key-file pw "$RL" kc_re ||
        { echo "kc_re could not be made or opened"; return 1; }

    # started and interrupted: the part that is done has the new key, the rest the old one
    reencrypt || { echo "the re-encryption ended before its helper devices were seen: $(tail -n 1 "$W/re.txt")"; return 1; }
    kill -INT "$RP"; wait "$RP"; RP=""
    [ "$(dmsetup table kc_re | grep -c ' crypt ')" = 2 ] || { echo "after the interruption kc_re has not two crypt targets:"; dmsetup table kc_re; return 1; }
    cryptsetup luksHeaderBackup "$RL" --header-backup-file "$W/re/theirs.hdr" || { echo "cryptsetup made no header backup"; return 1; }
    ctriage keyring || { echo "keep on the interrupted volume:"; cat "$W/re/keyring/screen.txt"; return 1; }
    K=$C
    cmp -s "$K/headers/kc_re.hdr" "$W/re/theirs.hdr" || { echo "the header backup differs from the file of luksHeaderBackup"; return 1; }
    [ "$(cfield "$K" kc_re verdict)" = "captured and proven" ] && [ "$(cfield "$K" kc_re route)" = "R3 memory" ] ||
        { echo "interrupted, keys in the keyring: $(cfield "$K" kc_re verdict)"; cat "$W/re/keyring/screen.txt"; return 1; }

    # the same volume with its keys in the table: what the kernel itself says they are
    cryptsetup close kc_re && cryptsetup open --disable-keyring --key-file pw "$RL" kc_re || { echo "kc_re could not be opened with --disable-keyring"; return 1; }
    t1=$(dmsetup table --showkeys kc_re | awk '$3 == "crypt" {print $5}' | sed -n 1p | hexsha)
    t2=$(dmsetup table --showkeys kc_re | awk '$3 == "crypt" {print $5}' | sed -n 2p | hexsha)
    [ "$t1" != "$t2" ] && [ "$t2" = "$(sha kc_re.vk)" ] || { echo "the table does not show a new key and then the key the volume was made from"; return 1; }
    ctriage table || { echo "keep on the volume with its keys in the table:"; cat "$W/re/table/screen.txt"; return 1; }
    [ "$(cfield "$C" kc_re verdict)" = "captured and proven" ] && [ "$(cfield "$C" kc_re route)" = "R1 table" ] &&
        [ "$(sha "$C/keys/kc_re.vk")" = "$t1" ] && [ "$(sha "$C/keys/kc_re-2.vk")" = "$t2" ] ||
        { echo "keys in the table: not both proven, or not the keys of the table in its order"; cat "$W/re/table/screen.txt"; return 1; }
    cmp -s "$K/keys/kc_re.vk" "$C/keys/kc_re.vk" && cmp -s "$K/keys/kc_re-2.vk" "$C/keys/kc_re-2.vk" ||
        { echo "the keys from memory are not the keys of the table, each with its part"; cat "$W/re/keyring/screen.txt"; return 1; }
    grep '"name": "kc_re"' "$C/verdict.json" | grep -q '"further_keys": \[{"key_file": "keys/kc_re-2.vk", ' || { echo "the report does not name the second key"; return 1; }

    # resumed and paused: the crypt targets are in the helper devices below the volume
    cryptsetup close kc_re && cryptsetup open --key-file pw "$RL" kc_re || { echo "kc_re could not be opened again"; return 1; }
    reencrypt --resume-only || { echo "the resumed re-encryption ended before its helper devices were seen: $(tail -n 1 "$W/re.txt")"; return 1; }
    kill -STOP "$RP"
    dmsetup table kc_re | grep -q ' linear ' && dmsetup table kc_re-overlay | grep -q ' crypt ' ||
        { echo "paused, but the crypt targets are not in kc_re-overlay"; dmsetup table kc_re; return 1; }
    ctriage paused || { echo "keep on the paused re-encryption:"; cat "$W/re/paused/screen.txt"; return 1; }
    [ "$(grep -c '"name": "kc_re' "$C/verdict.json")" = 1 ] || { echo "the volume is not listed once and its helper devices not at all"; return 1; }
    grep -q '^  re-encrypt   in work, with the helper devices of cryptsetup$' "$W/re/paused/screen.txt" &&
        grep -q '^  helpers      kc_re-overlay, kc_re-hotzone-forward$' "$W/re/paused/screen.txt" || { echo "the helper devices are not named"; return 1; }
    [ "$(cfield "$C" kc_re verdict)" = "captured and proven" ] && [ "$(sha "$C/keys/kc_re.vk")" = "$t1" ] && [ "$(sha "$C/keys/kc_re-2.vk")" = "$t2" ] ||
        { echo "paused: not both keys proven, or not each with its part"; cat "$W/re/paused/screen.txt"; return 1; }
    kill -CONT "$RP"; kill -INT "$RP"; wait "$RP"; RP=""
}
# in this shell, so that a paused re-encryption is known to the cleanup
if re_part > "$W/re-out.txt" 2>&1; then
    echo "PASS   a volume in re-encryption: interrupted, both keys from memory and proven, each with its part as the table shows them with --disable-keyring, the header backup that of luksHeaderBackup; resumed and paused, the volume listed once with both keys from the helper devices${KEEP_SAN:+, also with the sanitizers}"
else
    echo "FAIL   a volume in re-encryption"; sed 's/^/       /' "$W/re-out.txt"; PASS=0
fi

# Every screen of keep in this check went to a file, as through a pipe, and every report of
# it holds the lines of its screen: none may hold an escape byte or a carriage return, and
# none a line of more than 80 columns that has no word which needs them.
screens() {
    local f bad=0 n=0
    while read -r f; do
        [ "$(sed -n '1s/^\(keep \).*/\1/p' "$f")" = "keep " ] || continue       # a run that began
        n=$((n + 1))
        if grep -q "$(printf '[\033\r]')" "$f"; then echo "an escape byte or a carriage return: $f"; bad=1; fi
        awk 'length($0) > 80 { w = 0; for (i = 1; i <= NF; i++) if (length($i) > 40) w = 1
                               if (!w) { print FILENAME ": " $0; bad = 1 } }
             END { exit bad }' "$f" || bad=1
    done < <(find "$W" \( -name 'screen*.txt' -o -name triage.txt \) -type f | sort)
    echo "$n"
    return $bad
}
if screens > "$W/screens.txt" 2>&1; then
    echo "PASS   the screens and reports, $(tail -n 1 "$W/screens.txt") files: no escape byte through a pipe and in a report, no line of more than 80 columns but for a word that is longer"
else
    echo "FAIL   the screens and reports"; sed 's/^/       /' "$W/screens.txt"; PASS=0
fi
echo
if [ "$PASS" = 1 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; echo; echo "---- the screen of the main run"; cat "$W/dest/screen.txt"; fi
