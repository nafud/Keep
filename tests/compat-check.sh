#!/bin/bash
# compat-check.sh [-m] [-c] [KIT] : check keytriage.sh of Keep on one distribution.
#
#   sudo bash compat-check.sh            the tool medium is mounted at /media/tools
#   sudo bash compat-check.sh -m         also take the memory image and search it
#   sudo bash compat-check.sh -c         the same with the compressed image (keytriage.sh -m -c)
#
# For a throwaway test guest only, never for a system under examination: it makes two small
# encrypted containers with keys it has just drawn, opens them, runs the triage on them and
# removes everything again. The two containers are the two cases of the key map:
#   kc_l2   LUKS2 as cryptsetup opens it by default, the key in the kernel keyring (memory route)
#   kc_l1   LUKS1, the key in the device-mapper table (table route)
# Each container is formatted with a volume key from a file, so the ground truth is known without
# any dump. The check passes when both verdicts are "captured and proven" and the SHA-256 of each
# captured key equals that of its key file. No key is printed.
#
# Around these two it checks what only real device-mapper and real mounts can show:
#   No        a mapping of that name, made with dmsetup from a known key: "captured, in use"
#   kc_null   a mapping with the null cipher and no key: "no key needed"
#   the destination: the main run names none and is started in a directory on the guest's own
#             disk, which must take the folder of the run. A second run is started as an
#             examiner starts Keep, by the launcher "keep" and the questions of the dialogue,
#             with a FAT file system on a loop device as the destination, which must take
#             every file (where the guest has mkfs.vfat and can mount FAT)
#   kc_pv     a LUKS2 volume that carries an LVM volume group, as an installer lays out an
#             encrypted system, with a logical volume that is mounted and one that is swap:
#             the mapping below them is the one that is listed and proven, both are named as
#             what it carries, and the logical volume is the destination of that run (where
#             the guest has lvm2 and mkfs.ext4)
#   c/keep    the C program of Keep, which is to take the place of keytriage.sh. It is run on
#             the same mappings, after the main run and after the run on LVM, and must give
#             what keytriage.sh gave: every field of every volume in verdict.json, header
#             backups that are the files of "cryptsetup luksHeaderBackup" byte for byte, and
#             the same keys. Before any mapping is made it is run once on the guest as it
#             is, which on a guest without encrypted volumes is the run with none.
#             With KEEP_SAN=/path/to/keep-san in the environment, that build of the program
#             with the sanitizers of the compiler is run at the same places as well and must
#             end with status 0, which it does not where a sanitizer finds a fault
#   kc_it, kc_ik   LUKS2 with integrity (--integrity hmac-sha256), one with its key in the table
#             and one with its key in the keyring. The crypt target lies on a dm-integrity
#             device and the header on the device below that. keytriage.sh and the C program
#             must give the same: the first captured and proven with the key it was made
#             from, the second "live copy only", because its volume key holds a key of HMAC
#             that the search for AES key schedules does not find (where the kernel has
#             dm-integrity)
#   kc_re     a LUKS2 volume in re-encryption, for the C program alone: keytriage.sh takes one
#             key of such a volume, and lists the helper device in place of the volume while
#             cryptsetup works. The re-encryption is started and interrupted, so that the
#             volume has the crypt targets of two keys, then resumed and paused, so that they
#             lie in the helper devices that cryptsetup puts below the volume. In each state
#             the C program must list the volume once, prove both keys against the header and
#             name each key with its part: the keys are compared with those that the table
#             shows where the volume is opened with --disable-keyring, and the key of the
#             part not yet done with the key the volume was made from
# A part that the guest cannot run is reported as SKIP and does not fail the check.
#
# Needs root, cryptsetup, dmsetup and losetup on the guest (package cryptsetup on Debian, Ubuntu,
# Fedora, the RHEL family, openSUSE and Arch). dosfstools and lvm2 are needed for the parts with
# FAT and LVM.
set -u
MEM=""; IMAGE=memory.lime
while :; do
    case ${1:-} in
        -m) MEM=-m; shift ;;
        -c) MEM="-m -c"; IMAGE=memory.avml; shift ;;
        *) break ;;
    esac
done
KIT=${1:-/media/tools}
W=/root/kc-compat
fail() { echo "compat-check: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
[ -x "$KIT/bin/bash" ] && [ -f "$KIT/keytriage.sh" ] || fail "no tool medium at $KIT (mount it with -o ro,exec)"
[ -x "$KIT/c/keep" ] || fail "no C program on the medium at $KIT/c/keep (build-toolkit.sh puts it there)"
for c in cryptsetup dmsetup losetup sha256sum; do command -v "$c" >/dev/null || fail "$c is not installed on this guest"; done
for n in kc_l2 kc_l1 kc_null No kc_pv kc_vg-data kc_vg-swap kc_it kc_ik kc_re; do [ ! -e "/dev/mapper/$n" ] || fail "the mapping $n is already open, close it first"; done

LOOPS=()
RP=""
cleanup() {
    # a re-encryption that is still paused: let it go on and end it
    [ -z "$RP" ] || { kill -CONT "$RP" 2>/dev/null; kill -INT "$RP" 2>/dev/null; wait "$RP" 2>/dev/null; }
    cryptsetup close kc_re 2>/dev/null
    cryptsetup close kc_it 2>/dev/null
    cryptsetup close kc_ik 2>/dev/null
    umount "$W/fat" 2>/dev/null
    for b in "$W"/bind*; do [ -d "$b" ] && umount "$b" 2>/dev/null; done
    umount "$W/lvm" 2>/dev/null
    swapoff /dev/mapper/kc_vg-swap 2>/dev/null
    vgchange -an kc_vg >/dev/null 2>&1
    vgremove -ff kc_vg >/dev/null 2>&1
    cryptsetup close kc_pv 2>/dev/null
    cryptsetup close kc_l2 2>/dev/null
    cryptsetup close kc_l1 2>/dev/null
    dmsetup remove kc_null 2>/dev/null
    dmsetup remove No 2>/dev/null
    for l in "${LOOPS[@]}"; do losetup -d "$l" 2>/dev/null; done
    rm -rf "$W"
}
trap cleanup EXIT
rm -rf "$W"; mkdir -p "$W/dest" "$W/cdest" || fail "cannot create $W"
chmod 700 "$W"; cd "$W" && W=$(pwd -P) || exit 1

# The C program on the guest as it is, before a mapping is made: on a guest without encrypted
# volumes this is the run with none, which must end in order like any other.
mkdir "$W/empty"
( cd "$W/empty" && "$KIT/c/keep" triage ) > "$W/empty/screen.txt" 2>&1; RCE=$?
E=$(ls -d "$W"/empty/triage_* 2>/dev/null | tail -n 1)
EMPTY=FAIL
[ "$RCE" = 0 ] && grep -q '"volumes": \[' "$E/verdict.json" 2>/dev/null && (cd "$E" && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) && EMPTY=PASS
if [ -n "${KEEP_SAN:-}" ]; then
    mkdir "$W/empty-san"
    "$KEEP_SAN" triage -d "$W/empty-san" > "$W/empty-san/screen.txt" 2>&1 || { EMPTY=FAIL; cat "$W/empty-san/screen.txt" >> "$W/empty/screen.txt"; }
fi

# the key file option was renamed in cryptsetup 2.5.0, as in keytriage.sh
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

# No destination is named: it is the directory of the start, which lies on the disk of this
# guest. Where the destination lies is the examiner's decision, and no place is refused.
( cd "$W/dest" && "$KIT/bin/bash" -p "$KIT/keytriage.sh" $MEM ) > "$W/screen.txt" 2>&1
RC=$?
O=$(ls -d "$W"/dest/triage_* 2>/dev/null | tail -n 1)
J=$O/verdict.json

echo "==== Keep compatibility check"
echo "system:      $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')"
echo "kernel:      $(uname -r)"
echo "cryptsetup:  $(cryptsetup --version | head -n 1)"
echo "dmsetup:     $(dmsetup --version 2>/dev/null | head -n 1 | tr -s ' ')"
echo "key option:  $VK"
echo "lockdown:    $(cat /sys/kernel/security/lockdown 2>/dev/null || echo 'no lockdown file')"
echo "AES-NI:      $(grep -q -w aes /proc/cpuinfo && echo yes || echo no)"
echo "XTS driver:  $(awk '$1=="name" && $3=="xts(aes)" {f=1} f && $1=="driver" {print $3; exit}' /proc/crypto)"
echo "tool:        $(sed -n '1p' "$W/screen.txt"), exit $RC"
echo

PASS=1
if [ "$EMPTY" = PASS ]; then
    echo "PASS   the C program before any mapping is made: $(grep -c '^    {"name": .*, "type": ' "$E/verdict.json") volume(s) of the guest itself, status 0, manifest${KEEP_SAN:+, also with the sanitizers}"
else
    echo "FAIL   the C program before any mapping is made, status $RCE"; sed 's/^/       /' "$W/empty/screen.txt"; PASS=0
fi
field() { grep "\"name\": \"$1\"" "$J" | sed -n "s/.*\"$2\": \"\\([^\"]*\\)\".*/\\1/p"; }
for n in kc_l2 kc_l1; do
    want=$(sha256sum < "$n.vk" | cut -c1-16)
    v=$(field "$n" verdict); r=$(field "$n" route); h=$(field "$n" key_sha256_16)
    if [ "$v" = "captured and proven" ] && [ "$h" = "$want" ]; then res=PASS; else res=FAIL; PASS=0; fi
    printf '%-6s %-5s verdict "%s", route "%s", key %s\n' "$res" "$n" "${v:-none}" "${r:-none}" \
        "$([ "$h" = "$want" ] && echo "equals the ground truth" || echo "differs from the ground truth or is missing")"
done
want=$(sha256sum < No.vk | cut -c1-16)
if [ "$(field No verdict)" = "captured, in use" ] && [ "$(field No key_sha256_16)" = "$want" ]; then
    echo "PASS   No    verdict \"captured, in use\", key equals the ground truth"
else
    echo "FAIL   No    verdict \"$(field No verdict)\", the mapping is missing or its key differs"; PASS=0
fi
if [ "$(field kc_null verdict)" = "no key needed" ] && [ ! -e "$O/keys/kc_null.vk" ]; then
    echo "PASS   kc_null verdict \"no key needed\""
else
    echo "FAIL   kc_null verdict \"$(field kc_null verdict)\""; PASS=0
fi
[ "$RC" = 0 ] || { echo "FAIL   keytriage.sh ended with status $RC"; PASS=0; }
if [ -n "$MEM" ]; then
    img=$O/memory/$IMAGE
    if [ -s "$img" ]; then
        # the image was taken while the containers were open, so the scanner must read it to its
        # end and find in it the schedules of both halves of both volume keys
        "$KIT/bin/kcore-keyscan" "$img" > "$W/image-candidates.txt" 2> "$W/image-scan.txt"; rcs=$?
        inimg=1
        for n in kc_l2 kc_l1; do
            for o in 0 32; do
                grep -q " key $(od -An -v -tx1 -j "$o" -N 32 "$n.vk" | tr -d ' \n')\$" "$W/image-candidates.txt" || inimg=0
            done
        done
        if [ "$rcs" = 0 ] && [ "$inimg" = 1 ]; then res=PASS; else res=FAIL; PASS=0; fi
        echo "$res   memory image $IMAGE: $(stat -c%s "$img") bytes, $(sed -n 's/^kcore-keyscan [^,]*, \(.*\), [0-9]* segments*, \([0-9]* bytes\).*/\1, \2 of memory/p' "$W/image-scan.txt"), $(wc -l < "$W/image-candidates.txt") key schedules, $([ "$inimg" = 1 ] && echo "the keys of both containers among them" || echo "the keys of the containers are not all among them"), scanner status $rcs"
        echo "       banner: $(cut -c1-100 "$O/memory/banner.txt")"
        echo "       $(grep -m 1 'System.map' "$W/screen.txt" | sed 's/^ *//')"
        [ -s "$O/memory/System.map" ] && echo "       System.map: $(stat -c%s "$O/memory/System.map") bytes, $(wc -l < "$O/memory/System.map") lines"
    else
        PASS=0
        echo "FAIL   memory image: $(grep -A1 '==== memory image' "$W/screen.txt" | tail -n 1)"
    fi
fi
(cd "$O" && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) && echo "PASS   manifest of the triage folder" || { echo "FAIL   manifest"; PASS=0; }
if [ -n "$O" ] && [ -f "$J" ] && grep -q "^output: $O\$" "$W/screen.txt" && grep -q '^destination: .* mounted at ' "$W/screen.txt"; then
    echo "PASS   no destination named: the folder of the run is in the directory of the start, on the guest's own disk"
else
    echo "FAIL   no destination named: the folder of the run is not in the directory of the start: $(head -n 1 "$W/screen.txt")"; PASS=0
fi
# beside FOLDER DEST LABEL [RULE] : the C program on the mappings as they are now, into DEST,
# against the folder that keytriage.sh has just written. Both write one volume per line of
# verdict.json with the same fields in the same order, so the lines must be the same. RULE is
# a rule of sed for the lines of the C program, for a field that the two name differently.
beside() {
    local sh=$1 dest=$2 label=$3 rule=${4:-} c rc ok=1 f
    ( cd "$dest" && "$KIT/c/keep" triage ) > "$dest/screen-c.txt" 2>&1; rc=$?
    c=$(ls -d "$dest"/triage_* 2>/dev/null | tail -n 1)
    [ "$rc" = 0 ] && [ -f "$c/verdict.json" ] || ok=0
    # a volume is a line with a name and a type, which the two lines of "binaries" lack
    if ! diff <(grep '^    {"name": .*, "type": ' "$sh/verdict.json" | sed 's/,$//') \
              <(grep '^    {"name": .*, "type": ' "$c/verdict.json" 2>/dev/null | sed -e 's/,$//' -e "$rule") > "$dest/diff.txt" 2>&1; then
        ok=0
    fi
    for f in "$sh"/headers/*.hdr "$sh"/keys/*.vk; do
        [ -e "$f" ] || continue
        cmp -s "$f" "$c/${f#"$sh"/}" || { ok=0; echo "differs: ${f#"$sh"/}" >> "$dest/diff.txt"; }
    done
    (cd "$c" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || { ok=0; echo "the manifest does not verify" >> "$dest/diff.txt"; }
    if [ -n "${KEEP_SAN:-}" ]; then
        mkdir "$dest/san"
        "$KEEP_SAN" triage -d "$dest/san" > "$dest/san/screen.txt" 2>&1 || { ok=0; echo "the build with the sanitizers:" >> "$dest/diff.txt"; cat "$dest/san/screen.txt" >> "$dest/diff.txt"; }
    fi
    if [ "$ok" = 1 ]; then
        echo "PASS   $(sed -n '1p' "$dest/screen-c.txt"), $label: $(grep -c '^    {"name": .*, "type": ' "$c/verdict.json") volumes as keytriage.sh gave them in every field, $(ls "$sh"/headers/*.hdr 2>/dev/null | wc -l) header backups and $(ls "$sh"/keys/*.vk 2>/dev/null | wc -l) keys byte for byte the same, manifest${KEEP_SAN:+, also with the sanitizers}"
    else
        echo "FAIL   the C program, $label, status $rc"; sed 's/^/       /' "$dest/diff.txt" "$dest/screen-c.txt"; PASS=0
    fi
}
beside "$O" "$W/cdest" "the same mappings"
# A destination with FAT, and the way an examiner starts Keep: the launcher of the medium and
# the questions of the dialogue, answered through a pipe. Every name must be taken by FAT.
mkdir "$W/fat"; truncate -s 96M fat.img
if command -v mkfs.vfat >/dev/null && mkfs.vfat fat.img >/dev/null 2>&1 && mount -o loop fat.img "$W/fat" 2>/dev/null; then
    printf 'system\n%s\n\n\nyes\n' "$W/fat" | "$KIT/keep" > "$W/screen-fat.txt" 2>&1; rcf=$?
    F=$(ls -d "$W"/fat/triage_* 2>/dev/null | tail -n 1)
    ok=1
    [ "$rcf" = 0 ] && grep -q '(vfat) mounted at' "$W/screen-fat.txt" && grep -q '^keep-menu.sh: SUCCESS$' "$W/screen-fat.txt" || ok=0
    for n in kc_l2 kc_l1 No; do cmp -s "$F/keys/$n.vk" "$n.vk" || ok=0; done
    (cd "$F" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || ok=0
    if [ "$ok" = 1 ]; then
        echo "PASS   started as keep, through the questions, with a destination on FAT: three keys equal the ground truth, manifest"
    else
        echo "FAIL   started as keep, through the questions, with a destination on FAT, status $rcf"; sed 's/^/       /' "$W/screen-fat.txt"; PASS=0
    fi
else
    echo "SKIP   no mkfs.vfat or no FAT in this kernel, the destination with FAT is not run"
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
        "$KIT/bin/bash" -p "$KIT/keytriage.sh" -d "$W/lvm" > "$W/screen-lvm.txt" 2>&1; rcl=$?
        L=$(ls -d "$W"/lvm/triage_* 2>/dev/null | tail -n 1)
        ok=1
        [ "$rcl" = 0 ] || ok=0
        grep '"name": "kc_pv"' "$L/verdict.json" 2>/dev/null | grep -q '"verdict": "captured and proven"' || ok=0
        cmp -s "$L/keys/kc_pv.vk" kc_pv.vk || ok=0
        grep -q '"name": "kc_vg-data"' "$L/verdict.json" 2>/dev/null && ok=0
        # what the volume carries is named: the logical volume and where it is mounted
        use=$(grep '^  in use: .*kc_vg' "$W/screen-lvm.txt")
        case $use in *"kc_vg-data at $W/lvm,"*) ;; *) ok=0 ;; esac
        [ "$(grep -o 'kc_vg-data at ' <<<"$use" | wc -l)" = 8 ] || ok=0
        case $use in *"kc_vg-swap as swap"*) ;; *) ok=0 ;; esac
        case $use in *" and 2 more mounts") ;; *) ok=0 ;; esac
        grep -A3 '^==== kc_l1$' "$W/screen-lvm.txt" | grep -q '^  in use: not mounted' || ok=0
        if [ "$ok" = 1 ]; then
            echo "PASS   LVM on LUKS: kc_pv is captured and proven, the logical volumes are not listed as volumes and are named as what kc_pv carries, one mounted at ten places and one as swap"
        else
            echo "FAIL   LVM on LUKS, status $rcl"; sed 's/^/       /' "$W/screen-lvm.txt"; PASS=0
        fi
        mkdir "$W/lvm/c" && beside "$L" "$W/lvm/c" "LVM on LUKS"
    else
        echo "FAIL   LVM on LUKS: the volume group, a logical volume, the file system or the swap area could not be made: $(head -n 1 "$W/lvm.txt")"; PASS=0
    fi
else
    echo "SKIP   no lvm2 or no mkfs.ext4, LVM on LUKS is not run"
fi
sha() { sha256sum < "$1" | cut -c1-16; }
# cfield FOLDER VOLUME FIELD : a field of a volume in a report, not one of its further keys
cfield() { grep "\"name\": \"$2\"" "$1/verdict.json" | sed -n "s/.*\"name\": \"$2\"[^[]*\"$3\": \"\\([^\"]*\\)\".*/\\1/p"; }
# the first 16 digits of the SHA-256 of a key that is read in hexadecimal, as a table shows it
hexsha() { printf '%b' "$(sed 's/../\\x&/g')" | sha256sum | cut -c1-16; }

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
    "$KIT/bin/bash" -p "$KIT/keytriage.sh" -d "$W/int" > "$W/screen-int.txt" 2>&1; rci=$?
    I=$(ls -d "$W"/int/triage_* 2>/dev/null | tail -n 1)
    ok=1
    [ "$rci" = 0 ] || ok=0
    [ "$(cfield "$I" kc_it verdict)" = "captured and proven" ] && cmp -s "$I/keys/kc_it.vk" kc_it.vk || ok=0
    [ "$(cfield "$I" kc_ik verdict)" = "live copy only" ] && [ ! -e "$I/keys/kc_ik.vk" ] || ok=0
    grep '"name": "kc_it"' "$I/verdict.json" 2>/dev/null | grep -q '"key_bits": 768, "key_location": "dm-crypt"' || ok=0
    grep -q '"name": "kc_it_dif"' "$I/verdict.json" 2>/dev/null && ok=0
    if [ "$ok" = 1 ]; then
        echo "PASS   LUKS2 with integrity: kc_it is captured and proven with its key of 96 bytes, kc_ik with its key in the keyring is \"live copy only\", the dm-integrity devices are not listed"
    else
        echo "FAIL   LUKS2 with integrity, status $rci"; sed 's/^/       /' "$W/screen-int.txt"; PASS=0
    fi
    # the C program names the cipher as the kernel does, and keytriage.sh as cryptsetup does
    mkdir "$W/int/c" && beside "$I" "$W/int/c" "LUKS2 with integrity, the cipher in the form of the kernel" \
        "s/\"cipher\": \"$CAPI\"/\"cipher\": \"aes-xts-plain64\"/"
    grep '"name": "kc_it"' "$W"/int/c/triage_*/verdict.json 2>/dev/null | grep -q -F "\"cipher\": \"$CAPI\"" ||
        { echo "FAIL   the C program does not name the cipher of kc_it as $CAPI"; PASS=0; }
else
    echo "SKIP   LUKS2 with integrity is not run, the container could not be made or opened: $(grep -v '^$' "$W/int.txt" | head -n 1)"
fi

# A volume in re-encryption. The C program is run alone here.
# ctriage NAME : the C program on the mappings as they are now, into $W/re/NAME. Its folder is
# left in C, and the build with the sanitizers is run as well where it is given.
ctriage() {
    local d=$W/re/$1 rc
    mkdir "$d"
    ( cd "$d" && "$KIT/c/keep" triage ) > "$d/screen.txt" 2>&1; rc=$?
    C=$(ls -d "$d"/triage_* 2>/dev/null | tail -n 1)
    [ "$rc" = 0 ] && (cd "$C" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || return 1
    if [ -n "${KEEP_SAN:-}" ]; then
        mkdir "$d/san"
        "$KEEP_SAN" triage -d "$d/san" > "$d/san/screen.txt" 2>&1 || { cat "$d/san/screen.txt" >> "$d/screen.txt"; return 1; }
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
    ctriage keyring || { echo "the C program on the interrupted volume:"; cat "$W/re/keyring/screen.txt"; return 1; }
    K=$C
    cmp -s "$K/headers/kc_re.hdr" "$W/re/theirs.hdr" || { echo "the header backup differs from the file of luksHeaderBackup"; return 1; }
    [ "$(cfield "$K" kc_re verdict)" = "captured and proven" ] && [ "$(cfield "$K" kc_re route)" = "R3 memory" ] ||
        { echo "interrupted, keys in the keyring: $(cfield "$K" kc_re verdict)"; cat "$W/re/keyring/screen.txt"; return 1; }

    # the same volume with its keys in the table: what the kernel itself says they are
    cryptsetup close kc_re && cryptsetup open --disable-keyring --key-file pw "$RL" kc_re || { echo "kc_re could not be opened with --disable-keyring"; return 1; }
    t1=$(dmsetup table --showkeys kc_re | awk '$3 == "crypt" {print $5}' | sed -n 1p | hexsha)
    t2=$(dmsetup table --showkeys kc_re | awk '$3 == "crypt" {print $5}' | sed -n 2p | hexsha)
    [ "$t1" != "$t2" ] && [ "$t2" = "$(sha kc_re.vk)" ] || { echo "the table does not show a new key and then the key the volume was made from"; return 1; }
    ctriage table || { echo "the C program on the volume with its keys in the table:"; cat "$W/re/table/screen.txt"; return 1; }
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
    ctriage paused || { echo "the C program on the paused re-encryption:"; cat "$W/re/paused/screen.txt"; return 1; }
    [ "$(grep -c '"name": "kc_re' "$C/verdict.json")" = 1 ] || { echo "the volume is not listed once and its helper devices not at all"; return 1; }
    grep -q '^  in re-encryption: cryptsetup works on it with the helper devices kc_re-overlay, kc_re-hotzone-forward$' "$W/re/paused/screen.txt" || { echo "the helper devices are not named"; return 1; }
    [ "$(cfield "$C" kc_re verdict)" = "captured and proven" ] && [ "$(sha "$C/keys/kc_re.vk")" = "$t1" ] && [ "$(sha "$C/keys/kc_re-2.vk")" = "$t2" ] ||
        { echo "paused: not both keys proven, or not each with its part"; cat "$W/re/paused/screen.txt"; return 1; }
    kill -CONT "$RP"; kill -INT "$RP"; wait "$RP"; RP=""
}
# in this shell, so that a paused re-encryption is known to the cleanup
if re_part > "$W/re-out.txt" 2>&1; then
    echo "PASS   a volume in re-encryption, the C program: interrupted, both keys from memory and proven, each with its part as the table shows them with --disable-keyring, the header backup that of luksHeaderBackup; resumed and paused, the volume listed once with both keys from the helper devices${KEEP_SAN:+, also with the sanitizers}"
else
    echo "FAIL   a volume in re-encryption, the C program"; sed 's/^/       /' "$W/re-out.txt"; PASS=0
fi
echo
if [ "$PASS" = 1 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; echo; echo "---- screen output of the tool"; cat "$W/screen.txt"; fi
