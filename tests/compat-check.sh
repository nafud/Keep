#!/bin/bash
# compat-check.sh [-m] [KIT] : check keytriage.sh of Keep on one distribution.
#
#   sudo bash compat-check.sh            the tool medium is mounted at /media/tools
#   sudo bash compat-check.sh -m         also take the memory image and search it
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
#   the evidence directory: one on the guest's own disk is refused without -f, also on another
#             partition of that disk (/boot/efi or /boot, where the guest has one), and a FAT file
#             system on a loop device is accepted and takes every file (where the guest has
#             mkfs.vfat and can mount FAT)
#   kc_pv     a LUKS2 volume that carries an LVM volume group, as an installer lays out an
#             encrypted system: the mapping below the logical volume is the one that is listed
#             and proven, and an evidence directory on the logical volume is taken as lying on
#             that dm-crypt volume (where the guest has lvm2 and mkfs.ext4)
# A part that the guest cannot run is reported as SKIP and does not fail the check.
#
# Needs root, cryptsetup, dmsetup and losetup on the guest (package cryptsetup on Debian, Ubuntu,
# Fedora, the RHEL family, openSUSE and Arch). dosfstools and lvm2 are needed for the parts with
# FAT and LVM.
set -u
MEM=""
[ "${1:-}" = -m ] && { MEM=-m; shift; }
KIT=${1:-/media/tools}
W=/root/kc-compat
fail() { echo "compat-check: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
[ -x "$KIT/bin/bash" ] && [ -f "$KIT/keytriage.sh" ] || fail "no tool medium at $KIT (mount it with -o ro,exec)"
for c in cryptsetup dmsetup losetup sha256sum; do command -v "$c" >/dev/null || fail "$c is not installed on this guest"; done
for n in kc_l2 kc_l1 kc_null No kc_pv kc_vg-data; do [ ! -e "/dev/mapper/$n" ] || fail "the mapping $n is already open, close it first"; done

LOOPS=()
cleanup() {
    umount "$W/fat" 2>/dev/null
    umount "$W/lvm" 2>/dev/null
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
rm -rf "$W"; mkdir -p "$W/evid" || fail "cannot create $W"
chmod 700 "$W"; cd "$W" || exit 1

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

# $W is on the disk of this guest, which keytriage.sh refuses as an evidence directory unless -f
"$KIT/bin/bash" -p "$KIT/keytriage.sh" -e "$W/evid" > "$W/refused.txt" 2>&1
REFUSED=$?
"$KIT/bin/bash" -p "$KIT/keytriage.sh" -f -e "$W/evid" $MEM > "$W/screen.txt" 2>&1
RC=$?
O=$(ls -d "$W"/evid/triage_* 2>/dev/null | tail -n 1)
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
    img=$O/memory/memory.lime
    if [ -s "$img" ]; then
        "$KIT/bin/kcore-keyscan" "$img" > "$W/image-candidates.txt" 2> "$W/image-scan.txt"
        echo "PASS   memory image: $(stat -c%s "$img") bytes, $(wc -l < "$W/image-candidates.txt") key schedules found in it"
        echo "       banner: $(cut -c1-100 "$O/memory/banner.txt")"
        echo "       $(grep -m 1 'System.map' "$W/screen.txt" | sed 's/^ *//')"
        [ -s "$O/memory/System.map" ] && echo "       System.map: $(stat -c%s "$O/memory/System.map") bytes, $(wc -l < "$O/memory/System.map") lines"
    else
        PASS=0
        echo "FAIL   memory image: $(grep -A1 '==== memory image' "$W/screen.txt" | tail -n 1)"
    fi
fi
(cd "$O" && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) && echo "PASS   manifest of the triage folder" || { echo "FAIL   manifest"; PASS=0; }
if [ "$REFUSED" = 1 ] && grep -q 'is refused: it lies on' "$W/refused.txt" && [ "$(ls "$W/evid" | wc -l)" = 1 ]; then
    echo "PASS   an evidence directory on the guest's own disk is refused without -f"
else
    echo "FAIL   an evidence directory on the guest's own disk is not refused: $(head -n 1 "$W/refused.txt")"; PASS=0
fi
# another partition of the disk that carries the root file system
OTHER=""
for d in /boot/efi /boot; do
    [ "$(stat -c %d "$d" 2>/dev/null)" != "$(stat -c %d /)" ] && [ -d "$d" ] && grep -q " $d " /proc/self/mountinfo && { OTHER=$d; break; }
done
if [ -n "$OTHER" ]; then
    "$KIT/bin/bash" -p "$KIT/keytriage.sh" -e "$OTHER" > "$W/refused2.txt" 2>&1
    if [ $? = 1 ] && grep -q 'is refused: it lies on the disk' "$W/refused2.txt" && ! ls -d "$OTHER"/triage_* >/dev/null 2>&1; then
        echo "PASS   $OTHER is refused: $(sed -n 's/.*\(it lies on the disk [^,]*\),.*/\1/p' "$W/refused2.txt")"
    else
        echo "FAIL   $OTHER, a partition beside the root file system, is not refused: $(head -n 1 "$W/refused2.txt")"; PASS=0
    fi
else
    echo "SKIP   no /boot/efi or /boot on a partition of its own, the test of a second partition is not run"
fi
# an evidence medium with FAT, on a disk of its own: accepted without -f, and every name is taken
mkdir "$W/fat"; truncate -s 96M fat.img
if command -v mkfs.vfat >/dev/null && mkfs.vfat fat.img >/dev/null 2>&1 && mount -o loop fat.img "$W/fat" 2>/dev/null; then
    "$KIT/bin/bash" -p "$KIT/keytriage.sh" -e "$W/fat" > "$W/screen-fat.txt" 2>&1; rcf=$?
    F=$(ls -d "$W"/fat/triage_* 2>/dev/null | tail -n 1)
    ok=1
    [ "$rcf" = 0 ] && grep -q '(vfat) mounted at' "$W/screen-fat.txt" || ok=0
    for n in kc_l2 kc_l1 No; do cmp -s "$F/keys/$n.vk" "$n.vk" || ok=0; done
    (cd "$F" 2>/dev/null && sha256sum -c --quiet manifest.sha256 >/dev/null 2>&1) || ok=0
    if [ "$ok" = 1 ]; then
        echo "PASS   evidence medium with FAT: accepted without -f, three keys equal the ground truth, manifest"
    else
        echo "FAIL   evidence medium with FAT, status $rcf"; sed 's/^/       /' "$W/screen-fat.txt"; PASS=0
    fi
else
    echo "SKIP   no mkfs.vfat or no FAT in this kernel, the evidence medium with FAT is not run"
fi
# LVM on LUKS: the stack of an encrypted installation
mkdir "$W/lvm"
if command -v vgcreate >/dev/null && command -v mkfs.ext4 >/dev/null; then
    SIZE=256M mk kc_pv luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000
    if vgcreate -q kc_vg /dev/mapper/kc_pv >/dev/null 2>"$W/lvm.txt" && lvcreate -q -y -n data -l 100%FREE kc_vg >/dev/null 2>>"$W/lvm.txt" \
        && mkfs.ext4 -q /dev/mapper/kc_vg-data 2>>"$W/lvm.txt" && mount /dev/mapper/kc_vg-data "$W/lvm" 2>>"$W/lvm.txt"; then
        "$KIT/bin/bash" -p "$KIT/keytriage.sh" -e "$W/lvm" > "$W/screen-lvm.txt" 2>&1; rcl=$?
        L=$(ls -d "$W"/lvm/triage_* 2>/dev/null | tail -n 1)
        ok=1
        [ "$rcl" = 0 ] || ok=0
        grep -q 'the evidence directory lies on the open dm-crypt volume kc_pv' "$W/screen-lvm.txt" || ok=0
        grep '"name": "kc_pv"' "$L/verdict.json" 2>/dev/null | grep -q '"verdict": "captured and proven"' || ok=0
        cmp -s "$L/keys/kc_pv.vk" kc_pv.vk || ok=0
        grep -q '"name": "kc_vg-data"' "$L/verdict.json" 2>/dev/null && ok=0
        if [ "$ok" = 1 ]; then
            echo "PASS   LVM on LUKS: kc_pv is captured and proven, the logical volume is not listed, the evidence directory on it is taken as lying on kc_pv"
        else
            echo "FAIL   LVM on LUKS, status $rcl"; sed 's/^/       /' "$W/screen-lvm.txt"; PASS=0
        fi
    else
        echo "FAIL   LVM on LUKS: the volume group, the logical volume or its file system could not be made: $(head -n 1 "$W/lvm.txt")"; PASS=0
    fi
else
    echo "SKIP   no lvm2 or no mkfs.ext4, LVM on LUKS is not run"
fi
echo
if [ "$PASS" = 1 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; echo; echo "---- screen output of the tool"; cat "$W/screen.txt"; fi
