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
# Needs root, cryptsetup, dmsetup and losetup on the guest (package cryptsetup on Debian, Ubuntu,
# Fedora, the RHEL family, openSUSE and Arch).
set -u
MEM=""
[ "${1:-}" = -m ] && { MEM=-m; shift; }
KIT=${1:-/media/tools}
W=/root/kc-compat
fail() { echo "compat-check: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail "run as root"
[ -x "$KIT/bin/bash" ] && [ -f "$KIT/keytriage.sh" ] || fail "no tool medium at $KIT (mount it with -o ro,exec)"
for c in cryptsetup dmsetup losetup sha256sum; do command -v "$c" >/dev/null || fail "$c is not installed on this guest"; done
[ ! -e /dev/mapper/kc_l2 ] && [ ! -e /dev/mapper/kc_l1 ] || fail "kc_l2 or kc_l1 is already open, close it first"

cleanup() {
    cryptsetup close kc_l2 2>/dev/null
    cryptsetup close kc_l1 2>/dev/null
    rm -rf "$W"
}
trap cleanup EXIT
rm -rf "$W"; mkdir -p "$W/evid" || fail "cannot create $W"
chmod 700 "$W"; cd "$W" || exit 1

# the key file option was renamed in cryptsetup 2.5.0, as in keytriage.sh
if cryptsetup --help 2>&1 | grep -q -e '--volume-key-file'; then VK=--volume-key-file; else VK=--master-key-file; fi
printf 'compat-check-passphrase' > pw
mk() {  # mk NAME TYPE [options]
    local n=$1 t=$2; shift 2
    head -c 64 /dev/urandom > "$n.vk"
    truncate -s 64M "$n.img"
    cryptsetup luksFormat -q --type "$t" --cipher aes-xts-plain64 --key-size 512 "$VK" "$n.vk" "$@" --key-file pw "$n.img" \
        || fail "luksFormat $n failed"
    cryptsetup open --key-file pw "$n.img" "$n" || fail "open $n failed"
}
mk kc_l2 luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000
mk kc_l1 luks1 --pbkdf pbkdf2 --pbkdf-force-iterations 1000

"$KIT/bin/bash" "$KIT/keytriage.sh" -e "$W/evid" $MEM > "$W/screen.txt" 2>&1
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
echo
if [ "$PASS" = 1 ]; then echo "RESULT: PASS"; else echo "RESULT: FAIL"; echo; echo "---- screen output of the tool"; cat "$W/screen.txt"; fi
