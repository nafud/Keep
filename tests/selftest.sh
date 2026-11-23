#!/bin/bash
# selftest.sh [-a] : the checks of Keep that need neither root nor device-mapper.
#
#   tests/selftest.sh        run what this machine can run, a missing program is a SKIP
#   tests/selftest.sh -a     as the pipeline runs it: a SKIP counts as a failure
#
# It reads the files of this repository and writes only below a temporary directory, which is
# removed at the end. The test keys are drawn from /dev/urandom there and are never printed.
#
#   static     bash -n and shellcheck -S warning on every script, a compile of every Python file
#              and a static build of kcore-keyscan with -Wall -Werror
#   scanner    a fixture with the schedules of two known XTS keys and five traps, in each of the
#              four formats, the compressed image of AVML among them, and once with a step of
#              16. A gzip file is refused, and a cut or damaged image is searched up to the damage
#   verifier   LUKS2 and LUKS1 headers that cryptsetup makes from the same two keys: vkverify.py
#              on the headers, offline-keyscan.sh on a disk image that holds both, keep-report.py
#              on the report, and a candidate list without the keys, which must not prove. The
#              same headers with their keyslots erased, cut short, malformed, and under one name.
#              The disk image again as qemu-img writes it in the formats of virtual machines
#              and as ewfacquirestream writes it as an EnCase image
#   proof      the proof command of keytriage.sh on the same headers, with the key and with another
#   triage     keytriage.sh itself on stand-ins for the examined system's dmsetup, cryptsetup
#              status, /proc/kcore and AVML, with the same headers, the real header backup and proof
#   menu       keep-menu.sh through a pipe: a dry run, the format of the memory image, an input
#              that ends early, and an offline run
#   page       docs/index.html shows the version of keytriage.sh, every link inside the page has
#              its target, every file it names exists and nothing is loaded from another host
#
# On real device-mapper and a real /proc/kcore keytriage.sh is checked by compat-check.sh.
#
# Programs: bash, gcc with a static libc and python3, and for the full run shellcheck,
# cryptsetup, busybox, qemu-img and ewfacquirestream. With bash-static installed keytriage.sh runs in it, as on the medium.
# Ends with "RESULT: PASS" and status 0, or with "RESULT: FAIL" and status 1.
set -u
umask 077
export LC_ALL=C
# the comment at the head of this file, read by the shell itself
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
    *) printf 'usage: selftest.sh [-a]\n' >&2; exit 2 ;;
esac
R=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
cd "$R" || exit 1

FAILED=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILED=1; }
skip() { printf 'SKIP  %s\n' "$1"; [ "$ALL" = 0 ] || FAILED=1; }
# check NAME COMMAND... : the command's output is shown only when it fails. No command that is
# run through here writes a key to its output.
check() {
    local name=$1; shift
    if "$@" > "$T/out.txt" 2>&1; then pass "$name"; else fail "$name"; sed 's/^/      /' "$T/out.txt"; fi
}
finish() {
    echo
    if [ "$FAILED" = 0 ]; then echo "RESULT: PASS"; exit 0; fi
    echo "RESULT: FAIL"; exit 1
}
# 0 when no file named after the first argument holds a key of the first argument's files in hex
no_key_in() {  # no_key_in "KEYFILE..." FILE...
    python3 -I -c 'import sys
keys = [open(p, "rb").read() for p in sys.argv[1].split()]
hexes = [k[a:b].hex() for k in keys for a, b in ((0, len(k)), (0, len(k) // 2), (len(k) // 2, len(k)))]
for p in sys.argv[2:]:
    text = open(p, errors="replace").read()
    if any(h in text for h in hexes):
        sys.exit(p.rsplit("/", 1)[-1] + " holds key material")' "$@"
}

# ---- static ------------------------------------------------------------------------------------
syntax() { local f; for f in ./*.sh tests/*.sh; do bash -n "$f" || return 1; done; }
check "bash -n on every script" syntax
if command -v shellcheck >/dev/null; then
    check "shellcheck -S warning on every script" shellcheck -S warning ./*.sh tests/*.sh
else
    skip "shellcheck is not installed"
fi
# compile() and not py_compile, so that no __pycache__ is written into the repository
pysyntax() {
    python3 -I -c 'import sys
for f in sys.argv[1:]:
    compile(open(f, encoding="utf-8").read(), f, "exec")' keep-report.py vkverify.py tests/make-schedule-fixture.py
}
check "the Python files compile" pysyntax
SCAN=$T/kcore-keyscan
check "kcore-keyscan builds statically without a warning" gcc -static -O2 -Wall -Werror -o "$SCAN" kcore-keyscan.c
[ -x "$SCAN" ] || finish

# ---- scanner -----------------------------------------------------------------------------------
mkdir "$T/keys" "$T/evid" "$T/lab" "$T/lab2"
head -c 64 /dev/urandom > "$T/keys/k256.vk"     # two AES-256 keys
head -c 32 /dev/urandom > "$T/keys/k128.vk"     # two AES-128 keys
head -c 64 /dev/urandom > "$T/keys/other.vk"    # a key that is in no header
KEYS="$T/keys/k256.vk $T/keys/k128.vk"
FIX=tests/make-schedule-fixture.py

trap_addr() { sed -n "s/^trap $1: .* 0x\\([0-9a-f]*\\).*/\\1/p" "$2"; }
listed()    { grep -q "phys $(printf '0x%016x' "$((16#$1))") " "$2"; }
scanner_fixture() {  # scanner_fixture FORMAT
    local img=$T/fx.$1 cand=$T/keys/cand.$1.txt note=$T/fx.$1.txt n a
    # shellcheck disable=SC2086  # KEYS is two paths without spaces
    python3 -I "$FIX" --format "$1" --size 8 "$img" $KEYS > "$note" || return 1
    "$SCAN" "$img" > "$cand" 2> "$T/scan.$1.txt" || { echo "the scanner ended with status $?"; return 1; }
    # the four schedules of the two keys and the traps 1, 2, 4 and 5, and nothing else
    n=$(wc -l < "$cand")
    [ "$n" -eq 8 ] || { echo "$n schedules are listed, 8 are expected"; return 1; }
    python3 -I -c 'import sys
found = {line.split()[-1] for line in open(sys.argv[1])}
for p in sys.argv[2:]:
    k = open(p, "rb").read()
    if k[:len(k) // 2].hex() not in found or k[len(k) // 2:].hex() not in found:
        sys.exit("a half of " + p.rsplit("/", 1)[-1] + " is not among the schedules")' "$cand" $KEYS || return 1
    for n in 1 2 4 5; do
        a=$(trap_addr "$n" "$note")
        listed "$a" "$cand" || { echo "trap $n at 0x$a is not found"; return 1; }
    done
    a=$(trap_addr 3 "$note")
    ! listed "$a" "$cand" || { echo "trap 3 at 0x$a has a wrong bit and is reported"; return 1; }
}
for fmt in raw elf lime avml; do
    check "scanner on a $fmt fixture: both keys, four traps found, the broken schedule not" scanner_fixture "$fmt"
done
# with a step of 16 only the four schedules of the keys lie on the step
step16() { [ "$("$SCAN" -s 16 "$T/fx.raw" 2>/dev/null | wc -l)" -eq 4 ]; }
check "scanner with -s 16 lists only the aligned schedules" step16
# A file that holds memory in a compressed form is not searched as raw bytes, where it would give
# a part of the schedules or none with status 0. An AVML image of a version that is not read is
# refused too.
packed() {
    gzip -c "$T/fx.raw" > "$T/fx.raw.gz"
    { printf 'AVML\003\000\000\000'; head -c 24 /dev/zero; head -c 4096 /dev/urandom; } > "$T/fx.v3"
    local f
    for f in fx.raw.gz fx.v3; do
        "$SCAN" "$T/$f" > "$T/packed.out" 2> "$T/packed.err"
        [ $? -eq 1 ] && [ ! -s "$T/packed.out" ] && grep -q 'begins like' "$T/packed.err" || { echo "$f is not refused"; return 1; }
    done
    "$SCAN" -r "$T/fx.raw.gz" > /dev/null 2> "$T/packed.err" && grep -q ', raw, ' "$T/packed.err"
}
check "scanner refuses a gzip file and an AVML image of another version, and searches them with -r" packed
# A compressed AVML image that was cut, as on a medium that ran full, is searched up to the cut:
# the schedules before it are listed, the place is named and the status is 1. A chunk with a
# changed byte is named by its checksum, and a changed length after a range ends the search.
damaged() {
    local full n
    full=$(wc -c < "$T/fx.avml")
    head -c $((full * 3 / 5)) "$T/fx.avml" > "$T/cut.avml"
    "$SCAN" "$T/cut.avml" > "$T/keys/cut.txt" 2> "$T/cut.err"
    [ $? -eq 1 ] || { echo "a cut image does not end with status 1"; return 1; }
    grep -q 'damaged or ends early at file offset' "$T/cut.err" || { echo "the cut is not named"; return 1; }
    n=$(wc -l < "$T/keys/cut.txt")
    [ "$n" -ge 7 ] || { echo "$n schedules before the cut, at least 7 are expected"; return 1; }
    python3 -I -c 'import sys
d = bytearray(open(sys.argv[1], "rb").read())
d[32 + 10 + 5000] ^= 1          # inside the first chunk of the first range
open(sys.argv[2], "wb").write(d)
d[32 + 10 + 5000] ^= 1
d[-3] ^= 1                      # the length after the last range
open(sys.argv[3], "wb").write(d)' "$T/fx.avml" "$T/flip.avml" "$T/len.avml" || return 1
    "$SCAN" "$T/flip.avml" > /dev/null 2> "$T/flip.err" || { echo "a changed byte ends the search"; return 1; }
    grep -q 'differ from their checksum: 1\.' "$T/flip.err" || { echo "the changed chunk is not named"; return 1; }
    "$SCAN" "$T/len.avml" > /dev/null 2> "$T/len.err"
    [ $? -eq 1 ] && grep -q 'the length after a range' "$T/len.err" || { echo "a changed length is not named"; return 1; }
    # a LiME image with bytes after its last range
    { cat "$T/fx.lime"; printf 'bytes that are no header of a range, after the last one'; } > "$T/junk.lime"
    "$SCAN" "$T/junk.lime" > /dev/null 2> "$T/junk.err"
    [ $? -eq 1 ] && grep -q 'no header of a range' "$T/junk.err" || { echo "bytes after the last range are not named"; return 1; }
}
check "scanner searches a cut or damaged image up to the damage and names the place" damaged

# ---- verifier, proof ---------------------------------------------------------------------------
if command -v cryptsetup >/dev/null; then
    # the key file option was renamed in cryptsetup 2.5.0, as in keytriage.sh
    if cryptsetup --help 2>&1 | grep -q -e '--volume-key-file'; then VK=--volume-key-file; else VK=--master-key-file; fi
    printf 'selftest-passphrase' > "$T/pw"
    mkluks() {  # mkluks TYPE KEYFILE IMAGE SIZE
        truncate -s "$4" "$3" && cryptsetup luksFormat -q --type "$1" --cipher aes-xts-plain64 \
            --key-size "$(( $(wc -c < "$2") * 8 ))" "$VK" "$2" --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
            --key-file "$T/pw" "$3"
    }
    headers() { mkluks luks2 "$T/keys/k256.vk" "$T/l2.img" 32M && mkluks luks1 "$T/keys/k128.vk" "$T/l1.img" 8M; }
    check "cryptsetup makes a LUKS2 and a LUKS1 header from the two keys" headers
    CAND=$T/keys/cand.lime.txt

    verify_headers() {
        python3 -I vkverify.py "$CAND" "$T/l2.img" "$T/l1.img" --out "$T/keys/out" --json "$T/v.json" || return 1
        cmp "$T/keys/out/l2.vk" "$T/keys/k256.vk" && cmp "$T/keys/out/l1.vk" "$T/keys/k128.vk" &&
            no_key_in "$KEYS" "$T/v.json"
    }
    check "vkverify.py proves both keys against the headers and writes them" verify_headers

    # A disk that holds both volumes: the bare magic at sector 1, which is no header and must be
    # passed over, LUKS2 at 1 MiB and LUKS1 at 36 MiB.
    { head -c 512 /dev/zero; printf 'LUKS\272\276'; head -c 1048058 /dev/zero; cat "$T/l2.img"
      head -c 3145728 /dev/zero; cat "$T/l1.img"; } > "$T/disk.dd"
    offline() {
        ( cd "$T/lab" && KEYSCAN=$SCAN bash "$R/offline-keyscan.sh" "$T/fx.lime" "$T/disk.dd" ) || return 1
        local d m
        d=$(echo "$T"/lab/scan_*)
        cmp "$d/keys/disk.dd@0x100000.vk" "$T/keys/k256.vk" && cmp "$d/keys/disk.dd@0x2400000.vk" "$T/keys/k128.vk" || return 1
        m=$(stat -c %a "$d/keys" "$d"/keys/* | sort -u | tr '\n' ' ')
        [ "$m" = "600 700 " ] || { echo "modes below keys/: $m, 600 and 700 are expected"; return 1; }
        ( cd "$d" && sha256sum -c --quiet manifest.sha256 ) || return 1
        no_key_in "$KEYS" "$d/triage.txt" "$d/scan.txt" "$d/verdict.json" "$d/manifest.sha256"
    }
    check "offline-keyscan.sh finds both headers in a disk image and proves both keys" offline
    report() {
        local d; d=$(echo "$T"/lab/scan_*)
        python3 -I keep-report.py "$d/verdict.json" > "$T/report.txt" || return 1
        [ "$(python3 -I keep-report.py "$d/verdict.json" --brief | grep -c '^  key held .*: proven$')" -eq 2 ]
    }
    check "keep-report.py prints the report with both volumes as key held" report

    # The same disk as the file of a virtual machine. qemu-img writes it in each format, and
    # the verifier must read from each the disk as it is, byte for byte, find both headers at
    # the offsets they have on the disk and prove both keys. A VHD is a little larger than the
    # disk it was made from, because its size is rounded to whole cylinders: zeros follow.
    mkdir "$T/vm"
    as_disk() {  # as_disk FILE : the reader gives the disk, and both keys are proven from it
        local f=$1
        python3 -I -c 'import importlib.util, sys
spec = importlib.util.spec_from_file_location("vkverify", "vkverify.py")
vk = importlib.util.module_from_spec(spec); spec.loader.exec_module(vk)
raw, files = open(sys.argv[1], "rb").read(), []
disk = vk.open_disk(sys.argv[2], files)
data = b"".join(disk.read_at(off, 1 << 20) for off in range(0, disk.size, 1 << 20))
if disk.kind == "raw" or data[:len(raw)] != raw or any(data[len(raw):]):
    sys.exit("%s is read as %s and differs from the disk" % (sys.argv[2], disk.kind))
if disk.read_at(len(raw) // 2 - 7, 70001) != raw[len(raw) // 2 - 7:len(raw) // 2 + 69994]:
    sys.exit("a read across the borders of blocks differs from the disk")' "$T/disk.dd" "$f" || return 1
        rm -rf "$T/vm/keys"
        python3 -I vkverify.py "$T/keys/cand.lime.txt" --image "$f" --out "$T/vm/keys" > "$T/vm.txt" 2>/dev/null || { echo "not every header is proven"; cat "$T/vm.txt"; return 1; }
        cmp "$T/vm/keys/${f##*/}@0x100000.vk" "$T/keys/k256.vk" && cmp "$T/vm/keys/${f##*/}@0x2400000.vk" "$T/keys/k128.vk"
    }
    if command -v qemu-img >/dev/null; then
        vmdisk() {  # vmdisk FILE FORMAT [qemu-img option...]
            local f=$T/vm/$1 fmt=$2; shift 2
            qemu-img convert -f raw -O "$fmt" "$@" "$T/disk.dd" "$f" 2> "$T/vm.err" || { echo "qemu-img: $(cat "$T/vm.err")"; return 1; }
            as_disk "$f"
        }
        check "vkverify.py reads a qcow2 disk"                               vmdisk d.qcow2 qcow2
        check "vkverify.py reads a qcow2 disk with compressed clusters"      vmdisk d-c.qcow2 qcow2 -c
        check "vkverify.py reads a qcow2 disk of version 2"                  vmdisk d-v2.qcow2 qcow2 -o compat=0.10
        check "vkverify.py reads a qcow2 disk with clusters of 4 KiB"        vmdisk d-4k.qcow2 qcow2 -o cluster_size=4k
        check "vkverify.py reads a sparse VMDK disk"                         vmdisk d.vmdk vmdk
        check "vkverify.py reads a stream-optimized VMDK disk"               vmdisk d-stream.vmdk vmdk -o subformat=streamOptimized
        check "vkverify.py reads a VMDK descriptor with a sparse extent"     vmdisk d-2gbs.vmdk vmdk -o subformat=twoGbMaxExtentSparse
        check "vkverify.py reads a VMDK descriptor with a flat extent"       vmdisk d-flat.vmdk vmdk -o subformat=monolithicFlat
        check "vkverify.py reads a dynamic VDI disk"                         vmdisk d.vdi vdi
        check "vkverify.py reads a fixed VDI disk"                           vmdisk d-static.vdi vdi -o static=on
        check "vkverify.py reads a dynamic VHD disk"                         vmdisk d.vhd vpc
        check "vkverify.py reads a fixed VHD disk"                           vmdisk d-fixed.vhd vpc -o subformat=fixed
        check "vkverify.py reads a VHDX disk"                                vmdisk d.vhdx vhdx
        check "vkverify.py reads a VHDX disk with blocks of 1 MiB"           vmdisk d-1m.vhdx vhdx -o block_size=1M
        # What is recognised and not read is named, and is not searched as raw bytes, where an
        # uncompressed image gives headers at offsets that are those of the file.
        vm_refused() {
            local f
            qemu-img convert -f raw -O qcow2 -o extended_l2=on "$T/disk.dd" "$T/vm/r-el2.qcow2" 2>/dev/null || return 1
            qemu-img convert -f raw -O qed "$T/disk.dd" "$T/vm/r.qed" 2>/dev/null || return 1
            for f in r-el2.qcow2 r.qed; do
                python3 -I vkverify.py "$T/keys/cand.lime.txt" --image "$T/vm/$f" > "$T/vm.txt" 2>/dev/null
                [ $? -eq 1 ] && grep -q 'which \(is\|are\) not read' "$T/vm.txt" && ! grep -q 'header at offset' "$T/vm.txt" || { echo "$f is not refused"; cat "$T/vm.txt"; return 1; }
            done
            # an overlay holds nothing of its own: no header, and the backing file is named
            qemu-img create -q -f qcow2 -b "$T/vm/d.qcow2" -F qcow2 "$T/vm/over.qcow2" || return 1
            python3 -I vkverify.py "$T/keys/cand.lime.txt" --image "$T/vm/over.qcow2" > "$T/vm.txt" 2>/dev/null
            [ $? -eq 1 ] && grep -q 'it has the backing file' "$T/vm.txt" && grep -q 'no LUKS header found' "$T/vm.txt"
        }
        check "vkverify.py names a disk format it does not read, and the backing file of an overlay" vm_refused
    else
        skip "qemu-img is not installed: the disks of virtual machines are not checked"
    fi
    # The same disk as an EnCase image, as ewfacquirestream of libewf writes it: with and without
    # compression, in the older format of SMART, and in segment files of 8 MiB. Searched as raw
    # bytes such an image gives no header, also without compression. A missing segment, a cut
    # one and a chunk that differs from its checksum are named.
    if command -v ewfacquirestream >/dev/null; then
        ewf() {  # ewf NAME [ewfacquirestream option...]
            local n=$1; shift
            ewfacquirestream -C c -D d -e e -E e -N n -t "$T/vm/$n" "$@" < "$T/disk.dd" > "$T/ewf.log" 2>&1 || { tail -n 3 "$T/ewf.log"; return 1; }
            as_disk "$T/vm/$n.E01"
        }
        check "vkverify.py reads an E01 image with compressed chunks"        ewf e-fast -c fast
        check "vkverify.py reads an E01 image without compression"           ewf e-none -c none
        check "vkverify.py reads an E01 image in the SMART format"           ewf e-smart -f smart -c fast
        check "vkverify.py reads an E01 image in several segment files"      ewf e-split -c fast -S 8M
        ewf_damaged() {
            local d=$T/vm/dmg
            [ -f "$T/vm/e-split.E03" ] || { echo "the image has fewer than three segment files"; return 1; }
            mkdir "$d" "$d/miss" "$d/cut" && cp "$T/vm/e-split.E01" "$d/miss/" && cp "$T/vm/e-split.E01" "$T/vm/e-split.E02" "$d/cut/" || return 1
            head -c 100000 "$T/vm/e-split.E03" > "$d/cut/e-split.E03"
            python3 -I -c 'import sys
d = bytearray(open(sys.argv[1], "rb").read()); d[len(d) // 2] ^= 1; open(sys.argv[2], "wb").write(d)' "$T/vm/e-none.E01" "$d/flip.E01" || return 1
            local f want
            for f in "miss/e-split.E01:is not beside the first one" "cut/e-split.E01:it is cut" "flip.E01:differs from its checksum"; do
                want=${f#*:}; f=${f%%:*}
                python3 -I vkverify.py "$T/keys/cand.lime.txt" --image "$d/$f" > "$T/vm.txt" 2>/dev/null
                [ $? -eq 1 ] && grep -q "$want" "$T/vm.txt" || { echo "$f: not named as \"$want\""; cat "$T/vm.txt"; return 1; }
            done
        }
        check "vkverify.py names a missing or cut segment and a damaged chunk of an E01 image" ewf_damaged
    else
        skip "ewfacquirestream is not installed: EnCase images are not checked"
    fi

    refuse() {
        python3 -I "$FIX" --format lime --size 8 "$T/other.lime" "$T/keys/other.vk" > /dev/null || return 1
        "$SCAN" "$T/other.lime" > "$T/keys/cand.other.txt" 2>/dev/null || return 1
        python3 -I vkverify.py "$T/keys/cand.other.txt" "$T/l2.img" "$T/l1.img" > "$T/refuse.txt"
        [ $? -eq 1 ] && [ "$(grep -c '^  not proven' "$T/refuse.txt")" -eq 2 ]
    }
    check "vkverify.py proves nothing from a memory that does not hold the keys" refuse

    # "cryptsetup erase" destroys the keyslots. The digest stays, so the key from memory is still
    # proven, and for LUKS2 without a key size, which stood in the keyslots.
    erased() {
        cp "$T/l2.img" "$T/l2e.img" && cp "$T/l1.img" "$T/l1e.img" || return 1
        cryptsetup erase -q "$T/l2e.img" && cryptsetup erase -q "$T/l1e.img" || { echo "cryptsetup erase failed"; return 1; }
        python3 -I vkverify.py "$CAND" "$T/l2e.img" "$T/l1e.img" --out "$T/keys/erased" --json "$T/erased.json" > "$T/erased.txt" 2>&1 ||
            { cat "$T/erased.txt"; return 1; }
        grep -q 'key size not stated, no keyslot is left' "$T/erased.txt" || { echo "the erased LUKS2 header still states a key size"; return 1; }
        cmp "$T/keys/erased/l2e.vk" "$T/keys/k256.vk" && cmp "$T/keys/erased/l1e.vk" "$T/keys/k128.vk" && no_key_in "$KEYS" "$T/erased.txt" "$T/erased.json"
    }
    check "vkverify.py proves the keys of headers whose keyslots were erased" erased
    # A header that is cut short, and one whose JSON has a list where an object belongs: each is
    # an unreadable header, and the good header beside them is still proven.
    broken() {
        head -c 100 "$T/l1.img" > "$T/cut1.img"; head -c 5000 "$T/l2.img" > "$T/cut2.img"
        python3 -I -c 'import json, struct, sys
raw = bytearray(open(sys.argv[1], "rb").read(1 << 20))
size = struct.unpack(">Q", raw[8:16])[0]
meta = json.loads(bytes(raw[4096:size]).split(b"\0")[0])
meta["digests"] = [meta["digests"]]
area = json.dumps(meta).encode()
raw[4096:size] = area + bytes(size - 4096 - len(area))
open(sys.argv[2], "wb").write(raw)' "$T/l2.img" "$T/list.img" || return 1
        python3 -I vkverify.py "$CAND" "$T/l2.img" "$T/cut1.img" "$T/cut2.img" "$T/list.img" --json "$T/broken.json" > "$T/broken.txt" 2>&1
        [ $? -eq 1 ] || { echo "the status is not 1"; cat "$T/broken.txt"; return 1; }
        ! grep -q Traceback "$T/broken.txt" || { cat "$T/broken.txt"; return 1; }
        [ "$(grep -c '"verdict": "unreadable header"' "$T/broken.json")" -eq 3 ] && [ "$(grep -c '"verdict": "proven"' "$T/broken.json")" -eq 1 ]
    }
    check "vkverify.py reports cut and malformed headers as unreadable and proves the header beside them" broken
    same_name() {
        mkdir -p "$T/case-a" "$T/case-b"; cp "$T/l2.img" "$T/case-a/vol.img"; cp "$T/l1.img" "$T/case-b/vol.img"
        python3 -I vkverify.py "$CAND" "$T/case-a/vol.img" "$T/case-b/vol.img" --out "$T/keys/same" > "$T/same.txt" 2>&1 || { cat "$T/same.txt"; return 1; }
        cmp "$T/keys/same/vol.vk" "$T/keys/k256.vk" && cmp "$T/keys/same/vol-2.vk" "$T/keys/k128.vk"
    }
    check "vkverify.py keeps two headers of the same file name apart" same_name

    # what keytriage.sh runs as the proof on scene
    prove() { cryptsetup open --test-passphrase "$VK" "$1" "$2" >/dev/null 2>&1; }
    proof() {
        prove "$T/keys/k256.vk" "$T/l2.img" && prove "$T/keys/k128.vk" "$T/l1.img" || { echo "a header refuses its own key"; return 1; }
        ! prove "$T/keys/other.vk" "$T/l2.img" || { echo "the header accepts a key that is not its own"; return 1; }
    }
    check "the on-scene proof accepts the key of a header and refuses another ($VK)" proof

    menu_offline() {
        printf 'offline\n%s\n%s\n\n%s\nyes\n' "$T/fx.lime" "$T/disk.dd" "$T/lab2" | KEYSCAN=$SCAN bash -p keep-menu.sh > "$T/menu.txt" 2>&1 || return 1
        grep -q '^keep-menu.sh: SUCCESS$' "$T/menu.txt" && no_key_in "$KEYS" "$T/menu.txt"
    }
    check "keep-menu.sh runs the offline mode through a pipe" menu_offline

    # ---- triage --------------------------------------------------------------------------------
    # keytriage.sh itself, without root and without device-mapper. A copy of it runs from a kit
    # that is laid out like the medium, with the busybox applets in bin/. The examined system is
    # played by stand-ins, and everything else is the real thing. dmsetup and cryptsetup lie in
    # a directory of their own, which -p names, and the other stand-ins in the bin/ of the kit:
    #   dmsetup         prints its listing and the table lines from files
    #   cryptsetup      prints "status" from a file and hands every other call, so the header
    #                   backup and the proof, to the real cryptsetup
    #   kcore-keyscan   searches the fixture in place of /proc/kcore, with the real scanner
    #   id              says 0, which is the only thing asked of it
    #   sync            notes what it is asked to flush, fails while $STUB/sync-fails exists and
    #                   is the applet otherwise
    #   hostname        says what $STUB/hostname holds, and is the applet without that file
    #   avml            writes the fixture as the memory image, as LiME or with --compress as
    #                   the compressed image, and a part of it with status 1 while
    #                   $STUB/avml-fails exists
    # t_table is the LUKS1 header with its key in the table line (route R1), t_keyring the LUKS2
    # header with a keyring reference (route R3). t:plain and T:plain are plain mappings, whose
    # names FAT and exFAT refuse as file names and which differ only by case. The mappings of the
    # second list are the cases at the edge: the names "No" and "my data", the null cipher, a
    # mapping whose table dmsetup does not give, a key field that is no key, and in a list of its
    # own a LUKS2 mapping whose header cannot be backed up.
    if command -v busybox >/dev/null; then
        KIT=$T/kit; SYS=$T/sys; STUB=$T/stub; REALCS=$(command -v cryptsetup); BB=$(command -v busybox)
        TSH=$KIT/bin/bash                 # the shell of the kit: bash-static where it is installed
        mkdir -p "$KIT/bin" "$SYS" "$STUB" "$T/tevid" "$T/foreign"
        for a in busybox $(busybox --list); do
            case $a in bash) ;; *) ln -s "$BB" "$KIT/bin/$a" 2>/dev/null ;; esac
        done
        ln -s "$(command -v bash-static || command -v bash)" "$TSH"
        # What a root shell of the examined system could hand down: a file for the shell to run
        # first, a function in place of an applet, and a trace of every command, which would
        # print the keys. Under bash -p none of them takes effect.
        printf 'echo BASH_ENV >> "%s"\n' "$T/foreign.log" > "$T/benv.sh"
        HOSTILE=(/usr/bin/env "BASH_ENV=$T/benv.sh" "SHELLOPTS=xtrace" "BASH_FUNC_sed%%=() { echo function-sed >> \"$T/foreign.log\"; }")
        # A program of every name the kit has, and dirname, in the directory of dmsetup and first
        # on the PATH of the caller. Whichever of them runs, notes its name.
        for a in $( { echo dirname; busybox --list; } | sort -u ); do
            printf '#!/bin/bash\necho "%s" >> "%s"\n' "$a" "$T/foreign.log" > "$T/foreign/$a"; chmod 755 "$T/foreign/$a"
            ln -s "$T/foreign/$a" "$SYS/$a"
        done
        cp keytriage.sh "$KIT/"
        standin() { rm -f "$1"; cat > "$1"; chmod 755 "$1"; }   # standin FILE : the script on standard input
        standin "$KIT/bin/id" <<EOT
#!/bin/bash
echo 0
EOT
        standin "$KIT/bin/kcore-keyscan" <<EOT
#!/bin/bash
exec "$SCAN" "$T/fx.lime"
EOT
        standin "$KIT/bin/sync" <<EOT
#!/bin/bash
printf '%s\\n' "\$*" >> "$T/sync.log"
[ ! -e "$STUB/sync-fails" ] || { echo "sync: stand-in failure" >&2; exit 1; }
exec "$BB" sync "\$@"
EOT
        # avml --version, avml acquire [--compress] FILE
        standin "$KIT/bin/avml" <<EOT
#!/bin/bash
[ "\$1" = --version ] && { echo "avml stand-in"; exit 0; }
[ "\$1" = acquire ] || exit 2
shift
src="$T/fx.lime"; [ "\$1" = --compress ] && { src="$T/fx.avml"; shift; }
if [ -e "$STUB/avml-fails" ]; then
    head -c 100000 "\$src" > "\$1"; echo "Error: No space left on device (stand-in)" >&2; exit 1
fi
cat "\$src" > "\$1"
EOT
        standin "$KIT/bin/hostname" <<EOT
#!/bin/bash
if [ -f "$STUB/hostname" ]; then cat "$STUB/hostname"; else exec "$BB" hostname; fi
EOT
        standin "$SYS/dmsetup" <<EOT
#!/bin/bash
for n in "\$@"; do :; done                # the mapping is the last argument
case \$1 in
    ls)    cat "$STUB/ls.txt" ;;
    table) [ -f "$STUB/\$n.table" ] && cat "$STUB/\$n.table" ;;
esac
EOT
        standin "$SYS/cryptsetup" <<EOT
#!/bin/bash
for n in "\$@"; do :; done
if [ "\$1" = status ]; then cat "$STUB/\$n.status"; else exec "$REALCS" "\$@"; fi
EOT
        hexof() { od -An -v -tx1 "$1" | tr -d ' \n'; }
        status() {  # status NAME TYPE CIPHER BITS LOCATION DEVICE
            printf '/dev/mapper/%s is active.\n  type:    %s\n  cipher:  %s\n  keysize: %s bits\n  key location: %s\n  device:  %s\n' "$@" > "$STUB/$1.status"
        }
        printf 't_table\t(253:0)\nt_keyring\t(253:1)\nt:plain\t(253:2)\nT:plain\t(253:3)\n' > "$STUB/ls.txt"
        for n in t:plain T:plain; do
            printf '0 16384 crypt aes-xts-plain64 %s 0 7:2 0\n' "$(hexof "$T/keys/other.vk")" > "$STUB/$n.table"
            status "$n" PLAIN aes-xts-plain64 512 dm-crypt /dev/loop2
        done
        printf '0 16384 crypt aes-xts-plain64 %s 0 7:0 4096\n' "$(hexof "$T/keys/k128.vk")" > "$STUB/t_table.table"
        printf '0 32768 crypt aes-xts-plain64 :64:logon:cryptsetup:selftest-d0 0 7:1 32768\n' > "$STUB/t_keyring.table"
        for n in No "my data"; do
            printf '0 16384 crypt aes-xts-plain64 %s 0 7:2 0\n' "$(hexof "$T/keys/other.vk")" > "$STUB/$n.table"
            status "$n" PLAIN aes-xts-plain64 512 dm-crypt /dev/loop2
        done
        printf '0 16384 crypt cipher_null-ecb - 0 7:3 0\n' > "$STUB/t_null.table"
        status t_null PLAIN cipher_null-ecb 0 dm-crypt /dev/loop3
        status t_notable LUKS2 aes-xts-plain64 512 keyring "$T/l2.img"
        printf '0 16384 crypt aes-xts-plain64 zz 0 7:4 0\n' > "$STUB/t_odd.table"
        status t_odd PLAIN aes-xts-plain64 512 dm-crypt /dev/loop4
        printf '0 32768 crypt aes-xts-plain64 :64:logon:cryptsetup:selftest-d1 0 7:5 32768\n' > "$STUB/t_nohdr.table"
        status t_nohdr LUKS2 aes-xts-plain64 512 keyring "$T/no-such-device"
        # with_list LINES NAME : a run NAME with another listing of dmsetup
        with_list() {
            local rc
            cp "$STUB/ls.txt" "$STUB/ls.saved"; printf '%b' "$1" > "$STUB/ls.txt"
            triage "$2"; rc=$?
            mv "$STUB/ls.saved" "$STUB/ls.txt"; return "$rc"
        }
        status t_table LUKS1 aes-xts-plain64 256 dm-crypt "$T/l1.img"
        status t_keyring LUKS2 aes-xts-plain64 512 keyring "$T/l2.img"

        # triage NAME [OPTION...] : one run. The screen goes to $T/NAME.txt and the folder of the
        # run is $T/NAME.d, a link, because the name of the folder carries the time. The run
        # starts with the umask of an ordinary root shell, so the modes are the script's own doing.
        triage() {
            local name=$1 rc; shift
            mkdir "$T/tevid/$name" || return 1
            : > "$T/sync.log"
            ( umask 022; PATH=$T/foreign:$PATH "${HOSTILE[@]}" "$TSH" -p "$KIT/keytriage.sh" -f -p "/nowhere:$SYS" -e "$T/tevid/$name" "$@" > "$T/$name.txt" 2>&1 ); rc=$?
            ln -s "$(echo "$T/tevid/$name"/triage_*)" "$T/$name.d"
            return "$rc"
        }
        verdict_of() {  # verdict_of FOLDER VOLUME
            python3 -I -c 'import json, sys
for v in json.load(open(sys.argv[1] + "/verdict.json"))["volumes"]:
    if v["name"] == sys.argv[2]:
        print(v["verdict"])' "$1" "$2"
        }
        triage_both() {
            local d=$T/both.d
            triage both || { echo "keytriage.sh ended with status $?"; cat "$T/both.txt"; return 1; }
            [ "$(verdict_of "$d" t_table)" = "captured and proven" ] && [ "$(verdict_of "$d" t_keyring)" = "captured and proven" ] ||
                { echo "not both verdicts are captured and proven"; cat "$T/both.txt"; return 1; }
            cmp "$d/keys/t_table.vk" "$T/keys/k128.vk" && cmp "$d/keys/t_keyring.vk" "$T/keys/k256.vk" || return 1
            ( cd "$d" && sha256sum -c --quiet manifest.sha256 ) || return 1
            no_key_in "$KEYS" "$T/both.txt" "$d/triage.txt" "$d/verdict.json" "$d/manifest.sha256" || return 1
            [ "$(python3 -I keep-report.py "$d/verdict.json" --brief | grep -c '^  key held .*: captured and proven$')" -eq 2 ]
        }
        check "keytriage.sh captures and proves a key from the table and one from memory" triage_both
        cp "$T/sync.log" "$T/both.sync"
        triage_modes() {
            local open; open=$(find "$T/both.d/" -perm /077)
            [ -z "$open" ] || { echo "open to the group or to others:"; echo "$open"; return 1; }
        }
        check "keytriage.sh writes nothing that the group or others can read" triage_modes
        triage_medium_only() {
            [ ! -s "$T/foreign.log" ] || { echo "from outside the medium, these were run:"; sort "$T/foreign.log" | uniq -c; return 1; }
            ! grep -q '^+' "$T/both.txt" || { echo "the run is traced, SHELLOPTS of the environment took effect"; return 1; }
            ! grep -q 'not found' "$T/both.txt" || { grep 'not found' "$T/both.txt"; return 1; }
            python3 -I -c 'import json, sys
paths = sorted(b["path"] for b in json.load(open(sys.argv[1]))["binaries"])
sys.exit(0 if paths == [sys.argv[2] + "/cryptsetup", sys.argv[2] + "/dmsetup"] else "recorded: %r" % paths)' "$T/both.d/verdict.json" "$SYS"
        }
        check "keytriage.sh runs nothing from outside the medium but the dmsetup and cryptsetup of -p" triage_medium_only
        # The memory image, as LiME and compressed: the file, its format in the report, its line
        # in the manifest, and for the compressed one that the scanner reads what was written.
        triage_memory() {
            local d=$T/mem.d c=$T/memc.d
            triage mem -m || { echo "-m ended with status $?"; cat "$T/mem.txt"; return 1; }
            cmp "$d/memory/memory.lime" "$T/fx.lime" && grep -q ' memory/memory.lime$' "$d/manifest.sha256" || { echo "no LiME image"; return 1; }
            ( cd "$d" && sha256sum -c --quiet manifest.sha256 ) || return 1
            triage memc -m -c || { echo "-m -c ended with status $?"; cat "$T/memc.txt"; return 1; }
            cmp "$c/memory/memory.avml" "$T/fx.avml" && [ ! -e "$c/memory/memory.lime" ] && grep -q ' memory/memory.avml$' "$c/manifest.sha256" || { echo "no compressed image"; return 1; }
            ( cd "$c" && sha256sum -c --quiet manifest.sha256 ) || return 1
            [ "$("$SCAN" "$c/memory/memory.avml" 2>/dev/null | wc -l)" -eq 8 ] || { echo "the scanner does not read the compressed image"; return 1; }
            python3 -I -c 'import json, sys
a, b = (json.load(open(p + "/verdict.json"))["memory"] for p in sys.argv[1:3])
ok = ((a["status"], a["file"], a["format"]) == ("captured", "memory/memory.lime", "lime")
      and (b["status"], b["file"], b["format"]) == ("captured", "memory/memory.avml", "avml compressed"))
sys.exit(0 if ok else "the reports say %r and %r" % (a, b))' "$d" "$c" || return 1
            python3 -I keep-report.py "$c/verdict.json" | grep -q 'avml compressed' || { echo "keep-report.py does not print the format"; return 1; }
        }
        check "keytriage.sh -m writes the memory image as LiME, and compressed with -c" triage_memory
        # An image that AVML could not finish, as on a medium that ran full: the part is removed,
        # the image counts as failed, and the keys and the report are complete all the same.
        triage_memory_fail() {
            local d=$T/memf.d rc
            : > "$STUB/avml-fails"; triage memf -m -c; rc=$?; rm -f "$STUB/avml-fails"
            [ "$rc" -eq 0 ] || { echo "status $rc"; cat "$T/memf.txt"; return 1; }
            [ ! -e "$d/memory/memory.avml" ] || { echo "the part of the image is kept"; return 1; }
            grep -q 'memory image  *failed' "$T/memf.txt" && grep -q 'No space left' "$d/verdict.json" || { echo "the failure is not reported"; return 1; }
            [ "$(verdict_of "$d" t_table)" = "captured and proven" ] && ( cd "$d" && sha256sum -c --quiet manifest.sha256 )
        }
        check "keytriage.sh removes the part of a memory image that could not be finished" triage_memory_fail
        triage_c_alone() {
            "$TSH" -p "$KIT/keytriage.sh" -f -c -p "$SYS" -e "$T/tevid" > "$T/calone.txt" 2>&1
            [ $? -eq 2 ] && grep -q -e '-c belongs to -m' "$T/calone.txt"
        }
        check "keytriage.sh refuses -c without -m with status 2" triage_c_alone
        triage_shell() {
            "$TSH" "$KIT/keytriage.sh" -f -p "$SYS" -e "$T/tevid" > "$T/nop.txt" 2>&1
            [ $? -eq 1 ] && grep -q 'start this script with bash -p' "$T/nop.txt" || { echo "a start without -p is not refused"; return 1; }
            [ "$TSH" -ef /bin/bash ] && return 0      # no second shell on this machine to try
            /bin/bash -p "$KIT/keytriage.sh" -f -p "$SYS" -e "$T/tevid" > "$T/nop.txt" 2>&1
            [ $? -eq 1 ] && grep -q 'runs in the shell of the medium' "$T/nop.txt" || { echo "another shell than that of the kit is not refused"; return 1; }
        }
        check "keytriage.sh refuses a start without bash -p and a shell that is not the kit's" triage_shell
        # The menu in the kit, with a keytriage.sh whose "#!" line names a program that only fails.
        # The menu must start it in its own shell, with -p, and never through that line.
        menu_shell() {
            mkdir -p "$T/kit2" && ln -s "$KIT/bin" "$T/kit2/bin" && cp keep-menu.sh "$T/kit2/" || return 1
            printf '#!/bin/false\ncase $- in *p*) echo "ran in $BASH with -p" ;; esac\n' > "$T/kit2/keytriage.sh"; chmod 755 "$T/kit2/keytriage.sh"
            printf 'live\n%s\n\nyes\n' "$T/evid" | "$TSH" -p "$T/kit2/keep-menu.sh" > "$T/menu2.txt" 2>&1 || { cat "$T/menu2.txt"; return 1; }
            grep -q "^ran in $TSH with -p\$" "$T/menu2.txt" || { cat "$T/menu2.txt"; return 1; }
        }
        check "keep-menu.sh starts keytriage.sh in the shell of the medium with -p" menu_shell
        triage_flush() {
            local f d; d=$(readlink "$T/both.d")
            for f in keys/t_table.vk keys/t_keyring.vk keys/kcore-candidates.txt headers/t_table.hdr headers/t_keyring.hdr manifest.sha256; do
                grep -q -F "$d/$f" "$T/both.sync" || { echo "$f is not flushed"; return 1; }
            done
            [ "$(tail -n 1 "$T/both.sync")" = "-f $d" ] || { echo "the run does not end with a flush of the file system"; return 1; }
            grep -q 'every file of this run is flushed' "$T/both.txt"
        }
        check "keytriage.sh flushes the headers, the keys and at the end the file system" triage_flush
        triage_flushfail() {
            local rc
            : > "$STUB/sync-fails"; triage noflush; rc=$?; rm -f "$STUB/sync-fails"
            [ "$rc" -eq 1 ] || { echo "status $rc after a failed flush, 1 is expected"; return 1; }
            ! grep -q '"verdict": "captured' "$T/noflush.d/verdict.json" || { echo "a key that is not flushed counts as captured"; return 1; }
            grep -q 'FAILED, the folder is not complete' "$T/noflush.txt"
        }
        check "keytriage.sh counts no key as captured when the flush fails, and ends with status 1" triage_flushfail
        triage_own_disk() {
            "$TSH" -p "$KIT/keytriage.sh" -e / > "$T/own.txt" 2>&1
            [ $? -eq 1 ] && grep -q 'is refused: it lies on the root file system' "$T/own.txt" || { cat "$T/own.txt"; return 1; }
            grep -q 'accepted with -f although it lies on' "$T/both.d/triage.txt" || [ "$(stat -c %d "$T")" != "$(stat -c %d /)" ]
        }
        check "keytriage.sh refuses an evidence directory on the root file system without -f" triage_own_disk
        triage_names() {
            local d=$T/both.d
            cmp "$d/keys/T_plain.vk" "$T/keys/other.vk" && cmp "$d/keys/t_plain_.vk" "$T/keys/other.vk" || return 1
            [ "$(verdict_of "$d" t:plain)" = "captured, in use" ] && [ "$(verdict_of "$d" T:plain)" = "captured, in use" ] || return 1
            [ ! -e "$d/tmp" ] && grep -q ' log/t_table.status.txt$' "$d/manifest.sha256" && grep -q ' log/kcore-keyscan.txt$' "$d/manifest.sha256" ||
                { echo "log/ is not there or not in the manifest"; return 1; }
            # a host name that tries to leave the evidence directory and to clear the screen
            printf 'pc/../../out\033[2Jside\n' > "$STUB/hostname"; triage names; rm -f "$STUB/hostname"
            [ -d "$(echo "$T"/tevid/names/triage_pc_.._.._out__2Jside_*)" ] || { echo "the folder is not where it belongs"; ls -R "$T/tevid/names" | head; return 1; }
            ! grep -q "$(printf '\033')" "$T/names.txt" "$T/names.d/triage.txt" || { echo "an escape character reaches the screen"; return 1; }
            python3 -I -c 'import json, sys
host = json.load(open(sys.argv[1]))["host"]
sys.exit(0 if host == "pc/../../out [2Jside" else "host in the report: %r" % host)' "$T/names.d/verdict.json"
        }
        check "keytriage.sh keeps host and mapping names inside the evidence folder and off the terminal" triage_names
        triage_edge() {
            local d=$T/edge.d n
            with_list 'No\t(253:4)\nmy data\t(253:5)\nt_null\t(253:6)\nt_notable\t(253:7)\nt_odd\t(253:8)\n' edge ||
                { echo "keytriage.sh ended with status $?"; cat "$T/edge.txt"; return 1; }
            for n in No "my data"; do
                [ "$(verdict_of "$d" "$n")" = "captured, in use" ] || { echo "the mapping \"$n\" has the verdict \"$(verdict_of "$d" "$n")\""; return 1; }
            done
            cmp "$d/keys/No.vk" "$T/keys/other.vk" && cmp "$d/keys/my_data.vk" "$T/keys/other.vk" || return 1
            [ "$(verdict_of "$d" t_null)" = "no key needed" ] && [ ! -e "$d/keys/t_null.vk" ] || { echo "the null cipher: $(verdict_of "$d" t_null)"; return 1; }
            grep -q 'gave no table line' "$T/edge.txt" && [ "$(verdict_of "$d" t_notable)" = "captured and proven" ] || { echo "the mapping without a table line"; return 1; }
            [ "$(verdict_of "$d" t_odd)" = "needs a memory read" ] && [ ! -e "$d/keys/t_odd.vk" ] || { echo "a key field that is no key: $(verdict_of "$d" t_odd)"; return 1; }
            python3 -I keep-report.py "$d/verdict.json" --brief | grep -q '^  no key needed  *t_null: no key needed$' || { echo "keep-report.py does not class the null cipher"; return 1; }
            python3 -I keep-report.py "$d/verdict.json" | grep -q '^    Evidence medium: ' || { echo "keep-report.py does not print the evidence medium"; return 1; }
        }
        check "keytriage.sh takes mappings named No and with a space, the null cipher, a missing table and a bad key field" triage_edge
        triage_nohdr() {
            with_list 't_nohdr\t(253:9)\n' nohdr || return 1
            [ "$(verdict_of "$T/nohdr.d" t_nohdr)" = "needs a memory read" ] || return 1
            [ "$(wc -l < "$T/nohdr.d/keys/kcore-candidates.txt")" -eq 8 ] || { echo "the candidate list is not kept"; return 1; }
            grep -q ' keys/kcore-candidates.txt$' "$T/nohdr.d/manifest.sha256"
        }
        check "keytriage.sh keeps the candidate list of a volume whose header could not be backed up" triage_nohdr
        triage_none() {
            with_list 'No devices found\n' none || return 1
            grep -q '^no open dm-crypt volumes$' "$T/none.txt" || return 1
            [ "$(python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["volumes"]))' "$T/none.d/verdict.json")" = 0 ]
        }
        check "keytriage.sh reports no volume when dmsetup says that it found no devices" triage_none
    else
        skip "busybox is not installed: keytriage.sh is not run"
    fi
else
    skip "cryptsetup is not installed: the verifier and the proof are not checked"
fi

# ---- menu --------------------------------------------------------------------------------------
menu_dry() {
    printf 'live\n%s\n\nyes\n' "$T/evid" | bash -p keep-menu.sh -n > "$T/menu.txt" 2>&1 || return 1
    grep -q "keytriage.sh -e $T/evid -b 64\$" "$T/menu.txt" && grep -q 'dry run, nothing was run' "$T/menu.txt"
}
check "keep-menu.sh asks, lists the command and runs nothing with -n" menu_dry
# the mode with a memory image asks for its format, and "compressed" adds -c to the command
menu_memory() {
    printf 'live-memory\n%s\n\ncompressed\nyes\n' "$T/evid" | bash -p keep-menu.sh -n > "$T/menu-m.txt" 2>&1 || return 1
    grep -q -e ' -m -c$' "$T/menu-m.txt" || { echo "no -m -c in the command"; cat "$T/menu-m.txt"; return 1; }
    printf 'live-memory\n%s\n\n\nyes\n' "$T/evid" | bash -p keep-menu.sh -n > "$T/menu-m.txt" 2>&1 || return 1
    grep -q -e ' -m$' "$T/menu-m.txt" || { echo "the default is not -m alone"; cat "$T/menu-m.txt"; return 1; }
}
check "keep-menu.sh asks for the format of the memory image" menu_memory
menu_eof() { printf 'offline\n' | bash -p keep-menu.sh -n > /dev/null 2>&1; [ $? -eq 1 ]; }
check "keep-menu.sh ends with status 1 when the input ends early" menu_eof
# -h prints the whole comment at the head of a script, whatever its length, and a wrong option
# is an error
usage_text() {
    local f
    for f in keytriage.sh keep-menu.sh offline-keyscan.sh tests/selftest.sh tests/compat-guest.sh; do
        bash -p "$f" -h > "$T/usage.txt" || return 1
        awk 'NR == 1 { next } !/^#/ { exit } { print }' "$f" | cmp -s - "$T/usage.txt" || { echo "$f -h does not print its head comment"; return 1; }
        [ "$(wc -l < "$T/usage.txt")" -gt 5 ] || return 1
        bash -p "$f" -Z > /dev/null 2>&1; [ $? -eq 2 ] || { echo "$f does not end with status 2 for a wrong option"; return 1; }
    done
}
check "the scripts print their head comment with -h and refuse a wrong option with status 2" usage_text

# ---- page --------------------------------------------------------------------------------------
if [ -f docs/index.html ]; then
    page() {
        local v; v=$(sed -n 's/^VERSION="\([0-9.]*\).*/\1/p' keytriage.sh)
        [ -n "$v" ] && grep -q ">$v<" docs/index.html || { echo "docs/index.html does not show the version $v"; return 1; }
    }
    check "the page shows the version of keytriage.sh" page
    page_links() {
        python3 -I -c 'import os, re, sys
text = open("docs/index.html", encoding="utf-8").read()
ids = set(re.findall(r"\bid=\"([^\"]+)\"", text))
bad = ["no target for #" + h for h in re.findall(r"href=\"#([^\"]+)\"", text) if h not in ids]
for ref in re.findall(r"\b(?:src|href)=\"([^\"#][^\"]*)\"", text):
    if re.match(r"https://github\.com/nafud(/|$)", ref):
        continue                      # a link for the reader, nothing is loaded from it
    if ":" in ref or ref.startswith("/"):
        bad.append("another host or an absolute path: " + ref)
    elif not os.path.isfile(os.path.join("docs", ref)):
        bad.append("no such file: docs/" + ref)
for ref in re.findall(r"url\(\"([^\"]+)\"\)", open("docs/assets/keep.css", encoding="utf-8").read()):
    if not os.path.isfile(os.path.join("docs/assets", ref)):
        bad.append("no such file: docs/assets/" + ref)
sys.exit("\n".join(bad) or 0)'
    }
    check "the links and files of the page are all there and all its own" page_links
fi

finish
