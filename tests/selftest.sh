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
#              on the headers and on a disk image that holds both, with its report, and a
#              candidate list without the keys, which must not prove. The same headers with
#              their keyslots erased, cut short, malformed, and under one name. The disk image
#              again as qemu-img writes it in the formats of virtual machines and as
#              ewfacquirestream writes it as an EnCase image
#   usage      -h of a script prints its head comment, and a wrong option is refused
#   page       the sources of the pages in docs/ show the version of the C program and no
#              other, mkdocs.yml names it for the frame, and the home page offers the file of
#              that release. The pages themselves are built and read by tests/pages-check.sh
#
# The program keep is checked part by part by tests/unit-check.sh, and on real device-mapper
# and a real /proc/kcore by tests/compat-check.sh.
#
# Programs: bash, gcc with a static libc and python3, and for the full run shellcheck,
# cryptsetup, qemu-img and ewfacquirestream.
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
syntax() { local f; for f in tests/*.sh; do bash -n "$f" || return 1; done; }
check "bash -n on every script" syntax
if command -v shellcheck >/dev/null; then
    check "shellcheck -S warning on every script" shellcheck -S warning tests/*.sh
else
    skip "shellcheck is not installed"
fi
# compile() and not py_compile, so that no __pycache__ is written into the repository
pysyntax() {
    python3 -I -c 'import sys
for f in sys.argv[1:]:
    compile(open(f, encoding="utf-8").read(), f, "exec")' vkverify.py tests/make-schedule-fixture.py
}
check "the Python files compile" pysyntax
SCAN=$T/kcore-keyscan
check "kcore-keyscan builds statically without a warning" gcc -static -O2 -Wall -Werror -o "$SCAN" kcore-keyscan.c
[ -x "$SCAN" ] || finish

# ---- scanner -----------------------------------------------------------------------------------
mkdir "$T/keys" "$T/evid" "$T/lab"
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
    # a LiME image that ends inside a range, which the scanner before 1.3 searched with status
    # 0 and zeros in place of what was missing. A list that cannot be written is status 1 too.
    head -c 3000000 "$T/fx.lime" > "$T/cut.lime"
    "$SCAN" "$T/cut.lime" > "$T/keys/cut.txt" 2> "$T/cut.err"
    [ $? -eq 1 ] && grep -q 'ends early at file offset 3000000: the file ends inside a range' "$T/cut.err" ||
        { echo "a LiME image that is cut is not named with status 1"; cat "$T/cut.err"; return 1; }
    "$SCAN" "$T/fx.lime" > /dev/full 2> "$T/cut.err"
    [ $? -eq 1 ] && grep -q 'the list of the schedules could not be written' "$T/cut.err" ||
        { echo "a list that cannot be written is not named with status 1"; cat "$T/cut.err"; return 1; }
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

# ---- verifier ----------------------------------------------------------------------------------
if command -v cryptsetup >/dev/null; then
    # the key file option was renamed in cryptsetup 2.5.0
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
    disk_image() {
        python3 -I vkverify.py "$CAND" --image "$T/disk.dd" --out "$T/lab/keys" --json "$T/lab/verdict.json" > "$T/lab/screen.txt" 2>&1 ||
            { cat "$T/lab/screen.txt"; return 1; }
        local m
        cmp "$T/lab/keys/disk.dd@0x100000.vk" "$T/keys/k256.vk" && cmp "$T/lab/keys/disk.dd@0x2400000.vk" "$T/keys/k128.vk" || return 1
        m=$(stat -c %a "$T/lab/keys" "$T"/lab/keys/* | sort -u | tr '\n' ' ')
        [ "$m" = "600 700 " ] || { echo "modes below keys/: $m, 600 and 700 are expected"; return 1; }
        no_key_in "$KEYS" "$T/lab/screen.txt" "$T/lab/verdict.json"
    }
    check "vkverify.py finds both headers in a disk image and proves both keys" disk_image
    report() {
        python3 -I -c 'import hashlib, json, sys
r = json.load(open(sys.argv[1]))
got = sorted((v["verdict"], v["key_sha256_16"]) for v in r["volumes"])
want = sorted(("proven", hashlib.sha256(open(p, "rb").read()).hexdigest()[:16]) for p in sys.argv[2:])
sys.exit(0 if r["schema"] == "keep-report/2" and got == want else "the report says %r" % got)' "$T/lab/verdict.json" "$T/keys/k256.vk" "$T/keys/k128.vk"
    }
    check "the report of vkverify.py names both volumes as proven, each key by the start of its SHA-256" report

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

else
    skip "cryptsetup is not installed: the verifier is not checked"
fi

# ---- usage -------------------------------------------------------------------------------------
# -h prints the whole comment at the head of a script, whatever its length, and a wrong option
# is an error
usage_text() {
    local f
    for f in tests/selftest.sh tests/compat-guest.sh tests/unit-check.sh; do
        bash -p "$f" -h > "$T/usage.txt" || return 1
        awk 'NR == 1 { next } !/^#/ { exit } { print }' "$f" | cmp -s - "$T/usage.txt" || { echo "$f -h does not print its head comment"; return 1; }
        [ "$(wc -l < "$T/usage.txt")" -gt 5 ] || return 1
        bash -p "$f" -Z > /dev/null 2>&1; [ $? -eq 2 ] || { echo "$f does not end with status 2 for a wrong option"; return 1; }
    done
}
check "the scripts print their head comment with -h and refuse a wrong option with status 2" usage_text

# ---- page --------------------------------------------------------------------------------------
# The pages are built and read by tests/pages-check.sh, which needs MkDocs. What can be seen
# without it is seen here, so that a new version of the program without its pages fails early.
if [ -f docs/installation.md ]; then
    page() {
        local v n; v=$(sed -n 's/^#define KEEP_VERSION "\([^ "]*\).*/\1/p' src/triage.h)
        [ -n "$v" ] || { echo "no KEEP_VERSION in src/triage.h"; return 1; }
        grep -q "^keep $v (" docs/installation.md || { echo "docs/installation.md does not show keep $v"; return 1; }
        grep -q "^  keep_version: \"$v\"\$" mkdocs.yml || { echo "mkdocs.yml does not name keep $v as extra.keep_version"; return 1; }
        grep -qF "[download keep $v](https://github.com/nafud/Keep/releases/download/v$v/keep)" docs/index.md || { echo "docs/index.md does not offer keep $v of the release v$v"; return 1; }
        n=$(grep -ohE '[0-9]\.[0-9]-(pre|rc)[0-9]+' docs/*.md | grep -vcx "$v")
        [ "$n" -eq 0 ] || { echo "$n places of docs/*.md name another version than $v"; return 1; }
    }
    check "the sources of the pages show the version of the C program and no other" page
fi

finish
