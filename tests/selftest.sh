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
#   scanner    a fixture with the schedules of two known XTS keys and four traps, in each of the
#              three formats, and once with a step of 16. A gzip file and a compressed AVML image
#              are refused
#   verifier   LUKS2 and LUKS1 headers that cryptsetup makes from the same two keys: vkverify.py
#              on the headers, offline-keyscan.sh on a disk image that holds both, keep-report.py
#              on the report, and a candidate list without the keys, which must not prove. The
#              same headers with their keyslots erased, cut short, malformed, and under one name
#   proof      the proof command of keytriage.sh on the same headers, with the key and with another
#   triage     keytriage.sh itself on stand-ins for the examined system's dmsetup, cryptsetup
#              status and /proc/kcore, with the same headers, the real header backup and proof
#   menu       keep-menu.sh through a pipe: a dry run, an input that ends early, and an offline run
#   page       docs/index.html shows the version of keytriage.sh, every link inside the page has
#              its target, every file it names exists and nothing is loaded from another host
#
# On real device-mapper and a real /proc/kcore keytriage.sh is checked by compat-check.sh.
#
# Programs: bash, gcc with a static libc and python3, and for the full run shellcheck,
# cryptsetup and busybox. With bash-static installed keytriage.sh runs in it, as on the medium.
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
    # the four schedules of the two keys and the traps 1, 2 and 4, and nothing else
    n=$(wc -l < "$cand")
    [ "$n" -eq 7 ] || { echo "$n schedules are listed, 7 are expected"; return 1; }
    python3 -I -c 'import sys
found = {line.split()[-1] for line in open(sys.argv[1])}
for p in sys.argv[2:]:
    k = open(p, "rb").read()
    if k[:len(k) // 2].hex() not in found or k[len(k) // 2:].hex() not in found:
        sys.exit("a half of " + p.rsplit("/", 1)[-1] + " is not among the schedules")' "$cand" $KEYS || return 1
    for n in 1 2 4; do
        a=$(trap_addr "$n" "$note")
        listed "$a" "$cand" || { echo "trap $n at 0x$a is not found"; return 1; }
    done
    a=$(trap_addr 3 "$note")
    ! listed "$a" "$cand" || { echo "trap 3 at 0x$a has a wrong bit and is reported"; return 1; }
}
for fmt in raw elf lime; do
    check "scanner on a $fmt fixture: both keys, three traps found, the broken schedule not" scanner_fixture "$fmt"
done
# with a step of 16 only the four schedules of the keys lie on the step
step16() { [ "$("$SCAN" -s 16 "$T/fx.raw" 2>/dev/null | wc -l)" -eq 4 ]; }
check "scanner with -s 16 lists only the aligned schedules" step16
# A file that holds memory in a compressed form is not searched as raw bytes, where it would give
# a part of the schedules or none with status 0. The AVML file is its header alone, as
# "avml convert --format lime_compressed" writes it: the magic, version 2, the range, padding.
packed() {
    gzip -c "$T/fx.raw" > "$T/fx.raw.gz"
    { printf 'AVML\002\000\000\000'; head -c 24 /dev/zero; head -c 4096 /dev/urandom; } > "$T/fx.avml"
    local f
    for f in fx.raw.gz fx.avml; do
        "$SCAN" "$T/$f" > "$T/packed.out" 2> "$T/packed.err"
        [ $? -eq 1 ] && [ ! -s "$T/packed.out" ] && grep -q 'begins like' "$T/packed.err" || { echo "$f is not refused"; return 1; }
    done
    "$SCAN" -r "$T/fx.raw.gz" > /dev/null 2> "$T/packed.err" && grep -q ', raw, ' "$T/packed.err"
}
check "scanner refuses a gzip file and a compressed AVML image, and searches them with -r" packed

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
        printf 'offline\n%s\n%s\n\n%s\nyes\n' "$T/fx.lime" "$T/disk.dd" "$T/lab2" | KEYSCAN=$SCAN bash keep-menu.sh > "$T/menu.txt" 2>&1 || return 1
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
    # t_table is the LUKS1 header with its key in the table line (route R1), t_keyring the LUKS2
    # header with a keyring reference (route R3). t:plain and T:plain are plain mappings, whose
    # names FAT and exFAT refuse as file names and which differ only by case. The mappings of the
    # second list are the cases at the edge: the names "No" and "my data", the null cipher, a
    # mapping whose table dmsetup does not give, a key field that is no key, and in a list of its
    # own a LUKS2 mapping whose header cannot be backed up.
    if command -v busybox >/dev/null; then
        KIT=$T/kit; SYS=$T/sys; STUB=$T/stub; REALCS=$(command -v cryptsetup); BB=$(command -v busybox)
        TSH=$(command -v bash-static || command -v bash)
        mkdir -p "$KIT/bin" "$SYS" "$STUB" "$T/tevid" "$T/foreign"
        for a in busybox $(busybox --list); do
            case $a in bash) ;; *) ln -s "$BB" "$KIT/bin/$a" 2>/dev/null ;; esac
        done
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
            ( umask 022; PATH=$T/foreign:$PATH "$TSH" "$KIT/keytriage.sh" -f -p "/nowhere:$SYS" -e "$T/tevid/$name" "$@" > "$T/$name.txt" 2>&1 ); rc=$?
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
            [ ! -s "$T/foreign.log" ] || { echo "programs from outside the medium were run:"; sort "$T/foreign.log" | uniq -c; return 1; }
            ! grep -q 'not found' "$T/both.txt" || { grep 'not found' "$T/both.txt"; return 1; }
            python3 -I -c 'import json, sys
paths = sorted(b["path"] for b in json.load(open(sys.argv[1]))["binaries"])
sys.exit(0 if paths == [sys.argv[2] + "/cryptsetup", sys.argv[2] + "/dmsetup"] else "recorded: %r" % paths)' "$T/both.d/verdict.json" "$SYS"
        }
        check "keytriage.sh runs nothing from outside the medium but the dmsetup and cryptsetup of -p" triage_medium_only
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
            "$TSH" "$KIT/keytriage.sh" -e / > "$T/own.txt" 2>&1
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
            [ "$(wc -l < "$T/nohdr.d/keys/kcore-candidates.txt")" -eq 7 ] || { echo "the candidate list is not kept"; return 1; }
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
    printf 'live\n%s\n\nyes\n' "$T/evid" | bash keep-menu.sh -n > "$T/menu.txt" 2>&1 || return 1
    grep -q "keytriage.sh -e $T/evid -b 64\$" "$T/menu.txt" && grep -q 'dry run, nothing was run' "$T/menu.txt"
}
check "keep-menu.sh asks, lists the command and runs nothing with -n" menu_dry
menu_eof() { printf 'offline\n' | bash keep-menu.sh -n > /dev/null 2>&1; [ $? -eq 1 ]; }
check "keep-menu.sh ends with status 1 when the input ends early" menu_eof
# -h prints the whole comment at the head of a script, whatever its length, and a wrong option
# is an error
usage_text() {
    local f
    for f in keytriage.sh keep-menu.sh offline-keyscan.sh tests/selftest.sh; do
        bash "$f" -h > "$T/usage.txt" || return 1
        awk 'NR == 1 { next } !/^#/ { exit } { print }' "$f" | cmp -s - "$T/usage.txt" || { echo "$f -h does not print its head comment"; return 1; }
        [ "$(wc -l < "$T/usage.txt")" -gt 5 ] || return 1
        bash "$f" -Z > /dev/null 2>&1; [ $? -eq 2 ] || { echo "$f does not end with status 2 for a wrong option"; return 1; }
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
