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
#              three formats, and once with a step of 16
#   verifier   LUKS2 and LUKS1 headers that cryptsetup makes from the same two keys: vkverify.py
#              on the headers, offline-keyscan.sh on a disk image that holds both, keep-report.py
#              on the report, and a candidate list without the keys, which must not prove
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
ALL=0
case ${1:-} in
    -a) ALL=1 ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
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
    # names FAT and exFAT refuse as file names and which differ only by case.
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
usage() { local f; for f in keytriage.sh keep-menu.sh offline-keyscan.sh tests/selftest.sh; do bash "$f" -h | grep -q . || return 1; done; }
check "the scripts print their usage with -h" usage

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
