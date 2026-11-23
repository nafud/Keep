#!/bin/bash
# keytriage.sh, the scene-side script of Keep: decryption-readiness triage for an unlocked
# Linux system.
#
#   sudo /media/tools/bin/bash /media/tools/keytriage.sh [-e DIR] [-b BUDGET] [-m] [-f] [-p DIRS]
#
#   -e DIR   evidence directory, on the evidence medium (default /media/evidence)
#   -b N     memory-route proof budget: stop after N proof attempts per volume (default 64)
#   -m       after the keys, also write a memory image to the evidence medium (see below)
#   -f       accept an evidence directory on the examined system's own disk (for a test)
#   -p DIRS  where the examined system keeps dmsetup and cryptsetup, directories with full paths
#            separated by colons (default /usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin)
#   -h       this text
#
# The machine is met running with its encrypted storage unlocked. Powering it off turns the data
# back to ciphertext. For every open dm-crypt volume the script decides one of these and prints
# it as the verdict:
#
#   captured and proven   the volume key is obtained now and shown to open the LUKS header
#   captured, in use      the key is read from the live mapping, which has no header digest to
#                         test it against (plain, tcrypt). The lab open of the image confirms it
#   captured, not proven  a key is read but no proof was possible or the proof failed
#   needs a memory read   the key is not in reach of this run. A memory image keeps the route open
#   live copy only        no key route is open, so only the mounted plaintext can be copied
#
# The ladder, in order, per volume:
#   R1 table    the device-mapper table carries the key (LUKS1, plain, tcrypt, LUKS2 opened with
#               --disable-keyring). The key is read and, for LUKS, proven against the header digest.
#   R3 memory   the table carries only a keyring reference (LUKS2 default, systemd-homed). The AES
#               key schedules are searched in /proc/kcore with kcore-keyscan, once for all volumes,
#               and proven against the header. Blocked by kernel lockdown confidentiality. The
#               search finds AES keys only, so a volume with another cipher gets no memory route.
#   R5 live     the floor: nothing but a file-level copy of the mounted plaintext.
#
# No key is printed. A captured or recovered key is written only to the evidence medium (the header
# backups, the candidate list, the volume keys) and named on screen by the first 16 digits of its
# SHA-256. The suspect's own dmsetup and cryptsetup are used for R1, and their paths
# and SHA-256 are recorded so the hashes can be checked against the archive afterwards.
#
# Every file is created with umask 077. A header backup, the candidate list and a key are flushed
# to the medium (fsync) as soon as they are written, and a key counts as captured only after
# that, because the machine may lose power the moment the verdict is read. At the end the whole
# file system of the evidence medium is flushed (syncfs). Exit status: 0 when the run completed
# and was flushed, 1 when it could not start or a write or a flush to the medium failed.
#
# The memory image (-m). The keys come first, because an event can close their window within
# seconds and an image of a large machine takes minutes. Then AVML writes the physical memory in
# LiME format to memory/memory.lime, which Volatility 3 and kcore-keyscan read. Next to it go the
# kernel banner (/proc/version), the release, os-release and System.map (where the system has one
# with symbols; Debian keeps a placeholder in /boot), which the lab needs to
# pick or build the Volatility 3 symbol table of exactly this kernel. The image needs as much
# free space on the evidence medium as the machine has memory. Lockdown confidentiality refuses it.
#
# The evidence directory. A key that is written to the examined disk changes that disk, and a
# key that is written into an encrypted volume of the examined system is locked in with the data
# at power-off. The script therefore finds the mount that holds the directory in
# /proc/self/mountinfo and the whole disks beneath it in /sys, and refuses a directory on the root
# file system or on a disk that also carries the root file system. Where the kernel names no
# block device for a file system (a network share, tmpfs, ZFS) only the first test applies, and a
# loop device counts as a disk of its own. A directory on an open dm-crypt volume is accepted
# with a note, because an encrypted evidence medium is one too.
#
# Output on the evidence medium, in triage_<host>_<time>/: triage.txt (this screen), verdict.json
# (the same verdicts for a program, schema keep-report/1, no key in it), headers/, keys/, log/
# (what cryptsetup status, the scanner and AVML wrote), memory/ with -m, and manifest.sha256 over
# all of them. In the names of the folder and of the files, every character of the host name or
# of a mapping name that is not a letter, a digit or one of . _ + = @ , - becomes _, so that a
# name cannot leave the evidence directory and FAT and exFAT take it.
#
# Needs root. The shell is the kit's bash-static and the utilities its static busybox, so the
# script does not depend on the distribution. PATH is the bin/ of the medium and nothing else, so
# a program that the medium lacks is an error and is never taken from the examined system.
# dmsetup and cryptsetup are the suspect's own and the only programs run from outside the medium.
# They are looked up in the directories of -p and run by their full paths, and the option that
# hands a volume key to cryptsetup is chosen by what the installed release offers
# (--volume-key-file from 2.5.0, --master-key-file before).

VERSION="1.2.5 (2026-11)"
umask 077                               # keys and the candidate list are written by this script
case $0 in */*) KIT=${0%/*} ;; *) KIT=. ;; esac     # no dirname: no program runs before PATH is set
KIT=$(cd "$KIT" && pwd)
BIN=$KIT/bin
PATH=$BIN
export PATH LC_ALL=C TZ=UTC
SYSDIRS=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin

EVID=/media/evidence
BUDGET=64
MEMORY=0
FORCE=0
MOUNTS=/proc/mounts
# the comment at the head of this file, read by the shell itself, so that -h needs no medium
usage() {
    local line
    while IFS= read -r line; do
        case $line in '#!'*) ;; '#'*) printf '%s\n' "$line" ;; *) break ;; esac
    done < "$0"
}
while getopts "e:b:mfp:h" opt; do
    case $opt in
        e) EVID=$OPTARG ;;
        b) BUDGET=$OPTARG ;;
        m) MEMORY=1 ;;
        f) FORCE=1 ;;
        p) SYSDIRS=$OPTARG ;;
        h) usage; exit 0 ;;
        *) printf 'usage: keytriage.sh [-e DIR] [-b BUDGET] [-m] [-f] [-p DIRS], -h prints the description\n' >&2; exit 2 ;;
    esac
done

die()  { printf 'keytriage.sh: %s\n' "$*" >&2; exit 1; }
now()  { printf '%(%Y-%m-%dT%H:%M:%SZ)T' -1; }
stamp(){ printf '%(%Y%m%d_%H%M%S)T' -1; }
say()  { printf '%s\n' "$*" | tee -a "$REPORT"; }
keyhash() { sha256sum | cut -c1-16; }           # names a key without showing it
hex2bin() { printf '%b' "$(sed 's/../\\x&/g')"; }  # hex on stdin to raw bytes on stdout
# flush FILE... : fsync each file or directory, so that it is on the medium and not only in the
# page cache. The applet reports a failed fsync on standard error and by its status.
WRITEFAIL=0
flush() { sync "$@" || { WRITEFAIL=1; return 1; }; }
jesc() {                                        # a string as the inside of a JSON string
    local s=${1//\\/\\\\}; s=${s//\"/\\\"}; s=${s//[$'\001'-$'\037']/ }; printf '%s' "$s"
}
jstr() { if [ -n "$1" ]; then printf '"%s"' "$(jesc "$1")"; else printf 'null'; fi; }
# sysprog NAME : the full path of a program of the examined system, from the directories of -p
sysprog() {
    local d IFS=:
    for d in $SYSDIRS; do
        case $d in /*) ;; *) continue ;; esac
        [ -f "$d/$1" ] && [ -x "$d/$1" ] && { printf '%s' "$d/$1"; return 0; }
    done
    return 1
}
# a name of the examined system for the screen: the kernel takes any byte in a host name and in a
# mapping name, so control characters are replaced before the name reaches a terminal
clean() { printf '%s' "${1//[$'\001'-$'\037'$'\177']/ }"; }
# the same name as a part of a file name on the evidence medium (see the head of this script)
fname() { local f=${1//[!A-Za-z0-9._+=@,-]/_}; printf '%s' "${f:-_}"; }

# mount_of PATH : the mount that holds PATH, into M_ID, M_DEV (major:minor), M_POINT, M_OPTS,
# M_TYPE and M_SRC. The fields are those of /proc/self/mountinfo (Documentation/filesystems/
# proc.rst, 3.5). The mount with the longest mount point that is a prefix of PATH holds it, and
# of two at the same mount point the later line, which lies on top.
mount_of() {
    local id dev mp opts rest best=-1
    M_ID=""
    while read -r id _ dev _ mp opts rest; do
        printf -v mp '%b' "$mp"                 # a space in a mount point is written \040
        case $1/ in "${mp%/}/"*) ;; *) continue ;; esac
        [ "${#mp}" -ge "$best" ] || continue
        best=${#mp}; M_ID=$id; M_DEV=$dev; M_POINT=$mp; M_OPTS=$opts
        rest=" $rest"; rest=${rest#* - }        # past the optional fields and their separator
        read -r M_TYPE M_SRC _ <<<"$rest"
        printf -v M_SRC '%b' "$M_SRC"
    done < /proc/self/mountinfo
    [ -n "$M_ID" ]
}
# The block device of the mount just found, as major:minor, or nothing. For most file systems it
# is the device number of the mount. btrfs shows an anonymous number there and names its device
# as the source.
mount_blockdev() {
    local n
    if [ -e "/sys/dev/block/$M_DEV" ]; then printf '%s' "$M_DEV"; return; fi
    [ -b "$M_SRC" ] || return 0
    n=$(readlink -f "$M_SRC"); n=${n##*/}
    [ -r "/sys/class/block/$n/dev" ] && read -r n < "/sys/class/block/$n/dev" && printf '%s' "$n"
}
# under MAJOR:MINOR : the block devices a device stands on, one "dev NAME" per line for itself
# and every device beneath, and "disk NAME" for each whole disk at the bottom. In sysfs a
# partition lies in the directory of its disk, and a device-mapper, md or bcache device lists
# what it stands on in slaves/.
under() {
    local p s d any=0
    p=$(readlink -f "/sys/dev/block/$1") && [ -d "$p" ] || return 0
    printf 'dev %s\n' "${p##*/}"
    if [ -e "$p/partition" ]; then p=${p%/*}; printf 'dev %s\n' "${p##*/}"; fi
    for s in "$p"/slaves/*; do
        [ -r "$s/dev" ] && read -r d < "$s/dev" || continue
        any=1; under "$d"
    done
    [ "$any" = 1 ] || printf 'disk %s\n' "${p##*/}"
}

# ---- preflight ---------------------------------------------------------------------------------
[ -x "$BIN/busybox" ] || die "no medium beside this script: $BIN/busybox is missing (build-toolkit.sh makes the medium)"
[ "$(id -u)" = 0 ] || die "must run as root (sudo)"
[ -d "$EVID" ] || die "the evidence directory $EVID does not exist"
EVID=$(cd "$EVID" && pwd -P) || die "cannot enter the evidence directory"
# where the evidence directory lies, and where the root file system
mount_of / || die "no mount of / in /proc/self/mountinfo"
ROOT_ID=$M_ID; ROOT_UNDER=$(under "$(mount_blockdev)")
mount_of "$EVID" || die "no mount that holds $EVID in /proc/self/mountinfo"
EVID_UNDER=$(under "$(mount_blockdev)")
MEDIUM="$M_SRC ($M_TYPE) mounted at $M_POINT"
OWN=""
if [ "$M_ID" = "$ROOT_ID" ]; then
    OWN="it lies on the root file system of the examined system"
else
    while read -r kind name; do
        [ "$kind" = disk ] && grep -q -x "disk $name" <<<"$ROOT_UNDER" &&
            { OWN="it lies on the disk $name, which also carries the root file system of the examined system"; break; }
    done <<<"$EVID_UNDER"
fi
[ -z "$OWN" ] || [ "$FORCE" = 1 ] ||
    die "the evidence directory $EVID is refused: $OWN. Mount an evidence medium and name a directory on it with -e. For a test, -f accepts this one."
case ,$M_OPTS, in *,ro,*) die "$EVID is on a file system that is mounted read-only: $MEDIUM" ;; esac
[ -w "$EVID" ] || die "$EVID is not writable"
case $BUDGET in ''|*[!0-9]*) die "the budget must be a number" ;; esac
DMSETUP=$(sysprog dmsetup) || die "no dmsetup of the examined system in $SYSDIRS (see -p)"
CRYPTSETUP=$(sysprog cryptsetup) || die "no cryptsetup of the examined system in $SYSDIRS (see -p)"
[ -x "$BIN/kcore-keyscan" ] || die "kcore-keyscan is not on the medium ($BIN)"
[ "$MEMORY" = 0 ] || [ -x "$BIN/avml" ] || die "avml is not on the medium ($BIN), needed for -m"

HOST=$(clean "$(hostname)")
OUT=$EVID/triage_$(fname "$HOST")_$(stamp)
mkdir "$OUT" && mkdir "$OUT/headers" "$OUT/keys" "$OUT/log" || die "cannot create $OUT"
REPORT=$OUT/triage.txt
STARTED=$(now)
LOCKDOWN=$(cat /sys/kernel/security/lockdown 2>/dev/null | sed 's/.*\[\(.*\)\].*/\1/')
SB=""
for f in /sys/firmware/efi/efivars/SecureBoot-*; do
    [ -e "$f" ] && SB=$(od -An -tu1 "$f" | awk '{print $NF}'); break
done
# the distribution, read as text. The file is the suspect's and is never run as a script.
OSNAME=""
for f in /etc/os-release /usr/lib/os-release; do
    [ -r "$f" ] && { OSNAME=$(sed -n 's/^PRETTY_NAME=//p' "$f" | head -n 1 | tr -d '"'); break; }
done
# the option that hands a volume key to cryptsetup: renamed in release 2.5.0
CSVER=$("$CRYPTSETUP" --version 2>/dev/null | head -n 1 | awk '{print $1, $2}')
if "$CRYPTSETUP" --help 2>&1 | grep -q -e '--volume-key-file'; then VKOPT=--volume-key-file; else VKOPT=--master-key-file; fi

# ---- banner ------------------------------------------------------------------------------------
: > "$REPORT"
say "keytriage.sh $VERSION"
say "host $HOST, $STARTED, kernel $(uname -r)"
say "system: ${OSNAME:-unknown}"
say "kernel lockdown: ${LOCKDOWN:-unknown}"
if [ -n "$SB" ]; then say "secure boot: $SB (1 enabled)"; else say "secure boot: no SecureBoot variable"; fi
say "evidence: $OUT"
say "evidence medium: $MEDIUM, $(( $(df -k -P "$OUT" | awk 'NR==2{print $4}') / 1024 )) MiB free"
[ -z "$OWN" ] || say "  accepted with -f although $OWN"
say ""

# the suspect's R1 binaries, recorded for the later archive check
say "R1 binaries (suspect's own, hashes to be checked against the archive):"
JBIN=()
for p in "$DMSETUP" "$CRYPTSETUP"; do
    b=${p##*/}; rp=$(readlink -f "$p"); h=$(sha256sum "$rp" | cut -c1-64)
    say "  $b  $rp  sha256 $h"
    JBIN+=("{\"name\": $(jstr "$b"), \"path\": $(jstr "$rp"), \"sha256\": $(jstr "$h")}")
done
say "  ${CSVER:-cryptsetup of unknown version}, a volume key is handed over with $VKOPT"
say ""

# ---- enumerate the open crypt volumes ----------------------------------------------------------
mapfile -t MAPS < <("$DMSETUP" ls --target crypt 2>/dev/null | awk 'NF>=1 && $1!="No" {print $1}' | sort)
[ "${#MAPS[@]}" -gt 0 ] || say "no open dm-crypt volumes"
[ "${#MAPS[@]}" -gt 0 ] && say "${#MAPS[@]} open dm-crypt volume(s): $(clean "${MAPS[*]}")"
# The file name of each mapping. FAT and exFAT fold the case of a name, so two names that are the
# same but for that are kept apart by a further _.
declare -A FN TAKEN
for m in "${MAPS[@]}"; do
    f=$(fname "$m"); while [ -n "${TAKEN[${f,,}]:-}" ]; do f=${f}_; done
    TAKEN[${f,,}]=1; FN[$m]=$f
done
# an evidence directory on one of these volumes: right for an encrypted evidence medium, and
# fatal for the keys when the volume is the examined system's own
while read -r kind name; do
    [ "$kind" = dev ] && [ -r "/sys/class/block/$name/dm/name" ] && read -r dmname < "/sys/class/block/$name/dm/name" || continue
    for m in "${MAPS[@]}"; do
        [ "$m" = "$dmname" ] && say "note: the evidence directory lies on the open dm-crypt volume $(clean "$m"). If that volume belongs to the examined system, the keys written here are locked in with it at power-off."
    done
done <<<"$EVID_UNDER"
# mounted file systems that can carry their own encryption. They are not dm-crypt and are outside
# this script, so they are named, so that their absence from the verdicts is not read as "clear".
OTHERFS=$(awk '$3=="ecryptfs" || $3=="zfs" || $3 ~ /^fuse\.(gocryptfs|cryfs|encfs)$/ {print $3}' "$MOUNTS" | sort -u | tr '\n' ' ')
OTHERFS=${OTHERFS% }
[ -n "$OTHERFS" ] && say "mounted and not examined here (file systems that can encrypt by themselves): $OTHERFS"
say ""

declare -A VERDICT
JVOL=()

# prove a key file against a LUKS header backup with the suspect's cryptsetup; 0 if it opens
prove() {  # prove KEYFILE HEADER
    "$CRYPTSETUP" open --test-passphrase "$VKOPT" "$1" "$2" >/dev/null 2>&1
}

# close a volume: print the verdict and keep it for the summary and for verdict.json
verdict() {  # verdict VERDICT ROUTE KEYHASH NOTE
    say "  VERDICT: $1${4:+ ($4)}"
    VERDICT[$m]=$1
    JVOL+=("{\"name\": $(jstr "$m"), \"type\": $(jstr "$typ"), \"cipher\": $(jstr "$cip"), \"key_bits\": ${ksz:-null}, \"key_location\": $(jstr "$loc"), \"device\": $(jstr "$dev"), \"header_backup\": $(jstr "${hdr:+headers/$f.hdr}"), \"route\": $(jstr "$2"), \"verdict\": $(jstr "$1"), \"key_sha256_16\": $(jstr "$3"), \"note\": $(jstr "$4")}")
    say ""
}

# the schedule search of /proc/kcore, run once and used for every volume that needs it
CAND=$OUT/keys/kcore-candidates.txt
SCANNED=0; SCANOK=0; SCANERR=""
scan_once() {
    if [ "$SCANNED" = 1 ]; then
        [ "$SCANOK" = 1 ] || say "  R3 memory: the search of /proc/kcore failed, as above"
        return
    fi
    SCANNED=1
    say "  R3 memory: searching /proc/kcore for AES key schedules"
    if "$BIN/kcore-keyscan" /proc/kcore > "$CAND" 2> "$OUT/log/kcore-keyscan.txt"; then
        SCANOK=1
        say "  $(wc -l < "$CAND") schedules found, list in keys/kcore-candidates.txt"
        flush "$CAND" "$OUT/keys" || say "  the list could not be flushed to the evidence medium"
    else
        SCANERR=$(head -n 1 "$OUT/log/kcore-keyscan.txt")
        say "  the search failed: ${SCANERR:-no message}"
    fi
}

# one field of "cryptsetup status": everything after the label, so a value may hold a colon
field() {  # field LABEL
    awk -v k="$1" '$0 ~ "^[[:space:]]*" k ":" {sub(/^[^:]*:[[:space:]]*/, ""); print; exit}' "$status"
}

for m in "${MAPS[@]}"; do
    f=${FN[$m]}
    say "==== $(clean "$m")"
    status=$OUT/log/$f.status.txt
    "$CRYPTSETUP" status "$m" > "$status" 2>&1 || true
    typ=$(field type); cip=$(field cipher); loc=$(field "key location"); dev=$(field device)
    ksz=$(awk '/keysize:/{print $2}' "$status")
    case $ksz in ''|*[!0-9]*) ksz="" ;; esac
    say "  type ${typ:-?}, cipher ${cip:-?}, keysize ${ksz:-?} bits, key location ${loc:-?}"
    say "  backing device ${dev:-?}"

    # the table line of the crypt target: its cipher (4th token) and its key field (5th token),
    # which is the key in hexadecimal or a :size:type:description reference. The line is read
    # through a pipe by the shell itself, so the key passes no other program and no file.
    tcip=""; keyfield=""
    while read -r _ _ target c k _; do
        [ "$target" = crypt ] && { tcip=$c; keyfield=$k; break; }
    done < <("$DMSETUP" table --showkeys "$m" 2>/dev/null)
    # the class of the cipher, from the kernel's own table line when it is there
    case ${tcip:-$cip} in
        aes-xts-*|capi:xts\(aes\)-*) cclass=xts ;;      # two AES keys, data then tweak
        aes-*)                       cclass=aes ;;      # one AES key
        *)                           cclass=other ;;    # no AES key schedule of the volume key
    esac

    # back up a LUKS header to the evidence medium (a key is useless without it)
    hdr=""
    case $typ in
        LUKS1|LUKS2)
            hdr=$OUT/headers/$f.hdr
            if "$CRYPTSETUP" luksHeaderBackup "$dev" --header-backup-file "$hdr" 2>/dev/null; then
                say "  header backed up: headers/$f.hdr ($(stat -c%s "$hdr") bytes)"
                flush "$hdr" "$OUT/headers" || say "  the header backup could not be flushed to the evidence medium"
            else
                say "  header backup FAILED for $dev"; hdr=""
            fi ;;
    esac

    # ---- R1: the table carries the key ----
    if [ -n "$keyfield" ] && [ "${keyfield:0:1}" != ":" ]; then
        kf=$OUT/keys/$f.vk
        if ! { printf '%s' "$keyfield" | hex2bin > "$kf"; } || ! flush "$kf" "$OUT/keys"; then
            say "  R1 table: the key is in the table and could not be written to the evidence medium"
            verdict "needs a memory read" "" "" "the write of the key to the evidence medium failed"
            continue
        fi
        kh=$(keyhash < "$kf")
        say "  R1 table: key of $(( ${#keyfield} / 2 )) bytes, sha256 $kh"
        if [ -n "$hdr" ]; then
            if prove "$kf" "$hdr"; then
                verdict "captured and proven" "R1 table" "$kh" "opens the header"
            else
                verdict "captured, not proven" "R1 table" "$kh" "the header does not accept the key, unexpected"
            fi
        else
            case $typ in
                LUKS1|LUKS2) verdict "captured, not proven" "R1 table" "$kh" "no header backup to prove against" ;;
                *)           verdict "captured, in use" "R1 table" "$kh" "the key of the live mapping, no header digest exists, the lab open confirms" ;;
            esac
        fi
        continue
    fi

    # ---- the table carries only a keyring reference ----
    say "  R1 table: keyring reference ${keyfield} (no key in the table)"
    if [ "$cclass" = other ]; then
        say "  R3 memory: the cipher ${tcip:-${cip:-?}} is not AES, so the AES schedule search does not apply"
        verdict "live copy only" "" "" "a memory image keeps another method open"
        continue
    fi
    if [ "$LOCKDOWN" = confidentiality ]; then
        say "  R3 memory: /proc/kcore is blocked under lockdown confidentiality"
        verdict "live copy only" "" "" "lockdown confidentiality"
        continue
    fi
    if [ -z "$hdr" ] || [ -z "$ksz" ]; then
        say "  R3 memory: no header to prove against"
        verdict "needs a memory read" "" "" "no header backup, the lab searches the image"
        continue
    fi

    # ---- R3: search the schedules in /proc/kcore and prove against the header ----
    scan_once
    if [ "$SCANOK" = 0 ]; then
        case $SCANERR in
            *"not permitted"*) verdict "live copy only" "" "" "the kernel refused the read of /proc/kcore" ;;
            *)                 verdict "needs a memory read" "" "" "the search of /proc/kcore failed" ;;
        esac
        continue
    fi
    kf=$OUT/keys/$f.vk
    proven=0; tried=0
    if [ "$cclass" = xts ]; then
        half=$(( ksz / 2 ))                # bits of each XTS half: 256 or 128
        # candidate keys of the needed size, as "phys hex" pairs
        mapfile -t C < <(awk -v b="$half" '$1=="AES-"b {print $3, $NF}' "$CAND")
        say "  ${#C[@]} schedules of AES-$half"
        # index by numeric physical address, so the scanner's zero-padding does not matter
        declare -A KEYAT; for line in "${C[@]}"; do KEYAT[$(( ${line%% *} ))]=${line#* }; done
        # XTS volume key = data||tweak; the tweak schedule is first and the data schedule 496
        # bytes after it, so for a tweak at phys P the data is at P+496. Those pairs are tried.
        for line in "${C[@]}"; do
            [ "$tried" -ge "$BUDGET" ] && break
            tph=${line%% *}; tkey=${line#* }
            dnum=$(( tph + 496 ))
            dkey=${KEYAT[$dnum]:-}
            [ -n "$dkey" ] || continue
            tried=$((tried+1))
            { printf '%s' "$dkey" | hex2bin; printf '%s' "$tkey" | hex2bin; } > "$kf"
            if prove "$kf" "$hdr"; then
                kh=$(keyhash < "$kf")
                say "  recovered a volume key of $(stat -c%s "$kf") bytes, sha256 $kh"
                say "  the tweak schedule is at $tph and the data schedule 496 bytes after it at $(printf '0x%016x' "$dnum")"
                proven=1; break
            fi
        done
        unset KEYAT
    else
        # one AES key is the whole volume key: every candidate of that size is tried
        mapfile -t C < <(awk -v b="$ksz" '$1=="AES-"b {print $3, $NF}' "$CAND")
        say "  ${#C[@]} schedules of AES-$ksz"
        for line in "${C[@]}"; do
            [ "$tried" -ge "$BUDGET" ] && break
            tried=$((tried+1))
            printf '%s' "${line#* }" | hex2bin > "$kf"
            if prove "$kf" "$hdr"; then
                kh=$(keyhash < "$kf")
                say "  recovered a volume key of $(stat -c%s "$kf") bytes, sha256 $kh"
                say "  its schedule is at ${line%% *}"
                proven=1; break
            fi
        done
    fi
    if [ "$proven" = 1 ] && ! flush "$kf" "$OUT/keys"; then
        say "  the key could not be flushed to the evidence medium"
        verdict "needs a memory read" "" "" "the write of the key to the evidence medium failed"
    elif [ "$proven" = 1 ]; then
        verdict "captured and proven" "R3 memory" "$kh" "opens the header"
    else
        rm -f "$kf"
        say "  no candidate proved within $tried test(s) of budget $BUDGET"
        verdict "needs a memory read" "" "" "the candidate list is kept for the lab verifier"
    fi
done

# ---- optional: a memory image for the lab ------------------------------------------------------
# The keys are done, so the image no longer competes with them for time. AVML writes LiME, the
# format that Volatility 3 and kcore-keyscan read without conversion.
MEMJ=""
MEMHASH=""
if [ "$MEMORY" = 1 ]; then
    say "==== memory image"
    mkdir -p "$OUT/memory"
    img=$OUT/memory/memory.lime
    avmlv=$("$BIN/avml" --version 2>/dev/null | head -n 1)
    # the size to expect: the sum of the System RAM ranges, which is what AVML reads
    ram=0
    while read -r range _; do
        ram=$(( ram + 16#${range#*-} - 16#${range%-*} + 1 ))
    done < <(grep '^[0-9a-f]*-[0-9a-f]* : System RAM' /proc/iomem 2>/dev/null)
    [ "$ram" -gt 0 ] || ram=$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo) * 1024 ))
    free=$(( $(df -k -P "$OUT" | awk 'NR==2{print $4}') * 1024 ))
    mstatus=""; mnote=""; mbytes=null; msecs=null
    if [ "$free" -lt $(( ram + 67108864 )) ]; then
        mstatus="skipped"
        mnote="the evidence medium has $(( free / 1048576 )) MiB free and the image can take $(( ram / 1048576 )) MiB"
        say "  skipped: $mnote"
    else
        say "  writing up to $(( ram / 1048576 )) MiB with ${avmlv:-avml}"
        t0=$SECONDS
        if "$BIN/avml" acquire "$img" > "$OUT/log/avml.txt" 2>&1 && flush "$img" "$OUT/memory"; then
            msecs=$(( SECONDS - t0 )); mbytes=$(stat -c%s "$img")
            MEMHASH=$(sha256sum "$img" | cut -c1-64)
            mstatus="captured"
            say "  memory/memory.lime, $mbytes bytes, LiME format, written in $msecs s"
            say "  sha256 $MEMHASH"
        else
            rc=$?
            rm -f "$img"
            mstatus="failed"
            mnote=$(grep -v '^[[:space:]]*$' "$OUT/log/avml.txt" | head -n 6 | tr -s ' \t\n' ' ')
            mnote="avml exit $rc: ${mnote% }"
            say "  failed: $mnote"
            [ "$LOCKDOWN" = confidentiality ] && say "  lockdown confidentiality refuses every memory source"
        fi
    fi
    # what the lab needs to find the symbol table of exactly this kernel for Volatility 3
    cat /proc/version > "$OUT/memory/banner.txt" 2>/dev/null
    uname -r > "$OUT/memory/kernel-release.txt"
    for f in /etc/os-release /usr/lib/os-release; do
        [ -r "$f" ] && { cat "$f" > "$OUT/memory/os-release"; break; }
    done
    # A symbol table names the kernel's own symbols. Debian keeps a one-line placeholder in /boot
    # and the table in the debug package of the kernel, so a file without symbols is not kept.
    smap=""; nosym=""
    for f in "/boot/System.map-$(uname -r)" "/lib/modules/$(uname -r)/System.map" "/usr/lib/modules/$(uname -r)/System.map"; do
        [ -r "$f" ] || continue
        if grep -q -E ' (_stext|linux_banner)$' "$f"; then
            cat "$f" > "$OUT/memory/System.map"; smap=$f; break
        fi
        nosym=$f
    done
    if [ -n "$smap" ]; then
        say "  kernel banner, release and os-release kept in memory/, System.map from $smap"
    elif [ -n "$nosym" ]; then
        say "  kernel banner, release and os-release kept in memory/, no System.map kept: $nosym is a placeholder without symbols"
    else
        say "  kernel banner, release and os-release kept in memory/, no System.map found on this system"
    fi
    MEMJ="{\"status\": $(jstr "$mstatus"), \"file\": $(jstr "${MEMHASH:+memory/memory.lime}"), \"format\": $(jstr "${MEMHASH:+lime}"), \"bytes\": $mbytes, \"seconds\": $msecs, \"sha256\": $(jstr "$MEMHASH"), \"tool\": $(jstr "$avmlv"), \"system_map\": $(jstr "$smap"), \"note\": $(jstr "$mnote")}"
    say ""
fi

# ---- summary -----------------------------------------------------------------------------------
say "==== verdicts"
for m in "${MAPS[@]}"; do say "  $(printf '%-16s' "$(clean "$m")")  ${VERDICT[$m]:-unknown}"; done
[ "$MEMORY" = 1 ] && say "  $(printf '%-16s' "memory image")  $mstatus"
say ""
FINISHED=$(now)
say "finished $FINISHED"

# the same verdicts for a program. No key is in this file.
{
    printf '{\n  "schema": "keep-report/1",\n  "tool": "keytriage.sh %s",\n' "$(jesc "$VERSION")"
    printf '  "host": %s,\n  "kernel": %s,\n  "os": %s,\n' "$(jstr "$HOST")" "$(jstr "$(uname -r)")" "$(jstr "$OSNAME")"
    printf '  "cryptsetup": %s,\n  "other_filesystems": %s,\n' "$(jstr "$CSVER")" "$(jstr "$OTHERFS")"
    printf '  "started_utc": "%s",\n  "finished_utc": "%s",\n' "$STARTED" "$FINISHED"
    printf '  "lockdown": %s,\n  "secure_boot": %s,\n' "$(jstr "$LOCKDOWN")" "$(jstr "$SB")"
    printf '  "source": "/proc/kcore",\n  "evidence_medium": %s,\n' "$(jstr "$MEDIUM")"
    printf '  "memory": %s,\n  "binaries": [' "${MEMJ:-null}"
    sep=""; for j in "${JBIN[@]}"; do printf '%s\n    %s' "$sep" "$j"; sep=","; done
    printf '\n  ],\n  "volumes": ['
    sep=""; for j in "${JVOL[@]}"; do printf '%s\n    %s' "$sep" "$j"; sep=","; done
    printf '\n  ]\n}\n'
} > "$OUT/verdict.json"

# the manifest. The image was hashed once above, and that line is reused, so it is not read twice.
(
    cd "$OUT" || exit 1
    {
        find triage.txt verdict.json keys headers log memory -type f ! -name memory.lime -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null
        [ -n "$MEMHASH" ] && printf '%s  memory/memory.lime\n' "$MEMHASH"
    } | sort -k 2 > manifest.sha256
) || WRITEFAIL=1

# Everything of this run to the medium: the files that close it by fsync, which reports a failure,
# and then the whole file system of the medium by syncfs, which covers every file and directory.
flush "$REPORT" "$OUT/verdict.json" "$OUT/manifest.sha256" "$OUT"
sync -f "$OUT" || WRITEFAIL=1
if [ "$WRITEFAIL" = 0 ]; then
    printf 'keytriage.sh: every file of this run is flushed to the evidence medium\n'
else
    printf 'keytriage.sh: a write or a flush to the evidence medium FAILED, the folder is not complete\n' >&2
    exit 1
fi
