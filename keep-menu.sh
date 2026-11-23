#!/bin/bash
# keep-menu.sh [-n] : the interactive front-end of Keep, in the manner of ewfacquire.
#
#   sudo /media/tools/keep                                    on the medium, through its launcher
#   sudo /media/tools/bin/bash -p /media/tools/keep-menu.sh   the same start, written out
#   bash -p keep-menu.sh                                      in the lab
#
# Keep finds the keys of encrypted volumes. This script asks for the parameters of one run as
# plain questions, one per line. A question shows its choices in parentheses and its default in
# square brackets, and Enter takes the default. A value that cannot be used is asked for again.
# The values are then listed, a confirmation is asked for, and the script beside this one that
# does the work is run, with its output shown as it runs. "no" at the confirmation starts the
# questions again. One run per start.
#
# The first question is where the keys are searched.
#
#   system   the open volumes of this running system: keytriage.sh -d DIR -b N. A further
#            question offers a memory dump of the system, taken after the keys, in LiME format
#            (-m) or compressed (-m -c).
#   dump     a memory dump that exists. Where python3 and vkverify.py are present (the lab)
#            offline-keyscan.sh scans it and proves the keys against disk images. Otherwise (the
#            tool medium carries no Python) the dump is scanned to
#            DIR/scan_<dump>_<time>/keys/candidates.txt for the lab.
#
# The destination directory is asked for and is by default the directory this script is started
# in. Where it lies is the examiner's decision and is not tested.
#
# The script that does the work is started in the shell that runs this one, with -p, and not
# through its "#!" line, which would name the bash of the examined system.
#
#   -n   dry run: ask, list the values and the command, and do not run it
#   -h   this text
#
# Nothing but lines of text is written and read: no escape sequence, no cursor movement, no
# terminfo and no line editor, so the dialogue works on a console, over SSH, on a serial line and
# through a pipe, and no configuration file of the examined system takes part in it. It never
# shows a key. Exit status: that of the script that was run, 0 after a dry run, 1 when the
# dialogue ended without a run, 2 for a wrong option.
# The environment of this shell belongs to the examined system. Under bash -p the shell takes no
# functions from it, does not run the file that BASH_ENV names and ignores SHELLOPTS, which could
# switch on a trace of every command, keys included. All of that happens before the first line
# of a script, so the script can only refuse to run without -p.
case $- in
    *p*) ;;
    *) printf '%s\n' "keep-menu.sh: start Keep on the medium with: sudo /media/tools/keep (it runs this script with bash -p), in the lab with: bash -p keep-menu.sh" >&2; exit 1 ;;
esac
set -u
umask 077                               # a candidate list holds key material
VERSION="3.1 (2026-11)"
ME=keep-menu.sh
case $0 in */*) HERE=${0%/*} ;; *) HERE=. ;; esac   # no dirname: nothing external before PATH is set
HERE=$(cd "$HERE" && pwd)
START=$(pwd -P)                         # the default destination: where the examiner stands
# On the medium PATH is its bin/ and nothing else, as in keytriage.sh. Without a medium beside
# this script it is the lab, where python3 and the scanner are the workstation's own.
SYSDIRS=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
if [ -x "$HERE/bin/busybox" ]; then
    PATH=$HERE/bin
    [ "$BASH" -ef "$HERE/bin/bash" ] || { printf '%s\n' "keep-menu.sh: on the medium this script runs in its shell, not in $BASH: $HERE/bin/bash -p $HERE/keep-menu.sh" >&2; exit 1; }
else
    PATH=$SYSDIRS
fi
export PATH LC_ALL=C TZ=UTC
TRIAGE=$HERE/keytriage.sh
OFFLINE=$HERE/offline-keyscan.sh
# the comment at the head of this file, read by the shell itself
usage() {
    local line
    while IFS= read -r line; do
        case $line in '#!'*) ;; '#'*) printf '%s\n' "$line" ;; *) break ;; esac
    done < "$0"
}
DRY=0
case ${1:-} in
    -n) DRY=1 ;;
    -h|--help) usage; exit 0 ;;
    '') ;;
    *) printf 'usage: %s [-n]\n' "$ME" >&2; exit 2 ;;
esac

AGAIN="try again or end with Ctrl+C."
fail() { printf '\n%s: %s\n%s: FAILURE\n' "$ME" "$*" "$ME" >&2; exit 1; }
now()  { printf '%(%Y-%m-%dT%H:%M:%SZ)T' -1; }
row()  { printf '%-28s%s\n' "$1:" "$2"; }           # one line of the list of values
irow() { printf '    %-24s%s\n' "$1:" "$2"; }       # one line of the system information

# one line of input into REPLY. An input that ends, ends the run, so a closed pipe cannot loop.
getline() {
    IFS= read -r REPLY || { printf '\n'; fail "the input ended before the parameters were complete"; }
}
ask() {  # ask PROMPT [DEFAULT]
    if [ -n "${2:-}" ]; then printf '%s [%s]: ' "$1" "$2"; else printf '%s: ' "$1"; fi
    getline
    [ -n "$REPLY" ] || REPLY=${2:-}
}
choose() {  # choose PROMPT "A B C" DEFAULT
    local c
    while :; do
        ask "$1 (${2// /, })" "$3"
        for c in $2; do [ "$REPLY" = "$c" ] && return 0; done
        printf 'Unsupported value, %s\n' "$AGAIN"
    done
}
ask_file() {  # ask_file PROMPT : a readable regular file, as an absolute path, into REPLY
    while :; do
        ask "$1"
        [ -n "$REPLY" ] && [ -f "$REPLY" ] && [ -r "$REPLY" ] && break
        printf 'Not a readable file, %s\n' "$AGAIN"
    done
    case $REPLY in /*) ;; *) REPLY=$PWD/$REPLY ;; esac
}
ask_dir() {  # ask_dir PROMPT DEFAULT : a directory that can be written to, absolute, into REPLY
    while :; do
        ask "$1" "$2"
        [ -d "$REPLY" ] || { printf '%s is not a directory, %s\n' "$REPLY" "$AGAIN"; continue; }
        [ "$DRY" = 1 ] || [ -w "$REPLY" ] || { printf '%s is not writable, %s\n' "$REPLY" "$AGAIN"; continue; }
        break
    done
    case $REPLY in /*) ;; *) REPLY=$PWD/$REPLY ;; esac
}
free_of() { df -k -P "$1" 2>/dev/null | awk 'NR==2 {printf "%d MiB free", $4 / 1024}'; }

# sysprog NAME : the full path of a program of the examined system, which is run by that path as
# keytriage.sh runs it
sysprog() {
    local d IFS=:
    for d in $SYSDIRS; do [ -f "$d/$1" ] && [ -x "$d/$1" ] && { printf '%s' "$d/$1"; return 0; }; done
    return 1
}

# what a live capture will meet. The files of the examined system are read as text only.
sysinfo() {
    local os="" f lock names=()
    for f in /etc/os-release /usr/lib/os-release; do
        [ -r "$f" ] && { os=$(sed -n 's/^PRETTY_NAME=//p' "$f" | head -n 1 | tr -d '"'); break; }
    done
    lock=$(sed 's/.*\[\(.*\)\].*/\1/' /sys/kernel/security/lockdown 2>/dev/null)
    printf '\nSystem information:\n'
    irow "Host" "$(hostname)"
    irow "System" "${os:-unknown}"
    irow "Kernel" "$(uname -r)"
    irow "Kernel lockdown" "${lock:-unknown}"
    irow "Memory" "$(awk '/^MemTotal:/ {printf "%d MiB", $2 / 1024}' /proc/meminfo)"
    local dmsetup; dmsetup=$(sysprog dmsetup)
    if [ "$(id -u)" = 0 ] && [ -n "$dmsetup" ]; then
        # a mapping is a line with a tab before the device number, as in keytriage.sh
        while IFS= read -r f; do
            case $f in *$'\t('*')') names+=("${f%$'\t('*}") ;; esac
        done < <("$dmsetup" ls --target crypt 2>/dev/null | sort)
        irow "Open dm-crypt volumes" "${#names[@]}${names[*]:+ (${names[*]})}"
    else
        irow "Open dm-crypt volumes" "not listed, that needs root and dmsetup"
    fi
    printf '\n'
}

# Each source asks its questions and leaves: ROWS (the values to list), KIND and CMD (what to
# run), WHAT (the word for the run) and AFTER (a closing line).
from_system() {
    local dest budget
    [ -r "$TRIAGE" ] || fail "keytriage.sh is not beside this script"
    [ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || fail "the keys of a running system need root, start this script under sudo"
    sysinfo
    ask_dir "Destination directory" "$START"; dest=$REPLY
    while :; do
        ask "Proof attempts per volume on the memory route" 64; budget=$REPLY
        case $budget in
            ''|*[!0-9]*|0*) printf 'A whole number from 1 is needed, %s\n' "$AGAIN" ;;
            *) break ;;
        esac
    done
    KIND=triage; WHAT=Triage; AFTER=""
    CMD=("$BASH" -p "$TRIAGE" -d "$dest" -b "$budget")
    ROWS+=("Destination directory|$dest ($(free_of "$dest"))" "Proof attempts per volume|$budget")
    choose "Collect a memory dump" "no lime compressed" no
    case $REPLY in
        lime)       CMD+=(-m)
                    ROWS+=("Memory dump|after the keys, AVML, LiME format, the size of the memory above") ;;
        compressed) CMD+=(-m -c)
                    ROWS+=("Memory dump|after the keys, AVML, compressed format, at most the size of the memory above") ;;
        *)          ROWS+=("Memory dump|no") ;;
    esac
    ROWS+=("Command|${CMD[*]}")
}

from_dump() {
    local dump name scanner="" c imgs=() i
    ask_file "Memory dump (raw, LiME, compressed AVML or ELF core)"; dump=$REPLY
    ROWS+=("Memory dump|$dump")
    if command -v python3 >/dev/null && [ -r "$HERE/vkverify.py" ] && [ -r "$OFFLINE" ]; then
        while :; do
            ask "Disk image or LUKS header backup (an empty line ends the list)"
            if [ -z "$REPLY" ]; then
                [ ${#imgs[@]} -gt 0 ] && break
                printf 'At least one image is needed, %s\n' "$AGAIN"; continue
            fi
            [ -f "$REPLY" ] && [ -r "$REPLY" ] || { printf 'Not a readable file, %s\n' "$AGAIN"; continue; }
            case $REPLY in /*) ;; *) REPLY=$PWD/$REPLY ;; esac
            imgs+=("$REPLY")
        done
        ask_dir "Destination directory" "$START"; OUTDIR=$REPLY
        KIND=offline; WHAT=Scan; AFTER=""
        CMD=("$BASH" -p "$OFFLINE" -k "$HERE" "$dump" "${imgs[@]}")
        for i in "${imgs[@]}"; do ROWS+=("Image|$i"); done
        ROWS+=("Destination directory|$OUTDIR ($(free_of "$OUTDIR"))" "Proof|against every LUKS header located in the images"
               "Command|${CMD[*]}")
    else
        for c in "$HERE/bin/kcore-keyscan" "$HERE/kcore-keyscan" "$(command -v kcore-keyscan 2>/dev/null)"; do
            [ -n "$c" ] && [ -x "$c" ] && { scanner=$c; break; }
        done
        [ -n "$scanner" ] || fail "kcore-keyscan was not found beside this script or on PATH"
        printf 'python3 or vkverify.py is not here, so the dump is scanned to a candidate list for the lab.\n'
        ask_dir "Destination directory" "$START"; OUTDIR=$REPLY
        name=${dump##*/}; name=${name//[!A-Za-z0-9._-]/_}
        SCANDIR=$OUTDIR/scan_${name}_$(printf '%(%Y%m%d_%H%M%S)T' -1)
        KIND=scan; WHAT=Scan
        CMD=("$scanner" "$dump")
        AFTER="In the lab: python3 -I vkverify.py $SCANDIR/keys/candidates.txt --image DISK"
        ROWS+=("Destination directory|$OUTDIR ($(free_of "$OUTDIR"))" "Proof|none here, the candidate list goes to the lab"
               "Command|${CMD[*]} > $SCANDIR/keys/candidates.txt")
    fi
}

run_cmd() {
    local rc
    case $KIND in
        triage)  "${CMD[@]}" ;;
        offline) ( cd "$OUTDIR" && "${CMD[@]}" ) ;;
        scan)    mkdir -p "$SCANDIR/keys" || return 1
                 "${CMD[@]}" > "$SCANDIR/keys/candidates.txt" 2> "$SCANDIR/scan.txt"; rc=$?
                 cat "$SCANDIR/scan.txt"
                 return "$rc" ;;
    esac
}

printf '%s %s\n\n' "$ME" "$VERSION"
[ "$DRY" = 1 ] && printf 'Dry run: the command is shown and not run.\n\n'
KIND=""; WHAT=""; AFTER=""; OUTDIR=""; SCANDIR=""; CMD=()
while :; do
    printf 'Parameters required, please provide the necessary input\n'
    choose "Search for keys in" "system dump" system
    case $REPLY in
        system) ROWS=("Search for keys in|this running system"); from_system ;;
        dump)   ROWS=("Search for keys in|a memory dump"); from_dump ;;
    esac
    printf '\nThe following parameters were provided:\n'
    for r in "${ROWS[@]}"; do row "${r%%|*}" "${r#*|}"; done
    printf '\n'
    choose "Continue with these values" "yes no" yes
    [ "$REPLY" = yes ] && break
    printf '\n'
done

printf '\n'
if [ "$DRY" = 1 ]; then
    printf '%s: dry run, nothing was run\n' "$ME"
    exit 0
fi
printf '%s started at: %s\n\n' "$WHAT" "$(now)"
run_cmd; rc=$?
printf '\n%s completed at: %s\n' "$WHAT" "$(now)"
[ -n "$AFTER" ] && printf '%s\n' "$AFTER"
if [ "$rc" -eq 0 ]; then
    printf '\n%s: SUCCESS\n' "$ME"
else
    printf '\n%s: FAILURE (exit status %d)\n' "$ME" "$rc"
fi
exit "$rc"
