#!/bin/bash
# offline-keyscan.sh [-k KIT] DUMP IMAGE... : scan a memory dump that was collected earlier and
# prove which keys in it are the volume keys of the LUKS volumes in a disk image.
#
#   offline-keyscan.sh memory.lime /evidence/laptop.dd
#   offline-keyscan.sh -k /media/tools dump.raw luks-part.img other-disk.dd
#
# The lab-side counterpart of keytriage.sh. keytriage.sh captures keys from a live machine;
# this reads a dump that already exists, for the case that the machine is gone. DUMP is a raw
# physical-memory dump or a LiME image (what AVML and keytriage.sh -m write). Each IMAGE is a
# whole-disk image, a partition image or a LUKS header backup; every LUKS header in it is located
# and its volume key proven from the dump. No header backup is needed, the header is read from
# the image. Nothing is written to the inputs.
#
# It needs kcore-keyscan (the static scanner, found with -k, $KEYSCAN or on PATH) and python3 for
# vkverify.py (next to this script). The dump scan is the only slow step.
#
# Output in scan_<dump>_<time>/ in the current directory: triage.txt (this screen), scan.txt (the
# scanner summary), verdict.json (schema keep-report/1) and manifest.sha256, none of which
# holds a key value, and keys/ (mode 700) with candidates.txt, the schedules found, and one
# NAME.vk per proven volume key for "cryptsetup open --volume-key-file". The viewer
# keep-gui.py reads verdict.json. Exit status 0 when every located header is proven, else 1.
set -u
umask 077
KIT=""
while getopts "k:h" opt; do
    case $opt in
        k) KIT=$OPTARG ;;
        *) sed -n '2,22p' "$0"; exit 0 ;;
    esac
done
shift $((OPTIND - 1))
die() { printf 'offline-keyscan.sh: %s\n' "$*" >&2; exit 1; }
[ $# -ge 2 ] || die "usage: offline-keyscan.sh [-k KIT] DUMP IMAGE... (IMAGE: disk image or header)"

HERE=$(cd "$(dirname "$0")" && pwd)
DUMP=$1; shift
[ -r "$DUMP" ] || die "cannot read the dump $DUMP"
for img in "$@"; do [ -r "$img" ] || die "cannot read the image $img"; done

# the scanner: -k KIT/bin, $KEYSCAN, next to this script, or on PATH
SCAN=""
for c in "${KIT:+$KIT/bin/kcore-keyscan}" "${KEYSCAN:-}" "$HERE/bin/kcore-keyscan" \
         "$HERE/kcore-keyscan" "$(command -v kcore-keyscan 2>/dev/null)"; do
    [ -n "$c" ] && [ -x "$c" ] && { SCAN=$c; break; }
done
[ -n "$SCAN" ] || die "kcore-keyscan not found (give -k KIT, set \$KEYSCAN, or put it on PATH)"
command -v python3 >/dev/null || die "python3 is needed for vkverify.py"
[ -r "$HERE/vkverify.py" ] || die "vkverify.py is not next to this script"

OUT=scan_$(printf '%s' "$(basename "$DUMP")" | tr -c 'A-Za-z0-9._-' _)_$(date -u +%Y%m%d_%H%M%S)
mkdir -p "$OUT/keys" || die "cannot create $OUT"
say() { printf '%s\n' "$*" | tee -a "$OUT/triage.txt"; }

say "offline-keyscan.sh, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "dump:    $DUMP ($(stat -c%s "$DUMP") bytes)"
for img in "$@"; do say "image:   $img ($(stat -c%s "$img") bytes)"; done
say "scanner: $SCAN"
say ""

# scan the dump for AES key schedules; the list goes to keys/, the summary to the screen
"$SCAN" "$DUMP" > "$OUT/keys/candidates.txt" 2> "$OUT/scan.txt"
rc=$?
tee -a "$OUT/triage.txt" < "$OUT/scan.txt"
[ $rc -eq 0 ] || die "the scan of $DUMP failed (see $OUT/scan.txt)"

# prove the candidates against every LUKS header located in the images
img_args=()
for img in "$@"; do img_args+=(--image "$img"); done
python3 -I "$HERE/vkverify.py" "$OUT/keys/candidates.txt" "${img_args[@]}" \
    --json "$OUT/verdict.json" --out "$OUT/keys" | tee -a "$OUT/triage.txt"
proof=${PIPESTATUS[0]}

say ""
if [ "$proof" -eq 0 ]; then
    say "RESULT: every LUKS header located in the images is proven"
else
    say "RESULT: not every header is proven, or no header was located (see above)"
fi
say "output in $OUT"

(
    cd "$OUT" || exit 1
    find triage.txt scan.txt verdict.json keys -type f -print0 | xargs -0 sha256sum | sort -k 2 > manifest.sha256
)
exit "$proof"
