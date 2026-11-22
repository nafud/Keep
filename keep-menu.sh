#!/bin/bash
# keep-menu.sh [-n] : the full-screen text front-end of Keep.
#
#   sudo /media/tools/bin/bash /media/tools/keep-menu.sh
#
# A boxed full-screen menu moved with the up and down arrow keys (or j and k), chosen with Enter,
# in the manner of ewfacquire. It collects the choices and then calls the script beside it that
# does the work, whose output is shown as it runs:
#   1  keytriage.sh -e DIR        capture the keys of the open volumes of this live system
#   2  keytriage.sh -e DIR -m     the same, and a memory image for Volatility 3
#   3  a memory dump that was collected earlier: offline-keyscan.sh where python3 and
#      vkverify.py are present (the workstation), otherwise the scan alone to a candidate list
#      (the tool medium carries no Python)
#
#   -n   dry run: show the command of each choice and do not run it.
#
# The menu runs from the tool medium in the static shell. It is drawn with ANSI escape sequences
# by bash itself, so it needs no dialog program and no terminfo database, and it works on a
# console and over SSH. Paths are typed and confirmed with Enter. Without a terminal it asks the
# same questions as plain numbered lines. It never shows a key.
set -u
umask 077                               # a candidate list holds key material
DRY=0
case ${1:-} in -n) DRY=1 ;; -h|--help) sed -n '2,20p' "$0"; exit 0 ;; esac
case $0 in */*) HERE=${0%/*} ;; *) HERE=. ;; esac   # no dirname: nothing external before PATH is set
HERE=$(cd "$HERE" && pwd)
PATH=$HERE/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin
export PATH LC_ALL=C
TRIAGE=$HERE/keytriage.sh
OFFLINE=$HERE/offline-keyscan.sh

ESC=$'\033'
TUI=0
[ -t 0 ] && [ -t 1 ] && [ "${TERM:-dumb}" != dumb ] && TUI=1
B=""; D=""; Z=""
[ "$TUI" = 1 ] && { B=$ESC'[1m'; D=$ESC'[2m'; Z=$ESC'[0m'; }

COLS=80; ROWS=24
size() {
    shopt -s checkwinsize; { true; } 2>/dev/null
    COLS=${COLUMNS:-80}; ROWS=${LINES:-24}
    [ "$COLS" -ge 54 ] 2>/dev/null || COLS=80
    [ "$ROWS" -ge 14 ] 2>/dev/null || ROWS=24
}
at()      { printf '%s[%d;%dH' "$ESC" "$1" "$2"; }
show_cur(){ [ "$TUI" = 1 ] && printf '%s[?25h' "$ESC"; return 0; }
hide_cur(){ [ "$TUI" = 1 ] && printf '%s[?25l' "$ESC"; return 0; }
restore() { [ "$TUI" = 1 ] && printf '%s[0m%s[?25h%s[?1049l' "$ESC" "$ESC" "$ESC"; return 0; }
trap restore EXIT
trap 'restore; exit 130' INT TERM
[ "$TUI" = 1 ] && printf '%s[?1049h' "$ESC"      # alternate screen

# one key into KEY: up, down, enter, or the literal character
getkey() {
    local k r
    IFS= read -rsn1 k 2>/dev/null || { KEY=eof; return; }
    if [ "$k" = "$ESC" ]; then
        IFS= read -rsn2 -t 0.1 r 2>/dev/null || r=""
        case $r in '[A'|'OA') KEY=up ;; '[B'|'OB') KEY=down ;; *) KEY=esc ;; esac
    elif [ -z "$k" ]; then KEY=enter
    else KEY=$k
    fi
}

# a centred box of width w at top row t, a bold title, then the lines given after w and title
LM=1; BOXBOT=1
box() {
    local t=$1 w=$2 title=$3; shift 3
    local i r=$t dashes; LM=$(( (COLS - w) / 2 )); [ "$LM" -ge 1 ] || LM=1
    dashes=$(printf '%*s' $((w - 2)) ''); dashes=${dashes// /-}
    printf '%s[2J' "$ESC"
    at "$r" "$LM"; printf '+%s+' "$dashes"; r=$((r + 1))
    at "$r" "$LM"; printf '|%*s%s%s%s%*s|' $(( (w - 2 - ${#title}) / 2 )) "" \
        "$B" "$title" "$Z" $(( (w - 1 - ${#title}) / 2 )) ""; r=$((r + 1))
    at "$r" "$LM"; printf '+%s+' "$dashes"; r=$((r + 1))
    for i in "$@"; do at "$r" "$LM"; printf '|%-*s|' $((w - 2)) " $i"; r=$((r + 1)); done
    [ $# -eq 0 ] || { at "$r" "$LM"; printf '+%s+' "$dashes"; r=$((r + 1)); }
    BOXBOT=$((r + 1))
}

ITEMS=("Inspect this live system and capture the keys"
       "Inspect this live system and also save a memory image"
       "Scan a memory dump collected earlier"
       "Quit")
draw_menu() {
    local i lines=()
    for i in "${!ITEMS[@]}"; do lines+=(" $((i + 1))  ${ITEMS[$i]}"); done
    size
    box 2 62 "Keep   decryption-readiness triage" "" "${lines[@]}" ""
    # the chosen entry again in reverse video: the first entry is on the fifth row of the box
    at $((6 + $1)) $((LM + 1)); printf '%s[7m%-*s%s[0m' "$ESC" 60 "  $(($1 + 1))  ${ITEMS[$1]}" "$ESC"
    at "$BOXBOT" "$LM"; printf '%sup/down to move, Enter to choose, q to quit%s' "$D" "$Z"
    [ "$DRY" = 1 ] && { at $((BOXBOT + 1)) "$LM"; printf '%sdry run: nothing is executed%s' "$D" "$Z"; }
    return 0
}

# pick from the menu, 1-based into SEL (4 = quit)
pick() {
    if [ "$TUI" != 1 ]; then
        local i
        printf '\n== Keep ==\n'
        for i in "${!ITEMS[@]}"; do printf '  %d  %s\n' $((i + 1)) "${ITEMS[$i]}"; done
        [ "$DRY" = 1 ] && printf '  (dry run)\n'
        printf 'Choose: '; read -r SEL || SEL=4
        case $SEL in 1|2|3) ;; q|Q) SEL=4 ;; *) SEL=0 ;; esac
        return
    fi
    local sel=0
    hide_cur
    while :; do
        draw_menu "$sel"
        getkey
        case $KEY in
            up|k)    sel=$(( (sel + ${#ITEMS[@]} - 1) % ${#ITEMS[@]} )) ;;
            down|j)  sel=$(( (sel + 1) % ${#ITEMS[@]} )) ;;
            1|2|3|4) SEL=$KEY; return ;;
            q|Q|esc) SEL=4; return ;;
            enter)   SEL=$((sel + 1)); return ;;
            eof)     SEL=4; return ;;
        esac
    done
}

# typed helpers, used inside a mode below the header box
nl() { printf '\n'; }
ask() { local p=$1 d=${2:-} a; show_cur
    if [ -n "$d" ]; then printf '%s [%s]: ' "$p" "$d"; else printf '%s: ' "$p"; fi
    read -r a || { a=""; nl; }; hide_cur; REPLY=${a:-$d}; }
yesno() { local a; ask "$1 (y/n)" "$2"; a=${REPLY,,}; [ "$a" = y ] || [ "$a" = yes ]; }
pause() { show_cur; printf '\n%sPress Enter to go on%s ' "$D" "$Z"; read -r _ || true; hide_cur; }
modehead() {
    if [ "$TUI" = 1 ]; then size; box 2 62 "Keep   $1"; at "$BOXBOT" 1
    else printf '\n== Keep: %s ==\n' "$1"; fi
}

run() {
    printf '\n%s$ %s%s\n\n' "$B" "$*" "$Z"
    if [ "$DRY" = 1 ]; then printf '%s(dry run, not executed)%s\n' "$D" "$Z"; return 0; fi
    show_cur; "$@"; local rc=$?; hide_cur; return "$rc"
}

evidence_dir() {
    local d=${KEEP_EVID:-/media/evidence}
    ask "Evidence directory to write the capture to" "$d"; EVID=$REPLY
    if [ ! -d "$EVID" ]; then yesno "  $EVID does not exist. Use it anyway" n || { evidence_dir; return; }; fi
    [ -w "$EVID" ] || printf '  %s is not writable (run the menu under sudo)\n' "$EVID"
    df -h "$EVID" 2>/dev/null | tail -1 | awk '{printf "  free on %s: %s\n", $6, $4}'
}

live() {
    modehead "live capture"
    printf 'Inspect this live system and capture the volume keys.\n'
    [ "$1" = 1 ] && printf 'A memory image is written as well, for Volatility 3.\n'
    nl
    [ -x "$TRIAGE" ] || { printf 'keytriage.sh is not beside this menu.\n'; pause; return; }
    [ "$(id -u)" = 0 ] || printf '%sNote: this needs root. Start the menu under sudo.%s\n\n' "$D" "$Z"
    evidence_dir
    local cmd=("$TRIAGE" -e "$EVID"); [ "$1" = 1 ] && cmd+=(-m)
    nl; yesno "Run the capture now" y || { printf 'cancelled.\n'; pause; return; }
    run "${cmd[@]}"; pause
}

offline() {
    modehead "a dump collected earlier"
    printf 'Scan a memory dump that was collected earlier and find the keys in it.\n\n'
    local have=0; command -v python3 >/dev/null && [ -r "$HERE/vkverify.py" ] && have=1
    ask "Path of the memory dump (raw or LiME)" ""; local dump=$REPLY
    [ -r "$dump" ] || { printf '  cannot read %s\n' "$dump"; pause; return; }
    if [ "$have" = 1 ] && [ -x "$OFFLINE" ]; then
        local imgs=()
        printf 'Disk image(s) to read the LUKS headers from. One per line, empty to end.\n'
        while :; do ask "  disk image" ""; [ -n "$REPLY" ] || break
            [ -r "$REPLY" ] && imgs+=("$REPLY") || printf '    cannot read %s\n' "$REPLY"; done
        [ ${#imgs[@]} -gt 0 ] || { printf '  no readable image given.\n'; pause; return; }
        nl; yesno "Scan and prove now" y || { printf 'cancelled.\n'; pause; return; }
        run "$OFFLINE" -k "$HERE" "$dump" "${imgs[@]}"
    else
        printf '\n%sThe proof needs python3 and vkverify.py, which are not here (the tool medium\n' "$D"
        printf 'carries no Python). This scans the dump to a candidate list for the lab.%s\n\n' "$Z"
        ask "Write the candidate list to" "candidates.txt"; local out=$REPLY
        yesno "Scan now" y || { printf 'cancelled.\n'; pause; return; }
        printf '\n%s$ %s %s > %s%s\n\n' "$B" "$HERE/bin/kcore-keyscan" "$dump" "$out" "$Z"
        if [ "$DRY" = 1 ]; then printf '%s(dry run, not executed)%s\n' "$D" "$Z"
        else show_cur; "$HERE/bin/kcore-keyscan" "$dump" > "$out"; hide_cur; fi
        printf '\nIn the lab: vkverify.py %s --image DISK\n' "$out"
    fi
    pause
}

while :; do
    pick
    case $SEL in
        1) live 0 ;;
        2) live 1 ;;
        3) offline ;;
        4) restore; printf '\n'; exit 0 ;;
        *) ;;
    esac
done
