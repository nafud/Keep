#!/bin/bash
# build-toolkit.sh OUTDIR : assemble the Keep tool medium on the workstation and write it as an ISO.
#
#   sudo apt install bash-static busybox-static xorriso gcc make musl-tools curl file
#   ./build-toolkit.sh /path/to/work      -> work/tools/ (the tree) and work/tools.iso
#
# The medium carries: bin/bash (bash-static), bin/busybox with one symlink per applet, bin/avml
# (Microsoft AVML, release binary pinned by SHA-256), bin/kcore-keyscan (the project scanner, built
# here statically), keytriage.sh, VERSIONS.txt and MANIFEST.sha256. keytriage.sh is started in
# the shell of the medium: bin/bash -p keytriage.sh. While the C program of Keep is built it
# rides along as c/keep, static against musl, so that the checks can run it beside
# keytriage.sh. The ISO is written with Rock Ridge so that symlinks and execute bits survive;
# attached to a guest it is read-only by nature.
# The download is kept under work/cache/.
#
# The suspect's own dmsetup and cryptsetup are used for route R1, so they are not on
# the medium. keytriage.sh records their paths and hashes for the archive check.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:?usage: build-toolkit.sh OUTDIR}
AVML_URL=https://github.com/microsoft/avml/releases/download/v0.21.0/avml
AVML_SHA=e75597dcdcaaa8475fdc61643effb050f72aaa9cff677c7271386a9781bf4460
T=$OUT/tools; C=$OUT/cache
rm -rf "${T:?}"; mkdir -p "$T/bin" "$C"

# fetch URL SHA FILE : download once, refuse anything whose hash differs
fetch() {
    if [ ! -f "$3" ] || ! echo "$2  $3" | sha256sum -c --quiet - 2>/dev/null; then curl -sS -L -o "$3" "$1"; fi
    echo "$2  $3" | sha256sum -c - || { echo "$3: hash mismatch, refusing"; exit 1; }
}
fetch "$AVML_URL" "$AVML_SHA" "$C/avml"

# the scanner, static, so it runs on the suspect without its libraries
gcc -static -O2 -Wall -o "$C/kcore-keyscan" "$HERE/kcore-keyscan.c"

cp /bin/bash-static "$T/bin/bash"
cp /bin/busybox "$T/bin/busybox"
for a in $(/bin/busybox --list); do
    case $a in bash|busybox|sh) continue;; esac
    ln -s busybox "$T/bin/$a"
done
ln -s busybox "$T/bin/sh"
cp "$C/avml" "$T/bin/avml"
cp "$C/kcore-keyscan" "$T/bin/kcore-keyscan"
chmod 755 "$T/bin/bash" "$T/bin/busybox" "$T/bin/avml" "$T/bin/kcore-keyscan"
cp "$HERE/keytriage.sh" "$T/"
chmod 755 "$T/keytriage.sh"

# the C program, which is to take the place of everything above
make -s -C "$HERE" keep
mkdir "$T/c"
cp "$HERE/keep" "$T/c/keep"
chmod 755 "$T/c/keep"

for b in bin/bash bin/busybox bin/avml bin/kcore-keyscan c/keep; do
    file "$T/$b" | grep -q 'statically linked\|static-pie linked' || { echo "$b is not static"; exit 1; }
done
{
    echo "tool medium built $(date -u +%FT%TZ) on $(hostname), $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo "bash:         $("$T/bin/bash" --version | head -1)  (package bash-static $(dpkg-query -W -f='${Version}' bash-static))"
    echo "busybox:      $("$T/bin/busybox" | head -1)  (package busybox-static $(dpkg-query -W -f='${Version}' busybox-static))"
    echo "avml:         $("$T/bin/avml" --version)  from $AVML_URL"
    echo "kcore-keyscan: built here with $(gcc --version | head -1) from kcore-keyscan.c"
    echo "c/keep:       $("$T/c/keep" -V), built here with $(musl-gcc --version | head -1) against musl $(dpkg-query -W -f='${Version}' musl-dev)"
    echo "keytriage.sh: $(grep -m1 '^VERSION=' "$HERE/keytriage.sh")"
    echo
    echo "linkage:"; file "$T/bin/bash" "$T/bin/busybox" "$T/bin/avml" "$T/bin/kcore-keyscan" "$T/c/keep" | sed 's/, BuildID[^,]*//'
} > "$T/VERSIONS.txt"
(cd "$T" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
xorriso -as mkisofs -quiet -volid KEEPTOOLS -rational-rock -joliet -o "$OUT/tools.iso" "$T" 2>/dev/null
sha256sum "$OUT/tools.iso" | tee "$OUT/tools.iso.sha256"
echo "tree: $T"; du -sh "$T" "$OUT/tools.iso"
