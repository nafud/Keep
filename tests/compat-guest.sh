#!/bin/bash
# compat-guest.sh [-m] [-k] WORKDIR NAME [IMAGE] : boot a distribution's cloud image as a
# throwaway guest in QEMU, run tests/compat-check.sh in it and print what it printed.
#
#   tests/compat-guest.sh -m work fedora-45
#   tests/compat-guest.sh -m work mine ~/Downloads/some-cloud-image.x86_64.qcow2
#
# This is the unattended form of the compatibility check, for the pipeline and for a workstation
# without libvirt. tests/make-compat-vm.sh starts a guest that stays, for work by hand.
#
# Without IMAGE, NAME is a name of tests/compat-images.txt. The image of that line is fetched
# from the distribution's site into WORKDIR/images/ unless it is there, and it is used only when
# its SHA-256 or SHA-512 equals the value of the line. With IMAGE, that file is taken: an x86-64
# cloud image (qcow2 or raw) which the caller has checked against its published checksum.
# The image is only read: the guest runs on a copy, WORKDIR/guest/NAME/disk.qcow2, grown to
# 20 GB. WORKDIR/tools.iso is the tool medium that build-toolkit.sh WORKDIR wrote, attached as a
# CD-ROM.
#
# The guest: 2 vCPU, 2 GiB (MEM=4096 raises it), BIOS boot, so kernel lockdown is "none". It runs
# under KVM where /dev/kvm can be opened and is emulated otherwise, which is slow but runs the
# same kernel. cloud-init makes the user "tester" with a key that is drawn for this run and sudo
# without a password, and installs cryptsetup, dosfstools and lvm2. The check is started over
# SSH through sudo, as an examiner would start it, on the port PORT of this machine (2222).
#
#   -m   compat-check.sh also takes the memory image and searches it
#   -k   keep the guest running afterwards and print how to log in
#
# Output: what compat-check.sh printed, also in WORKDIR/guest/NAME/compat.txt, and the serial
# console of the guest in console.log beside it. Exit status 0 when the check ended with
# "RESULT: PASS", 2 for a wrong option, else 1.
# Packages on this machine: qemu-system-x86, qemu-utils, xorriso, openssh-client and curl.
set -u
usage() {
    local line
    while IFS= read -r line; do
        case $line in '#!'*) ;; '#'*) printf '%s\n' "$line" ;; *) break ;; esac
    done < "$0"
}
MEMFLAG=""; KEEP=0
while getopts "mkh" opt; do
    case $opt in
        m) MEMFLAG=-m ;;
        k) KEEP=1 ;;
        h) usage; exit 0 ;;
        *) printf 'usage: compat-guest.sh [-m] [-k] WORKDIR NAME [IMAGE], -h prints the description\n' >&2; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
die() { printf 'compat-guest.sh: %s\n' "$*" >&2; exit 1; }
[ $# -eq 2 ] || [ $# -eq 3 ] || { printf 'usage: compat-guest.sh [-m] [-k] WORKDIR NAME [IMAGE], -h prints the description\n' >&2; exit 2; }
for c in qemu-system-x86_64 qemu-img xorriso ssh scp ssh-keygen; do
    command -v "$c" >/dev/null || die "$c is not installed"
done
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(realpath "$1") || die "no such directory: $1"
N=$2
case $N in *[!a-z0-9-]*|'') die "NAME: lower-case letters, digits and hyphens only" ;; esac
if [ $# -eq 3 ]; then
    IMG=$(realpath "$3") || die "no such image: $3"
    [ -f "$IMG" ] || die "no such image: $IMG"
else
    URL=""; SUM=""
    while read -r name url sum _; do
        [ "$name" = "$N" ] && { URL=$url; SUM=$sum; break; }
    done < "$HERE/compat-images.txt"
    [ -n "$URL" ] || die "$N is not a name of $HERE/compat-images.txt, and no IMAGE is given"
    case ${#SUM} in 64) HASH=sha256sum ;; 128) HASH=sha512sum ;; *) die "the value of $N in compat-images.txt is neither a SHA-256 nor a SHA-512" ;; esac
    mkdir -p "$W/images" || die "cannot create $W/images"
    IMG=$W/images/${URL##*/}
    if [ ! -f "$IMG" ]; then
        command -v curl >/dev/null || die "curl is not installed"
        echo "fetching $URL"
        curl -s -S -L --fail --retry 3 -o "$IMG.part" "$URL" || { rm -f "$IMG.part"; die "cannot fetch $URL (a build that the distribution has removed is replaced in compat-images.txt)"; }
        mv "$IMG.part" "$IMG"
    fi
    GOT=$("$HASH" < "$IMG"); GOT=${GOT%% *}
    [ "$GOT" = "$SUM" ] || die "$IMG has the $HASH $GOT, not the value of compat-images.txt, and is not used"
    echo "image ${URL##*/}: $HASH equals the pinned value"
fi
[ -f "$W/tools.iso" ] || die "no $W/tools.iso (build-toolkit.sh $W makes it)"
[ -f "$HERE/compat-check.sh" ] || die "compat-check.sh is not next to this script"
D=$W/guest/$N
[ ! -e "$D" ] || die "$D exists, remove it first"
mkdir -p "$D" || die "cannot create $D"
PORT=${PORT:-2222}

qemu-img convert -O qcow2 "$IMG" "$D/disk.qcow2" || die "cannot copy the image"
qemu-img resize -q "$D/disk.qcow2" 20G || die "cannot grow the copy"
ssh-keygen -q -t ed25519 -N '' -C "compat-guest $N" -f "$D/key" || die "cannot draw a key"

# the NoCloud seed of cloud-init: a medium labelled "cidata" with user-data and meta-data
cat > "$D/user-data" <<EOT
#cloud-config
users:
  - name: tester
    shell: /bin/bash
    lock_passwd: true
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - $(cat "$D/key.pub")
package_update: true
packages:
  - cryptsetup
  - dosfstools
  - lvm2
EOT
printf 'instance-id: kc-%s\nlocal-hostname: kc-%s\n' "$N" "$N" > "$D/meta-data"
xorriso -as mkisofs -quiet -volid cidata -joliet -rational-rock -o "$D/seed.iso" "$D/user-data" "$D/meta-data" 2>/dev/null \
    || die "cannot write the seed medium"

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL=(-accel kvm -cpu host); HOW="KVM"; BOOTWAIT=600
else
    ACCEL=(-accel "tcg,thread=multi" -cpu max); HOW="emulation, no /dev/kvm"; BOOTWAIT=2400
fi
qemu-system-x86_64 "${ACCEL[@]}" -m "${MEM:-2048}" -smp 2 -display none \
    -serial "file:$D/console.log" -pidfile "$D/qemu.pid" -daemonize \
    -device virtio-rng-pci \
    -drive "file=$D/disk.qcow2,if=virtio,format=qcow2" \
    -drive "file=$D/seed.iso,media=cdrom,readonly=on,format=raw" \
    -drive "file=$W/tools.iso,media=cdrom,readonly=on,format=raw" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$PORT-:22" \
    || die "QEMU did not start"
PID=$(cat "$D/qemu.pid")
stop() {
    [ "$KEEP" = 1 ] && return
    kill -0 "$PID" 2>/dev/null && kill "$PID" 2>/dev/null
}
trap stop EXIT
echo "guest kc-$N: $(qemu-system-x86_64 --version | head -n 1), $HOW, ${MEM:-2048} MiB"

SSH=(-i "$D/key" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
     -o BatchMode=yes -o ConnectTimeout=10)
guest() { ssh "${SSH[@]}" -p "$PORT" tester@127.0.0.1 "$@"; }
t0=$SECONDS
until guest true 2>/dev/null; do
    kill -0 "$PID" 2>/dev/null || die "QEMU ended before the guest answered (see $D/console.log)"
    [ $((SECONDS - t0)) -lt "$BOOTWAIT" ] || die "no SSH answer from the guest within $BOOTWAIT s (see $D/console.log)"
    sleep 5
done
echo "guest kc-$N: SSH answers after $((SECONDS - t0)) s"
# the packages are installed by cloud-init after SSH is up
guest 'sudo cloud-init status --wait' > "$D/cloud-init.txt" 2>&1
echo "guest kc-$N: cloud-init $(tr -s '.\n' ' ' < "$D/cloud-init.txt" | sed 's/^ *//') after $((SECONDS - t0)) s"

scp "${SSH[@]}" -q -P "$PORT" "$HERE/compat-check.sh" tester@127.0.0.1:compat-check.sh || die "cannot copy compat-check.sh into the guest"
guest "sudo mkdir -p /media/tools && sudo mount -o ro,exec /dev/disk/by-label/KEEPTOOLS /media/tools" \
    || die "the guest cannot mount the tool medium"
guest "sudo bash compat-check.sh $MEMFLAG /media/tools" 2>&1 | tee "$D/compat.txt"

if [ "$KEEP" = 1 ]; then
    echo "guest kc-$N keeps running, process $PID. Log in: ssh -i $D/key -p $PORT tester@127.0.0.1"
else
    guest 'sudo poweroff' 2>/dev/null
    for _ in $(seq 60); do kill -0 "$PID" 2>/dev/null || break; sleep 1; done
fi
grep -q '^RESULT: PASS$' "$D/compat.txt"
