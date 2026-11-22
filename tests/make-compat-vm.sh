#!/bin/bash
# make-compat-vm.sh WORKDIR NAME IMAGE : start a throwaway guest from a distribution's cloud image,
# for the compatibility check of Keep (tests/compat-check.sh).
#
#   tests/make-compat-vm.sh work fedora ~/Downloads/Fedora-Cloud-Base-Generic.x86_64.qcow2
#
# IMAGE is the x86-64 cloud image (qcow2 or raw) that the distribution publishes, downloaded by
# the user from the distribution's own site and checked against its published checksum. The image
# is not changed: the guest runs on a copy, WORKDIR/compat/NAME/disk.qcow2, grown to 20 GB.
# The guest kc-NAME: 2 vCPU, 4 GiB (MEM=2048 lowers it), BIOS boot, so kernel lockdown is "none".
# cloud-init makes the user "tester" with the key WORKDIR/tester_key.pub and sudo without a
# password, and installs the package cryptsetup. The tool medium WORKDIR/tools.iso is attached as
# a CD-ROM. Packages on the host: qemu-utils, libvirt-daemon-system, virtinst and xorriso.
#
#   address:   virsh domifaddr kc-NAME          log in: ssh -i WORKDIR/tester_key tester@ADDRESS
#   remove:    virsh destroy kc-NAME; virsh undefine kc-NAME; rm -r WORKDIR/compat/NAME
set -eu
W=$(realpath "${1:?usage: make-compat-vm.sh WORKDIR NAME IMAGE}")
N=${2:?usage: make-compat-vm.sh WORKDIR NAME IMAGE}
IMG=$(realpath "${3:?usage: make-compat-vm.sh WORKDIR NAME IMAGE}")
case $N in *[!a-z0-9-]*|'') echo "NAME: lower-case letters, digits and hyphens only" >&2; exit 1 ;; esac
[ -f "$IMG" ] || { echo "no such image: $IMG" >&2; exit 1; }
[ -f "$W/tester_key.pub" ] || { echo "no $W/tester_key.pub (generate it first with ssh-keygen)" >&2; exit 1; }
[ -f "$W/tools.iso" ] || { echo "no $W/tools.iso (build-toolkit.sh $W makes it)" >&2; exit 1; }
D=$W/compat/$N
[ ! -e "$D" ] || { echo "$D exists; remove the old guest first (see the head of this script)" >&2; exit 1; }
mkdir -p "$D"

qemu-img convert -O qcow2 "$IMG" "$D/disk.qcow2"
qemu-img resize -q "$D/disk.qcow2" 20G

# the NoCloud seed of cloud-init: a medium labelled "cidata" with user-data and meta-data
cat > "$D/user-data" <<EOT
#cloud-config
users:
  - name: tester
    shell: /bin/bash
    lock_passwd: true
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    ssh_authorized_keys:
      - $(cat "$W/tester_key.pub")
packages:
  - cryptsetup
EOT
printf 'instance-id: kc-%s\nlocal-hostname: kc-%s\n' "$N" "$N" > "$D/meta-data"
xorriso -as mkisofs -quiet -volid cidata -joliet -rational-rock -o "$D/seed.iso" "$D/user-data" "$D/meta-data" 2>/dev/null

virt-install --name "kc-$N" --memory "${MEM:-4096}" --vcpus 2 --osinfo detect=on,require=off --import \
    --disk "path=$D/disk.qcow2,format=qcow2,bus=virtio" \
    --disk "path=$D/seed.iso,device=cdrom,readonly=on" \
    --disk "path=$W/tools.iso,device=cdrom,readonly=on" \
    "--network=network=default,model=virtio" --graphics spice --video virtio --noautoconsole
echo "guest kc-$N started. cloud-init needs a minute or two for the user and the package."
echo "address: virsh domifaddr kc-$N     log in: ssh -i $W/tester_key tester@ADDRESS"
