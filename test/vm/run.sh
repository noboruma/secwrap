#!/bin/bash
# Runs the end-to-end tests (tests.sh) as root inside a throwaway QEMU VM,
# without root on the host.
#
# The VM boots the host's kernel (or $KERNEL) with systemd as PID 1. The
# host's / is shared read-only and sits under a tmpfs overlay, so the VM
# sees the host's programs and kernel modules but cannot change anything
# on the host. QEMU reads host files as the invoking user, so root in the
# VM can only read what that user can. The one writable share is a temp
# directory holding the secwrap binary, the tests and their results.
#
# Needs: qemu-system-x86_64, busybox, cpio, xz, go; /dev/kvm (else slow TCG).
# Usage: test/vm/run.sh [secwrap binary]   (default: builds one)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
kver=${KVER:-$(uname -r)}
kernel=${KERNEL:-/boot/vmlinuz-$kver}
moddir=/lib/modules/$kver
timeout=${VMTEST_TIMEOUT:-300}

[ "$(uname -m)" = x86_64 ] || { echo "vmtest: only x86_64 hosts are supported" >&2; exit 2; }
for t in qemu-system-x86_64 busybox cpio xz; do
	command -v $t >/dev/null || { echo "vmtest: $t not found" >&2; exit 2; }
done
[ -r "$kernel" ] || { echo "vmtest: cannot read kernel $kernel (set KERNEL=)" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/secwrap-vmtest.XXXXXX")
trap 'rm -rf "$work"' EXIT
share=$work/share initrd=$work/initrd
mkdir -p "$share" "$initrd"/{bin,mods,proc,sys,dev,lower,upper,newroot}

if [ $# -gt 0 ]; then
	cp "$1" "$share/secwrap"
else
	(cd "$repo" && go build -trimpath -o "$share/secwrap" ./cmd/secwrap)
fi
cp "$here/tests.sh" "$share/tests.sh"

# initramfs: busybox (with its libraries), the modules to mount the shares,
# and init.
cp /usr/bin/busybox "$initrd/bin/"
for lib in $(ldd /usr/bin/busybox 2>/dev/null | grep -o '/[^ ]*'); do
	mkdir -p "$initrd$(dirname "$lib")" && cp -L "$lib" "$initrd$lib"
done
for m in fs/netfs/netfs net/9p/9pnet net/9p/9pnet_virtio fs/9p/9p fs/overlayfs/overlay; do
	src=$moddir/kernel/$m.ko
	if [ -e "$src.xz" ]; then xz -dc "$src.xz" >"$initrd/mods/${m##*/}.ko"
	elif [ -e "$src" ]; then cp "$src" "$initrd/mods/"
	fi # else built in
done
cp "$here/init" "$initrd/init"
chmod +x "$initrd/init"
(cd "$initrd" && find . | cpio -o -H newc 2>/dev/null | gzip) >"$work/initrd.gz"

accel=(-accel tcg)
[ -w /dev/kvm ] && accel=(-enable-kvm -cpu host)

echo "vmtest: booting $kernel" >&2
timeout "$timeout" qemu-system-x86_64 "${accel[@]}" -m 2G -smp 2 \
	-nodefaults -nographic -serial stdio -no-reboot \
	-kernel "$kernel" -initrd "$work/initrd.gz" \
	-append "console=ttyS0 rdinit=/init panic=-1 systemd.unit=secwrap-vmtest.service systemd.show_status=0 quiet" \
	-fsdev local,id=root,path=/,security_model=none,readonly=on \
	-device virtio-9p-pci,fsdev=root,mount_tag=hostroot \
	-fsdev local,id=share,path="$share",security_model=none \
	-device virtio-9p-pci,fsdev=share,mount_tag=share \
	>"$work/console.log" 2>&1 || true

if [ ! -f "$share/status" ]; then
	echo "vmtest: the tests did not finish; VM console:" >&2
	tail -n 40 "$work/console.log" >&2
	exit 1
fi
cat "$share/result.txt"
exit "$(cat "$share/status")"
