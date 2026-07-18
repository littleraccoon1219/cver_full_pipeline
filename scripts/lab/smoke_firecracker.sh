#!/usr/bin/env bash
# Fixed, non-destructive Firecracker boot smoke test.
# The test succeeds when the guest emits CVER_FIRECRACKER_SMOKE_OK on serial.
set -Eeuo pipefail
IFS=$'\n\t'

[[ $# -eq 2 ]] || { echo "usage: $0 KERNEL ROOTFS" >&2; exit 2; }
KERNEL="$(readlink -f "$1")"
ROOTFS="$(readlink -f "$2")"
[[ -r "$KERNEL" ]] || { echo "kernel not readable: $KERNEL" >&2; exit 2; }
[[ -r "$ROOTFS" ]] || { echo "rootfs not readable: $ROOTFS" >&2; exit 2; }
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo "/dev/kvm is not read/write" >&2; exit 2; }
command -v firecracker >/dev/null || { echo "firecracker not found" >&2; exit 2; }
command -v timeout >/dev/null || { echo "timeout not found" >&2; exit 2; }

TMP="$(mktemp -d -t cver-firecracker-smoke.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
ROOTFS_COPY="$TMP/rootfs.ext4"
cp --reflink=auto "$ROOTFS" "$ROOTFS_COPY"
CONFIG="$TMP/config.json"
LOG="$TMP/serial.log"

cat > "$CONFIG" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$KERNEL",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw init=/sbin/cver-smoke-init"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "$ROOTFS_COPY",
      "is_root_device": true,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 128,
    "smt": false
  }
}
EOF

set +e
timeout --signal=TERM 45s firecracker --no-api --config-file "$CONFIG" >"$LOG" 2>&1
rc=$?
set -e
cat "$LOG"
if grep -Fq CVER_FIRECRACKER_SMOKE_OK "$LOG"; then
  exit 0
fi
echo "Firecracker guest did not emit CVER_FIRECRACKER_SMOKE_OK (exit=$rc)." >&2
echo "Provision a CVER-compatible rootfs using scripts/install/install_firecracker_assets.sh." >&2
exit 1
