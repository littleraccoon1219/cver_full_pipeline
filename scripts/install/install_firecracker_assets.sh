#!/usr/bin/env bash
# Resolution order: existing env paths -> verified manifest download -> local build.
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASSET_ROOT="${CVER_FIRECRACKER_ASSET_DIR:-$HOME/cver-lab/firecracker-assets}"
MANIFEST="${CVER_FIRECRACKER_ASSET_MANIFEST:-$ROOT/scripts/install/firecracker_assets_manifest.yaml}"
MODE="${CVER_FIRECRACKER_ASSET_MODE:-auto}"  # auto|existing|download|build
mkdir -p "$ASSET_ROOT"

validate_existing() {
  [[ -n "${CVER_FIRECRACKER_KERNEL:-}" && -r "${CVER_FIRECRACKER_KERNEL}" ]] || return 1
  [[ -n "${CVER_FIRECRACKER_ROOTFS:-}" && -r "${CVER_FIRECRACKER_ROOTFS}" ]] || return 1
  echo "Using existing Firecracker assets:"
  echo "  kernel=$CVER_FIRECRACKER_KERNEL"
  echo "  rootfs=$CVER_FIRECRACKER_ROOTFS"
  return 0
}

download_verified() {
  command -v python3 >/dev/null || return 1
  local record
  record="$(python3 - "$MANIFEST" "$(uname -m)" <<'PY_ASSET'
import sys, yaml
manifest, arch = sys.argv[1:]
normalized = {'aarch64':'arm64','arm64':'arm64','x86_64':'amd64','amd64':'amd64'}.get(arch, arch)
with open(manifest, encoding='utf-8') as f:
    data = yaml.safe_load(f) or {}
for item in data.get('assets', []):
    if item.get('arch') == normalized:
        print('\t'.join([item['kernel_url'], item['kernel_sha256'], item['rootfs_url'], item['rootfs_sha256']]))
        break
PY_ASSET
)"
  [[ -n "$record" ]] || return 1
  IFS=$'\t' read -r kernel_url kernel_sha rootfs_url rootfs_sha <<<"$record"
  local kernel="$ASSET_ROOT/vmlinux" rootfs="$ASSET_ROOT/rootfs.ext4"
  curl --fail --location --retry 5 --retry-all-errors -o "$kernel.tmp" "$kernel_url"
  curl --fail --location --retry 5 --retry-all-errors -o "$rootfs.tmp" "$rootfs_url"
  echo "$kernel_sha  $kernel.tmp" | sha256sum -c -
  echo "$rootfs_sha  $rootfs.tmp" | sha256sum -c -
  mv "$kernel.tmp" "$kernel"
  mv "$rootfs.tmp" "$rootfs"
  printf 'export CVER_FIRECRACKER_KERNEL=%q\nexport CVER_FIRECRACKER_ROOTFS=%q\n' "$kernel" "$rootfs" > "$ASSET_ROOT/env.sh"
  echo "Verified Firecracker assets written to $ASSET_ROOT"
}

build_local() {
  local arch
  case "$(uname -m)" in
    aarch64|arm64) arch=arm64 ;;
    x86_64|amd64) arch=x86_64 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; return 1 ;;
  esac
  for tool in git make gcc bc bison flex cpio gzip mkfs.ext4; do
    command -v "$tool" >/dev/null || { echo "build mode requires $tool" >&2; return 1; }
  done
  local work="$ASSET_ROOT/build"
  mkdir -p "$work"
  local kernel_src="${CVER_LINUX_SOURCE:-$work/linux}"
  local busybox_src="${CVER_BUSYBOX_SOURCE:-$work/busybox}"
  if [[ ! -d "$kernel_src/.git" ]]; then
    git clone --depth 1 --branch "${CVER_LINUX_TAG:-v6.6}" https://github.com/torvalds/linux.git "$kernel_src"
  fi
  if [[ ! -d "$busybox_src/.git" ]]; then
    git clone --depth 1 --branch "${CVER_BUSYBOX_TAG:-1_36_1}" https://github.com/mirror/busybox.git "$busybox_src"
  fi

  if [[ "$arch" == arm64 ]]; then
    make -C "$kernel_src" ARCH=arm64 defconfig
    "$ROOT/scripts/install/patch_firecracker_kernel_config.sh" "$kernel_src/.config"
    make -C "$kernel_src" ARCH=arm64 olddefconfig
    make -C "$kernel_src" ARCH=arm64 -j"$(nproc)" Image
    install -m 0644 "$kernel_src/arch/arm64/boot/Image" "$ASSET_ROOT/vmlinux"
  else
    make -C "$kernel_src" defconfig
    "$ROOT/scripts/install/patch_firecracker_kernel_config.sh" "$kernel_src/.config"
    make -C "$kernel_src" olddefconfig
    make -C "$kernel_src" -j"$(nproc)" bzImage
    install -m 0644 "$kernel_src/arch/x86/boot/bzImage" "$ASSET_ROOT/vmlinux"
  fi

  make -C "$busybox_src" defconfig
  sed -i 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' "$busybox_src/.config"
  make -C "$busybox_src" -j"$(nproc)"
  local root="$work/rootfs"
  rm -rf "$root"
  mkdir -p "$root"/{bin,sbin,etc,proc,sys,dev,tmp}
  make -C "$busybox_src" CONFIG_PREFIX="$root" install
  cat > "$root/sbin/cver-smoke-init" <<'INIT_GUEST'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
echo CVER_FIRECRACKER_SMOKE_OK
poweroff -f
INIT_GUEST
  chmod 0755 "$root/sbin/cver-smoke-init"
  truncate -s 128M "$ASSET_ROOT/rootfs.ext4"
  mkfs.ext4 -F -d "$root" "$ASSET_ROOT/rootfs.ext4"
  printf 'export CVER_FIRECRACKER_KERNEL=%q\nexport CVER_FIRECRACKER_ROOTFS=%q\n' \
    "$ASSET_ROOT/vmlinux" "$ASSET_ROOT/rootfs.ext4" > "$ASSET_ROOT/env.sh"
  echo "Locally built Firecracker assets written to $ASSET_ROOT"
}

case "$MODE" in
  existing) validate_existing ;;
  download) download_verified ;;
  build) build_local ;;
  auto)
    validate_existing || download_verified || {
      echo "No verified download manifest entry; falling back to source build." >&2
      build_local
    }
    ;;
  *) echo "unknown CVER_FIRECRACKER_ASSET_MODE=$MODE" >&2; exit 2 ;;
esac
