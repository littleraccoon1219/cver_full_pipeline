#!/usr/bin/env bash
# Idempotent coordinator for the CVER research-lab component installers.
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [[ ${EUID} -eq 0 ]]; then
  echo 'Run as a normal user; component installers invoke sudo when needed.' >&2
  exit 2
fi

source /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo 'This coordinator currently supports Ubuntu.' >&2; exit 1; }
case "$(uname -m)" in
  aarch64|arm64|x86_64|amd64) ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

echo "OS=${PRETTY_NAME:-unknown}"
echo "ARCH=$(uname -m)"
echo "KERNEL=$(uname -r)"
echo "KVM_RW=$([[ -r /dev/kvm && -w /dev/kvm ]] && echo yes || echo no)"
echo "BTF=$([[ -r /sys/kernel/btf/vmlinux ]] && echo yes || echo no)"

run_if_enabled() {
  local flag="$1" script="$2"
  if [[ "$flag" != 1 ]]; then
    echo "SKIPPED_WITH_REASON: $script disabled by environment flag"
    return 0
  fi
  if [[ -x "$script" ]]; then
    echo "==> $script"
    "$script"
  elif [[ -f "$script" ]]; then
    echo "==> bash $script"
    bash "$script"
  else
    echo "SKIPPED_WITH_REASON: missing $script"
  fi
}

run_if_enabled "${CVER_INSTALL_SYFT:-1}" scripts/install/install_syft.sh
run_if_enabled "${CVER_INSTALL_TRACEE:-1}" scripts/install/install_tracee.sh
run_if_enabled "${CVER_INSTALL_FIRECRACKER:-1}" scripts/install/install_firecracker.sh
run_if_enabled "${CVER_INSTALL_KATA:-1}" scripts/install/install_kata.sh
run_if_enabled "${CVER_INSTALL_FIRECRACKER_ASSETS:-1}" scripts/install/install_firecracker_assets.sh

python -m cver discovery-init
python -m cver discovery-doctor --project-root .
