#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

IMAGE="${CVER_KATA_IMAGE:-docker.io/library/alpine:3.20}"
command -v ctr >/dev/null || { echo "ctr not found" >&2; exit 1; }

if ctr images ls -q | grep -Fxq "$IMAGE"; then
  echo "Kata smoke image already present: $IMAGE"
  exit 0
fi

echo "Pulling $IMAGE into containerd"
if [[ ${EUID} -eq 0 ]]; then
  ctr images pull "$IMAGE"
else
  sudo ctr images pull "$IMAGE"
fi
