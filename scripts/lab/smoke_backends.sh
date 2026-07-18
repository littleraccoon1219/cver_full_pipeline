#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

BACKENDS=("$@")
if [[ ${#BACKENDS[@]} -eq 0 ]]; then
  BACKENDS=(docker kata firecracker)
fi

args=()
for backend in "${BACKENDS[@]}"; do
  args+=(--backend "$backend")
done
exec python -m cver sandbox-smoke "${args[@]}" --project-root .
