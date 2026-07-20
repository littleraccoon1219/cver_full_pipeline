#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ "${CVER_ACK_PRIVILEGED_SMOKE:-}" != "yes" ]]; then
  echo "Set CVER_ACK_PRIVILEGED_SMOKE=yes after reviewing the non-destructive sandbox commands."
  exit 2
fi

"$PYTHON_BIN" -m cver.cli fullstack-capabilities
"$PYTHON_BIN" -m cver.cli sandbox-smoke --backend docker --backend kata --backend firecracker

echo "verify_sandbox: completed; unavailable backends must report SKIPPED_WITH_REASON"
