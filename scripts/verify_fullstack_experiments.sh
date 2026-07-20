#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON_BIN="${PYTHON_BIN:-python3}"
"$PYTHON_BIN" -m cver.cli discovery-doctor --project-root .
"$PYTHON_BIN" -m cver.cli fullstack-capabilities

if [[ -n "${CVER_RUNC_TARGET:-}" ]]; then
  "$PYTHON_BIN" -m cver.cli historical-replay CVE-2024-21626 --target "$CVER_RUNC_TARGET" --project-root .
  "$PYTHON_BIN" -m cver.cli historical-replay CVE-2019-5736 --target "$CVER_RUNC_TARGET" --project-root .
else
  echo "CVER_RUNC_TARGET is unset; historical non-destructive runc replay skipped."
fi

cat <<'EOF'
M1 verifies platform foundations and capability adapters. Full active fuzzing,
unified Docker/Kata/Firecracker experiment execution, Aya observation, and
attack-chain validation are M2 acceptance items and are not reported as passed here.
EOF
