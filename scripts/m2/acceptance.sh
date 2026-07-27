#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
PYTHON_BIN="${PYTHON_BIN:-python3}"

if "$PYTHON_BIN" -c 'import importlib.util; raise SystemExit(0 if importlib.util.find_spec("cver.__main__") else 1)' >/dev/null 2>&1; then
  CVER=("$PYTHON_BIN" -m cver m2)
else
  # The local-only M2 overlay package intentionally does not redistribute unchanged
  # repository files. Use the direct M2 module for overlay validation.
  CVER=("$PYTHON_BIN" -m cver.m2.cli --project-root .)
fi

"$PYTHON_BIN" -m compileall -q cver/m2 tests/m2
"$PYTHON_BIN" -m pytest -q tests/m2
"${CVER[@]}" benchmark
"${CVER[@]}" harness build
"${CVER[@]}" harness fuzz --seconds 2 --profile quick
"${CVER[@]}" real-fuzz toolchain

if [[ "${CVER_M2_ACK_KATA_SMOKE:-}" == "yes" ]]; then
  "${CVER[@]}" kata-smoke
else
  echo "Kata host smoke skipped; set CVER_M2_ACK_KATA_SMOKE=yes after installing the restricted helper."
fi
