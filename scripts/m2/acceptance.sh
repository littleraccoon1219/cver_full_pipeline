#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
PYTHON_BIN="${PYTHON_BIN:-python3}"

"$PYTHON_BIN" -m compileall -q cver/m2 tests/m2
"$PYTHON_BIN" -m pytest -q tests/m2
"$PYTHON_BIN" -m cver m2 benchmark
"$PYTHON_BIN" -m cver m2 harness build
"$PYTHON_BIN" -m cver m2 harness fuzz --seconds 2 --profile quick

if [[ "${CVER_M2_ACK_KATA_SMOKE:-}" == "yes" ]]; then
  "$PYTHON_BIN" -m cver m2 kata-smoke
else
  echo "Kata host smoke skipped; set CVER_M2_ACK_KATA_SMOKE=yes after installing the restricted helper."
fi
