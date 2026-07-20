#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[1/5] Compile Python sources"
"$PYTHON_BIN" -m compileall -q cver

echo "[2/5] Initialize/migrate discovery runtime database"
"$PYTHON_BIN" -m cver.cli discovery-init

echo "[3/5] Validate fixed RC1-RC5 and SP1-SP13 taxonomies"
"$PYTHON_BIN" -m cver.cli taxonomy-report >/dev/null

echo "[4/5] Run unit/integration tests"
"$PYTHON_BIN" -m pytest -q

echo "[5/5] Optional Ruff checks"
if "$PYTHON_BIN" -c 'import ruff' >/dev/null 2>&1; then
  "$PYTHON_BIN" -m ruff check cver tests
else
  echo "ruff not installed; skipped"
fi

echo "verify_basic: PASS"
