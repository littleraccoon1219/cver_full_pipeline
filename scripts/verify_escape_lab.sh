#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${CVER_DISPOSABLE_LAB_READY:-false}" != "true" ]]; then
  echo "Refusing: CVER_DISPOSABLE_LAB_READY=true is required."
  exit 2
fi
if [[ ! "${CVER_ESCAPE_APPROVAL_DIGEST:-}" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Refusing: CVER_ESCAPE_APPROVAL_DIGEST must be the approved immutable 64-hex experiment digest."
  exit 2
fi
if [[ "${CVER_AUTHORIZED_TARGETS:-}" == "" ]]; then
  echo "Refusing: CVER_AUTHORIZED_TARGETS must enumerate authorized lab targets."
  exit 2
fi

cat <<'EOF'
Lab guards validated. M1 intentionally contains no L3-L5 escape executor.
The M2/M3 executor must additionally verify snapshot identity, artifact digests,
authorized egress policy, resource limits, and approval expiry before execution.
EOF
