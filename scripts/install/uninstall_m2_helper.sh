#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -eq 0 ]]; then
  echo "Run as the normal user; this script invokes sudo." >&2
  exit 2
fi

sudo rm -f /etc/sudoers.d/cver-m2
sudo rm -f /usr/local/libexec/cver-m2-helper
cat <<'EOF'
Removed the CVER M2 helper and sudoers rule.
The cver-m2 group, evidence, backups, and Kata configuration are intentionally preserved.
EOF
