#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

if [[ ${EUID} -eq 0 ]]; then
  echo "Run this installer as the normal research user; it invokes sudo for fixed installation steps." >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SOURCE="$ROOT/scripts/install/cver-m2-helper"
DEST="/usr/local/libexec/cver-m2-helper"
SUDOERS="/etc/sudoers.d/cver-m2"
GROUP="cver-m2"

[[ -f "$SOURCE" ]] || { echo "Missing helper source: $SOURCE" >&2; exit 2; }
command -v visudo >/dev/null || { echo "visudo is required" >&2; exit 2; }

sudo groupadd --force "$GROUP"
sudo usermod -a -G "$GROUP" "$USER"
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 "$SOURCE" "$DEST"

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
cat >"$TMP" <<EOF
# CVER M2 fixed-function helper. The executable is root-owned and validates every subcommand.
%${GROUP} ALL=(root) NOPASSWD: ${DEST} *
EOF
sudo chown root:root "$TMP"
sudo chmod 0440 "$TMP"
sudo visudo -cf "$TMP"
sudo install -o root -g root -m 0440 "$TMP" "$SUDOERS"
sudo visudo -cf "$SUDOERS"

cat <<EOF
Installed:
  helper:  $DEST
  sudoers: $SUDOERS
  group:   $GROUP

Start a new login shell (or run: newgrp $GROUP) before using passwordless helper commands.
EOF
