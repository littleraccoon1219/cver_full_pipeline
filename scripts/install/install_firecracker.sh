#!/usr/bin/env bash
# Install versioned Firecracker and jailer binaries from an official GitHub release.
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

if [[ ${EUID} -eq 0 ]]; then
  echo 'Run as a normal user; this script invokes sudo only for installation.' >&2
  exit 2
fi

CVER_LAB_ROOT="${CVER_LAB_ROOT:-$HOME/cver-lab}"
LOG_DIR="$CVER_LAB_ROOT/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/install_firecracker-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
TMP_DIR="$(mktemp -d -t cver-firecracker.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

retry_curl() {
  curl --fail --location --silent --show-error \
    --retry 6 --retry-delay 3 --retry-all-errors \
    --connect-timeout 20 --max-time 900 "$@"
}

github_api() {
  local url="$1"
  local headers=(-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
  [[ -z "${GITHUB_TOKEN:-}" ]] || headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  retry_curl "${headers[@]}" "$url"
}

case "$(uname -m)" in
  aarch64|arm64) RELEASE_ARCH=aarch64 ;;
  x86_64|amd64) RELEASE_ARCH=x86_64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 1; }
command -v jq >/dev/null || { echo 'jq is required.' >&2; exit 1; }
command -v sha256sum >/dev/null || { echo 'sha256sum is required.' >&2; exit 1; }

RELEASE_REF="${CVER_FIRECRACKER_VERSION:-latest}"
if [[ "$RELEASE_REF" == latest ]]; then
  RELEASE_URL='https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest'
else
  [[ "$RELEASE_REF" == v* ]] || RELEASE_REF="v$RELEASE_REF"
  RELEASE_URL="https://api.github.com/repos/firecracker-microvm/firecracker/releases/tags/$RELEASE_REF"
fi
RELEASE_JSON="$(github_api "$RELEASE_URL")"
TAG="$(jq -r '.tag_name // empty' <<<"$RELEASE_JSON")"
[[ -n "$TAG" ]] || { echo 'Unable to resolve Firecracker release.' >&2; exit 1; }
ASSET="firecracker-${TAG}-${RELEASE_ARCH}.tgz"
ASSET_URL="$(jq -r --arg n "$ASSET" '.assets[] | select(.name==$n) | .browser_download_url' <<<"$RELEASE_JSON" | head -n1)"
DIGEST="$(jq -r --arg n "$ASSET" '.assets[] | select(.name==$n) | (.digest // empty)' <<<"$RELEASE_JSON" | head -n1)"
[[ -n "$ASSET_URL" ]] || { echo "Release $TAG has no $ASSET asset." >&2; exit 1; }

EXPECTED_SHA="${CVER_FIRECRACKER_SHA256:-${DIGEST#sha256:}}"
if [[ -z "$EXPECTED_SHA" || "$EXPECTED_SHA" == "$DIGEST" ]]; then
  echo 'No publisher SHA-256 digest was available. Set CVER_FIRECRACKER_SHA256 explicitly.' >&2
  exit 1
fi
[[ "$EXPECTED_SHA" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'Invalid Firecracker SHA-256 value.' >&2; exit 1; }

VERSION="${TAG#v}"
INSTALL_DIR="/opt/firecracker/$VERSION"
if [[ -x "$INSTALL_DIR/firecracker" && -x "$INSTALL_DIR/jailer" ]]; then
  echo "Firecracker $VERSION is already installed at $INSTALL_DIR."
else
  ARCHIVE="$TMP_DIR/$ASSET"
  EXTRACT="$TMP_DIR/extract"
  mkdir -p "$EXTRACT"
  retry_curl -o "$ARCHIVE" "$ASSET_URL"
  echo "$EXPECTED_SHA  $ARCHIVE" | sha256sum -c -
  tar -xzf "$ARCHIVE" -C "$EXTRACT"
  FIRECRACKER_BIN="$(find "$EXTRACT" -type f -name "firecracker-${TAG}-${RELEASE_ARCH}" -print -quit)"
  JAILER_BIN="$(find "$EXTRACT" -type f -name "jailer-${TAG}-${RELEASE_ARCH}" -print -quit)"
  [[ -n "$FIRECRACKER_BIN" && -n "$JAILER_BIN" ]] || { echo 'Expected Firecracker binaries were not found in the archive.' >&2; exit 1; }
  sudo install -d -m 0755 "$INSTALL_DIR"
  sudo install -m 0755 "$FIRECRACKER_BIN" "$INSTALL_DIR/firecracker"
  sudo install -m 0755 "$JAILER_BIN" "$INSTALL_DIR/jailer"
fi
sudo ln -sfn "$INSTALL_DIR/firecracker" /usr/local/bin/firecracker
sudo ln -sfn "$INSTALL_DIR/jailer" /usr/local/bin/jailer
firecracker --version
jailer --version
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  echo 'SKIPPED_WITH_REASON: Firecracker installed, but /dev/kvm is not readable and writable in this session.'
fi
echo "Firecracker installation completed. Log: $LOG_FILE"
