#!/usr/bin/env bash
# Install a versioned Kata Containers static package without registering it as the default runtime.
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
LOG_FILE="$LOG_DIR/install_kata-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
TMP_DIR="$(mktemp -d -t cver-kata.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

retry_curl() {
  curl --fail --location --silent --show-error \
    --retry 6 --retry-delay 3 --retry-all-errors \
    --connect-timeout 20 --max-time 1200 "$@"
}

github_api() {
  local url="$1"
  local headers=(-H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28')
  [[ -z "${GITHUB_TOKEN:-}" ]] || headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  retry_curl "${headers[@]}" "$url"
}

case "$(uname -m)" in
  aarch64|arm64) RELEASE_ARCH=arm64 ;;
  x86_64|amd64) RELEASE_ARCH=amd64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

for tool in curl jq sha256sum tar xz; do
  command -v "$tool" >/dev/null || { echo "$tool is required." >&2; exit 1; }
done

RELEASE_REF="${CVER_KATA_VERSION:-latest}"
if [[ "$RELEASE_REF" == latest ]]; then
  RELEASE_URL='https://api.github.com/repos/kata-containers/kata-containers/releases/latest'
else
  [[ "$RELEASE_REF" == *.* ]] || { echo 'CVER_KATA_VERSION must be a release version or latest.' >&2; exit 1; }
  [[ "$RELEASE_REF" == *-* || "$RELEASE_REF" == v* ]] || RELEASE_REF="${RELEASE_REF}"
  RELEASE_URL="https://api.github.com/repos/kata-containers/kata-containers/releases/tags/$RELEASE_REF"
fi
RELEASE_JSON="$(github_api "$RELEASE_URL")"
TAG="$(jq -r '.tag_name // empty' <<<"$RELEASE_JSON")"
[[ -n "$TAG" ]] || { echo 'Unable to resolve Kata Containers release.' >&2; exit 1; }
ASSET_NAME="$(jq -r --arg arch "$RELEASE_ARCH" '[.assets[].name | select(test("^kata-static-.*-" + $arch + "\\.tar\\.xz$"; "i"))][0] // empty' <<<"$RELEASE_JSON")"
[[ -n "$ASSET_NAME" ]] || { echo "Release $TAG has no static package for $RELEASE_ARCH." >&2; exit 1; }
ASSET_URL="$(jq -r --arg n "$ASSET_NAME" '.assets[] | select(.name==$n) | .browser_download_url' <<<"$RELEASE_JSON" | head -n1)"
DIGEST="$(jq -r --arg n "$ASSET_NAME" '.assets[] | select(.name==$n) | (.digest // empty)' <<<"$RELEASE_JSON" | head -n1)"
EXPECTED_SHA="${CVER_KATA_SHA256:-${DIGEST#sha256:}}"
if [[ -z "$EXPECTED_SHA" || "$EXPECTED_SHA" == "$DIGEST" ]]; then
  echo 'No publisher SHA-256 digest was available. Set CVER_KATA_SHA256 explicitly.' >&2
  exit 1
fi
[[ "$EXPECTED_SHA" =~ ^[0-9a-fA-F]{64}$ ]] || { echo 'Invalid Kata SHA-256 value.' >&2; exit 1; }

VERSION="${TAG#v}"
INSTALL_DIR="/opt/kata-$VERSION"
if [[ -x "$INSTALL_DIR/bin/kata-runtime" || -x "$INSTALL_DIR/bin/kata-ctl" ]]; then
  echo "Kata $VERSION is already installed at $INSTALL_DIR."
else
  ARCHIVE="$TMP_DIR/$ASSET_NAME"
  EXTRACT="$TMP_DIR/extract"
  mkdir -p "$EXTRACT"
  retry_curl -o "$ARCHIVE" "$ASSET_URL"
  echo "$EXPECTED_SHA  $ARCHIVE" | sha256sum -c -
  tar -xJf "$ARCHIVE" -C "$EXTRACT"
  SOURCE_DIR=''
  if [[ -d "$EXTRACT/opt/kata" ]]; then
    SOURCE_DIR="$EXTRACT/opt/kata"
  elif [[ -d "$EXTRACT/kata" ]]; then
    SOURCE_DIR="$EXTRACT/kata"
  fi
  [[ -n "$SOURCE_DIR" ]] || { echo 'The archive did not contain opt/kata or kata.' >&2; exit 1; }
  sudo rm -rf "$INSTALL_DIR.tmp"
  sudo mkdir -p "$INSTALL_DIR.tmp"
  sudo cp -a "$SOURCE_DIR/." "$INSTALL_DIR.tmp/"
  sudo mv "$INSTALL_DIR.tmp" "$INSTALL_DIR"
fi

if [[ -e /opt/kata && ! -L /opt/kata ]]; then
  BACKUP="/opt/kata.backup-$(date +%Y%m%d-%H%M%S)"
  sudo mv /opt/kata "$BACKUP"
  echo "Existing /opt/kata moved to $BACKUP"
fi
sudo ln -sfn "$INSTALL_DIR" /opt/kata
for name in kata-runtime kata-ctl kata-collect-data.sh \
  containerd-shim-kata-v2 containerd-shim-kata-qemu-v2 \
  containerd-shim-kata-clh-v2 containerd-shim-kata-fc-v2; do
  [[ -e "/opt/kata/bin/$name" ]] && sudo ln -sfn "/opt/kata/bin/$name" "/usr/local/bin/$name"
done
sudo tee /etc/profile.d/kata.sh >/dev/null <<'PROFILE'
export PATH="/opt/kata/bin:$PATH"
PROFILE
export PATH="/opt/kata/bin:$PATH"

if command -v kata-runtime >/dev/null 2>&1; then
  kata-runtime --version
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    sudo kata-runtime check || sudo kata-runtime kata-check || true
  else
    echo 'SKIPPED_WITH_REASON: Kata installed, but /dev/kvm is not readable and writable in this session.'
  fi
elif command -v kata-ctl >/dev/null 2>&1; then
  kata-ctl version
else
  echo 'Kata package extracted, but no kata-runtime or kata-ctl executable was found.' >&2
  exit 1
fi

echo 'Kata was not registered as the default containerd runtime.'
echo "Kata installation completed. Log: $LOG_FILE"
