#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

if [[ ${EUID} -eq 0 ]]; then
  echo '请以普通用户运行；脚本会自行调用 sudo。' >&2
  exit 2
fi

CVER_LAB_ROOT="${CVER_LAB_ROOT:-$HOME/cver-lab}"
LOG_DIR="$CVER_LAB_ROOT/logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/install_syft-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
TMP_DIR="$(mktemp -d -t cver-syft.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

retry_curl() {
  curl --fail --location --silent --show-error \
    --retry 6 --retry-delay 3 --retry-all-errors \
    --connect-timeout 20 --max-time 600 "$@"
}

github_api() {
  local url="$1"
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    retry_curl -H 'Accept: application/vnd.github+json' \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H 'X-GitHub-Api-Version: 2022-11-28' "$url"
  else
    retry_curl -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' "$url"
  fi
}

sudo -v
sudo apt-get update
sudo apt-get install -y ca-certificates curl jq tar gzip

case "$(uname -m)" in
  aarch64|arm64) ARCH=arm64 ;;
  x86_64|amd64) ARCH=amd64 ;;
  *) echo "不支持的架构：$(uname -m)" >&2; exit 1 ;;
esac

RELEASE_JSON="$(github_api https://api.github.com/repos/anchore/syft/releases/latest)"
TAG="$(jq -r '.tag_name // empty' <<<"$RELEASE_JSON")"
VERSION="${TAG#v}"
[[ -n "$VERSION" ]] || { echo '无法解析 Syft 最新版本。' >&2; exit 1; }

ASSET="syft_${VERSION}_linux_${ARCH}.tar.gz"
CHECKSUMS="syft_${VERSION}_checksums.txt"
ASSET_URL="$(jq -r --arg n "$ASSET" '.assets[]|select(.name==$n)|.browser_download_url' <<<"$RELEASE_JSON" | head -n1)"
CHECKSUM_URL="$(jq -r --arg n "$CHECKSUMS" '.assets[]|select(.name==$n)|.browser_download_url' <<<"$RELEASE_JSON" | head -n1)"

if [[ -z "$ASSET_URL" ]]; then
  echo "未找到 $ASSET。可用资产：" >&2
  jq -r '.assets[].name' <<<"$RELEASE_JSON" >&2
  exit 1
fi

ARCHIVE="$TMP_DIR/$ASSET"
echo "下载 $ASSET"
retry_curl -o "$ARCHIVE" "$ASSET_URL"

if [[ -n "$CHECKSUM_URL" ]]; then
  retry_curl -o "$TMP_DIR/$CHECKSUMS" "$CHECKSUM_URL"
  EXPECTED="$(awk -v n="$ASSET" '$2==n || $2=="*"n {print $1; exit}' "$TMP_DIR/$CHECKSUMS")"
  [[ -n "$EXPECTED" ]] || { echo '校验文件中找不到目标资产。' >&2; exit 1; }
  echo "$EXPECTED  $ARCHIVE" | sha256sum -c -
else
  echo '警告：未找到 checksums 文件，跳过发布方校验。'
fi

tar -xzf "$ARCHIVE" -C "$TMP_DIR"
[[ -x "$TMP_DIR/syft" ]] || { echo '归档中没有 syft。' >&2; exit 1; }
sudo install -m 0755 "$TMP_DIR/syft" /usr/local/bin/syft

syft version
mkdir -p "$TMP_DIR/smoke"
printf '{"name":"cver-syft-smoke","version":"1.0.0"}\n' > "$TMP_DIR/smoke/package.json"
syft "dir:$TMP_DIR/smoke" -o json > "$TMP_DIR/result.json"
jq -e '.artifacts | type == "array"' "$TMP_DIR/result.json" >/dev/null

echo "Syft 安装完成。日志：$LOG_FILE"
