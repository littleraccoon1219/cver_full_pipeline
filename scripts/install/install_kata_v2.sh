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
sudo apt-get install -y ca-certificates curl jq tar xz-utils zstd qemu-system-arm qemu-utils

[[ -r /dev/kvm && -w /dev/kvm ]] || { echo '当前用户无法读写 /dev/kvm。' >&2; ls -l /dev/kvm || true; exit 1; }

case "$(uname -m)" in
  aarch64|arm64) ARCH_RE='(arm64|aarch64)' ;;
  x86_64|amd64) ARCH_RE='(x86_64|amd64)' ;;
  *) echo "不支持的架构：$(uname -m)" >&2; exit 1 ;;
esac

RELEASE_JSON="$(github_api https://api.github.com/repos/kata-containers/kata-containers/releases/latest)"
TAG="$(jq -r '.tag_name // empty' <<<"$RELEASE_JSON")"
[[ -n "$TAG" ]] || { echo '无法解析 Kata 最新版本。' >&2; exit 1; }

ASSET_JSON="$(jq -c --arg re "$ARCH_RE" '[.assets[] | select(.name|test("kata-static";"i")) | select(.name|test($re;"i")) | select(.name|test("\\.tar\\.(xz|gz|zst)$";"i"))][0] // empty' <<<"$RELEASE_JSON")"
if [[ -z "$ASSET_JSON" ]]; then
  echo "${TAG} 没有找到当前架构的 Kata static bundle。发布资产如下：" >&2
  jq -r '.assets[].name' <<<"$RELEASE_JSON" >&2
  exit 1
fi

ASSET="$(jq -r '.name' <<<"$ASSET_JSON")"
ASSET_ID="$(jq -r '.id // empty' <<<"$ASSET_JSON")"
DIGEST="$(jq -r '.digest // empty' <<<"$ASSET_JSON")"
ARCHIVE="$TMP_DIR/$ASSET"

[[ -n "$ASSET_ID" ]] || { echo '无法解析 GitHub Release asset id。' >&2; exit 1; }
ASSET_API_URL="https://api.github.com/repos/kata-containers/kata-containers/releases/assets/${ASSET_ID}"

echo "通过 GitHub Release Asset API 下载 $ASSET"
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  retry_curl -o "$ARCHIVE" \
    -H 'Accept: application/octet-stream' \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$ASSET_API_URL"
else
  retry_curl -o "$ARCHIVE" \
    -H 'Accept: application/octet-stream' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$ASSET_API_URL"
fi
if [[ "$DIGEST" == sha256:* ]]; then
  echo "${DIGEST#sha256:}  $ARCHIVE" | sha256sum -c -
else
  echo '警告：GitHub API 未提供资产 digest，跳过发布方 SHA-256 校验。'
fi

STAGE="$TMP_DIR/stage"
mkdir -p "$STAGE"
case "$ASSET" in
  *.tar.xz) tar -xJf "$ARCHIVE" -C "$STAGE" ;;
  *.tar.gz) tar -xzf "$ARCHIVE" -C "$STAGE" ;;
  *.tar.zst) tar --zstd -xf "$ARCHIVE" -C "$STAGE" ;;
  *) echo "不支持的归档：$ASSET" >&2; exit 1 ;;
esac

if [[ -d "$STAGE/opt/kata" ]]; then
  KATA_STAGE="$STAGE/opt/kata"
else
  KATA_STAGE="$(find "$STAGE" -type d -path '*/opt/kata' | head -n1 || true)"
fi
[[ -n "$KATA_STAGE" && -d "$KATA_STAGE" ]] || { echo '归档中未找到 opt/kata。' >&2; find "$STAGE" -maxdepth 4 -type d; exit 1; }

if [[ -d /opt/kata ]]; then
  BACKUP="/opt/kata.backup-$(date +%Y%m%d-%H%M%S)"
  echo "备份 /opt/kata 到 $BACKUP"
  sudo mv /opt/kata "$BACKUP"
fi
sudo mkdir -p /opt
sudo cp -a "$KATA_STAGE" /opt/kata

while IFS= read -r -d '' f; do
  n="$(basename "$f")"
  case "$n" in
    kata-*|containerd-shim-kata-*) sudo ln -sfn "$f" "/usr/local/bin/$n" ;;
  esac
done < <(sudo find /opt/kata -type f -perm /111 -print0)

sudo tee /etc/profile.d/kata.sh >/dev/null <<'PROFILE'
export PATH="/opt/kata/bin:/usr/local/bin:$PATH"
PROFILE
sudo chmod 0644 /etc/profile.d/kata.sh
export PATH="/opt/kata/bin:/usr/local/bin:$PATH"

sudo mkdir -p /etc/cver-kata
sudo tee /etc/cver-kata/containerd-kata-runtime.toml >/dev/null <<'FRAG'
# 参考片段。为避免破坏 Docker 管理的 containerd，本安装脚本不自动修改
# /etc/containerd/config.toml。推荐 runtime_type：io.containerd.kata.v2
# 应先检查：sudo containerd config dump
FRAG

FOUND=0
for t in kata-runtime kata-ctl containerd-shim-kata-v2 containerd-shim-kata-qemu-v2 containerd-shim-kata-fc-v2; do
  if command -v "$t" >/dev/null 2>&1; then
    printf '%-36s %s\n' "$t" "$(command -v "$t")"
    FOUND=1
  fi
done
[[ $FOUND -eq 1 ]] || { echo '安装后未发现 Kata 可执行文件。' >&2; find /opt/kata -maxdepth 4 -type f -perm /111; exit 1; }

if command -v kata-ctl >/dev/null 2>&1; then
  kata-ctl version || true
  sudo kata-ctl check || true
fi
if command -v kata-runtime >/dev/null 2>&1; then
  kata-runtime --version || true
  sudo kata-runtime check || sudo kata-runtime kata-check || true
fi

sudo tee /usr/local/bin/kata-smoke-test >/dev/null <<'SMOKE'
#!/usr/bin/env bash
set -Eeuo pipefail
echo "arch=$(uname -m) kernel=$(uname -r) kvm=$([[ -r /dev/kvm && -w /dev/kvm ]] && echo rw || echo unavailable)"
for t in kata-runtime kata-ctl containerd-shim-kata-v2 containerd-shim-kata-qemu-v2 containerd-shim-kata-fc-v2; do
  command -v "$t" >/dev/null 2>&1 && printf '%-36s %s\n' "$t" "$(command -v "$t")"
done
if command -v kata-ctl >/dev/null 2>&1; then
  kata-ctl version || true
  sudo kata-ctl check || true
elif command -v kata-runtime >/dev/null 2>&1; then
  kata-runtime --version || true
  sudo kata-runtime check || sudo kata-runtime kata-check || true
else
  exit 1
fi
echo 'containerd runtime 尚未自动注册。参考：/etc/cver-kata/containerd-kata-runtime.toml'
SMOKE
sudo chmod 0755 /usr/local/bin/kata-smoke-test

echo "Kata 安装完成。检测命令：kata-smoke-test"
echo "日志：$LOG_FILE"
