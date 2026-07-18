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
LOG_FILE="$LOG_DIR/install_tracee-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

sudo -v
sudo apt-get update
sudo apt-get install -y ca-certificates curl jq

command -v docker >/dev/null 2>&1 || { echo '未找到 Docker。' >&2; exit 1; }

if docker info >/dev/null 2>&1; then
  DOCKER=(docker)
elif sudo docker info >/dev/null 2>&1; then
  DOCKER=(sudo docker)
  echo '当前会话尚未获得 docker 组权限，临时使用 sudo docker。'
else
  echo 'Docker daemon 不可用。' >&2
  sudo systemctl status docker --no-pager || true
  exit 1
fi

[[ -r /sys/kernel/btf/vmlinux ]] || { echo '/sys/kernel/btf/vmlinux 不可读。' >&2; exit 1; }
[[ -r /proc/kallsyms ]] || echo '警告：/proc/kallsyms 不可读，部分符号解析能力可能受限。'

TRACEE_IMAGE="${TRACEE_IMAGE:-aquasec/tracee:latest}"
"${DOCKER[@]}" pull "$TRACEE_IMAGE"
IMAGE_ARCH="$("${DOCKER[@]}" image inspect "$TRACEE_IMAGE" --format '{{.Architecture}}')"
case "$(uname -m)" in
  aarch64|arm64) EXPECTED=arm64 ;;
  x86_64|amd64) EXPECTED=amd64 ;;
  *) EXPECTED="$(uname -m)" ;;
esac
[[ "$IMAGE_ARCH" == "$EXPECTED" ]] || { echo "镜像架构 $IMAGE_ARCH 与宿主 $EXPECTED 不匹配。" >&2; exit 1; }

sudo tee /usr/local/bin/tracee-docker >/dev/null <<'WRAP'
#!/usr/bin/env bash
set -Eeuo pipefail
TRACEE_IMAGE="${TRACEE_IMAGE:-aquasec/tracee:latest}"
if docker info >/dev/null 2>&1; then DOCKER=(docker); else DOCKER=(sudo docker); fi
TTY=()
if [[ -t 0 && -t 1 ]]; then TTY=(-it); fi
exec "${DOCKER[@]}" run --name tracee --rm "${TTY[@]}" \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  "$TRACEE_IMAGE" "$@"
WRAP
sudo chmod 0755 /usr/local/bin/tracee-docker

sudo tee /usr/local/bin/tracee-smoke-test >/dev/null <<'SMOKE'
#!/usr/bin/env bash
set -Eeuo pipefail
TRACEE_IMAGE="${TRACEE_IMAGE:-aquasec/tracee:latest}"
if docker info >/dev/null 2>&1; then DOCKER=(docker); else DOCKER=(sudo docker); fi
"${DOCKER[@]}" image inspect "$TRACEE_IMAGE" --format 'id={{.Id}} arch={{.Architecture}} os={{.Os}}'
"${DOCKER[@]}" run --rm "$TRACEE_IMAGE" --help >/tmp/tracee-help.txt
test -s /tmp/tracee-help.txt
head -n 20 /tmp/tracee-help.txt
echo 'Tracee CLI 冒烟测试通过。实时运行：tracee-docker'
SMOKE
sudo chmod 0755 /usr/local/bin/tracee-smoke-test

tracee-smoke-test
echo "Tracee 安装完成。日志：$LOG_FILE"
