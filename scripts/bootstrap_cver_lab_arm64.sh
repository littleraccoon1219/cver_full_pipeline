#!/usr/bin/env bash
# CVER ARM64 research-lab bootstrap
# Target: Ubuntu 24.04, aarch64/arm64, KVM and BTF available.
# Run as a normal user: ./bootstrap_cver_lab_arm64.sh

set -uo pipefail
IFS=$'\n\t'
umask 022

CVER_LAB_ROOT="${CVER_LAB_ROOT:-$HOME/cver-lab}"
INSTALL_CODEQL="${INSTALL_CODEQL:-1}"
INSTALL_TRACEE="${INSTALL_TRACEE:-1}"
INSTALL_FIRECRACKER="${INSTALL_FIRECRACKER:-1}"
INSTALL_KATA="${INSTALL_KATA:-1}"
INSTALL_RUNC_SOURCE="${INSTALL_RUNC_SOURCE:-1}"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_DIR="${CVER_LAB_ROOT}/logs"
LOG_FILE="${LOG_DIR}/bootstrap-${TIMESTAMP}.log"
STATUS_FILE="${LOG_DIR}/bootstrap-${TIMESTAMP}.status"
TMP_ROOT="$(mktemp -d -t cver-bootstrap.XXXXXX)"

mkdir -p "$LOG_DIR" "$CVER_LAB_ROOT"/{bin,sources,tools,artifacts,cache}
touch "$STATUS_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

cleanup() { rm -rf "$TMP_ROOT"; }
trap cleanup EXIT

if [[ "${EUID}" -eq 0 ]]; then
    echo "ERROR: 请以普通用户运行，不要使用 sudo bash。脚本会在需要时自行调用 sudo。"
    exit 2
fi

case "$(uname -m)" in
  aarch64|arm64) HOST_ARCH=aarch64; GO_ARCH=arm64; KATA_ARCH=arm64 ;;
  x86_64|amd64) HOST_ARCH=x86_64; GO_ARCH=amd64; KATA_ARCH=x86_64 ;;
  *) echo "ERROR: Unsupported architecture: $(uname -m)"; exit 2 ;;
esac
export HOST_ARCH GO_ARCH KATA_ARCH

log() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
record() { printf '%s\t%s\t%s\n' "$1" "$2" "${3:-}" >> "$STATUS_FILE"; }
skip_step() { echo "SKIP: $1"; return 20; }

run_step() {
    local name="$1"; shift
    log "========== START: ${name} =========="
    ( set -Eeuo pipefail; "$@" )
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        record OK "$name"
        log "========== OK: ${name} =========="
    elif [[ $rc -eq 20 ]]; then
        record SKIPPED "$name"
        log "========== SKIPPED: ${name} =========="
    else
        record FAILED "$name" "exit=${rc}"
        log "========== FAILED: ${name} (exit=${rc}) =========="
    fi
    return 0
}

retry_curl() {
    curl --fail --location --silent --show-error \
      --retry 5 --retry-delay 3 --retry-all-errors \
      --connect-timeout 20 --max-time 300 "$@"
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

ensure_profile_line() {
    local file="$1" line="$2"
    touch "$file"
    grep -Fqx "$line" "$file" || printf '\n%s\n' "$line" >> "$file"
}

detect_environment() {
    source /etc/os-release
    [[ "${ID:-}" == ubuntu ]] || { echo "Only Ubuntu is supported"; return 1; }

    echo "OS=${PRETTY_NAME:-Ubuntu}"
    echo "ARCH=${HOST_ARCH}"
    echo "KERNEL=$(uname -r)"
    echo "VIRTUALIZATION=$(systemd-detect-virt 2>/dev/null || true)"
    echo "KVM_RW=$([[ -r /dev/kvm && -w /dev/kvm ]] && echo yes || echo no)"
    echo "BTF=$([[ -r /sys/kernel/btf/vmlinux ]] && echo yes || echo no)"
    sudo -v
}

install_base_packages() {
    export DEBIAN_FRONTEND=noninteractive
    sudo apt-get update
    sudo apt-get install -y \
      ca-certificates curl wget gnupg jq unzip xz-utils tar git \
      make gcc g++ build-essential pkg-config cmake ninja-build \
      clang llvm lld \
      libseccomp-dev libelf-dev zlib1g-dev libssl-dev linux-libc-dev \
      python3 python3-venv python3-pip pipx \
      uidmap slirp4netns fuse-overlayfs \
      qemu-system-arm qemu-utils socat conntrack iptables nftables \
      skopeo umoci

    sudo apt-get install -y bpftool bpfcc-tools linux-tools-generic || true
    sudo apt-get install -y "linux-tools-$(uname -r)" || true
    python3 -m pipx ensurepath || true

    ensure_profile_line "$HOME/.bashrc" 'export PATH="$HOME/.local/bin:$HOME/cver-lab/bin:$PATH"'
    export PATH="$HOME/.local/bin:$CVER_LAB_ROOT/bin:$PATH"
}

install_docker() {
    export DEBIAN_FRONTEND=noninteractive
    for pkg in docker.io docker-compose docker-compose-v2 podman-docker containerd runc; do
        sudo apt-get remove -y "$pkg" >/dev/null 2>&1 || true
    done

    sudo install -m 0755 -d /etc/apt/keyrings
    retry_curl https://download.docker.com/linux/ubuntu/gpg \
      | sudo tee /etc/apt/keyrings/docker.asc >/dev/null
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    local codename dpkg_arch
    codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
    dpkg_arch="$(dpkg --print-architecture)"

    sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${codename}
Components: stable
Architectures: ${dpkg_arch}
Signed-By: /etc/apt/keyrings/docker.asc
EOF

    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
    sudo systemctl enable --now docker
    sudo usermod -aG docker "$USER"
    sudo docker version
    sudo docker info >/dev/null
}

install_go() {
    local manifest row version filename sha256 archive
    manifest="$(retry_curl 'https://go.dev/dl/?mode=json')"
    row="$(jq -r --arg arch "$GO_ARCH" '
      map(select(.stable == true))[0] as $r
      | $r.files[]
      | select(.os == "linux" and .arch == $arch and .kind == "archive")
      | [$r.version, .filename, .sha256] | @tsv
    ' <<<"$manifest" | head -n1)"
    [[ -n "$row" ]] || { echo "No stable Go archive for linux/${GO_ARCH}"; return 1; }

    IFS=$'\t' read -r version filename sha256 <<<"$row"
    archive="${TMP_ROOT}/${filename}"
    retry_curl -o "$archive" "https://go.dev/dl/${filename}"
    echo "${sha256}  ${archive}" | sha256sum --check -

    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$archive"
    sudo tee /etc/profile.d/go.sh >/dev/null <<'EOF'
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
EOF
    export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"
    go version
}

install_rust() {
    local installer="${TMP_ROOT}/rustup-init.sh"
    retry_curl -o "$installer" https://sh.rustup.rs
    sh "$installer" -y --profile minimal --default-toolchain stable
    source "$HOME/.cargo/env"
    rustup component add rustfmt clippy
    rustc --version
    cargo --version
}

install_semgrep() {
    export PATH="$HOME/.local/bin:$PATH"
    if command -v semgrep >/dev/null 2>&1; then
        pipx upgrade semgrep || pipx install --force semgrep
    else
        pipx install semgrep
    fi
    semgrep --version
}

install_trivy() {
    retry_curl https://aquasecurity.github.io/trivy-repo/deb/public.key \
      | gpg --dearmor \
      | sudo tee /usr/share/keyrings/trivy.gpg >/dev/null
    sudo tee /etc/apt/sources.list.d/trivy.list >/dev/null <<'EOF'
deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main
EOF
    sudo apt-get update
    sudo apt-get install -y trivy
    trivy --version
}

install_syft() {
    local installer="${TMP_ROOT}/install-syft.sh"
    retry_curl -o "$installer" https://get.anchore.io/syft
    sudo sh "$installer" -s -- -b /usr/local/bin
    syft version
}

install_runc_source() {
    [[ "$INSTALL_RUNC_SOURCE" == 1 ]] || skip_step "INSTALL_RUNC_SOURCE=${INSTALL_RUNC_SOURCE}"
    local release_json tag dest
    release_json="$(github_api https://api.github.com/repos/opencontainers/runc/releases/latest)"
    tag="$(jq -r '.tag_name // empty' <<<"$release_json")"
    [[ -n "$tag" ]] || { echo "Cannot resolve latest stable runc release"; return 1; }

    dest="${CVER_LAB_ROOT}/sources/runc-${tag}"
    if [[ ! -d "${dest}/.git" ]]; then
        git clone --depth 1 --branch "$tag" https://github.com/opencontainers/runc.git "$dest"
    else
        git -C "$dest" fetch --depth 1 origin "$tag"
        git -C "$dest" checkout -f "$tag"
    fi
    ln -sfn "$dest" "${CVER_LAB_ROOT}/sources/runc-current"

    export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH"
    make -C "$dest" -j"$(nproc)" BUILDTAGS=seccomp
    install -m 0755 "${dest}/runc" "${CVER_LAB_ROOT}/bin/runc-research"
    "${CVER_LAB_ROOT}/bin/runc-research" --version
}

install_codeql() {
    [[ "$INSTALL_CODEQL" == 1 ]] || skip_step "INSTALL_CODEQL=${INSTALL_CODEQL}"
    local release_json asset_url asset_name archive extract_dir binary
    release_json="$(github_api https://api.github.com/repos/github/codeql-cli-binaries/releases/latest)"

    if [[ "$HOST_ARCH" == aarch64 ]]; then
        asset_url="$(jq -r '[.assets[] | select(.name | test("linux.*(arm64|aarch64).*(zip|tar\\.gz)$"; "i"))][0].browser_download_url // empty' <<<"$release_json")"
    else
        asset_url="$(jq -r '[.assets[] | select(.name | test("^codeql-linux64\\.(zip|tar\\.gz)$"; "i"))][0].browser_download_url // empty' <<<"$release_json")"
    fi

    [[ -n "$asset_url" ]] || skip_step "No official CodeQL Linux asset for ${HOST_ARCH}. Semgrep remains available."
    asset_name="$(basename "$asset_url")"
    archive="${TMP_ROOT}/${asset_name}"
    extract_dir="${TMP_ROOT}/codeql-extract"
    retry_curl -o "$archive" "$asset_url"
    mkdir -p "$extract_dir"
    case "$asset_name" in
      *.zip) unzip -q "$archive" -d "$extract_dir" ;;
      *.tar.gz) tar -xzf "$archive" -C "$extract_dir" ;;
      *) echo "Unsupported CodeQL archive: $asset_name"; return 1 ;;
    esac

    binary="$(find "$extract_dir" -type f -name codeql -perm -u+x | head -n1)"
    [[ -n "$binary" ]] || { echo "CodeQL executable not found"; return 1; }
    sudo rm -rf /opt/codeql
    sudo mkdir -p /opt/codeql
    sudo cp -a "$(dirname "$binary")/." /opt/codeql/
    sudo ln -sfn /opt/codeql/codeql /usr/local/bin/codeql

    if [[ ! -d "${CVER_LAB_ROOT}/tools/codeql-repo/.git" ]]; then
        git clone --depth 1 https://github.com/github/codeql.git "${CVER_LAB_ROOT}/tools/codeql-repo"
    fi
    codeql version
}

install_tracee() {
    [[ "$INSTALL_TRACEE" == 1 ]] || skip_step "INSTALL_TRACEE=${INSTALL_TRACEE}"
    sudo docker pull aquasec/tracee:latest
    sudo tee /usr/local/bin/tracee-docker >/dev/null <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if docker info >/dev/null 2>&1; then DOCKER=(docker); else DOCKER=(sudo docker); fi
exec "${DOCKER[@]}" run --name tracee --rm -it \
  --pid=host --cgroupns=host --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  aquasec/tracee:latest "$@"
EOF
    sudo chmod 0755 /usr/local/bin/tracee-docker
    sudo docker image inspect aquasec/tracee:latest >/dev/null
}

install_firecracker() {
    [[ "$INSTALL_FIRECRACKER" == 1 ]] || skip_step "INSTALL_FIRECRACKER=${INSTALL_FIRECRACKER}"
    [[ -r /dev/kvm && -w /dev/kvm ]] || { echo "/dev/kvm is not readable/writable"; return 1; }

    local release_json tag asset_url archive extract_dir fc_bin jailer_bin
    release_json="$(github_api https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest)"
    tag="$(jq -r '.tag_name // empty' <<<"$release_json")"
    [[ -n "$tag" ]] || { echo "Cannot resolve Firecracker release"; return 1; }
    asset_url="$(jq -r --arg arch "$HOST_ARCH" --arg tag "$tag" '[.assets[] | select(.name == ("firecracker-" + $tag + "-" + $arch + ".tgz"))][0].browser_download_url // empty' <<<"$release_json")"
    [[ -n "$asset_url" ]] || { echo "No Firecracker ${HOST_ARCH} asset for ${tag}"; return 1; }

    archive="${TMP_ROOT}/$(basename "$asset_url")"
    extract_dir="${TMP_ROOT}/firecracker-extract"
    retry_curl -o "$archive" "$asset_url"
    mkdir -p "$extract_dir"
    tar -xzf "$archive" -C "$extract_dir"
    fc_bin="$(find "$extract_dir" -type f -name "firecracker-${tag}-${HOST_ARCH}" | head -n1)"
    jailer_bin="$(find "$extract_dir" -type f -name "jailer-${tag}-${HOST_ARCH}" | head -n1)"
    [[ -n "$fc_bin" && -n "$jailer_bin" ]] || { echo "Firecracker binaries not found"; return 1; }
    sudo install -m 0755 "$fc_bin" /usr/local/bin/firecracker
    sudo install -m 0755 "$jailer_bin" /usr/local/bin/jailer
    firecracker --version
    jailer --version
}

install_kata() {
    [[ "$INSTALL_KATA" == 1 ]] || skip_step "INSTALL_KATA=${INSTALL_KATA}"
    [[ -r /dev/kvm && -w /dev/kvm ]] || { echo "/dev/kvm is not readable/writable"; return 1; }

    local release_json tag asset_url archive backup
    release_json="$(github_api https://api.github.com/repos/kata-containers/kata-containers/releases/latest)"
    tag="$(jq -r '.tag_name // empty' <<<"$release_json")"
    [[ -n "$tag" ]] || { echo "Cannot resolve Kata release"; return 1; }
    asset_url="$(jq -r --arg arch "$KATA_ARCH" '[.assets[] | select(.name | test(("^kata-static-.*-" + $arch + "\\.tar\\.xz$"); "i"))][0].browser_download_url // empty' <<<"$release_json")"
    [[ -n "$asset_url" ]] || skip_step "No Kata static asset for ${KATA_ARCH}."

    archive="${TMP_ROOT}/$(basename "$asset_url")"
    retry_curl -o "$archive" "$asset_url"
    if [[ -d /opt/kata ]]; then
        backup="/opt/kata.backup-${TIMESTAMP}"
        sudo mv /opt/kata "$backup"
        echo "Existing /opt/kata moved to ${backup}"
    fi
    sudo tar -xJf "$archive" -C /
    [[ -d /opt/kata ]] || { echo "Kata archive did not create /opt/kata"; return 1; }

    for name in kata-runtime kata-ctl kata-collect-data.sh \
      containerd-shim-kata-v2 containerd-shim-kata-qemu-v2 \
      containerd-shim-kata-clh-v2 containerd-shim-kata-fc-v2; do
        [[ -e "/opt/kata/bin/${name}" ]] && sudo ln -sfn "/opt/kata/bin/${name}" "/usr/local/bin/${name}"
    done
    sudo tee /etc/profile.d/kata.sh >/dev/null <<'EOF'
export PATH="/opt/kata/bin:$PATH"
EOF
    export PATH="/opt/kata/bin:$PATH"

    if command -v kata-runtime >/dev/null 2>&1; then
        kata-runtime --version || true
        sudo kata-runtime check || sudo kata-runtime kata-check || true
    elif command -v kata-ctl >/dev/null 2>&1; then
        kata-ctl version || true
        sudo kata-ctl check || true
    else
        echo "Kata extracted, but no kata-runtime/kata-ctl found"
        return 1
    fi
    echo "Kata installed under /opt/kata. containerd registration is deferred."
}

write_doctor_script() {
    cat > "${CVER_LAB_ROOT}/bin/cver-lab-doctor" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
export PATH="/usr/local/go/bin:$HOME/go/bin:$HOME/.cargo/bin:$HOME/.local/bin:$HOME/cver-lab/bin:/opt/kata/bin:$PATH"

echo "===== SYSTEM ====="
grep PRETTY_NAME /etc/os-release || true
echo "arch=$(uname -m)"
echo "kernel=$(uname -r)"
echo "virt=$(systemd-detect-virt 2>/dev/null || true)"
echo "kvm_rw=$([[ -r /dev/kvm && -w /dev/kvm ]] && echo yes || echo no)"
echo "btf=$([[ -r /sys/kernel/btf/vmlinux ]] && echo yes || echo no)"

echo
echo "===== TOOLS ====="
for tool in docker containerd ctr runc go rustc cargo semgrep trivy syft \
  codeql tracee-docker firecracker jailer kata-runtime kata-ctl \
  skopeo umoci bpftool; do
    if command -v "$tool" >/dev/null 2>&1; then
        printf '%-24s %s\n' "$tool" "$(command -v "$tool")"
    else
        printf '%-24s %s\n' "$tool" MISSING
    fi
done

echo
echo "===== VERSIONS ====="
docker --version 2>/dev/null || sudo docker --version 2>/dev/null || true
containerd --version 2>/dev/null || true
runc --version 2>/dev/null | head -n2 || true
go version 2>/dev/null || true
rustc --version 2>/dev/null || true
cargo --version 2>/dev/null || true
semgrep --version 2>/dev/null || true
trivy --version 2>/dev/null | head -n4 || true
syft version 2>/dev/null | head -n8 || true
codeql version 2>/dev/null | head -n4 || true
firecracker --version 2>/dev/null || true
jailer --version 2>/dev/null || true
kata-runtime --version 2>/dev/null || true

echo
echo "===== DOCKER ACCESS ====="
if docker info >/dev/null 2>&1; then
    echo "docker_without_sudo=yes"
elif sudo docker info >/dev/null 2>&1; then
    echo "docker_without_sudo=no (重新登录或重连 VS Code Remote)"
else
    echo "docker_daemon=unavailable"
fi
EOF
    chmod 0755 "${CVER_LAB_ROOT}/bin/cver-lab-doctor"
    "${CVER_LAB_ROOT}/bin/cver-lab-doctor"
}

print_summary() {
    echo
    echo '============================================================'
    echo 'CVER bootstrap summary'
    echo '============================================================'
    column -t -s $'\t' "$STATUS_FILE" 2>/dev/null || cat "$STATUS_FILE"
    echo
    echo "Log:    $LOG_FILE"
    echo "Status: $STATUS_FILE"
    echo "Doctor: $CVER_LAB_ROOT/bin/cver-lab-doctor"
    echo
    echo 'IMPORTANT:'
    echo '1. Docker 用户组需要新登录会话后生效。'
    echo '2. 安装结束后重开终端或重连 VS Code Remote。'
    echo "3. 然后运行: $CVER_LAB_ROOT/bin/cver-lab-doctor"
    echo '4. 暂时不要把 Kata 注册成 containerd 默认 runtime。'
    echo '============================================================'
}

log "CVER research-lab bootstrap starting"
log "Root: ${CVER_LAB_ROOT}"
log "Log:  ${LOG_FILE}"

run_step 'environment detection' detect_environment
run_step 'base packages' install_base_packages
run_step 'Docker Engine' install_docker
run_step 'Go' install_go
run_step 'Rust' install_rust
run_step 'Semgrep' install_semgrep
run_step 'Trivy' install_trivy
run_step 'Syft' install_syft
run_step 'runc source and research build' install_runc_source
run_step 'CodeQL CLI' install_codeql
run_step 'Tracee' install_tracee
run_step 'Firecracker' install_firecracker
run_step 'Kata Containers' install_kata
run_step 'doctor command' write_doctor_script

print_summary
