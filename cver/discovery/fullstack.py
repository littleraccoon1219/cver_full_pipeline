from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from .tools import CommandRunner


@dataclass(frozen=True, slots=True)
class ComponentSpec:
    component_id: str
    display_name: str
    layer: str
    source_repositories: tuple[str, ...]
    languages: tuple[str, ...]
    version_matrix: str
    required_capabilities: tuple[str, ...]
    discovery_methods: tuple[str, ...]
    integration_stage: str = "M1"


@dataclass(frozen=True, slots=True)
class Capability:
    capability_id: str
    status: str
    version: str | None
    path: str | None
    reason: str | None
    remediation: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ComponentRegistry:
    def __init__(self, path: str | Path = "data/components/fullstack_components.yaml") -> None:
        payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        if payload.get("registry_id") != "cver-fullstack-components":
            raise ValueError("invalid full-stack component registry")
        self.version = str(payload["version"])
        self.components = {
            item["id"]: ComponentSpec(
                component_id=item["id"],
                display_name=item["display_name"],
                layer=item["layer"],
                source_repositories=tuple(item.get("source_repositories", [])),
                languages=tuple(item.get("languages", [])),
                version_matrix=item["version_matrix"],
                required_capabilities=tuple(item.get("required_capabilities", [])),
                discovery_methods=tuple(item.get("discovery_methods", [])),
                integration_stage=item.get("integration_stage", "M1"),
            )
            for item in payload["components"]
        }

    def get(self, component_id: str) -> ComponentSpec:
        try:
            return self.components[component_id]
        except KeyError as exc:
            raise KeyError(f"unknown full-stack component: {component_id}") from exc


class CapabilityScanner:
    _COMMANDS: dict[str, tuple[str, ...]] = {
        "git": ("git", "--version"),
        "go": ("go", "version"),
        "rustc": ("rustc", "--version"),
        "cargo": ("cargo", "--version"),
        "semgrep": ("semgrep", "--version"),
        "trivy": ("trivy", "--version"),
        "syft": ("syft", "version"),
        "docker": ("docker", "version", "--format", "{{.Client.Version}}"),
        "containerd": ("containerd", "--version"),
        "ctr": ("ctr", "version"),
        "runc": ("runc", "--version"),
        "crio": ("crio", "--version"),
        "conmon": ("conmon", "--version"),
        "kubectl": ("kubectl", "version", "--client=true", "--output=yaml"),
        "buildctl": ("buildctl", "--version"),
        "runsc": ("runsc", "--version"),
        "kata": ("kata-runtime", "--version"),
        "firecracker": ("firecracker", "--version"),
        "bpftool": ("bpftool", "version"),
        "tracee": ("tracee", "--version"),
    }

    _REMEDIATION = {
        "semgrep": "install Semgrep and rerun scripts/verify_basic.sh",
        "trivy": "install Trivy and initialize its databases",
        "syft": "install Syft for SBOM generation",
        "docker": "install Docker and grant the current user access to the daemon",
        "containerd": "install containerd; Kata experiments use a dedicated CVER instance",
        "ctr": "install the containerd client",
        "runc": "install runc or supply a source checkout",
        "crio": "install CRI-O for CRI-O experiments",
        "conmon": "install conmon for CRI-O lifecycle experiments",
        "kubectl": "install kubectl and configure an authorized test cluster",
        "buildctl": "install BuildKit/buildctl",
        "runsc": "install gVisor runsc",
        "kata": "install Kata Containers without replacing the default containerd runtime",
        "firecracker": "install Firecracker and provision checksum-pinned guest assets",
        "bpftool": "install bpftool matching the host kernel",
        "tracee": "install Tracee as the compatibility observation backend",
    }

    def __init__(self, runner: CommandRunner, *, registry: ComponentRegistry | None = None) -> None:
        self.runner = runner
        self.registry = registry or ComponentRegistry()

    @staticmethod
    def _special(capability_id: str) -> Capability | None:
        if capability_id == "kvm":
            path = Path("/dev/kvm")
            ok = path.exists() and os.access(path, os.R_OK | os.W_OK)
            return Capability(
                capability_id,
                "available" if ok else "unavailable",
                None,
                str(path),
                None if ok else "/dev/kvm is not readable and writable",
                "enable KVM and grant the user access to /dev/kvm",
            )
        if capability_id == "btf":
            path = Path("/sys/kernel/btf/vmlinux")
            ok = path.is_file()
            return Capability(
                capability_id,
                "available" if ok else "unavailable",
                None,
                str(path),
                None if ok else "kernel BTF is unavailable",
                "boot a kernel with CONFIG_DEBUG_INFO_BTF=y",
            )
        if capability_id == "cgroup_v2":
            path = Path("/sys/fs/cgroup/cgroup.controllers")
            ok = path.is_file()
            return Capability(
                capability_id,
                "available" if ok else "unavailable",
                None,
                str(path),
                None if ok else "cgroup v2 unified hierarchy not detected",
                "enable the cgroup v2 unified hierarchy",
            )
        if capability_id == "ebpf":
            btf = Path("/sys/kernel/btf/vmlinux").is_file()
            disabled = Path("/proc/sys/kernel/unprivileged_bpf_disabled")
            detail = disabled.read_text(encoding="utf-8", errors="replace").strip() if disabled.is_file() else "unknown"
            status = "available" if btf else "degraded"
            return Capability(
                capability_id,
                status,
                f"unprivileged_bpf_disabled={detail}",
                "/sys/kernel/btf/vmlinux",
                None if btf else "BTF unavailable; CO-RE agent cannot load",
                "enable BTF and run privileged lab collection only",
            )
        if capability_id == "rust_shyper":
            root = os.getenv("CVER_RUST_SHYPER_ROOT")
            ok = bool(root and Path(root).expanduser().is_dir())
            return Capability(
                capability_id,
                "available" if ok else "not_configured",
                None,
                root,
                None if ok else "Rust-Shyper is an M3 adapter and CVER_RUST_SHYPER_ROOT is not configured",
                "configure Rust-Shyper only after the generic M1/M2 platform is stable",
            )
        return None

    def scan(self) -> dict[str, Any]:
        capability_ids = set(self._COMMANDS)
        capability_ids.update({"kvm", "btf", "cgroup_v2", "ebpf", "rust_shyper"})
        capabilities: dict[str, Capability] = {}
        for capability_id in sorted(capability_ids):
            special = self._special(capability_id)
            if special is not None:
                capabilities[capability_id] = special
                continue
            argv = self._COMMANDS[capability_id]
            executable = shutil.which(argv[0])
            if not executable:
                capabilities[capability_id] = Capability(
                    capability_id,
                    "unavailable",
                    None,
                    None,
                    f"{argv[0]} was not found in PATH",
                    self._REMEDIATION.get(capability_id),
                )
                continue
            result = self.runner.run(list(argv), tool=f"capability-{capability_id}", timeout_seconds=20)
            text = (result.stdout or result.stderr).strip().replace("\n", " ")[:1000]
            capabilities[capability_id] = Capability(
                capability_id,
                "available" if result.status == "succeeded" else "degraded",
                text or None,
                executable,
                None if result.status == "succeeded" else result.reason or result.stderr[:1000],
                self._REMEDIATION.get(capability_id),
            )

        component_results = []
        for spec in self.registry.components.values():
            required = [capabilities.get(value) for value in spec.required_capabilities]
            missing = [
                value.capability_id for value in required if value and value.status in {"unavailable", "not_configured"}
            ]
            degraded = [value.capability_id for value in required if value and value.status == "degraded"]
            status = (
                "available" if not missing and not degraded else "degraded" if not missing else "skipped_with_reason"
            )
            component_results.append(
                {
                    **asdict(spec),
                    "status": status,
                    "missing_capabilities": missing,
                    "degraded_capabilities": degraded,
                    "reason": None if status == "available" else f"missing={missing}; degraded={degraded}",
                }
            )

        host = {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        }
        fingerprint = hashlib.sha256(json.dumps(host, sort_keys=True).encode()).hexdigest()
        return {
            "registry_version": self.registry.version,
            "host": host,
            "host_fingerprint": fingerprint,
            "capabilities": {key: value.to_dict() for key, value in capabilities.items()},
            "components": component_results,
        }
