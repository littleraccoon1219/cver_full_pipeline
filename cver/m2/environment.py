from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
from pathlib import Path
from typing import Any

from .config import M2Settings
from .runner import SafeCommandRunner


_VERSION_RE = re.compile(r"(?P<version>\d+(?:\.\d+){1,3})")


def _read_os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def _binary_version(runner: SafeCommandRunner, name: str, args: list[str] | None = None) -> dict[str, Any]:
    executable = shutil.which(name)
    if not executable:
        return {"status": "missing", "path": None, "version": None, "raw": ""}
    result = runner.run([name, *(args or ["--version"])], timeout=20)
    raw = (result.stdout or result.stderr).strip()
    match = _VERSION_RE.search(raw)
    return {
        "status": "ok" if result.ok else "error",
        "path": executable,
        "version": match.group("version") if match else None,
        "raw": raw[:4000],
        "returncode": result.returncode,
    }


class EnvironmentCollector:
    def __init__(self, settings: M2Settings, runner: SafeCommandRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or SafeCommandRunner(helper=settings.sudo_helper)

    def collect(self) -> dict[str, Any]:
        tools = {
            "python": {"path": shutil.which("python3"), "version": platform.python_version()},
            "git": _binary_version(self.runner, "git"),
            "clang": _binary_version(self.runner, "clang-18" if shutil.which("clang-18") else "clang"),
            "gcc": _binary_version(self.runner, "gcc"),
            "go": _binary_version(self.runner, "go", ["version"]),
            "rustc": _binary_version(self.runner, "rustc"),
            "cargo": _binary_version(self.runner, "cargo"),
            "cmake": _binary_version(self.runner, "cmake"),
            "ninja": _binary_version(self.runner, "ninja"),
            "protoc": _binary_version(self.runner, "protoc"),
            "grpc_cpp_plugin": self._path_only("grpc_cpp_plugin"),
            "containerd": _binary_version(self.runner, "containerd"),
            "ctr": _binary_version(self.runner, "ctr", ["version"]),
            "docker": _binary_version(self.runner, "docker"),
        }
        kata = self._kata_environment()
        qemu = self._qemu_environment(kata)
        virtiofsd = self._virtiofsd_environment(kata)
        config = self._kata_config()
        issues = self._issues(kata, qemu, config, tools)
        payload = {
            "schema_version": 1,
            "host": {
                "architecture": platform.machine(),
                "kernel": platform.release(),
                "platform": platform.platform(),
                "cpu_count": os.cpu_count(),
                "os_release": _read_os_release(),
                "kvm": self._kvm(),
            },
            "tools": tools,
            "kata": kata,
            "qemu": qemu,
            "virtiofsd": virtiofsd,
            "configuration": config,
            "namespace": self.settings.namespace,
            "issues": issues,
        }
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        payload["digest"] = hashlib.sha256(canonical).hexdigest()
        return payload

    @staticmethod
    def _path_only(name: str) -> dict[str, Any]:
        path = shutil.which(name)
        return {"status": "ok" if path else "missing", "path": path}

    @staticmethod
    def _kvm() -> dict[str, Any]:
        path = Path("/dev/kvm")
        if not path.exists():
            return {"status": "missing", "path": str(path)}
        stat = path.stat()
        return {
            "status": "present",
            "path": str(path),
            "mode": oct(stat.st_mode & 0o777),
            "uid": stat.st_uid,
            "gid": stat.st_gid,
            "readable": os.access(path, os.R_OK),
            "writable": os.access(path, os.W_OK),
        }

    def _kata_environment(self) -> dict[str, Any]:
        candidates = [
            shutil.which("kata-runtime"),
            "/opt/kata/bin/kata-runtime",
        ]
        executable = next((item for item in candidates if item and Path(item).is_file()), None)
        if not executable:
            return {"status": "missing"}
        runner = SafeCommandRunner(helper=self.settings.sudo_helper)
        version = runner.run([executable, "--version"], timeout=20)
        environment = runner.run([executable, "env"], timeout=30)
        raw = environment.stdout or environment.stderr
        fields = {
            "runtime_path": executable,
            "version_raw": (version.stdout or version.stderr).strip(),
            "env_raw": raw[:20000],
            "status": "ok" if environment.ok else "error",
        }
        patterns = {
            "version": r'Version\s*=\s*"([^"]+)"',
            "commit": r'Commit\s*=\s*"([0-9a-f]{7,40})"',
            "machine_type": r'MachineType\s*=\s*"([^"]*)"',
            "shared_fs": r'SharedFS\s*=\s*"([^"]*)"',
            "block_driver": r'BlockDeviceDriver\s*=\s*"([^"]*)"',
            "disable_guest_seccomp": r'DisableGuestSeccomp\s*=\s*(true|false)',
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, raw)
            if match:
                value: Any = match.group(1)
                if value in {"true", "false"}:
                    value = value == "true"
                fields[key] = value
        paths = re.findall(r'^\s*Path\s*=\s*"([^"]+)"', raw, flags=re.MULTILINE)
        fields["paths"] = paths
        return fields

    def _qemu_environment(self, kata: dict[str, Any]) -> dict[str, Any]:
        candidates = [
            "/opt/kata/bin/qemu-system-aarch64",
            shutil.which("qemu-system-aarch64"),
        ]
        for item in kata.get("paths", []):
            if "qemu-system" in item:
                candidates.insert(0, item)
        executable = next((str(item) for item in candidates if item and Path(item).is_file()), None)
        if not executable:
            return {"status": "missing"}
        runner = SafeCommandRunner(helper=self.settings.sudo_helper)
        result = runner.run([executable, "--version"], timeout=20)
        raw = (result.stdout or result.stderr).strip()
        match = _VERSION_RE.search(raw)
        return {
            "status": "ok" if result.ok else "error",
            "path": executable,
            "version": match.group("version") if match else None,
            "raw": raw[:4000],
        }

    def _virtiofsd_environment(self, kata: dict[str, Any]) -> dict[str, Any]:
        candidates = ["/opt/kata/libexec/virtiofsd", shutil.which("virtiofsd")]
        for item in kata.get("paths", []):
            if item.endswith("virtiofsd"):
                candidates.insert(0, item)
        executable = next((str(item) for item in candidates if item and Path(item).is_file()), None)
        if not executable:
            return {"status": "missing"}
        runner = SafeCommandRunner(helper=self.settings.sudo_helper)
        result = runner.run([executable, "--version"], timeout=20)
        raw = (result.stdout or result.stderr).strip()
        match = _VERSION_RE.search(raw)
        return {
            "status": "ok" if result.ok else "error",
            "path": executable,
            "version": match.group("version") if match else None,
            "raw": raw[:4000],
        }

    def _kata_config(self) -> dict[str, Any]:
        path = self.settings.kata_config
        if not path.is_file():
            return {"status": "missing", "path": str(path)}
        text = path.read_text(encoding="utf-8", errors="replace")
        keys = {
            "cpu_features": r'^\s*cpu_features\s*=\s*"([^"]*)"',
            "machine_type": r'^\s*machine_type\s*=\s*"([^"]*)"',
            "shared_fs": r'^\s*shared_fs\s*=\s*"([^"]*)"',
            "block_device_driver": r'^\s*block_device_driver\s*=\s*"([^"]*)"',
            "disable_guest_seccomp": r'^\s*disable_guest_seccomp\s*=\s*(true|false)',
            "enable_debug": r'^\s*enable_debug\s*=\s*(true|false)',
        }
        values: dict[str, Any] = {"status": "ok", "path": str(path)}
        for key, pattern in keys.items():
            match = re.search(pattern, text, flags=re.MULTILINE | re.IGNORECASE)
            if match:
                value: Any = match.group(1)
                if value.lower() in {"true", "false"}:
                    value = value.lower() == "true"
                values[key] = value
        values["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return values

    @staticmethod
    def _issues(
        kata: dict[str, Any],
        qemu: dict[str, Any],
        config: dict[str, Any],
        tools: dict[str, Any],
    ) -> list[dict[str, Any]]:
        issues: list[dict[str, Any]] = []
        if platform.machine() in {"aarch64", "arm64"} and config.get("cpu_features") == "pmu=off":
            issues.append(
                {
                    "code": "KATA_QEMU_ARM64_PMU_PROPERTY_MISMATCH",
                    "severity": "high",
                    "status": "blocked",
                    "summary": (
                        "The installed Kata/QEMU combination is known on this host to fail when "
                        "cpu_features contains pmu=off. Use the explicit compatibility command."
                    ),
                    "evidence": {
                        "kata_version": kata.get("version"),
                        "kata_commit": kata.get("commit"),
                        "qemu_version": qemu.get("version"),
                        "cpu_features": config.get("cpu_features"),
                    },
                }
            )
        if config.get("disable_guest_seccomp") is True or kata.get("disable_guest_seccomp") is True:
            issues.append(
                {
                    "code": "KATA_GUEST_SECCOMP_DISABLED",
                    "severity": "medium",
                    "status": "review",
                    "summary": "Guest seccomp is disabled; this expands the guest agent/container syscall surface.",
                }
            )
        required = ["git", "clang", "go", "rustc", "cargo", "protoc", "containerd", "ctr"]
        missing = [name for name in required if tools.get(name, {}).get("status") == "missing"]
        if missing:
            issues.append(
                {
                    "code": "M2_TOOLCHAIN_INCOMPLETE",
                    "severity": "medium",
                    "status": "blocked",
                    "summary": f"Missing required tools: {', '.join(missing)}",
                }
            )
        return issues

    def doctor(self) -> dict[str, Any]:
        payload = self.collect()
        helper = self.settings.sudo_helper
        payload["privileged_helper"] = {
            "path": str(helper),
            "installed": helper.is_file(),
            "root_owned": helper.is_file() and helper.stat().st_uid == 0,
            "user_writable": helper.is_file() and os.access(helper, os.W_OK),
        }
        payload["settings"] = self.settings.redacted()
        payload["ready"] = not any(issue["status"] == "blocked" for issue in payload["issues"])
        return payload
