from __future__ import annotations

import shutil
from pathlib import Path

from ..config import DiscoverySettings
from ..models import ToolResult
from ..tools.runner import CommandRunner
from .base import BackendAvailability


class FirecrackerBackend:
    name = "firecracker"

    def __init__(self, settings: DiscoverySettings, runner: CommandRunner, *, project_root: str | Path = ".") -> None:
        self.settings = settings
        self.runner = runner
        self.project_root = Path(project_root).resolve()

    def availability(self) -> BackendAvailability:
        binary = shutil.which("firecracker")
        if not binary:
            return BackendAvailability(self.name, False, "firecracker executable not found", {})
        kvm = Path("/dev/kvm")
        if not kvm.exists() or not __import__("os").access(kvm, __import__("os").R_OK | __import__("os").W_OK):
            return BackendAvailability(self.name, False, "/dev/kvm is not readable and writable", {"binary": binary})
        if not self.settings.firecracker_kernel or not self.settings.firecracker_kernel.is_file():
            return BackendAvailability(self.name, False, "CVER_FIRECRACKER_KERNEL is missing", {"binary": binary})
        if not self.settings.firecracker_rootfs or not self.settings.firecracker_rootfs.is_file():
            return BackendAvailability(self.name, False, "CVER_FIRECRACKER_ROOTFS is missing", {"binary": binary})
        version = self.runner.run([binary, "--version"], tool="firecracker")
        return BackendAvailability(
            self.name,
            version.status == "succeeded",
            "available" if version.status == "succeeded" else (version.reason or version.stderr.strip()),
            {
                "binary": binary,
                "version": (version.stdout + version.stderr).strip(),
                "kernel": str(self.settings.firecracker_kernel),
                "rootfs": str(self.settings.firecracker_rootfs),
            },
        )

    def smoke(self) -> ToolResult:
        available = self.availability()
        if not available.available:
            return ToolResult("skipped_with_reason", "firecracker", [], None, "", "", 0, reason=available.reason)
        return self.runner.run(
            [
                str(self.project_root / "scripts/lab/smoke_firecracker.sh"),
                str(self.settings.firecracker_kernel),
                str(self.settings.firecracker_rootfs),
            ],
            cwd=self.project_root,
            tool="firecracker-smoke",
            timeout_seconds=120,
        )
