from __future__ import annotations

import shutil
import uuid
from pathlib import Path

from ..config import DiscoverySettings
from ..models import ToolResult
from ..tools.runner import CommandRunner
from .base import BackendAvailability


class KataBackend:
    name = "kata"

    def __init__(self, settings: DiscoverySettings, runner: CommandRunner) -> None:
        self.settings = settings
        self.runner = runner

    def availability(self) -> BackendAvailability:
        shim = shutil.which("containerd-shim-kata-v2") or "/opt/kata/bin/containerd-shim-kata-v2"
        runtime = shutil.which("kata-runtime") or "/opt/kata/bin/kata-runtime"
        if not shutil.which("ctr"):
            return BackendAvailability(self.name, False, "ctr executable not found", {})
        if not Path(shim).is_file() and not shutil.which("containerd-shim-kata-v2"):
            return BackendAvailability(self.name, False, "containerd-shim-kata-v2 not found", {})
        if not Path(runtime).is_file() and not shutil.which("kata-runtime"):
            return BackendAvailability(self.name, False, "kata-runtime not found", {})
        check = self.runner.run([runtime, "check"], tool="kata-runtime", timeout_seconds=60)
        return BackendAvailability(
            self.name,
            check.status == "succeeded",
            "available"
            if check.status == "succeeded"
            else (check.reason or check.stderr.strip() or "kata-runtime check failed"),
            {"runtime": runtime, "shim": shim, "runtime_type": self.settings.kata_runtime},
        )

    def smoke(self) -> ToolResult:
        availability = self.availability()
        if not availability.available:
            return ToolResult("skipped_with_reason", "kata", [], None, "", "", 0, reason=availability.reason)

        image_list = self.runner.run(["ctr", "images", "ls", "-q"], tool="kata-image")
        available_images = {line.strip() for line in image_list.stdout.splitlines() if line.strip()}
        if image_list.status != "succeeded" or self.settings.kata_image not in available_images:
            return ToolResult(
                "skipped_with_reason",
                "kata",
                image_list.command,
                image_list.exit_code,
                image_list.stdout,
                image_list.stderr,
                image_list.duration_ms,
                reason=(
                    f"Kata image is not imported into containerd: {self.settings.kata_image}. "
                    "Run scripts/lab/prepare_kata_image.sh first."
                ),
            )

        container_id = f"cver-kata-smoke-{uuid.uuid4().hex[:12]}"
        return self.runner.run(
            [
                "ctr",
                "run",
                "--rm",
                "--runtime",
                self.settings.kata_runtime,
                self.settings.kata_image,
                container_id,
                "/bin/echo",
                "CVER_KATA_SMOKE_OK",
            ],
            tool="kata-smoke",
            timeout_seconds=180,
        )
