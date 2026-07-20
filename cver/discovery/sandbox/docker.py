from __future__ import annotations

import shutil

from ..config import DiscoverySettings
from ..models import ToolResult
from ..tools.runner import CommandRunner
from .base import BackendAvailability


class DockerBackend:
    name = "docker"

    def __init__(self, settings: DiscoverySettings, runner: CommandRunner) -> None:
        self.settings = settings
        self.runner = runner

    def availability(self) -> BackendAvailability:
        if not shutil.which("docker"):
            return BackendAvailability(self.name, False, "docker executable not found", {})
        result = self.runner.run(["docker", "info", "--format", "{{json .ServerVersion}}"], tool="docker")
        return BackendAvailability(
            self.name,
            result.status == "succeeded",
            "available"
            if result.status == "succeeded"
            else (result.reason or result.stderr.strip() or "docker daemon unavailable"),
            {"server_version": result.stdout.strip()},
        )

    def smoke(self) -> ToolResult:
        available = self.availability()
        if not available.available:
            return ToolResult("skipped_with_reason", "docker", [], None, "", "", 0, reason=available.reason)
        return self.runner.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--cpus",
                "0.5",
                self.settings.docker_image,
                "/bin/echo",
                "CVER_DOCKER_SMOKE_OK",
            ],
            tool="docker-smoke",
            timeout_seconds=90,
        )
