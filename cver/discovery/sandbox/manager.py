from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from ..config import DiscoverySettings
from ..models import ToolResult
from ..tools.runner import CommandRunner
from .base import BackendAvailability, SandboxBackend
from .docker import DockerBackend
from .firecracker import FirecrackerBackend
from .kata import KataBackend


class SandboxManager:
    def __init__(self, settings: DiscoverySettings, runner: CommandRunner, *, project_root: str | Path = ".") -> None:
        self.backends: dict[str, SandboxBackend] = {
            "docker": DockerBackend(settings, runner),
            "kata": KataBackend(settings, runner),
            "firecracker": FirecrackerBackend(settings, runner, project_root=project_root),
        }

    def availability(self) -> dict[str, BackendAvailability]:
        return {name: backend.availability() for name, backend in self.backends.items()}

    def require(self, name: str) -> BackendAvailability:
        if name not in self.backends:
            return BackendAvailability(name, False, "unknown backend", {})
        return self.backends[name].availability()

    def smoke(self, names: Iterable[str] | None = None) -> dict[str, ToolResult]:
        selected = list(names or self.backends.keys())
        return {name: self.backends[name].smoke() for name in selected if name in self.backends}
