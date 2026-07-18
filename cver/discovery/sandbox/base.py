from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol

from ..models import ToolResult


@dataclass(frozen=True, slots=True)
class BackendAvailability:
    name: str
    available: bool
    reason: str
    details: dict[str, str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class SandboxBackend(Protocol):
    name: str

    def availability(self) -> BackendAvailability:
        ...

    def smoke(self) -> ToolResult:
        ...
