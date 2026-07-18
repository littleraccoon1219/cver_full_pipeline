"""Evidence-gated autonomous container-vulnerability discovery subsystem.

Imports are lazy so the stdlib-only database migration can run before optional
runtime dependencies are installed.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "DiscoveryRepository",
    "DiscoverySettings",
    "ExperimentKind",
    "JobStatus",
    "PromotionStage",
    "RiskLevel",
]


def __getattr__(name: str) -> Any:
    if name == "DiscoverySettings":
        from .config import DiscoverySettings

        return DiscoverySettings
    if name == "DiscoveryRepository":
        from .db import DiscoveryRepository

        return DiscoveryRepository
    if name in {"ExperimentKind", "JobStatus", "PromotionStage", "RiskLevel"}:
        from . import models

        return getattr(models, name)
    raise AttributeError(name)
