from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from typing import Any


class RunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped_with_reason"


class FindingStatus(str, enum.Enum):
    CANDIDATE = "candidate"
    SUPPORTED = "supported"
    REJECTED = "rejected"
    NEEDS_DYNAMIC_EVIDENCE = "needs_dynamic_evidence"
    UNREVIEWED = "unreviewed"
    SEALED = "sealed_zero_day"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Evidence:
    evidence_id: str
    kind: str
    source: str
    summary: str
    sha256: str | None = None
    artifact_path: str | None = None
    restricted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    finding_id: str
    component: str
    title: str
    category: str
    severity: Severity
    status: FindingStatus = FindingStatus.CANDIDATE
    confidence: float = 0.0
    file: str | None = None
    line: int | None = None
    description: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    exploitability: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


def to_dict(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {field.name: to_dict(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): to_dict(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_dict(item) for item in value]
    return value
