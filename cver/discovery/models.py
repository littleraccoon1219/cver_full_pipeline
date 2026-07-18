from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PromotionStage(str, Enum):
    CANDIDATE_DEFECT = "candidate_defect"
    REPRODUCIBLE_BUG = "reproducible_bug"
    SECURITY_VULNERABILITY = "security_vulnerability"
    EXPLOITABLE_ZERO_DAY = "exploitable_zero_day"


class ExperimentKind(str, Enum):
    VERSION_CHECK = "version_check"
    SEMGREP_SCAN = "semgrep_scan"
    GO_TEST = "go_test"
    GO_FUZZ = "go_fuzz"
    PATCH_DIFF = "patch_diff"
    SYNTHETIC_FIXTURE = "synthetic_fixture"
    TRACEE_OBSERVE = "tracee_observe"
    HISTORICAL_POC = "historical_poc"


@dataclass(slots=True)
class Job:
    job_id: str
    kind: str
    target: str
    target_kind: str
    status: JobStatus
    risk: RiskLevel
    requested_backend: str
    selected_backend: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    error: str | None = None
    attempts: int = 0
    max_attempts: int = 3
    leased_by: str | None = None
    lease_expires_at: str | None = None
    created_at: str | None = None
    updated_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        value["risk"] = self.risk.value
        return value


@dataclass(slots=True)
class Hypothesis:
    title: str
    root_cause_l1: str
    root_cause_l2: str
    security_boundary: str
    invariant: str
    rationale: str
    confidence: float
    experiment_kinds: list[str]
    known_cve_candidates: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ToolResult:
    status: str
    tool: str
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_ms: int
    artifact_paths: list[str] = field(default_factory=list)
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    decision: str
    risk: RiskLevel
    backend: str | None
    reasons: list[str]
    requires_human_approval: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["risk"] = self.risk.value
        return value
