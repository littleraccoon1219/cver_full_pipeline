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


class DataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class SecurityStatus(str, Enum):
    NON_SECURITY_BUG = "NON_SECURITY_BUG"
    SECURITY_VULNERABILITY = "SECURITY_VULNERABILITY"
    INDETERMINATE = "INDETERMINATE"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


class ClassificationStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    REJECTED = "REJECTED"


class ExploitabilityStatus(str, Enum):
    EXPLOITABLE = "EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    INDETERMINATE = "INDETERMINATE"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"


class ExploitabilityLevel(str, Enum):
    E0 = "E0"  # not affected
    E1 = "E1"  # version may be affected
    E2 = "E2"  # environmental preconditions satisfied
    E3 = "E3"  # trigger reproduced
    E4 = "E4"  # attack chain established
    E5 = "E5"  # controlled real escape reproduced


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
    experiment_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["risk"] = self.risk.value
        return value


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    profile: str
    max_duration_seconds: int
    max_llm_calls: int
    max_experiments: int
    fuzz_budget_seconds: int
    max_deep_experiments: int
    max_api_cost_usd: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
