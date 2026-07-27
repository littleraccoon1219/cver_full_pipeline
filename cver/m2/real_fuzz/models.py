from __future__ import annotations

import dataclasses
import enum
from dataclasses import dataclass, field
from typing import Any


class AdapterState(str, enum.Enum):
    COMPATIBLE = "COMPATIBLE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    ADAPTER_REQUIRED = "ADAPTER_REQUIRED"
    APPROVED = "APPROVED"
    SEMANTIC_DRIFT = "ADAPTER_SEMANTIC_DRIFT"
    BUILD_FAILED = "BUILD_FAILED"


class CandidateLevel(str, enum.Enum):
    OBSERVATION = "OBSERVATION"
    WEAK = "WEAK_CANDIDATE"
    STRONG = "STRONG_CANDIDATE"
    VALIDATED = "VALIDATED_CANDIDATE"


class ReplayLevel(str, enum.Enum):
    RPC_ONLY = "L1_RPC_ONLY"
    GUEST_NON_DESTRUCTIVE = "L2_GUEST_NON_DESTRUCTIVE"
    ISOLATION_INVARIANT = "L3_ISOLATION_INVARIANT"


@dataclass(frozen=True, slots=True)
class HandlerTarget:
    handler_id: str
    rust_method: str
    request_type: str
    response_type: str | None
    group: str
    source_path: str
    source_line: int
    signature: str
    signature_sha256: str
    stateful: bool = False
    concurrency_pairs: tuple[str, ...] = ()


@dataclass(slots=True)
class SourceInspection:
    source_root: str
    version: str
    commit: str | None
    rpc_path: str
    rpc_sha256: str
    interface_fingerprint: str
    handlers: list[HandlerTarget]
    missing_handlers: list[str]
    status: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AdapterManifest:
    schema_version: int
    adapter_id: str
    component: str
    version_selector: str
    source_path: str
    approved_interface_fingerprints: list[str]
    handlers: list[dict[str, Any]]
    patch_policy: dict[str, Any]
    approved: bool = False
    approved_by: str | None = None
    approved_at: str | None = None
    source_commit: str | None = None
    source_sha256: str | None = None


@dataclass(slots=True)
class ToolchainStatus:
    stable_rustc: str | None
    stable_cargo: str | None
    pinned_nightly: str
    pinned_nightly_installed: bool
    cargo_fuzz_installed: bool
    llvm_tools_installed: bool
    status: str
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class FuzzExecution:
    run_id: str
    source_track: str
    kata_version: str
    source_commit: str | None
    adapter_id: str
    handler_id: str
    mode: str
    status: str
    command: list[str]
    duration_seconds: float
    exit_code: int | None
    corpus_dir: str
    artifact_dir: str
    coverage: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    reproducibility: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None


@dataclass(slots=True)
class CandidateRecord:
    candidate_id: str
    level: CandidateLevel
    component: str
    kata_version: str
    source_track: str
    handler_id: str
    finding_type: str
    title: str
    evidence: list[dict[str, Any]]
    reproductions: int
    deterministic_seed: int | None
    state_sequence: list[dict[str, Any]]
    isolation_invariant: dict[str, Any] | None
    source_commit: str | None
    adapter_id: str | None
    status_reason: str
    metadata: dict[str, Any] = field(default_factory=dict)


def asdict(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {field.name: asdict(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): asdict(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [asdict(item) for item in value]
    return value
