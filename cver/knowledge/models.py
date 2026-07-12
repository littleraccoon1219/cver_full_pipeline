from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class RecordType(str, Enum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    ATTACK_PATTERN = "attack_pattern"
    SUPPLY_CHAIN_INCIDENT = "supply_chain_incident"


class RecordStatus(str, Enum):
    CANDIDATE = "candidate"
    NORMALIZED = "normalized"
    ANNOTATED = "annotated"
    VERIFIED = "verified"
    GOLD = "gold"
    DEPRECATED = "deprecated"
    CONFLICTED = "conflicted"


class EvidenceLevel(str, Enum):
    E0_PRIMARY = "E0"
    E1_AUTHORITY = "E1"
    E2_INDEPENDENT = "E2"
    E3_EXPERIMENT = "E3"
    E4_INFERRED = "E4"


class VerificationStatus(str, Enum):
    VERIFIED = "verified"
    STRONG = "strong"
    MODERATE = "moderate"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class TriState(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class KnowledgeRecord:
    record_id: str
    record_type: RecordType
    title_en: str
    title_zh: str = ""
    external_id: str = ""
    status: RecordStatus = RecordStatus.CANDIDATE
    root_cause_l1: str = ""
    root_cause_l2: str = ""
    root_cause_confidence: VerificationStatus = VerificationStatus.UNKNOWN
    summary_en: str = ""
    summary_zh: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["record_type"] = self.record_type.value
        data["status"] = self.status.value
        data["root_cause_confidence"] = self.root_cause_confidence.value
        return data


@dataclass(slots=True)
class Source:
    source_id: str
    name: str
    source_type: str
    authority_level: EvidenceLevel
    url: str = ""
    publisher: str = ""
    license_name: str = "unknown"
    retrieved_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["authority_level"] = self.authority_level.value
        return data


@dataclass(slots=True)
class EvidenceFragment:
    evidence_id: str
    source_id: str
    snapshot_id: str
    locator: str
    excerpt: str
    evidence_level: EvidenceLevel
    content_hash: str
    language: str = "en"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence_level"] = self.evidence_level.value
        return data


@dataclass(slots=True)
class Assertion:
    assertion_id: str
    record_id: str
    predicate: str
    object_value: Any
    evidence_ids: list[str]
    verification_status: VerificationStatus
    asserted_by: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verification_status"] = self.verification_status.value
        return data


@dataclass(slots=True)
class EnvironmentProfile:
    environment_id: str
    name: str
    architecture: str
    runtime: str
    description: str = ""
    facts: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuleDefinition:
    rule_id: str
    record_id: str
    version: str
    expression: dict[str, Any]
    evidence_ids: list[str] = field(default_factory=list)
    description_zh: str = ""
    description_en: str = ""


@dataclass(slots=True)
class RuleEvaluation:
    rule_id: str
    environment_id: str
    result: TriState
    trace: list[dict[str, Any]]
    evaluator_version: str
    input_hash: str
