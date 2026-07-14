from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .models import EvidenceLevel, RecordType, VerificationStatus


@dataclass(slots=True)
class ValidationIssue:
    code: str
    message: str
    severity: str = "error"


@dataclass(slots=True)
class ValidationReport:
    eligible: bool
    issues: list[ValidationIssue]
    checks: dict[str, bool]

    def to_dict(self) -> dict[str, Any]:
        return {
            "eligible": self.eligible,
            "issues": [
                {"code": issue.code, "message": issue.message, "severity": issue.severity}
                for issue in self.issues
            ],
            "checks": self.checks,
        }


def _nonempty_json(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return bool(value.strip())
    return value not in (None, "", [], {})


def _validated_experiment(experiment: dict[str, Any]) -> bool:
    level = str(experiment.get("validation_level") or "").upper()
    level_rank = {"L0": 0, "L1": 1, "L2": 2, "L3": 3}.get(level, -1)
    return all(
        [
            experiment.get("status") == "completed",
            level_rank >= 1,
            bool(experiment.get("environment_snapshot_id")),
            bool(str(experiment.get("outcome") or "").strip()),
            _nonempty_json(experiment.get("artifacts_json") or experiment.get("artifacts"))
            or _nonempty_json(experiment.get("observations_json") or experiment.get("observations")),
        ]
    )


class GoldAdmissionValidator:
    """Deterministic Gold admission policy. No model-generated field is accepted."""

    ROOT_CAUSE_ALLOWED = {VerificationStatus.VERIFIED.value, VerificationStatus.STRONG.value}

    def validate(self, bundle: dict[str, Any]) -> ValidationReport:
        record = bundle.get("record", {})
        sources = bundle.get("sources", [])
        assertions = bundle.get("assertions", [])
        experiments = bundle.get("experiments", [])
        issues: list[ValidationIssue] = []

        record_type = record.get("record_type")
        evidence_levels = {source.get("authority_level") for source in sources}
        source_types = {source.get("source_type") for source in sources}
        predicates = {assertion.get("predicate") for assertion in assertions}
        validated_experiments = [experiment for experiment in experiments if _validated_experiment(experiment)]

        checks = {
            "has_primary_source": EvidenceLevel.E0_PRIMARY.value in evidence_levels,
            "has_independent_source": EvidenceLevel.E2_INDEPENDENT.value in evidence_levels,
            "has_verified_root_cause": record.get("root_cause_confidence") in self.ROOT_CAUSE_ALLOWED,
            "has_root_cause_labels": bool(record.get("root_cause_l1") and record.get("root_cause_l2")),
            "has_field_evidence": all(assertion.get("evidence_ids") for assertion in assertions) and bool(assertions),
            "has_version_assertions": {"affected_versions", "fixed_versions"}.issubset(predicates),
            "has_patch_or_source_evidence": bool({"patch", "source_code"} & source_types),
            "has_experiment": bool(experiments),
            "has_validated_experiment": bool(validated_experiments),
        }

        required_common = ["has_primary_source", "has_verified_root_cause", "has_root_cause_labels", "has_field_evidence"]
        for check in required_common:
            if not checks[check]:
                issues.append(ValidationIssue(check.upper(), f"Gold admission failed: {check}"))

        if record_type == RecordType.VULNERABILITY.value:
            for check in [
                "has_independent_source",
                "has_version_assertions",
                "has_patch_or_source_evidence",
                "has_experiment",
                "has_validated_experiment",
            ]:
                if not checks[check]:
                    issues.append(ValidationIssue(check.upper(), f"Vulnerability Gold admission failed: {check}"))
        elif record_type == RecordType.MISCONFIGURATION.value:
            for check in ["has_independent_source", "has_experiment", "has_validated_experiment"]:
                if not checks[check]:
                    issues.append(ValidationIssue(check.upper(), f"Misconfiguration Gold admission failed: {check}"))
        elif record_type in {RecordType.ATTACK_PATTERN.value, RecordType.SUPPLY_CHAIN_INCIDENT.value}:
            has_authoritative_case = bool({"peer_reviewed_paper", "incident_report", "official_advisory"} & source_types)
            checks["has_authoritative_case"] = has_authoritative_case
            if not has_authoritative_case:
                issues.append(ValidationIssue("AUTHORITATIVE_CASE_REQUIRED", "Attack pattern or incident requires a paper, incident report, or official advisory"))
        else:
            issues.append(ValidationIssue("UNKNOWN_RECORD_TYPE", f"Unsupported record type: {record_type}"))

        if record.get("generated_by_model"):
            issues.append(ValidationIssue("MODEL_GENERATED_GOLD_FORBIDDEN", "Gold facts must not be generated or decided by a model"))

        unresolved = bundle.get("unresolved_conflicts", [])
        if unresolved:
            issues.append(ValidationIssue("UNRESOLVED_CONFLICTS", "Record has unresolved source conflicts"))

        return ValidationReport(eligible=not any(issue.severity == "error" for issue in issues), issues=issues, checks=checks)
