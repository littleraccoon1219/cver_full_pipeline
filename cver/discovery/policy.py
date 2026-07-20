from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .config import DiscoverySettings
from .models import ExperimentKind, PolicyDecision, RiskLevel

_BACKEND_STRENGTH = {"docker": 1, "kata": 2, "firecracker": 3}
_RISK_BACKEND = {
    RiskLevel.LOW: "docker",
    RiskLevel.MEDIUM: "kata",
    RiskLevel.HIGH: "firecracker",
    RiskLevel.CRITICAL: "firecracker",
}
_EXPERIMENT_RISK = {
    ExperimentKind.VERSION_CHECK: RiskLevel.LOW,
    ExperimentKind.SEMGREP_SCAN: RiskLevel.LOW,
    ExperimentKind.GO_TEST: RiskLevel.MEDIUM,
    ExperimentKind.GO_FUZZ: RiskLevel.HIGH,
    ExperimentKind.PATCH_DIFF: RiskLevel.LOW,
    ExperimentKind.SYNTHETIC_FIXTURE: RiskLevel.LOW,
    ExperimentKind.TRACEE_OBSERVE: RiskLevel.MEDIUM,
    ExperimentKind.HISTORICAL_POC: RiskLevel.CRITICAL,
}
_RISK_ORDER = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def max_risk(*risks: RiskLevel) -> RiskLevel:
    return max(risks, key=lambda value: _RISK_ORDER[value])


@dataclass(slots=True)
class PolicyContext:
    job_id: str
    target: str
    target_kind: str
    experiment_kind: ExperimentKind
    requested_backend: str = "auto"
    human_approved: bool = False
    job_risk: RiskLevel = RiskLevel.LOW
    target_risk: RiskLevel = RiskLevel.LOW
    architecture: str = "unknown"
    data_class: str = "internal"
    network_mode: str = "online-audited"
    experiment_spec: dict[str, Any] = field(default_factory=dict)


class DiscoveryPolicy:
    """Non-bypassable policy for all active experiments.

    The LLM selects a reviewed experiment kind only. Trusted adapters build the
    executable spec. High-risk approval is bound to the immutable digest of the
    complete experiment package, not merely a job name or scope string.
    """

    def __init__(self, settings: DiscoverySettings) -> None:
        self.settings = settings

    @staticmethod
    def experiment_digest(context: PolicyContext) -> str:
        payload = {
            "schema": "cver-immutable-experiment-v1",
            "job_id": context.job_id,
            "target": context.target,
            "target_kind": context.target_kind,
            "experiment_kind": context.experiment_kind.value,
            "requested_backend": context.requested_backend,
            "job_risk": context.job_risk.value,
            "target_risk": context.target_risk.value,
            "architecture": context.architecture,
            "data_class": context.data_class,
            "network_mode": context.network_mode,
            "experiment_spec": context.experiment_spec,
        }
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def decide(self, context: PolicyContext) -> PolicyDecision:
        experiment_digest = self.experiment_digest(context)
        risk = max_risk(_EXPERIMENT_RISK[context.experiment_kind], context.job_risk, context.target_risk)
        required_backend = _RISK_BACKEND[risk]
        reasons: list[str] = []
        requires_approval = risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}

        if context.data_class == "restricted":
            return PolicyDecision(
                False,
                "deny",
                risk,
                None,
                ["restricted evidence cannot enter the cloud-LLM experiment workflow"],
                requires_human_approval=requires_approval,
                experiment_digest=experiment_digest,
            )
        if context.requested_backend not in {"auto", "docker", "kata", "firecracker"}:
            return PolicyDecision(
                False, "deny", risk, None, ["unknown sandbox backend"], experiment_digest=experiment_digest
            )

        selected = required_backend if context.requested_backend == "auto" else context.requested_backend
        if _BACKEND_STRENGTH[selected] < _BACKEND_STRENGTH[required_backend]:
            return PolicyDecision(
                False,
                "deny",
                risk,
                selected,
                [f"composed risk {risk.value} requires at least {required_backend}"],
                requires_human_approval=requires_approval,
                experiment_digest=experiment_digest,
            )

        if context.experiment_kind == ExperimentKind.HISTORICAL_POC:
            if not self.settings.disposable_lab_ready:
                reasons.append("BLOCKED_NO_DISPOSABLE_LAB")
            if not self.settings.allow_historical_poc:
                reasons.append("historical PoC feature flag is disabled")
            if not context.human_approved:
                reasons.append("approval matching the immutable experiment digest is required")
            if reasons:
                return PolicyDecision(False, "deny", risk, selected, reasons, True, experiment_digest)

        if requires_approval and not context.human_approved:
            return PolicyDecision(
                False,
                "await_approval",
                risk,
                selected,
                ["high-risk experiment requires approval for this exact immutable digest"],
                True,
                experiment_digest,
            )

        return PolicyDecision(True, "allow", risk, selected, ["policy passed"], requires_approval, experiment_digest)
