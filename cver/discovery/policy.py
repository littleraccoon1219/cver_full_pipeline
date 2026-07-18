from __future__ import annotations

from dataclasses import dataclass

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


@dataclass(slots=True)
class PolicyContext:
    job_id: str
    target: str
    target_kind: str
    experiment_kind: ExperimentKind
    requested_backend: str = "auto"
    human_approved: bool = False


class DiscoveryPolicy:
    """Non-bypassable policy for all active experiments.

    The LLM selects an experiment *kind* only. It never supplies a command line.
    Commands are constructed by trusted adapters after this decision.
    """

    def __init__(self, settings: DiscoverySettings) -> None:
        self.settings = settings

    def decide(self, context: PolicyContext) -> PolicyDecision:
        risk = _EXPERIMENT_RISK[context.experiment_kind]
        required_backend = _RISK_BACKEND[risk]
        reasons: list[str] = []
        requires_approval = risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}

        if context.requested_backend not in {"auto", "docker", "kata", "firecracker"}:
            return PolicyDecision(False, "deny", risk, None, ["unknown sandbox backend"])

        selected = required_backend if context.requested_backend == "auto" else context.requested_backend
        if _BACKEND_STRENGTH[selected] < _BACKEND_STRENGTH[required_backend]:
            return PolicyDecision(
                False,
                "deny",
                risk,
                selected,
                [f"{context.experiment_kind.value} requires at least {required_backend}"],
                requires_human_approval=requires_approval,
            )

        if context.experiment_kind == ExperimentKind.HISTORICAL_POC:
            if not self.settings.disposable_lab_ready:
                reasons.append("BLOCKED_NO_DISPOSABLE_LAB")
            if not self.settings.allow_historical_poc:
                reasons.append("historical PoC feature flag is disabled")
            if not context.human_approved:
                reasons.append("explicit high-risk human approval is required")
            if reasons:
                return PolicyDecision(False, "deny", risk, selected, reasons, True)

        if requires_approval and not context.human_approved:
            return PolicyDecision(False, "await_approval", risk, selected, ["high-risk experiment requires human approval"], True)

        return PolicyDecision(True, "allow", risk, selected, ["policy passed"], requires_approval)
