from __future__ import annotations

from cver.discovery.models import ExperimentKind
from cver.discovery.policy import DiscoveryPolicy, PolicyContext


def test_low_risk_uses_docker(settings):
    decision = DiscoveryPolicy(settings).decide(
        PolicyContext("job", "/tmp/target", "source", ExperimentKind.SEMGREP_SCAN)
    )
    assert decision.allowed
    assert decision.backend == "docker"


def test_historical_poc_is_hard_blocked_without_disposable_lab(settings):
    decision = DiscoveryPolicy(settings).decide(
        PolicyContext(
            "job",
            "/tmp/target",
            "source",
            ExperimentKind.HISTORICAL_POC,
            human_approved=True,
        )
    )
    assert not decision.allowed
    assert "BLOCKED_NO_DISPOSABLE_LAB" in decision.reasons
