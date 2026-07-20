from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from cver.discovery.config import DiscoverySettings
from cver.discovery.llm.base import LLMRequest, LLMResponse


@dataclass
class FakeProvider:
    planner_payload: dict[str, Any] | None = None
    name: str = "fake-test-provider"

    def complete_json(self, request: LLMRequest) -> LLMResponse:
        if request.role == "planner":
            data = self.planner_payload or {
                "hypotheses": [
                    {
                        "title": "Synthetic path boundary candidate",
                        "root_cause_l1": "RC-1",
                        "root_cause_l2": "RC-1.2",
                        "security_boundary": "sandbox root",
                        "invariant": "resolved paths remain beneath the sandbox root",
                        "rationale": "A deterministic synthetic fixture can test the evidence gate.",
                        "confidence": 0.8,
                        "experiment_kinds": ["synthetic_fixture"],
                        "known_cve_candidates": [],
                    }
                ],
                "coverage_gaps": [],
            }
        elif request.role == "critic":
            data = {
                "verdict": "supported",
                "supported_claims": ["synthetic boundary violation reproduced"],
                "unsupported_claims": ["novelty and real-world exploitability are not established"],
                "next_experiments": [],
                "recommended_stage": "security_vulnerability",
            }
        else:
            data = {
                "executive_summary": "Synthetic evidence gate completed.",
                "findings": ["A synthetic path boundary violation was reproduced."],
                "limitations": ["No real container escape was attempted."],
                "next_actions": ["Run reviewed target-specific adapters."],
            }
        return LLMResponse(data=data, provider=self.name, model=request.model, response_id="test-response")


@pytest.fixture
def settings(tmp_path: Path) -> DiscoverySettings:
    return DiscoverySettings(
        runtime_db=tmp_path / "runtime.db",
        trusted_kb_db=tmp_path / "trusted.db",
        artifacts_dir=tmp_path / "artifacts",
        workspace_root=tmp_path / "workspaces",
        candidates_dir=tmp_path / "candidates",
        zero_day_vault_dir=tmp_path / "zero_day_vault",
        emergency_stop_file=tmp_path / "EMERGENCY_STOP",
        planner_model="planner-test",
        critic_model="critic-test",
        summary_model="summary-test",
        api_token="test-token",
        api_auth_required=True,
        test_mode=True,
    )
