from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cver.discovery.db import DiscoveryRepository
from cver.discovery.factory import build_workflow
from cver.discovery.models import RiskLevel

from .conftest import FakeProvider


@pytest.mark.skipif(not shutil.which("go"), reason="Go is required for the synthetic fixture")
def test_synthetic_evidence_gates_to_security_vulnerability(settings):
    project_root = Path(__file__).parents[2]
    repository = DiscoveryRepository(settings.runtime_db)
    job = repository.submit_job(
        target=str(project_root),
        target_kind="source",
        risk=RiskLevel.LOW,
        payload={"benchmark_mode": "synthetic_pathguard"},
    )
    workflow = build_workflow(
        settings,
        provider=FakeProvider(),
        project_root=project_root,
    )
    result = workflow.process(job)
    assert result["hypotheses"][0]["adjudicated_stage"] == "security_vulnerability"
    assert Path(result["report_artifact"]).is_file()


def test_synthetic_fixture_is_not_target_evidence_without_benchmark_flag(settings):
    project_root = Path(__file__).parents[2]
    repository = DiscoveryRepository(settings.runtime_db)
    job = repository.submit_job(target=str(project_root), target_kind="source", risk=RiskLevel.LOW)
    workflow = build_workflow(settings, provider=FakeProvider(), project_root=project_root)
    result = workflow.process(job)
    report = result["hypotheses"][0]
    assert report["adjudicated_stage"] == "candidate_defect"
    assert report["experiments"][0]["status"] == "skipped_with_reason"
