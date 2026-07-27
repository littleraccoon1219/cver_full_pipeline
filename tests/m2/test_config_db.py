from __future__ import annotations

from cver.m2.config import BUDGETS
from cver.m2.db import M2Repository


def test_balanced_budget_matches_acceptance():
    budget = BUDGETS["balanced"]
    assert budget.parallel_harnesses == 2
    assert budget.fuzz_seconds == 1800
    assert budget.max_tasks_per_component == 6


def test_repository_persists_job_and_events(m2_settings):
    repository = M2Repository(m2_settings.runtime_db)
    assert repository.migrate()["schema_version"] == 2
    job_id = repository.create_job("kata-discovery", "balanced", {"actor": "tester"})
    repository.update_job(job_id, status="running", phase="environment", result={"x": 1})
    repository.event(job_id, "info", "test", "event")
    job = repository.get_job(job_id)
    assert job is not None
    assert job["status"] == "running"
    assert job["result"] == {"x": 1}
    assert any(item["event_type"] == "test" for item in job["events"])
