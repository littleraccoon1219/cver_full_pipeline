from __future__ import annotations

from cver.discovery.db import DiscoveryRepository
from cver.discovery.models import JobStatus, RiskLevel


def test_durable_queue_claim_and_finish(tmp_path):
    repository = DiscoveryRepository(tmp_path / "runtime.db")
    repository.migrate()
    submitted = repository.submit_job(target=str(tmp_path), risk=RiskLevel.LOW)
    claimed = repository.claim_next("worker-1", lease_seconds=30)
    assert claimed is not None
    assert claimed.job_id == submitted.job_id
    assert claimed.status == JobStatus.RUNNING
    assert claimed.attempts == 1

    repository.finish_job(claimed.job_id, {"ok": True})
    finished = repository.get_job(claimed.job_id)
    assert finished is not None
    assert finished.status == JobStatus.SUCCEEDED
    assert finished.result == {"ok": True}
    assert [event["event_type"] for event in repository.list_events(claimed.job_id)] == [
        "job.submitted",
        "job.claimed",
        "job.succeeded",
    ]


def test_waiting_job_can_be_requeued_after_scoped_approval(tmp_path):
    repository = DiscoveryRepository(tmp_path / "runtime.db")
    repository.migrate()
    submitted = repository.submit_job(target=str(tmp_path), risk=RiskLevel.HIGH)
    repository.finish_job(
        submitted.job_id,
        {"workflow_status": "waiting_approval"},
        status=JobStatus.WAITING_APPROVAL,
    )
    approval_id = repository.add_approval(
        submitted.job_id,
        scope="experiment:go_fuzz",
        decision="approve",
        actor="test-operator",
        reason="reviewed bounded experiment",
    )
    assert approval_id.startswith("appr-")
    assert repository.requeue_job(submitted.job_id, reason="approval:experiment:go_fuzz") is True
    requeued = repository.get_job(submitted.job_id)
    assert requeued is not None
    assert requeued.status == JobStatus.QUEUED
    assert repository.list_events(submitted.job_id)[-1]["event_type"] == "job.requeued"
