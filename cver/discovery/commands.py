from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import DiscoverySettings
from .db import DiscoveryRepository
from .doctor import doctor
from .historical import HistoricalReplay
from .models import RiskLevel
from .sandbox import SandboxManager
from .tools import CommandRunner


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def init_runtime() -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    settings.ensure_directories()
    return DiscoveryRepository(settings.runtime_db).migrate()


def submit(
    *,
    target: str,
    target_kind: str,
    risk: str,
    backend: str,
    kind: str = "discover",
    payload: dict[str, Any] | None = None,
    data_class: str = "internal",
) -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    if settings.emergency_stop_active():
        raise SystemExit(f"emergency stop is active: {settings.emergency_stop_file}")
    if target_kind not in {"source", "binary"}:
        raise SystemExit(f"target kind {target_kind!r} is reserved for a later reviewed adapter")
    if data_class == "restricted":
        raise SystemExit("restricted data cannot be submitted to the cloud-LLM discovery workflow")
    if data_class not in {"public", "internal", "confidential"}:
        raise SystemExit(f"unsupported data classification: {data_class}")
    settings.ensure_directories()
    repository = DiscoveryRepository(settings.runtime_db)
    job = repository.submit_job(
        target=target,
        target_kind=target_kind,
        kind=kind,
        risk=RiskLevel(risk),
        requested_backend=backend,
        payload={**(payload or {}), "data_class": data_class},
    )
    return job.to_dict()


def submit_synthetic_benchmark(*, name: str = "synthetic_pathguard", project_root: str = ".") -> dict[str, Any]:
    if name != "synthetic_pathguard":
        raise SystemExit(f"unsupported benchmark: {name}")
    root = Path(project_root).expanduser().resolve()
    fixture = root / "benchmarks" / "synthetic_pathguard"
    if not (fixture / "go.mod").is_file():
        raise SystemExit(f"synthetic benchmark fixture not found: {fixture}")
    return submit(
        target=str(root),
        target_kind="source",
        risk=RiskLevel.LOW.value,
        backend="docker",
        payload={"benchmark_mode": name, "fixture": str(fixture)},
        data_class="public",
    )


def status(job_id: str) -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    repository = DiscoveryRepository(settings.runtime_db)
    job = repository.get_job(job_id)
    if not job:
        raise SystemExit(f"job not found: {job_id}")
    return {**job.to_dict(), "events": repository.list_events(job_id)}


def list_jobs(limit: int, job_status: str | None = None) -> list[dict[str, Any]]:
    settings = DiscoverySettings.from_env()
    repository = DiscoveryRepository(settings.runtime_db)
    repository.migrate()
    return [item.to_dict() for item in repository.list_jobs(limit=limit, status=job_status)]


def approve(job_id: str, *, scope: str, actor: str, reason: str, decision: str = "approve") -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    repository = DiscoveryRepository(settings.runtime_db)
    if not repository.get_job(job_id):
        raise SystemExit(f"job not found: {job_id}")
    approval_id = repository.add_approval(job_id, scope=scope, decision=decision, actor=actor, reason=reason)
    requeued = repository.requeue_job(job_id, reason=f"approval:{scope}") if decision == "approve" else False
    return {
        "approval_id": approval_id,
        "job_id": job_id,
        "scope": scope,
        "decision": decision,
        "requeued": requeued,
    }


def emergency_stop(*, actor: str, reason: str) -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    marker = settings.emergency_stop_file
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "active": True,
        "actor": actor,
        "reason": reason,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    marker.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return {**payload, "path": str(marker)}


def emergency_resume(*, actor: str, reason: str) -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    marker = settings.emergency_stop_file
    existed = marker.is_file()
    if existed:
        marker.unlink()
    return {
        "active": settings.emergency_stop_active(),
        "actor": actor,
        "reason": reason,
        "marker_removed": existed,
        "path": str(marker),
    }


def discovery_doctor(project_root: str = ".") -> dict[str, Any]:
    return doctor(DiscoverySettings.from_env(), project_root=project_root)


def sandbox_smoke(backends: list[str], project_root: str = ".") -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    if settings.emergency_stop_active():
        raise SystemExit(f"emergency stop is active: {settings.emergency_stop_file}")
    runner = CommandRunner(
        timeout_seconds=settings.max_tool_seconds,
        cancel_check=settings.emergency_stop_active,
    )
    manager = SandboxManager(settings, runner, project_root=project_root)
    return {name: result.to_dict() for name, result in manager.smoke(backends or None).items()}


def historical_replay(case_id: str, target: str, project_root: str = ".") -> dict[str, Any]:
    settings = DiscoverySettings.from_env()
    runner = CommandRunner(timeout_seconds=settings.max_tool_seconds)
    replay = HistoricalReplay(Path(project_root) / "data/benchmarks/historical_runc_cves.yaml", runner)
    return replay.replay(case_id, target)
