from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .budget import resolve_budget
from .candidates import AnnotationService, CandidateArtifactInput, CandidateBundleBuilder
from .config import DiscoverySettings
from .db import DiscoveryRepository
from .doctor import doctor
from .fullstack import CapabilityScanner, ComponentRegistry
from .historical import HistoricalReplay
from .models import RiskLevel
from .sandbox import SandboxManager
from .taxonomy import TaxonomyCatalog
from .tools import CommandRunner
from .zeroday import ZeroDayVault, master_key_provider


def print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _runtime() -> tuple[DiscoverySettings, DiscoveryRepository]:
    settings = DiscoverySettings.from_env()
    settings.ensure_directories()
    repository = DiscoveryRepository(settings.runtime_db)
    repository.migrate()
    return settings, repository


def init_runtime() -> dict[str, Any]:
    _, repository = _runtime()
    return repository.migrate()


def submit(
    *,
    target: str,
    target_kind: str,
    risk: str,
    backend: str,
    kind: str = "discover",
    payload: dict[str, Any] | None = None,
    data_class: str = "internal",
    component_id: str | None = None,
    budget_profile: str | None = None,
) -> dict[str, Any]:
    settings, repository = _runtime()
    if settings.emergency_stop_active():
        raise SystemExit(f"emergency stop is active: {settings.emergency_stop_file}")
    if target_kind not in {"source", "binary"}:
        raise SystemExit(f"target kind {target_kind!r} is reserved for a later reviewed adapter")
    if data_class == "restricted":
        raise SystemExit("restricted data cannot be submitted to the cloud-LLM discovery workflow")
    if data_class not in {"public", "internal", "confidential"}:
        raise SystemExit(f"unsupported data classification: {data_class}")
    if component_id:
        ComponentRegistry(settings.component_registry_path).get(component_id)
    profile = budget_profile or settings.default_budget_profile
    resolve_budget(profile)
    merged_payload = {
        **(payload or {}),
        "data_class": data_class,
        "component_id": component_id,
        "budget_profile": profile,
    }
    job = repository.submit_job(
        target=target,
        target_kind=target_kind,
        kind=kind,
        risk=RiskLevel(risk),
        requested_backend=backend,
        payload=merged_payload,
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
        component_id="application-dependencies",
        budget_profile="quick",
    )


def status(job_id: str) -> dict[str, Any]:
    _, repository = _runtime()
    job = repository.get_job(job_id)
    if not job:
        raise SystemExit(f"job not found: {job_id}")
    return {**job.to_dict(), "events": repository.list_events(job_id)}


def list_jobs(limit: int, job_status: str | None = None) -> list[dict[str, Any]]:
    _, repository = _runtime()
    return [item.to_dict() for item in repository.list_jobs(limit=limit, status=job_status)]


def approve(
    job_id: str,
    *,
    scope: str,
    actor: str,
    reason: str,
    decision: str = "approve",
    experiment_digest: str | None = None,
    expires_at: str | None = None,
) -> dict[str, Any]:
    _, repository = _runtime()
    if not repository.get_job(job_id):
        raise SystemExit(f"job not found: {job_id}")
    if scope.startswith("experiment:") and decision == "approve" and not experiment_digest:
        raise SystemExit("experiment approvals must include --experiment-digest from the waiting experiment record")
    approval_id = repository.add_approval(
        job_id,
        scope=scope,
        decision=decision,
        actor=actor,
        reason=reason,
        experiment_digest=experiment_digest,
        expires_at=expires_at,
    )
    requeued = repository.requeue_job(job_id, reason=f"approval:{scope}") if decision == "approve" else False
    return {
        "approval_id": approval_id,
        "job_id": job_id,
        "scope": scope,
        "decision": decision,
        "experiment_digest": experiment_digest,
        "expires_at": expires_at,
        "requeued": requeued,
    }


def emergency_stop(*, actor: str, reason: str) -> dict[str, Any]:
    settings, repository = _runtime()
    marker = settings.emergency_stop_file
    marker.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "active": True,
        "actor": actor,
        "reason": reason,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    marker.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    repository.add_audit(actor, "emergency_stop.activated", "control", "global", payload)
    return {**payload, "path": str(marker)}


def emergency_resume(*, actor: str, reason: str) -> dict[str, Any]:
    settings, repository = _runtime()
    marker = settings.emergency_stop_file
    existed = marker.is_file()
    if existed:
        marker.unlink()
    payload = {
        "active": settings.emergency_stop_active(),
        "actor": actor,
        "reason": reason,
        "marker_removed": existed,
        "path": str(marker),
    }
    repository.add_audit(actor, "emergency_stop.cleared", "control", "global", payload)
    return payload


def discovery_doctor(project_root: str = ".") -> dict[str, Any]:
    return doctor(DiscoverySettings.from_env(), project_root=project_root)


def capability_matrix() -> dict[str, Any]:
    settings, repository = _runtime()
    runner = CommandRunner(timeout_seconds=min(settings.max_tool_seconds, 60))
    matrix = CapabilityScanner(runner, registry=ComponentRegistry(settings.component_registry_path)).scan()
    matrix["snapshot_id"] = repository.add_capability_snapshot(matrix)
    return matrix


def taxonomy_report() -> dict[str, Any]:
    settings, _ = _runtime()
    catalog = TaxonomyCatalog(settings.taxonomy_path, settings.security_properties_path)
    return catalog.prompt_context()


def ingest_candidate(
    *,
    source_type: str,
    component_id: str,
    title: str,
    data_class: str,
    artifact_specs: list[str],
    external_id: str | None = None,
    source_url: str | None = None,
    split_group_id: str | None = None,
) -> dict[str, Any]:
    settings, repository = _runtime()
    ComponentRegistry(settings.component_registry_path).get(component_id)
    artifacts: list[CandidateArtifactInput] = []
    for value in artifact_specs:
        if "=" not in value:
            raise SystemExit("artifact must use KIND=/path/to/file")
        kind, path = value.split("=", 1)
        artifacts.append(CandidateArtifactInput(Path(path), kind))
    return CandidateBundleBuilder(repository, root=settings.candidates_dir).build(
        source_type=source_type,
        component_id=component_id,
        title=title,
        data_class=data_class,
        artifacts=artifacts,
        external_id=external_id,
        source_url=source_url,
        split_group_id=split_group_id,
    )


def list_candidates(
    *, limit: int = 100, component_id: str | None = None, status: str | None = None
) -> list[dict[str, Any]]:
    _, repository = _runtime()
    return repository.list_candidates(limit=limit, component_id=component_id, status=status)


def annotate_candidate(candidate_id: str, *, annotation_file: str, annotator: str) -> dict[str, Any]:
    settings, repository = _runtime()
    payload = json.loads(Path(annotation_file).read_text(encoding="utf-8"))
    catalog = TaxonomyCatalog(settings.taxonomy_path, settings.security_properties_path)
    return AnnotationService(repository, catalog).submit(candidate_id, payload, annotator=annotator)


def seal_zero_day_case(
    *,
    files: list[str],
    metadata_file: str,
    actor: str,
    job_id: str | None = None,
    hypothesis_id: str | None = None,
) -> dict[str, Any]:
    settings, repository = _runtime()
    metadata = json.loads(Path(metadata_file).read_text(encoding="utf-8"))
    provider = master_key_provider(settings.zero_day_key_mode)
    vault = ZeroDayVault(repository, root=settings.zero_day_vault_dir, master_key=provider)
    return vault.seal_case(
        files=files,
        metadata=metadata,
        actor=actor,
        job_id=job_id,
        hypothesis_id=hypothesis_id,
    )


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
