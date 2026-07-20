from __future__ import annotations

import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from .budget import DEFAULT_BUDGETS, resolve_budget
from .candidates import AnnotationService, CandidateArtifactInput, CandidateBundleBuilder
from .config import DiscoverySettings
from .db import SCHEMA_VERSION, DiscoveryRepository
from .doctor import doctor
from .fullstack import CapabilityScanner, ComponentRegistry
from .models import RiskLevel
from .taxonomy import TaxonomyCatalog
from .tools import CommandRunner


class JobCreate(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    target_kind: str = Field(default="source", pattern="^(source|binary)$")
    kind: str = Field(default="discover", pattern="^discover$")
    risk: RiskLevel = RiskLevel.LOW
    backend: str = Field(default="auto", pattern="^(auto|docker|kata|firecracker)$")
    data_class: str = Field(default="internal", pattern="^(public|internal|confidential|restricted)$")
    component_id: str | None = Field(default=None, max_length=120)
    budget_profile: str = Field(default="balanced", pattern="^(quick|balanced|deep)$")
    budget_overrides: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)


class ControlCreate(BaseModel):
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)


class ApprovalCreate(BaseModel):
    scope: str = Field(min_length=1, max_length=200)
    decision: str = Field(pattern="^(approve|deny)$")
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(default="", max_length=2000)
    experiment_digest: str | None = Field(default=None, pattern="^[0-9a-f]{64}$")
    expires_at: str | None = None


class CandidateArtifactCreate(BaseModel):
    path: str = Field(min_length=1, max_length=4096)
    kind: str = Field(min_length=1, max_length=100)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CandidateCreate(BaseModel):
    source_type: str = Field(min_length=1, max_length=100)
    component_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=500)
    data_class: str = Field(default="public", pattern="^(public|internal|confidential|restricted)$")
    external_id: str | None = Field(default=None, max_length=200)
    source_url: str | None = Field(default=None, max_length=4000)
    split_group_id: str | None = Field(default=None, max_length=100)
    artifacts: list[CandidateArtifactCreate] = Field(min_length=1, max_length=50)


class AnnotationCreate(BaseModel):
    annotator: str = Field(min_length=1, max_length=200)
    annotation: dict[str, Any]


def create_app(settings: DiscoverySettings | None = None, *, project_root: str | Path = ".") -> FastAPI:
    resolved = settings or DiscoverySettings.from_env()
    resolved.ensure_directories()
    repository = DiscoveryRepository(resolved.runtime_db)
    repository.migrate()
    registry = ComponentRegistry(resolved.component_registry_path)
    taxonomy = TaxonomyCatalog(resolved.taxonomy_path, resolved.security_properties_path)
    app = FastAPI(title="CVER Autonomous Discovery API", version="2.0.0")

    def require_token(
        authorization: Annotated[str | None, Header()] = None,
        x_api_key: Annotated[str | None, Header()] = None,
    ) -> None:
        if not resolved.api_auth_required:
            return
        if not resolved.api_token:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is enabled but CVER_API_TOKEN is not configured",
            )
        candidate = x_api_key
        if authorization and authorization.lower().startswith("bearer "):
            candidate = authorization[7:].strip()
        if not candidate or not hmac.compare_digest(candidate, resolved.api_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API token")

    protected = Depends(require_token)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "stopped" if resolved.emergency_stop_active() else "ok",
            "service": "cver-autonomous-discovery",
            "milestone": "M1",
            "schema_version": SCHEMA_VERSION,
            "taxonomy_version": taxonomy.version,
            "emergency_stop_active": resolved.emergency_stop_active(),
        }

    @app.get("/v1/doctor", dependencies=[protected])
    def doctor_endpoint() -> dict[str, Any]:
        return doctor(resolved, project_root=project_root)

    @app.post("/v1/jobs", status_code=status.HTTP_202_ACCEPTED, dependencies=[protected])
    def create_job(payload: JobCreate) -> dict[str, Any]:
        if resolved.emergency_stop_active():
            raise HTTPException(status_code=423, detail="emergency stop is active")
        if payload.data_class == "restricted":
            raise HTTPException(
                status_code=400, detail="restricted data cannot be submitted to the cloud-LLM discovery workflow"
            )
        try:
            if payload.component_id:
                registry.get(payload.component_id)
            budget = resolve_budget(payload.budget_profile, payload.budget_overrides)
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        job = repository.submit_job(
            target=payload.target,
            target_kind=payload.target_kind,
            kind=payload.kind,
            risk=payload.risk,
            requested_backend=payload.backend,
            payload={
                **payload.payload,
                "data_class": payload.data_class,
                "component_id": payload.component_id,
                "budget_profile": budget.profile,
                "budget_overrides": payload.budget_overrides,
            },
        )
        return job.to_dict()

    @app.get("/v1/jobs", dependencies=[protected])
    def list_jobs(
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        job_status: str | None = None,
    ) -> list[dict[str, Any]]:
        return [item.to_dict() for item in repository.list_jobs(limit=limit, status=job_status)]

    @app.get("/v1/jobs/{job_id}", dependencies=[protected])
    def get_job(job_id: str) -> dict[str, Any]:
        job = repository.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="job not found")
        return {**job.to_dict(), "events": repository.list_events(job_id)}

    @app.post("/v1/jobs/{job_id}/approvals", dependencies=[protected])
    def approve_job(job_id: str, payload: ApprovalCreate) -> dict[str, Any]:
        if not repository.get_job(job_id):
            raise HTTPException(status_code=404, detail="job not found")
        if payload.decision == "approve" and payload.scope.startswith("experiment:") and not payload.experiment_digest:
            raise HTTPException(status_code=400, detail="experiment approval requires the immutable experiment_digest")
        approval_id = repository.add_approval(
            job_id,
            scope=payload.scope,
            decision=payload.decision,
            actor=payload.actor,
            reason=payload.reason,
            experiment_digest=payload.experiment_digest,
            expires_at=payload.expires_at,
        )
        requeued = payload.decision == "approve" and repository.requeue_job(job_id, reason=f"approval:{payload.scope}")
        return {"approval_id": approval_id, "job_id": job_id, "requeued": requeued, **payload.model_dump()}

    @app.post("/v1/control/emergency-stop", dependencies=[protected])
    def emergency_stop(payload: ControlCreate) -> dict[str, Any]:
        marker = resolved.emergency_stop_file
        marker.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "active": True,
            "actor": payload.actor,
            "reason": payload.reason,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        marker.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        repository.add_audit(payload.actor, "emergency_stop.activated", "control", "global", record)
        return {**record, "path": str(marker)}

    @app.delete("/v1/control/emergency-stop", dependencies=[protected])
    def emergency_resume(payload: ControlCreate) -> dict[str, Any]:
        marker = resolved.emergency_stop_file
        existed = marker.is_file()
        if existed:
            marker.unlink()
        record = {
            "active": resolved.emergency_stop_active(),
            "actor": payload.actor,
            "reason": payload.reason,
            "marker_removed": existed,
            "path": str(marker),
        }
        repository.add_audit(payload.actor, "emergency_stop.cleared", "control", "global", record)
        return record

    @app.get("/v2/capabilities", dependencies=[protected])
    def capabilities() -> dict[str, Any]:
        runner = CommandRunner(timeout_seconds=min(resolved.max_tool_seconds, 60))
        matrix = CapabilityScanner(runner, registry=registry).scan()
        matrix["snapshot_id"] = repository.add_capability_snapshot(matrix)
        return matrix

    @app.get("/v2/taxonomy", dependencies=[protected])
    def taxonomy_endpoint() -> dict[str, Any]:
        return taxonomy.prompt_context()

    @app.get("/v2/budgets", dependencies=[protected])
    def budgets() -> dict[str, Any]:
        return {name: item.to_dict() for name, item in DEFAULT_BUDGETS.items()}

    @app.post("/v2/candidates", status_code=status.HTTP_201_CREATED, dependencies=[protected])
    def create_candidate(payload: CandidateCreate) -> dict[str, Any]:
        try:
            registry.get(payload.component_id)
            return CandidateBundleBuilder(repository, root=resolved.candidates_dir).build(
                source_type=payload.source_type,
                component_id=payload.component_id,
                title=payload.title,
                data_class=payload.data_class,
                external_id=payload.external_id,
                source_url=payload.source_url,
                split_group_id=payload.split_group_id,
                artifacts=[
                    CandidateArtifactInput(Path(item.path), item.kind, item.metadata) for item in payload.artifacts
                ],
            )
        except (KeyError, ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/v2/candidates", dependencies=[protected])
    def candidates(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        component_id: str | None = None,
        candidate_status: str | None = None,
    ) -> list[dict[str, Any]]:
        return repository.list_candidates(limit=limit, component_id=component_id, status=candidate_status)

    @app.post(
        "/v2/candidates/{candidate_id}/annotations", status_code=status.HTTP_201_CREATED, dependencies=[protected]
    )
    def annotate(candidate_id: str, payload: AnnotationCreate) -> dict[str, Any]:
        try:
            return AnnotationService(repository, taxonomy).submit(
                candidate_id, payload.annotation, annotator=payload.annotator
            )
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return app


app = create_app()
