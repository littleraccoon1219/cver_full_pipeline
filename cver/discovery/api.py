from __future__ import annotations

import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from .config import DiscoverySettings
from .db import DiscoveryRepository
from .doctor import doctor
from .models import RiskLevel


class JobCreate(BaseModel):
    target: str = Field(min_length=1, max_length=4096)
    target_kind: str = Field(default="source", pattern="^(source|binary)$")
    kind: str = Field(default="discover", pattern="^discover$")
    risk: RiskLevel = RiskLevel.LOW
    backend: str = Field(default="auto", pattern="^(auto|docker|kata|firecracker)$")
    data_class: str = Field(default="internal", pattern="^(public|internal|confidential|restricted)$")
    payload: dict[str, Any] = Field(default_factory=dict)


class ControlCreate(BaseModel):
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=2000)


class ApprovalCreate(BaseModel):
    scope: str = Field(min_length=1, max_length=200)
    decision: str = Field(pattern="^(approve|deny)$")
    actor: str = Field(min_length=1, max_length=200)
    reason: str = Field(default="", max_length=2000)


def create_app(settings: DiscoverySettings | None = None, *, project_root: str | Path = ".") -> FastAPI:
    resolved = settings or DiscoverySettings.from_env()
    resolved.ensure_directories()
    repository = DiscoveryRepository(resolved.runtime_db)
    repository.migrate()
    app = FastAPI(title="CVER Autonomous Discovery API", version="1.0.0")

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
            "schema_version": 1,
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
                status_code=400,
                detail="restricted data cannot be submitted to the cloud-LLM discovery workflow",
            )
        job = repository.submit_job(
            target=payload.target,
            target_kind=payload.target_kind,
            kind=payload.kind,
            risk=payload.risk,
            requested_backend=payload.backend,
            payload={**payload.payload, "data_class": payload.data_class},
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
        approval_id = repository.add_approval(
            job_id,
            scope=payload.scope,
            decision=payload.decision,
            actor=payload.actor,
            reason=payload.reason,
        )
        requeued = False
        if payload.decision == "approve":
            requeued = repository.requeue_job(job_id, reason=f"approval:{payload.scope}")
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
        return {**record, "path": str(marker)}

    @app.delete("/v1/control/emergency-stop", dependencies=[protected])
    def emergency_resume(payload: ControlCreate) -> dict[str, Any]:
        marker = resolved.emergency_stop_file
        existed = marker.is_file()
        if existed:
            marker.unlink()
        return {
            "active": resolved.emergency_stop_active(),
            "actor": payload.actor,
            "reason": payload.reason,
            "marker_removed": existed,
            "path": str(marker),
        }

    return app


app = create_app()
