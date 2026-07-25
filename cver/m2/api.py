from __future__ import annotations

import html
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .config import M2Settings
from .db import M2Repository
from .reporting import redact
from .workflow import M2Workflow

try:
    from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import HTMLResponse
except ImportError:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment]


_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cver-m2")


def create_app(settings: M2Settings | None = None):
    if FastAPI is None:
        raise RuntimeError("FastAPI is not installed")
    resolved = settings or M2Settings.from_env()
    workflow = M2Workflow(resolved)
    repository = M2Repository(resolved.runtime_db)
    app = FastAPI(title="CVER M2 Kata Discovery", version="0.1.0")

    def auth(
        authorization: str | None = Header(default=None),
        x_api_key: str | None = Header(default=None),
    ) -> None:
        if not resolved.api_token:
            return
        provided = x_api_key or (authorization[7:] if authorization and authorization.startswith("Bearer ") else None)
        if provided != resolved.api_token:
            raise HTTPException(status_code=401, detail="invalid API token")

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "stage": "M2", "namespace": resolved.namespace}

    @app.get("/api/m2/dashboard", dependencies=[Depends(auth)])
    def dashboard() -> dict[str, Any]:
        return redact(repository.dashboard())

    @app.get("/api/m2/jobs", dependencies=[Depends(auth)])
    def list_jobs(limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        return redact(repository.list_jobs(limit=limit, status=status))

    @app.get("/api/m2/jobs/{job_id}", dependencies=[Depends(auth)])
    def get_job(job_id: str) -> dict[str, Any]:
        job = repository.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return redact(job)

    @app.post("/api/m2/jobs", status_code=202, dependencies=[Depends(auth)])
    def submit(payload: dict[str, Any], background: BackgroundTasks) -> dict[str, Any]:
        job_id = workflow.submit(payload)
        background.add_task(_EXECUTOR.submit, workflow.run, job_id)
        return {"job_id": job_id, "status": "queued"}

    @app.post("/api/m2/jobs/{job_id}/resume", status_code=202, dependencies=[Depends(auth)])
    def resume(job_id: str, background: BackgroundTasks) -> dict[str, Any]:
        if repository.get_job(job_id) is None:
            raise HTTPException(status_code=404, detail="job not found")
        background.add_task(_EXECUTOR.submit, workflow.run, job_id, resume=True)
        return {"job_id": job_id, "status": "resume_queued"}

    @app.get("/", response_class=HTMLResponse)
    def web_console(request: Request) -> str:
        data = redact(repository.dashboard())
        rows = []
        for job in data.get("recent_jobs", []):
            job_id = html.escape(str(job.get("job_id", "")))
            rows.append(
                "<tr>"
                f"<td><a href='/m2/jobs/{job_id}'>{job_id}</a></td>"
                f"<td>{html.escape(str(job.get('status', '')))}</td>"
                f"<td>{html.escape(str(job.get('phase', '')))}</td>"
                f"<td>{html.escape(str(job.get('profile', '')))}</td>"
                "</tr>"
            )
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>CVER M2</title>"
            "<style>body{font:15px system-ui;max-width:1200px;margin:30px auto;padding:0 20px}"
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #bbb;padding:8px;text-align:left}"
            "pre{white-space:pre-wrap;background:#f3f3f3;padding:12px}</style></head><body>"
            "<h1>CVER M2 · Kata漏洞发掘控制台</h1>"
            "<p>界面仅展示脱敏摘要。Corpus、触发输入和疑似0-day完整调用路径不会直接显示。</p>"
            f"<pre>{html.escape(json.dumps(data, ensure_ascii=False, indent=2, default=str))}</pre>"
            "<h2>Recent jobs</h2><table><tr><th>Job</th><th>Status</th><th>Phase</th><th>Profile</th></tr>"
            + "".join(rows)
            + "</table></body></html>"
        )

    @app.get("/m2/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(job_id: str) -> str:
        job = repository.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        safe = redact(job)
        return (
            "<!doctype html><html><head><meta charset='utf-8'><title>CVER M2 Job</title>"
            "<style>body{font:14px system-ui;max-width:1200px;margin:30px auto;padding:0 20px}"
            "pre{white-space:pre-wrap;background:#f3f3f3;padding:12px}</style></head><body>"
            f"<h1>{html.escape(job_id)}</h1>"
            f"<pre>{html.escape(json.dumps(safe, ensure_ascii=False, indent=2, default=str))}</pre>"
            "</body></html>"
        )

    return app


app = create_app() if FastAPI is not None else None
