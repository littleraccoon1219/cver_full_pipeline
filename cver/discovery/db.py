from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import Job, JobStatus, RiskLevel

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class DiscoveryRepository:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            yield connection
        finally:
            connection.close()

    def migrate(self) -> dict[str, Any]:
        with self.connect() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS discovery_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS discovery_jobs(
                    job_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    requested_backend TEXT NOT NULL,
                    selected_backend TEXT,
                    payload_json TEXT NOT NULL,
                    result_json TEXT,
                    error TEXT,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_attempts INTEGER NOT NULL DEFAULT 3,
                    leased_by TEXT,
                    lease_expires_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_discovery_jobs_claim
                    ON discovery_jobs(status, lease_expires_at, created_at);
                CREATE TABLE IF NOT EXISTS discovery_events(
                    event_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES discovery_jobs(job_id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_discovery_events_job
                    ON discovery_events(job_id, created_at);
                CREATE TABLE IF NOT EXISTS discovery_llm_calls(
                    call_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES discovery_jobs(job_id) ON DELETE SET NULL,
                    role TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    request_classification TEXT NOT NULL,
                    response_json TEXT,
                    usage_json TEXT,
                    status TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS discovery_hypotheses(
                    hypothesis_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES discovery_jobs(job_id) ON DELETE CASCADE,
                    stage TEXT NOT NULL,
                    title TEXT NOT NULL,
                    root_cause_l1 TEXT,
                    root_cause_l2 TEXT,
                    security_boundary TEXT,
                    invariant TEXT,
                    confidence REAL NOT NULL,
                    body_json TEXT NOT NULL,
                    trusted_record_ids_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS discovery_experiments(
                    experiment_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES discovery_jobs(job_id) ON DELETE CASCADE,
                    hypothesis_id TEXT REFERENCES discovery_hypotheses(hypothesis_id) ON DELETE SET NULL,
                    kind TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    backend TEXT,
                    policy_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS discovery_approvals(
                    approval_id TEXT PRIMARY KEY,
                    job_id TEXT NOT NULL REFERENCES discovery_jobs(job_id) ON DELETE CASCADE,
                    scope TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )
            c.execute(
                "INSERT INTO discovery_meta(key,value) VALUES('schema_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )
            c.commit()
        return {"ok": True, "path": self.path, "schema_version": SCHEMA_VERSION}

    def submit_job(
        self,
        *,
        target: str,
        target_kind: str = "source",
        kind: str = "discover",
        risk: RiskLevel = RiskLevel.LOW,
        requested_backend: str = "auto",
        payload: dict[str, Any] | None = None,
        max_attempts: int = 3,
    ) -> Job:
        self.migrate()
        now = utc_now()
        job = Job(
            job_id=f"job-{uuid.uuid4().hex}",
            kind=kind,
            target=target,
            target_kind=target_kind,
            status=JobStatus.QUEUED,
            risk=risk,
            requested_backend=requested_backend,
            payload=payload or {},
            max_attempts=max_attempts,
            created_at=now,
            updated_at=now,
        )
        with self.connect() as c:
            c.execute(
                """
                INSERT INTO discovery_jobs(
                    job_id,kind,target,target_kind,status,risk,requested_backend,selected_backend,
                    payload_json,result_json,error,attempts,max_attempts,leased_by,lease_expires_at,
                    created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    job.job_id, job.kind, job.target, job.target_kind, job.status.value,
                    job.risk.value, job.requested_backend, None, _json(job.payload), None,
                    None, 0, job.max_attempts, None, None, now, now,
                ),
            )
            c.commit()
        self.add_event(job.job_id, "job.submitted", job.to_dict())
        return job

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> Job:
        return Job(
            job_id=row["job_id"], kind=row["kind"], target=row["target"],
            target_kind=row["target_kind"], status=JobStatus(row["status"]),
            risk=RiskLevel(row["risk"]), requested_backend=row["requested_backend"],
            selected_backend=row["selected_backend"], payload=json.loads(row["payload_json"]),
            result=json.loads(row["result_json"]) if row["result_json"] else None,
            error=row["error"], attempts=row["attempts"], max_attempts=row["max_attempts"],
            leased_by=row["leased_by"], lease_expires_at=row["lease_expires_at"],
            created_at=row["created_at"], updated_at=row["updated_at"],
        )

    def get_job(self, job_id: str) -> Job | None:
        with self.connect() as c:
            row = c.execute("SELECT * FROM discovery_jobs WHERE job_id=?", (job_id,)).fetchone()
        return self._row_to_job(row) if row else None

    def list_jobs(self, *, limit: int = 50, status: str | None = None) -> list[Job]:
        query = "SELECT * FROM discovery_jobs"
        params: list[Any] = []
        if status:
            query += " WHERE status=?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self.connect() as c:
            rows = c.execute(query, params).fetchall()
        return [self._row_to_job(row) for row in rows]

    def claim_next(self, worker_id: str, *, lease_seconds: int = 300) -> Job | None:
        self.migrate()
        now = datetime.now(timezone.utc)
        now_s = now.isoformat().replace("+00:00", "Z")
        lease = (now + timedelta(seconds=lease_seconds)).isoformat().replace("+00:00", "Z")
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                """
                SELECT * FROM discovery_jobs
                WHERE attempts < max_attempts
                  AND (
                    status='queued'
                    OR (status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?)
                  )
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (now_s,),
            ).fetchone()
            if not row:
                c.commit()
                return None
            c.execute(
                """
                UPDATE discovery_jobs
                SET status='running', attempts=attempts+1, leased_by=?, lease_expires_at=?, updated_at=?
                WHERE job_id=?
                """,
                (worker_id, lease, now_s, row["job_id"]),
            )
            c.commit()
        job = self.get_job(row["job_id"])
        if job:
            self.add_event(job.job_id, "job.claimed", {"worker_id": worker_id, "lease_expires_at": lease})
        return job

    def heartbeat(self, job_id: str, worker_id: str, *, lease_seconds: int = 300) -> bool:
        lease = (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat().replace("+00:00", "Z")
        now = utc_now()
        with self.connect() as c:
            cur = c.execute(
                "UPDATE discovery_jobs SET lease_expires_at=?,updated_at=? "
                "WHERE job_id=? AND leased_by=? AND status='running'",
                (lease, now, job_id, worker_id),
            )
            c.commit()
            return cur.rowcount == 1

    def finish_job(self, job_id: str, result: dict[str, Any], *, status: JobStatus = JobStatus.SUCCEEDED) -> None:
        now = utc_now()
        with self.connect() as c:
            c.execute(
                "UPDATE discovery_jobs SET status=?,result_json=?,error=NULL,leased_by=NULL,"
                "lease_expires_at=NULL,updated_at=? WHERE job_id=?",
                (status.value, _json(result), now, job_id),
            )
            c.commit()
        self.add_event(job_id, f"job.{status.value}", result)

    def fail_job(self, job_id: str, error: str, *, retryable: bool = False) -> None:
        job = self.get_job(job_id)
        status = JobStatus.QUEUED if retryable and job and job.attempts < job.max_attempts else JobStatus.FAILED
        now = utc_now()
        with self.connect() as c:
            c.execute(
                "UPDATE discovery_jobs SET status=?,error=?,leased_by=NULL,lease_expires_at=NULL,updated_at=? WHERE job_id=?",
                (status.value, error[:8000], now, job_id),
            )
            c.commit()
        self.add_event(job_id, "job.retry" if status == JobStatus.QUEUED else "job.failed", {"error": error})

    def requeue_job(self, job_id: str, *, reason: str) -> bool:
        """Requeue a job after a scoped approval or explicit operator action."""
        now = utc_now()
        with self.connect() as c:
            cur = c.execute(
                "UPDATE discovery_jobs SET status='queued',error=NULL,leased_by=NULL,"
                "lease_expires_at=NULL,updated_at=? WHERE job_id=? AND status IN ('waiting_approval','failed')",
                (now, job_id),
            )
            c.commit()
        if cur.rowcount == 1:
            self.add_event(job_id, "job.requeued", {"reason": reason})
            return True
        return False

    def add_event(self, job_id: str, event_type: str, payload: dict[str, Any]) -> str:
        event_id = f"evt-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                "INSERT INTO discovery_events(event_id,job_id,event_type,payload_json,created_at) VALUES(?,?,?,?,?)",
                (event_id, job_id, event_type, _json(payload), utc_now()),
            )
            c.commit()
        return event_id

    def list_events(self, job_id: str) -> list[dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT * FROM discovery_events WHERE job_id=? ORDER BY created_at,event_id", (job_id,)
            ).fetchall()
        return [
            {
                "event_id": row["event_id"], "job_id": row["job_id"],
                "event_type": row["event_type"], "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def create_llm_call(
        self, *, job_id: str | None, role: str, provider: str, model: str,
        request_hash: str, classification: str,
    ) -> str:
        call_id = f"llm-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                """
                INSERT INTO discovery_llm_calls(
                    call_id,job_id,role,provider,model,request_hash,request_classification,
                    response_json,usage_json,status,error,created_at,completed_at
                ) VALUES(?,?,?,?,?,?,?,NULL,NULL,'running',NULL,?,NULL)
                """,
                (call_id, job_id, role, provider, model, request_hash, classification, utc_now()),
            )
            c.commit()
        return call_id

    def finish_llm_call(self, call_id: str, *, response: dict[str, Any] | None, usage: dict[str, Any] | None, error: str | None = None) -> None:
        with self.connect() as c:
            c.execute(
                "UPDATE discovery_llm_calls SET response_json=?,usage_json=?,status=?,error=?,completed_at=? WHERE call_id=?",
                (_json(response) if response is not None else None, _json(usage or {}), "failed" if error else "succeeded", error, utc_now(), call_id),
            )
            c.commit()

    def add_hypothesis(self, job_id: str, body: dict[str, Any], *, stage: str = "candidate_defect", trusted_record_ids: list[str] | None = None) -> str:
        hid = f"hyp-{uuid.uuid4().hex}"
        now = utc_now()
        with self.connect() as c:
            c.execute(
                """
                INSERT INTO discovery_hypotheses(
                    hypothesis_id,job_id,stage,title,root_cause_l1,root_cause_l2,security_boundary,
                    invariant,confidence,body_json,trusted_record_ids_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    hid, job_id, stage, body.get("title", "untitled"), body.get("root_cause_l1"),
                    body.get("root_cause_l2"), body.get("security_boundary"), body.get("invariant"),
                    float(body.get("confidence", 0.0)), _json(body), _json(trusted_record_ids or []), now, now,
                ),
            )
            c.commit()
        self.add_event(job_id, "hypothesis.created", {"hypothesis_id": hid, "stage": stage, "title": body.get("title")})
        return hid

    def update_hypothesis_stage(self, hypothesis_id: str, stage: str) -> None:
        with self.connect() as c:
            row = c.execute("SELECT job_id FROM discovery_hypotheses WHERE hypothesis_id=?", (hypothesis_id,)).fetchone()
            if not row:
                raise KeyError(hypothesis_id)
            c.execute(
                "UPDATE discovery_hypotheses SET stage=?,updated_at=? WHERE hypothesis_id=?",
                (stage, utc_now(), hypothesis_id),
            )
            c.commit()
        self.add_event(row["job_id"], "hypothesis.promoted", {"hypothesis_id": hypothesis_id, "stage": stage})

    def add_experiment(self, job_id: str, hypothesis_id: str | None, *, kind: str, risk: str, backend: str | None, policy: dict[str, Any], status: str = "planned") -> str:
        eid = f"exp-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                """
                INSERT INTO discovery_experiments(
                    experiment_id,job_id,hypothesis_id,kind,risk,backend,policy_json,status,result_json,created_at,completed_at
                ) VALUES(?,?,?,?,?,?,?,?,NULL,?,NULL)
                """,
                (eid, job_id, hypothesis_id, kind, risk, backend, _json(policy), status, utc_now()),
            )
            c.commit()
        return eid

    def finish_experiment(self, experiment_id: str, *, status: str, result: dict[str, Any]) -> None:
        with self.connect() as c:
            row = c.execute("SELECT job_id FROM discovery_experiments WHERE experiment_id=?", (experiment_id,)).fetchone()
            if not row:
                raise KeyError(experiment_id)
            c.execute(
                "UPDATE discovery_experiments SET status=?,result_json=?,completed_at=? WHERE experiment_id=?",
                (status, _json(result), utc_now(), experiment_id),
            )
            c.commit()
        self.add_event(row["job_id"], "experiment.completed", {"experiment_id": experiment_id, "status": status})

    def add_approval(self, job_id: str, *, scope: str, decision: str, actor: str, reason: str = "") -> str:
        approval_id = f"appr-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                "INSERT INTO discovery_approvals(approval_id,job_id,scope,decision,actor,reason,created_at) VALUES(?,?,?,?,?,?,?)",
                (approval_id, job_id, scope, decision, actor, reason, utc_now()),
            )
            c.commit()
        self.add_event(job_id, "approval.recorded", {"approval_id": approval_id, "scope": scope, "decision": decision, "actor": actor})
        return approval_id

    def has_approval(self, job_id: str, scope: str) -> bool:
        with self.connect() as c:
            row = c.execute(
                "SELECT 1 FROM discovery_approvals WHERE job_id=? AND scope=? AND decision='approve' ORDER BY created_at DESC LIMIT 1",
                (job_id, scope),
            ).fetchone()
        return bool(row)
