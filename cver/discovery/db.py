from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import Job, JobStatus, RiskLevel

SCHEMA_VERSION = 2


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

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

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
                    experiment_digest TEXT,
                    expires_at TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS discovery_capability_snapshots(
                    snapshot_id TEXT PRIMARY KEY,
                    host_fingerprint TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_capability_host_time
                    ON discovery_capability_snapshots(host_fingerprint, created_at);
                CREATE TABLE IF NOT EXISTS discovery_candidates(
                    candidate_id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    component_id TEXT NOT NULL,
                    external_id TEXT,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data_class TEXT NOT NULL,
                    source_url TEXT,
                    discovered_at TEXT,
                    content_sha256 TEXT NOT NULL,
                    split_group_id TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(source_type, component_id, content_sha256)
                );
                CREATE INDEX IF NOT EXISTS idx_candidates_component_status
                    ON discovery_candidates(component_id, status, created_at);
                CREATE TABLE IF NOT EXISTS discovery_candidate_artifacts(
                    artifact_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL REFERENCES discovery_candidates(candidate_id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    mime_type TEXT,
                    size_bytes INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_candidate_artifact_unique
                    ON discovery_candidate_artifacts(candidate_id, kind, sha256);
                CREATE TABLE IF NOT EXISTS discovery_evidence(
                    evidence_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES discovery_jobs(job_id) ON DELETE CASCADE,
                    hypothesis_id TEXT REFERENCES discovery_hypotheses(hypothesis_id) ON DELETE SET NULL,
                    experiment_id TEXT REFERENCES discovery_experiments(experiment_id) ON DELETE SET NULL,
                    evidence_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    quality_score REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_job_hypothesis
                    ON discovery_evidence(job_id, hypothesis_id, created_at);
                CREATE TABLE IF NOT EXISTS discovery_annotations(
                    annotation_id TEXT PRIMARY KEY,
                    candidate_id TEXT NOT NULL REFERENCES discovery_candidates(candidate_id) ON DELETE CASCADE,
                    taxonomy_version TEXT NOT NULL,
                    security_status TEXT NOT NULL,
                    primary_root_cause_l1 TEXT NOT NULL,
                    primary_root_cause_l2 TEXT NOT NULL,
                    secondary_root_causes_json TEXT NOT NULL,
                    primary_security_property TEXT,
                    secondary_security_properties_json TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    primary_causal_role TEXT,
                    primary_counterfactual_changes_outcome INTEGER,
                    rationale TEXT NOT NULL,
                    status TEXT NOT NULL,
                    annotator TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_annotations_candidate_status
                    ON discovery_annotations(candidate_id, status, updated_at);
                CREATE TABLE IF NOT EXISTS discovery_audit_log(
                    audit_id TEXT PRIMARY KEY,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_object
                    ON discovery_audit_log(object_type, object_id, created_at);
                CREATE TABLE IF NOT EXISTS discovery_zero_day_cases(
                    case_id TEXT PRIMARY KEY,
                    job_id TEXT REFERENCES discovery_jobs(job_id) ON DELETE SET NULL,
                    hypothesis_id TEXT REFERENCES discovery_hypotheses(hypothesis_id) ON DELETE SET NULL,
                    status TEXT NOT NULL,
                    data_class TEXT NOT NULL,
                    case_digest TEXT NOT NULL UNIQUE,
                    encrypted_manifest_path TEXT NOT NULL,
                    key_ref TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            self._ensure_column(c, "discovery_jobs", "next_attempt_at", "TEXT")
            self._ensure_column(c, "discovery_approvals", "experiment_digest", "TEXT")
            self._ensure_column(c, "discovery_approvals", "expires_at", "TEXT")
            self._ensure_column(c, "discovery_annotations", "primary_causal_role", "TEXT")
            self._ensure_column(c, "discovery_annotations", "primary_counterfactual_changes_outcome", "INTEGER")
            c.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_digest ON discovery_approvals(job_id,scope,experiment_digest,decision,created_at)"
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
                    job.job_id,
                    job.kind,
                    job.target,
                    job.target_kind,
                    job.status.value,
                    job.risk.value,
                    job.requested_backend,
                    None,
                    _json(job.payload),
                    None,
                    None,
                    0,
                    job.max_attempts,
                    None,
                    None,
                    now,
                    now,
                ),
            )
            c.commit()
        self.add_event(job.job_id, "job.submitted", job.to_dict())
        return job

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> Job:
        return Job(
            job_id=row["job_id"],
            kind=row["kind"],
            target=row["target"],
            target_kind=row["target_kind"],
            status=JobStatus(row["status"]),
            risk=RiskLevel(row["risk"]),
            requested_backend=row["requested_backend"],
            selected_backend=row["selected_backend"],
            payload=json.loads(row["payload_json"]),
            result=json.loads(row["result_json"]) if row["result_json"] else None,
            error=row["error"],
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            leased_by=row["leased_by"],
            lease_expires_at=row["lease_expires_at"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
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
                    (status='queued' AND (next_attempt_at IS NULL OR next_attempt_at <= ?))
                    OR (status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?)
                  )
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (now_s, now_s),
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
                "lease_expires_at=NULL,next_attempt_at=NULL,updated_at=? WHERE job_id=?",
                (status.value, _json(result), now, job_id),
            )
            c.commit()
        self.add_event(job_id, f"job.{status.value}", result)

    def fail_job(self, job_id: str, error: str, *, retryable: bool = False) -> None:
        job = self.get_job(job_id)
        status = JobStatus.QUEUED if retryable and job and job.attempts < job.max_attempts else JobStatus.FAILED
        now = utc_now()
        next_attempt_at = None
        if status == JobStatus.QUEUED and job is not None:
            delay_seconds = min(300, 2 ** max(1, job.attempts))
            next_attempt_at = (
                (datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)).isoformat().replace("+00:00", "Z")
            )
        with self.connect() as c:
            c.execute(
                "UPDATE discovery_jobs SET status=?,error=?,leased_by=NULL,lease_expires_at=NULL,next_attempt_at=?,updated_at=? WHERE job_id=?",
                (status.value, error[:8000], next_attempt_at, now, job_id),
            )
            c.commit()
        self.add_event(
            job_id,
            "job.retry" if status == JobStatus.QUEUED else "job.failed",
            {"error": error, "next_attempt_at": next_attempt_at, "retryable": retryable},
        )

    def requeue_job(self, job_id: str, *, reason: str) -> bool:
        """Requeue a job after a scoped approval or explicit operator action."""
        now = utc_now()
        with self.connect() as c:
            cur = c.execute(
                "UPDATE discovery_jobs SET status='queued',error=NULL,leased_by=NULL,"
                "lease_expires_at=NULL,next_attempt_at=NULL,updated_at=? WHERE job_id=? AND status IN ('waiting_approval','failed')",
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
                "event_id": row["event_id"],
                "job_id": row["job_id"],
                "event_type": row["event_type"],
                "payload": json.loads(row["payload_json"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def create_llm_call(
        self,
        *,
        job_id: str | None,
        role: str,
        provider: str,
        model: str,
        request_hash: str,
        classification: str,
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

    def finish_llm_call(
        self, call_id: str, *, response: dict[str, Any] | None, usage: dict[str, Any] | None, error: str | None = None
    ) -> None:
        with self.connect() as c:
            c.execute(
                "UPDATE discovery_llm_calls SET response_json=?,usage_json=?,status=?,error=?,completed_at=? WHERE call_id=?",
                (
                    _json(response) if response is not None else None,
                    _json(usage or {}),
                    "failed" if error else "succeeded",
                    error,
                    utc_now(),
                    call_id,
                ),
            )
            c.commit()

    def add_hypothesis(
        self,
        job_id: str,
        body: dict[str, Any],
        *,
        stage: str = "candidate_defect",
        trusted_record_ids: list[str] | None = None,
    ) -> str:
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
                    hid,
                    job_id,
                    stage,
                    body.get("title", "untitled"),
                    body.get("root_cause_l1"),
                    body.get("root_cause_l2"),
                    body.get("security_boundary"),
                    body.get("invariant"),
                    float(body.get("confidence", 0.0)),
                    _json(body),
                    _json(trusted_record_ids or []),
                    now,
                    now,
                ),
            )
            c.commit()
        self.add_event(job_id, "hypothesis.created", {"hypothesis_id": hid, "stage": stage, "title": body.get("title")})
        return hid

    def update_hypothesis_stage(self, hypothesis_id: str, stage: str) -> None:
        with self.connect() as c:
            row = c.execute(
                "SELECT job_id FROM discovery_hypotheses WHERE hypothesis_id=?", (hypothesis_id,)
            ).fetchone()
            if not row:
                raise KeyError(hypothesis_id)
            c.execute(
                "UPDATE discovery_hypotheses SET stage=?,updated_at=? WHERE hypothesis_id=?",
                (stage, utc_now(), hypothesis_id),
            )
            c.commit()
        self.add_event(row["job_id"], "hypothesis.promoted", {"hypothesis_id": hypothesis_id, "stage": stage})

    def add_experiment(
        self,
        job_id: str,
        hypothesis_id: str | None,
        *,
        kind: str,
        risk: str,
        backend: str | None,
        policy: dict[str, Any],
        status: str = "planned",
    ) -> str:
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
            row = c.execute(
                "SELECT job_id FROM discovery_experiments WHERE experiment_id=?", (experiment_id,)
            ).fetchone()
            if not row:
                raise KeyError(experiment_id)
            c.execute(
                "UPDATE discovery_experiments SET status=?,result_json=?,completed_at=? WHERE experiment_id=?",
                (status, _json(result), utc_now(), experiment_id),
            )
            c.commit()
        self.add_event(row["job_id"], "experiment.completed", {"experiment_id": experiment_id, "status": status})

    def add_approval(
        self,
        job_id: str,
        *,
        scope: str,
        decision: str,
        actor: str,
        reason: str = "",
        experiment_digest: str | None = None,
        expires_at: str | None = None,
    ) -> str:
        approval_id = f"appr-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                "INSERT INTO discovery_approvals(approval_id,job_id,scope,decision,actor,reason,experiment_digest,expires_at,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (approval_id, job_id, scope, decision, actor, reason, experiment_digest, expires_at, utc_now()),
            )
            c.commit()
        self.add_event(
            job_id,
            "approval.recorded",
            {
                "approval_id": approval_id,
                "scope": scope,
                "decision": decision,
                "actor": actor,
                "experiment_digest": experiment_digest,
                "expires_at": expires_at,
            },
        )
        self.add_audit(
            actor,
            "approval.recorded",
            "job",
            job_id,
            {"approval_id": approval_id, "scope": scope, "experiment_digest": experiment_digest},
        )
        return approval_id

    def has_approval(self, job_id: str, scope: str, *, experiment_digest: str | None = None) -> bool:
        now = utc_now()
        query = (
            "SELECT 1 FROM discovery_approvals WHERE job_id=? AND scope=? AND decision='approve' "
            "AND (expires_at IS NULL OR expires_at>?)"
        )
        params: list[Any] = [job_id, scope, now]
        if experiment_digest is not None:
            query += " AND experiment_digest=?"
            params.append(experiment_digest)
        query += " ORDER BY created_at DESC LIMIT 1"
        with self.connect() as c:
            row = c.execute(query, params).fetchone()
        return bool(row)

    def add_capability_snapshot(self, payload: dict[str, Any]) -> str:
        snapshot_id = f"cap-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                "INSERT INTO discovery_capability_snapshots(snapshot_id,host_fingerprint,payload_json,created_at) VALUES(?,?,?,?)",
                (snapshot_id, payload["host_fingerprint"], _json(payload), utc_now()),
            )
            c.commit()
        return snapshot_id

    def add_candidate(
        self,
        *,
        source_type: str,
        component_id: str,
        title: str,
        data_class: str,
        content_sha256: str,
        split_group_id: str,
        manifest: dict[str, Any],
        external_id: str | None = None,
        source_url: str | None = None,
        discovered_at: str | None = None,
        status: str = "candidate",
    ) -> str:
        candidate_id = f"cand-{uuid.uuid4().hex}"
        now = utc_now()
        with self.connect() as c:
            existing = c.execute(
                "SELECT candidate_id FROM discovery_candidates WHERE source_type=? AND component_id=? AND content_sha256=?",
                (source_type, component_id, content_sha256),
            ).fetchone()
            if existing:
                return str(existing["candidate_id"])
            c.execute(
                """
                INSERT INTO discovery_candidates(
                    candidate_id,source_type,component_id,external_id,title,status,data_class,source_url,
                    discovered_at,content_sha256,split_group_id,manifest_json,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    candidate_id,
                    source_type,
                    component_id,
                    external_id,
                    title,
                    status,
                    data_class,
                    source_url,
                    discovered_at,
                    content_sha256,
                    split_group_id,
                    _json(manifest),
                    now,
                    now,
                ),
            )
            c.commit()
        return candidate_id

    def add_candidate_artifact(
        self,
        candidate_id: str,
        *,
        kind: str,
        path: str,
        sha256: str,
        size_bytes: int,
        mime_type: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        artifact_id = f"cart-{uuid.uuid4().hex}"
        with self.connect() as c:
            existing = c.execute(
                "SELECT artifact_id FROM discovery_candidate_artifacts WHERE candidate_id=? AND kind=? AND sha256=?",
                (candidate_id, kind, sha256),
            ).fetchone()
            if existing:
                return str(existing["artifact_id"])
            c.execute(
                "INSERT INTO discovery_candidate_artifacts(artifact_id,candidate_id,kind,path,sha256,mime_type,size_bytes,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    artifact_id,
                    candidate_id,
                    kind,
                    path,
                    sha256,
                    mime_type,
                    size_bytes,
                    _json(metadata or {}),
                    utc_now(),
                ),
            )
            c.commit()
        return artifact_id

    def get_candidate(self, candidate_id: str) -> dict[str, Any] | None:
        with self.connect() as c:
            row = c.execute("SELECT * FROM discovery_candidates WHERE candidate_id=?", (candidate_id,)).fetchone()
            if not row:
                return None
            artifacts = c.execute(
                "SELECT * FROM discovery_candidate_artifacts WHERE candidate_id=? ORDER BY created_at,artifact_id",
                (candidate_id,),
            ).fetchall()
        candidate = dict(row)
        candidate.pop("manifest_json", None)
        candidate["manifest"] = json.loads(row["manifest_json"])
        candidate["artifacts"] = [
            {
                **{key: value for key, value in dict(item).items() if key != "metadata_json"},
                "metadata": json.loads(item["metadata_json"]),
            }
            for item in artifacts
        ]
        return candidate

    def list_candidates(
        self, *, limit: int = 100, component_id: str | None = None, status: str | None = None
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM discovery_candidates WHERE 1=1"
        params: list[Any] = []
        if component_id:
            query += " AND component_id=?"
            params.append(component_id)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        with self.connect() as c:
            rows = c.execute(query, params).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item.pop("manifest_json", None)
            item["manifest"] = json.loads(row["manifest_json"])
            result.append(item)
        return result

    def update_candidate_status(self, candidate_id: str, status: str) -> None:
        with self.connect() as c:
            cursor = c.execute(
                "UPDATE discovery_candidates SET status=?,updated_at=? WHERE candidate_id=?",
                (status, utc_now(), candidate_id),
            )
            c.commit()
        if cursor.rowcount != 1:
            raise KeyError(candidate_id)

    def add_annotation(self, candidate_id: str, annotation: dict[str, Any], *, annotator: str) -> str:
        annotation_id = f"ann-{uuid.uuid4().hex}"
        now = utc_now()
        with self.connect() as c:
            c.execute(
                """
                INSERT INTO discovery_annotations(
                    annotation_id,candidate_id,taxonomy_version,security_status,primary_root_cause_l1,
                    primary_root_cause_l2,secondary_root_causes_json,primary_security_property,
                    secondary_security_properties_json,evidence_ids_json,primary_causal_role,
                    primary_counterfactual_changes_outcome,rationale,status,annotator,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    annotation_id,
                    candidate_id,
                    annotation["taxonomy_version"],
                    annotation["security_status"],
                    annotation["primary_root_cause"],
                    annotation["primary_secondary_root_cause"],
                    _json(annotation.get("secondary_root_causes", [])),
                    annotation.get("primary_security_property"),
                    _json(annotation.get("secondary_security_properties", [])),
                    _json(annotation.get("evidence_ids", [])),
                    annotation.get("primary_causal_role"),
                    1 if annotation.get("primary_counterfactual_changes_outcome") is True else 0,
                    annotation["rationale"],
                    annotation.get("status", "draft"),
                    annotator,
                    now,
                    now,
                ),
            )
            c.commit()
        self.add_audit(annotator, "annotation.created", "candidate", candidate_id, {"annotation_id": annotation_id})
        return annotation_id

    def add_evidence(
        self,
        *,
        evidence_type: str,
        source: str,
        sha256: str,
        payload: dict[str, Any],
        quality_score: float,
        job_id: str | None = None,
        hypothesis_id: str | None = None,
        experiment_id: str | None = None,
    ) -> str:
        evidence_id = f"evd-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                "INSERT INTO discovery_evidence(evidence_id,job_id,hypothesis_id,experiment_id,evidence_type,source,sha256,quality_score,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    evidence_id,
                    job_id,
                    hypothesis_id,
                    experiment_id,
                    evidence_type,
                    source,
                    sha256,
                    max(0.0, min(1.0, quality_score)),
                    _json(payload),
                    utc_now(),
                ),
            )
            c.commit()
        return evidence_id

    def add_audit(self, actor: str, action: str, object_type: str, object_id: str, payload: dict[str, Any]) -> str:
        audit_id = f"audit-{uuid.uuid4().hex}"
        with self.connect() as c:
            c.execute(
                "INSERT INTO discovery_audit_log(audit_id,actor,action,object_type,object_id,payload_json,created_at) VALUES(?,?,?,?,?,?,?)",
                (audit_id, actor, action, object_type, object_id, _json(payload), utc_now()),
            )
            c.commit()
        return audit_id

    def register_zero_day_case(
        self,
        *,
        case_id: str,
        status: str,
        data_class: str,
        case_digest: str,
        encrypted_manifest_path: str,
        key_ref: str,
        job_id: str | None = None,
        hypothesis_id: str | None = None,
    ) -> None:
        now = utc_now()
        with self.connect() as c:
            c.execute(
                "INSERT INTO discovery_zero_day_cases(case_id,job_id,hypothesis_id,status,data_class,case_digest,encrypted_manifest_path,key_ref,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    case_id,
                    job_id,
                    hypothesis_id,
                    status,
                    data_class,
                    case_digest,
                    encrypted_manifest_path,
                    key_ref,
                    now,
                    now,
                ),
            )
            c.commit()
