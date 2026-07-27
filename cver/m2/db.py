from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
CREATE TABLE IF NOT EXISTS m2_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_jobs(
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    profile TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    request_json TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '{}',
    error TEXT
);
CREATE TABLE IF NOT EXISTS m2_events(
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_m2_events_job ON m2_events(job_id, event_id);
CREATE TABLE IF NOT EXISTS m2_environment_snapshots(
    snapshot_id TEXT PRIMARY KEY,
    job_id TEXT,
    created_at TEXT NOT NULL,
    digest TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_source_snapshots(
    snapshot_id TEXT PRIMARY KEY,
    job_id TEXT,
    component TEXT NOT NULL,
    track TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    requested_ref TEXT,
    resolved_commit TEXT,
    source_digest TEXT,
    status TEXT NOT NULL,
    path TEXT,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS m2_findings(
    finding_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    component TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    title TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_m2_findings_job ON m2_findings(job_id, status);
CREATE TABLE IF NOT EXISTS m2_evidence(
    evidence_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    finding_id TEXT,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    sha256 TEXT,
    restricted INTEGER NOT NULL DEFAULT 0,
    artifact_path TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_harness_runs(
    run_id TEXT PRIMARY KEY,
    job_id TEXT,
    harness_id TEXT NOT NULL,
    status TEXT NOT NULL,
    binary_path TEXT,
    compiler TEXT,
    exit_code INTEGER,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_fuzz_runs(
    run_id TEXT PRIMARY KEY,
    job_id TEXT,
    harness_id TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    exit_code INTEGER,
    crash_count INTEGER NOT NULL DEFAULT 0,
    sanitizer_kind TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS m2_adapter_evaluations(
    evaluation_id TEXT PRIMARY KEY,
    job_id TEXT,
    adapter_id TEXT,
    source_track TEXT NOT NULL,
    kata_version TEXT NOT NULL,
    interface_fingerprint TEXT,
    state TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_real_fuzz_runs(
    run_id TEXT PRIMARY KEY,
    job_id TEXT,
    source_track TEXT NOT NULL,
    kata_version TEXT NOT NULL,
    source_commit TEXT,
    adapter_id TEXT,
    handler_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_seconds REAL NOT NULL DEFAULT 0,
    exit_code INTEGER,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_m2_real_fuzz_track ON m2_real_fuzz_runs(source_track,kata_version,handler_id);
CREATE TABLE IF NOT EXISTS m2_candidates_v2(
    candidate_id TEXT PRIMARY KEY,
    job_id TEXT,
    dedup_key TEXT NOT NULL,
    level TEXT NOT NULL,
    component TEXT NOT NULL,
    kata_version TEXT NOT NULL,
    source_track TEXT NOT NULL,
    handler_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_m2_candidates_v2_dedup ON m2_candidates_v2(dedup_key,source_track,kata_version);
CREATE TABLE IF NOT EXISTS m2_runtime_asset_manifests(
    manifest_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    manifest_path TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_agent_runs(
    run_id TEXT PRIMARY KEY,
    job_id TEXT,
    candidate_id TEXT,
    model TEXT,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_dataset_releases(
    release_id TEXT PRIMARY KEY,
    strategy TEXT NOT NULL,
    leakage_passed INTEGER NOT NULL,
    manifest_path TEXT,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS m2_audit(
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT,
    payload_json TEXT NOT NULL
);
"""


class M2Repository:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.path), timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def migrate(self) -> dict[str, Any]:
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute(
                "INSERT OR REPLACE INTO m2_meta(key,value) VALUES('schema_version','2')"
            )
        return {"ok": True, "schema_version": 2, "path": str(self.path)}

    def create_job(self, kind: str, profile: str, request: dict[str, Any]) -> str:
        self.migrate()
        job_id = f"m2-{uuid.uuid4().hex}"
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO m2_jobs(
                    job_id,kind,status,phase,profile,created_at,updated_at,request_json,result_json
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (job_id, kind, "queued", "queued", profile, now, now, json.dumps(request), "{}"),
            )
        self.event(job_id, "info", "job.created", "M2 job created", {"kind": kind, "profile": profile})
        return job_id

    def update_job(
        self,
        job_id: str,
        *,
        status: str | None = None,
        phase: str | None = None,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        updates = ["updated_at=?"]
        values: list[Any] = [utc_now()]
        if status is not None:
            updates.append("status=?")
            values.append(status)
        if phase is not None:
            updates.append("phase=?")
            values.append(phase)
        if result is not None:
            updates.append("result_json=?")
            values.append(json.dumps(result, ensure_ascii=False, default=str))
        if error is not None:
            updates.append("error=?")
            values.append(error)
        values.append(job_id)
        with self.connect() as connection:
            connection.execute(f"UPDATE m2_jobs SET {', '.join(updates)} WHERE job_id=?", values)

    def event(
        self,
        job_id: str | None,
        level: str,
        event_type: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        self.migrate()
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO m2_events(job_id,created_at,level,event_type,message,data_json) VALUES(?,?,?,?,?,?)",
                (
                    job_id,
                    utc_now(),
                    level,
                    event_type,
                    message,
                    json.dumps(data or {}, ensure_ascii=False, default=str),
                ),
            )

    def audit(
        self,
        actor: str,
        action: str,
        object_type: str,
        object_id: str | None,
        payload: dict[str, Any] | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO m2_audit(created_at,actor,action,object_type,object_id,payload_json) VALUES(?,?,?,?,?,?)",
                (utc_now(), actor, action, object_type, object_id, json.dumps(payload or {}, ensure_ascii=False)),
            )

    def get_job(self, job_id: str, *, include_events: bool = True) -> dict[str, Any] | None:
        self.migrate()
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM m2_jobs WHERE job_id=?", (job_id,)).fetchone()
            if row is None:
                return None
            payload = dict(row)
            payload["request"] = json.loads(payload.pop("request_json"))
            payload["result"] = json.loads(payload.pop("result_json"))
            if include_events:
                events = connection.execute(
                    "SELECT * FROM m2_events WHERE job_id=? ORDER BY event_id", (job_id,)
                ).fetchall()
                payload["events"] = [self._decode_event(dict(item)) for item in events]
            return payload

    def list_jobs(self, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
        self.migrate()
        query = "SELECT * FROM m2_jobs"
        params: list[Any] = []
        if status:
            query += " WHERE status=?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self.connect() as connection:
            rows = connection.execute(query, params).fetchall()
        output = []
        for row in rows:
            item = dict(row)
            item["request"] = json.loads(item.pop("request_json"))
            item["result"] = json.loads(item.pop("result_json"))
            output.append(item)
        return output

    @staticmethod
    def _decode_event(item: dict[str, Any]) -> dict[str, Any]:
        item["data"] = json.loads(item.pop("data_json"))
        return item

    def add_environment_snapshot(self, job_id: str | None, digest: str, payload: dict[str, Any]) -> str:
        snapshot_id = f"env-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO m2_environment_snapshots VALUES(?,?,?,?,?)",
                (snapshot_id, job_id, utc_now(), digest, json.dumps(payload, ensure_ascii=False, default=str)),
            )
        return snapshot_id

    def add_source_snapshot(self, job_id: str | None, payload: dict[str, Any]) -> str:
        snapshot_id = f"src-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                """INSERT INTO m2_source_snapshots(
                    snapshot_id,job_id,component,track,repository_url,requested_ref,resolved_commit,
                    source_digest,status,path,created_at,metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    snapshot_id,
                    job_id,
                    payload["component"],
                    payload["track"],
                    payload["repository_url"],
                    payload.get("requested_ref"),
                    payload.get("resolved_commit"),
                    payload.get("source_digest"),
                    payload["status"],
                    payload.get("path"),
                    utc_now(),
                    json.dumps(payload.get("metadata", {}), ensure_ascii=False, default=str),
                ),
            )
        return snapshot_id

    def add_finding(self, job_id: str, payload: dict[str, Any]) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_findings(
                    finding_id,job_id,component,status,severity,confidence,title,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    payload["finding_id"],
                    job_id,
                    payload["component"],
                    payload["status"],
                    payload["severity"],
                    payload.get("confidence", 0.0),
                    payload["title"],
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )

    def add_evidence(self, job_id: str, payload: dict[str, Any], finding_id: str | None = None) -> None:
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_evidence(
                    evidence_id,job_id,finding_id,kind,source,sha256,restricted,artifact_path,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    payload["evidence_id"],
                    job_id,
                    finding_id,
                    payload["kind"],
                    payload["source"],
                    payload.get("sha256"),
                    int(bool(payload.get("restricted"))),
                    payload.get("artifact_path"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )

    def add_harness_run(self, job_id: str | None, payload: dict[str, Any]) -> str:
        run_id = payload.get("run_id") or f"harness-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_harness_runs(
                    run_id,job_id,harness_id,status,binary_path,compiler,exit_code,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    job_id,
                    payload["harness_id"],
                    payload["status"],
                    payload.get("binary_path"),
                    payload.get("compiler"),
                    payload.get("exit_code"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return run_id

    def add_fuzz_run(self, job_id: str | None, payload: dict[str, Any]) -> str:
        run_id = payload.get("run_id") or f"fuzz-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_fuzz_runs(
                    run_id,job_id,harness_id,status,duration_seconds,exit_code,crash_count,
                    sanitizer_kind,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    job_id,
                    payload["harness_id"],
                    payload["status"],
                    payload.get("duration_seconds", 0.0),
                    payload.get("exit_code"),
                    payload.get("crash_count", 0),
                    payload.get("sanitizer_kind"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return run_id

    def add_adapter_evaluation(self, job_id: str | None, payload: dict[str, Any]) -> str:
        evaluation_id = payload.get("evaluation_id") or f"adapter-{uuid.uuid4().hex}"
        inspection = payload.get("inspection") or {}
        adapter = payload.get("adapter") or {}
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_adapter_evaluations(
                    evaluation_id,job_id,adapter_id,source_track,kata_version,interface_fingerprint,
                    state,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    evaluation_id,
                    job_id,
                    adapter.get("adapter_id"),
                    payload.get("track", "unknown"),
                    inspection.get("version", "unknown"),
                    inspection.get("interface_fingerprint"),
                    payload.get("state") or payload.get("adapter", {}).get("state") or "unknown",
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return evaluation_id

    def add_real_fuzz_run(self, job_id: str | None, payload: dict[str, Any]) -> str:
        run_id = payload.get("run_id") or f"realfuzz-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_real_fuzz_runs(
                    run_id,job_id,source_track,kata_version,source_commit,adapter_id,handler_id,
                    mode,status,duration_seconds,exit_code,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    job_id,
                    payload.get("source_track", "unknown"),
                    payload.get("kata_version", "unknown"),
                    payload.get("source_commit"),
                    payload.get("adapter_id"),
                    payload.get("handler_id", "unknown"),
                    payload.get("mode", "stateless"),
                    payload.get("status", "unknown"),
                    payload.get("duration_seconds", 0.0),
                    payload.get("exit_code"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return run_id

    def add_candidate_v2(self, job_id: str | None, payload: dict[str, Any]) -> str:
        candidate_id = payload.get("candidate_id") or f"m2cand-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_candidates_v2(
                    candidate_id,job_id,dedup_key,level,component,kata_version,source_track,
                    handler_id,finding_type,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    candidate_id,
                    job_id,
                    payload.get("dedup_key", candidate_id),
                    payload.get("level", "OBSERVATION"),
                    payload.get("component", "kata-agent"),
                    payload.get("kata_version", "unknown"),
                    payload.get("source_track", "unknown"),
                    payload.get("handler_id", "unknown"),
                    payload.get("finding_type", "unexpected_behavior"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return candidate_id

    def list_candidates_v2(self, limit: int = 100, level: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT payload_json FROM m2_candidates_v2"
        parameters: list[Any] = []
        if level:
            query += " WHERE level=?"
            parameters.append(level)
        query += " ORDER BY created_at DESC LIMIT ?"
        parameters.append(max(1, min(limit, 1000)))
        with self.connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]

    def add_runtime_asset_manifest(self, payload: dict[str, Any]) -> str:
        manifest_id = payload.get("manifest_id") or f"runtime-assets-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_runtime_asset_manifests(
                    manifest_id,version,status,manifest_path,payload_json,created_at
                ) VALUES(?,?,?,?,?,?)""",
                (
                    manifest_id,
                    payload.get("version", "unknown"),
                    payload.get("status", "unknown"),
                    payload.get("manifest_path"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return manifest_id

    def add_agent_run(self, job_id: str | None, candidate_id: str | None, payload: dict[str, Any]) -> str:
        run_id = payload.get("run_id") or f"agents-{uuid.uuid4().hex}"
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_agent_runs(
                    run_id,job_id,candidate_id,model,status,payload_json,created_at
                ) VALUES(?,?,?,?,?,?,?)""",
                (
                    run_id,
                    job_id,
                    candidate_id,
                    payload.get("model"),
                    payload.get("status", "unknown"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return run_id

    def add_dataset_release(self, payload: dict[str, Any]) -> str:
        release_id = str(payload["release_id"])
        with self.connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO m2_dataset_releases(
                    release_id,strategy,leakage_passed,manifest_path,payload_json,created_at
                ) VALUES(?,?,?,?,?,?)""",
                (
                    release_id,
                    payload.get("strategy", "unknown"),
                    int(bool((payload.get("leakage_audit") or {}).get("passed"))),
                    payload.get("manifest_path"),
                    json.dumps(payload, ensure_ascii=False, default=str),
                    utc_now(),
                ),
            )
        return release_id

    def dashboard(self) -> dict[str, Any]:
        self.migrate()
        with self.connect() as connection:
            status_counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status,COUNT(*) AS count FROM m2_jobs GROUP BY status"
                ).fetchall()
            }
            finding_counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status,COUNT(*) AS count FROM m2_findings GROUP BY status"
                ).fetchall()
            }
            harness_counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status,COUNT(*) AS count FROM m2_harness_runs GROUP BY status"
                ).fetchall()
            }
            candidate_counts = {
                row["level"]: row["count"]
                for row in connection.execute(
                    "SELECT level,COUNT(*) AS count FROM m2_candidates_v2 GROUP BY level"
                ).fetchall()
            }
            real_fuzz_counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status,COUNT(*) AS count FROM m2_real_fuzz_runs GROUP BY status"
                ).fetchall()
            }
        return {
            "jobs": status_counts,
            "findings": finding_counts,
            "harnesses": harness_counts,
            "real_fuzz": real_fuzz_counts,
            "candidates_v2": candidate_counts,
            "recent_jobs": self.list_jobs(limit=10),
        }
