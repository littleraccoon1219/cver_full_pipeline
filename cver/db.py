from __future__ import annotations
import json, sqlite3
from pathlib import Path
from typing import Any
from .logging_utils import now_iso

SCHEMA = [
"CREATE TABLE IF NOT EXISTS targets(target_id TEXT PRIMARY KEY, kind TEXT, name TEXT, labels_json TEXT, created_at TEXT)",
"CREATE TABLE IF NOT EXISTS scans(scan_id TEXT PRIMARY KEY, target_id TEXT, mode TEXT, profile TEXT, status TEXT, started_at TEXT, finished_at TEXT, correlation_id TEXT, json TEXT)",
"CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, source TEXT, type TEXT, severity TEXT, cve_id TEXT, component TEXT, macro_type TEXT, fine_type TEXT, confidence REAL, dedup_key TEXT, correlation_id TEXT, json TEXT)",
"CREATE TABLE IF NOT EXISTS evidences(evidence_id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, category TEXT, key TEXT, confidence REAL, correlation_id TEXT, json TEXT)",
"CREATE TABLE IF NOT EXISTS cve_knowledge(cve_id TEXT PRIMARY KEY, component TEXT, root_cause TEXT, fine_type TEXT, severity TEXT, cvss_score REAL, published TEXT, last_modified TEXT, json TEXT, retrieved_at TEXT)",
"CREATE TABLE IF NOT EXISTS reports(report_id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, json_path TEXT, markdown_path TEXT, html_path TEXT, created_at TEXT, json TEXT)",
"CREATE TABLE IF NOT EXISTS benchmark_runs(benchmark_id TEXT PRIMARY KEY, profile TEXT, metrics_json TEXT, output_path TEXT, created_at TEXT, json TEXT)",
"CREATE TABLE IF NOT EXISTS audit_log(audit_id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, scan_id TEXT, target_id TEXT, campaign_id TEXT, action TEXT, decision TEXT, reason TEXT, json TEXT)"
]

def conn(db_path: str | Path) -> sqlite3.Connection:
    p = Path(db_path); p.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(p)); c.row_factory = sqlite3.Row
    return c

def init_db(db_path: str | Path) -> None:
    with conn(db_path) as c:
        for s in SCHEMA: c.execute(s)
        try:
            c.execute("CREATE VIRTUAL TABLE IF NOT EXISTS cve_knowledge_fts USING fts5(cve_id, component, description, semantic_json)")
        except sqlite3.OperationalError:
            pass
        c.commit()

def upsert_json(db_path: str | Path, table: str, key: str, obj: dict[str,Any]) -> None:
    raw = json.dumps(obj, ensure_ascii=False, default=str)
    with conn(db_path) as c:
        if table == "targets":
            c.execute("INSERT OR REPLACE INTO targets VALUES(?,?,?,?,?)",(key,obj.get("kind"),obj.get("name"),json.dumps(obj.get("labels",{}),ensure_ascii=False),now_iso()))
        elif table == "scans":
            c.execute("INSERT OR REPLACE INTO scans VALUES(?,?,?,?,?,?,?,?,?)",(key,obj.get("target_id"),obj.get("mode"),obj.get("profile"),obj.get("status"),obj.get("started_at"),obj.get("finished_at"),obj.get("correlation_id"),raw))
        elif table == "findings":
            c.execute("INSERT OR REPLACE INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(key,obj.get("scan_id"),obj.get("target_id"),obj.get("source"),obj.get("type"),obj.get("severity"),obj.get("cve_id"),obj.get("component"),obj.get("macro_type"),obj.get("fine_type"),obj.get("confidence"),obj.get("dedup_key"),obj.get("correlation_id"),raw))
        elif table == "evidences":
            c.execute("INSERT OR REPLACE INTO evidences VALUES(?,?,?,?,?,?,?,?)",(key,obj.get("scan_id"),obj.get("target_id"),obj.get("category"),obj.get("key"),obj.get("confidence"),obj.get("correlation_id"),raw))
        elif table == "reports":
            c.execute("INSERT OR REPLACE INTO reports VALUES(?,?,?,?,?,?,?,?)",(key,obj.get("scan_id"),obj.get("target_id"),obj.get("json_path"),obj.get("markdown_path"),obj.get("html_path"),obj.get("created_at"),raw))
        elif table == "benchmark_runs":
            c.execute("INSERT OR REPLACE INTO benchmark_runs VALUES(?,?,?,?,?,?)",(key,obj.get("profile"),json.dumps(obj.get("metrics",{}),ensure_ascii=False),obj.get("output_path"),obj.get("created_at"),raw))
        else:
            raise ValueError(table)
        c.commit()

def audit(db_path: str | Path, record: dict[str,Any]) -> None:
    with conn(db_path) as c:
        c.execute("INSERT INTO audit_log(ts,scan_id,target_id,campaign_id,action,decision,reason,json) VALUES(?,?,?,?,?,?,?,?)",
                  (now_iso(),record.get("scan_id",""),record.get("target_id",""),record.get("campaign_id",""),json.dumps(record.get("action",{}),ensure_ascii=False,default=str),record.get("decision",""),record.get("reason",""),json.dumps(record,ensure_ascii=False,default=str)))
        c.commit()
