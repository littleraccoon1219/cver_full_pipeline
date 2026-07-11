from __future__ import annotations
import json, sqlite3
from pathlib import Path
from typing import Any
from . import db
from .logging_utils import now_iso
from .models import CVEKnowledge

class VulnDB:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        db.init_db(db_path)

    def import_seed(self, path: str = "data/cve_knowledge/container_cves_seed.json") -> int:
        p = Path(path)
        if not p.exists():
            return 0
        payload = json.loads(p.read_text(encoding="utf-8"))
        count = 0
        with db.conn(self.db_path) as c:
            for r in payload.get("records", []):
                facts = r.get("facts", {})
                sem = r.get("semantic_annotations", {})
                cve_id = facts.get("cve_id")
                if not cve_id:
                    continue
                cvss = facts.get("cvss") or {}
                raw = json.dumps(r, ensure_ascii=False)
                c.execute("INSERT OR REPLACE INTO cve_knowledge VALUES(?,?,?,?,?,?,?,?,?,?)",
                          (cve_id, facts.get("component"), sem.get("root_cause"), sem.get("fine_type"), facts.get("severity"), cvss.get("score"), facts.get("published"), facts.get("last_modified"), raw, now_iso()))
                try:
                    c.execute("INSERT OR REPLACE INTO cve_knowledge_fts(rowid,cve_id,component,description,semantic_json) VALUES((SELECT rowid FROM cve_knowledge WHERE cve_id=?),?,?,?,?)",
                              (cve_id, cve_id, facts.get("component"), facts.get("description"), json.dumps(sem, ensure_ascii=False)))
                except sqlite3.OperationalError:
                    pass
                count += 1
            c.commit()
        return count

    def get(self, cve_id: str) -> CVEKnowledge | None:
        if not cve_id:
            return None
        with db.conn(self.db_path) as c:
            row = c.execute("SELECT json FROM cve_knowledge WHERE cve_id=?", (cve_id,)).fetchone()
        if not row:
            return None
        obj = json.loads(row["json"])
        return CVEKnowledge(obj.get("facts", {}).get("cve_id", cve_id), obj.get("facts", {}), obj.get("semantic_annotations", {}), obj.get("evidence_sources", []), obj.get("redteam_mapping", []))

    def search(self, query: str, limit: int = 5) -> list[dict[str,Any]]:
        rows = []
        with db.conn(self.db_path) as c:
            try:
                rows = c.execute("SELECT cve_id FROM cve_knowledge_fts WHERE cve_knowledge_fts MATCH ? LIMIT ?", (query, limit)).fetchall()
            except Exception:
                like = f"%{query}%"
                rows = c.execute("SELECT cve_id FROM cve_knowledge WHERE cve_id LIKE ? OR component LIKE ? OR json LIKE ? LIMIT ?", (like, like, like, limit)).fetchall()
        out = []
        for r in rows:
            item = self.get(r["cve_id"])
            if item:
                out.append({"cve_id": item.cve_id, "facts": item.facts, "semantic_annotations": item.semantic_annotations})
        return out
