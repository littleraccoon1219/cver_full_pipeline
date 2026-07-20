from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class TrustedKnowledgeReader:
    """Read-only bridge to the formal trusted knowledge base.

    Model output is never written to the trusted database. Discovery records only
    keep stable links to reviewed KB records.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def available(self) -> bool:
        return self.path.is_file()

    def _connect(self) -> sqlite3.Connection:
        uri = f"file:{self.path.resolve()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        return connection

    def find_cves(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        if not self.available() or not cve_ids:
            return []
        normalized = sorted({value.strip().upper() for value in cve_ids if value.strip()})[:50]
        placeholders = ",".join("?" for _ in normalized)
        query = f"""
            SELECT record_id,record_type,external_id,title_en,title_zh,status,
                   root_cause_l1,root_cause_l2,root_cause_confidence,
                   summary_en,summary_zh,attributes_json,review_status,generated_by_model
            FROM kb_records
            WHERE external_id IN ({placeholders})
            ORDER BY external_id
        """
        try:
            with self._connect() as c:
                rows = c.execute(query, normalized).fetchall()
        except sqlite3.Error:
            return []
        result = []
        for row in rows:
            item = dict(row)
            try:
                item["attributes"] = json.loads(item.pop("attributes_json") or "{}")
            except json.JSONDecodeError:
                item["attributes"] = {}
            result.append(item)
        return result

    def search(self, text: str, *, limit: int = 12) -> list[dict[str, Any]]:
        if not self.available() or not text.strip():
            return []
        tokens = [token for token in text.replace("/", " ").replace("_", " ").split() if len(token) >= 3][:8]
        if not tokens:
            return []
        clauses = []
        params: list[Any] = []
        for token in tokens:
            clauses.append(
                "(title_en LIKE ? OR title_zh LIKE ? OR summary_en LIKE ? OR summary_zh LIKE ? OR external_id LIKE ?)"
            )
            pattern = f"%{token}%"
            params.extend([pattern] * 5)
        params.append(max(1, min(limit, 50)))
        query = (
            "SELECT record_id,external_id,title_en,title_zh,status,root_cause_l1,root_cause_l2,"
            "root_cause_confidence,summary_en,summary_zh,review_status,generated_by_model "
            "FROM kb_records WHERE " + " OR ".join(clauses) + " ORDER BY updated_at DESC LIMIT ?"
        )
        try:
            with self._connect() as c:
                rows = c.execute(query, params).fetchall()
        except sqlite3.Error:
            return []
        return [dict(row) for row in rows]
