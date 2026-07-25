from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from .config import M2Settings


class TrustedKnowledgeMatcher:
    """Read-only, schema-tolerant matching against the existing trusted KB."""

    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings

    def match(self, components: Iterable[str], versions: dict[str, str | None]) -> dict[str, Any]:
        path = self.settings.trusted_kb_db
        if not path.is_file():
            return {
                "status": "skipped_with_reason",
                "reason": f"trusted KB does not exist: {path}",
                "matches": [],
            }
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
            matches: list[dict[str, Any]] = []
            for table in ("kb_records", "vulnerabilities", "cve_knowledge"):
                if table not in tables:
                    continue
                columns = [row["name"] for row in connection.execute(f"PRAGMA table_info({table})")]
                matches.extend(self._query_table(connection, table, columns, components, versions))
            return {
                "status": "ok",
                "database": str(path),
                "tables": sorted(tables),
                "matches": matches[:500],
                "match_count": len(matches),
            }
        finally:
            connection.close()

    @staticmethod
    def _query_table(
        connection: sqlite3.Connection,
        table: str,
        columns: list[str],
        components: Iterable[str],
        versions: dict[str, str | None],
    ) -> list[dict[str, Any]]:
        searchable = [
            name
            for name in columns
            if name.lower()
            in {
                "component",
                "product",
                "title",
                "description",
                "attributes_json",
                "json",
                "payload_json",
                "external_id",
                "record_id",
                "cve_id",
            }
        ]
        if not searchable:
            return []
        output: list[dict[str, Any]] = []
        quoted_table = '"' + table.replace('"', '""') + '"'
        for component in components:
            clauses = " OR ".join(f"CAST(\"{column}\" AS TEXT) LIKE ?" for column in searchable)
            params = [f"%{component}%"] * len(searchable)
            query = f"SELECT * FROM {quoted_table} WHERE {clauses} LIMIT 100"
            for row in connection.execute(query, params):
                payload = dict(row)
                output.append(
                    {
                        "table": table,
                        "component_query": component,
                        "installed_version": versions.get(component),
                        "record": payload,
                        "match_status": "candidate_version_review",
                        "reason": (
                            "Component text matched. Version-range evidence must be reviewed before "
                            "an exploitability level above E1 is assigned."
                        ),
                    }
                )
        return output


class ExternalCandidateCollector:
    """Official-source collection that only creates untrusted Candidate bundles."""

    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings

    def collect_nvd(
        self,
        components: Iterable[str],
        *,
        confirm: bool = False,
        max_per_component: int = 20,
    ) -> dict[str, Any]:
        if not confirm:
            raise ValueError("external collection requires explicit confirmation")
        if not self.settings.allow_external_candidates:
            raise PermissionError("CVER_M2_ALLOW_EXTERNAL_CANDIDATES is not enabled")
        run_id = f"nvd-{int(time.time())}"
        output_dir = self.settings.candidates_dir / "external" / run_id
        output_dir.mkdir(parents=True, exist_ok=False)
        entries = []
        api_key = __import__("os").getenv("NVD_API_KEY", "")
        for component in components:
            query = urllib.parse.urlencode(
                {
                    "keywordSearch": component,
                    "resultsPerPage": max(1, min(max_per_component, 100)),
                    "noRejected": "",
                }
            )
            request = urllib.request.Request(
                f"{self.NVD_URL}?{query}",
                headers={
                    "User-Agent": "CVER-M2/0.1 defensive-research",
                    **({"apiKey": api_key} if api_key else {}),
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    body = response.read(25_000_000)
                    status = response.status
            except Exception as exc:
                entries.append(
                    {
                        "component": component,
                        "status": "failed",
                        "reason": f"{type(exc).__name__}: {exc}",
                    }
                )
                continue
            digest = hashlib.sha256(body).hexdigest()
            path = output_dir / f"{component.replace('/', '_')}-{digest[:12]}.json"
            path.write_bytes(body)
            payload = json.loads(body)
            entries.append(
                {
                    "component": component,
                    "status": "candidate_collected",
                    "http_status": status,
                    "sha256": digest,
                    "path": str(path),
                    "source_url": self.NVD_URL,
                    "record_count": len(payload.get("vulnerabilities", [])),
                    "admission": "candidate_only_not_trusted",
                }
            )
        manifest = {
            "schema_version": 1,
            "run_id": run_id,
            "source": "NVD API 2.0",
            "trust_state": "untrusted_candidate",
            "created_at": time.time(),
            "entries": entries,
        }
        manifest_path = output_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest["manifest_path"] = str(manifest_path)
        manifest["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        return manifest
