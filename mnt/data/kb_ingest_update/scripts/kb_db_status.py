#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

OPERATIONAL_TABLES = {
    "targets",
    "scans",
    "findings",
    "evidences",
    "reports",
    "benchmark_runs",
    "audit_log",
}
LEGACY_KNOWLEDGE_TABLES = {"cve_knowledge", "cve_knowledge_fts"}


def inspect_database(path: str) -> dict:
    db = Path(path)
    if not db.exists():
        return {"database": str(db), "exists": False, "tables": []}
    with sqlite3.connect(str(db)) as connection:
        names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view') ORDER BY name"
            ).fetchall()
            if not row[0].startswith("sqlite_")
        ]
        rows = []
        for name in names:
            try:
                count = connection.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
            except sqlite3.DatabaseError:
                count = None
            if name.startswith("kb_"):
                role = "trusted_kb"
            elif name in LEGACY_KNOWLEDGE_TABLES or name.startswith("cve_knowledge_fts_"):
                role = "legacy_knowledge"
            elif name in OPERATIONAL_TABLES:
                role = "operational_pipeline"
            else:
                role = "other"
            rows.append({"table": name, "rows": count, "role": role})
    return {"database": str(db), "exists": True, "tables": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description="Show SQLite tables, row counts, and migration roles.")
    parser.add_argument("database", nargs="+", help="one or more SQLite database paths")
    args = parser.parse_args()
    print(json.dumps([inspect_database(path) for path in args.database], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
