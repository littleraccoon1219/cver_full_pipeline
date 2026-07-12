#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import sqlite3
from pathlib import Path

LEGACY_OBJECTS = (
    "cve_knowledge_fts_config",
    "cve_knowledge_fts_docsize",
    "cve_knowledge_fts_idx",
    "cve_knowledge_fts_data",
    "cve_knowledge_fts_content",
    "cve_knowledge_fts",
    "cve_knowledge",
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Drop only the old CVE knowledge tables. Do not run this until CVERPipeline "
            "has stopped using cver.vulndb.VulnDB."
        )
    )
    parser.add_argument("--db", default="data/cver_full_pipeline.db")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--pipeline-migrated", action="store_true")
    args = parser.parse_args()

    db = Path(args.db)
    if not db.exists():
        raise SystemExit(f"database does not exist: {db}")
    if not args.execute:
        print("DRY RUN: would back up the database and drop only legacy CVE knowledge objects:")
        for name in LEGACY_OBJECTS:
            print(f"  - {name}")
        print("Re-run with --execute --pipeline-migrated only after the pipeline lookup has been migrated.")
        return 0
    if not args.pipeline_migrated:
        raise SystemExit(
            "refusing to drop tables: add --pipeline-migrated only after cver/pipeline.py no longer uses VulnDB"
        )

    backup = db.with_suffix(db.suffix + ".before-legacy-drop.bak")
    shutil.copy2(db, backup)
    with sqlite3.connect(str(db)) as connection:
        for name in LEGACY_OBJECTS:
            connection.execute(f'DROP TABLE IF EXISTS "{name}"')
        connection.commit()
    print(f"backup: {backup}")
    print("legacy CVE knowledge tables dropped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
