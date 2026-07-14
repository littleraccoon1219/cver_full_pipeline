#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cver.knowledge.candidate_importer import import_candidate_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a validated Candidate bundle into the formal trusted KB.")
    parser.add_argument("--db", default="data/trusted_knowledge.db")
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--actor-id", required=True)
    parser.add_argument("--actor-name")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = import_candidate_bundle(
        db_path=args.db,
        bundle_dir=args.bundle,
        actor_id=args.actor_id,
        actor_name=args.actor_name,
        dry_run=args.dry_run,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
