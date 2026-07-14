#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cver.knowledge.collectors.nvd import collect_nvd_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect NVD records into a Candidate bundle; do not write the database.")
    parser.add_argument("--start-year", type=int, default=2020)
    parser.add_argument("--end-year", type=int, default=2026)
    parser.add_argument("--target-count", type=int, default=160)
    parser.add_argument("--quota-config", default="configs/cve_collection_2020_2026.yaml")
    parser.add_argument("--output", required=True)
    parser.add_argument("--sleep", type=float, default=None)
    args = parser.parse_args()
    result = collect_nvd_candidates(
        output_dir=args.output,
        quota_config=args.quota_config,
        start_year=args.start_year,
        end_year=args.end_year,
        target_count=args.target_count,
        sleep_seconds=args.sleep,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("candidate_count", 0) else 2


if __name__ == "__main__":
    raise SystemExit(main())
