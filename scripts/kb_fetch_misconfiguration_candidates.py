#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cver.knowledge.collectors.misconfiguration import collect_misconfiguration_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect container/cloud-native misconfiguration Candidate records.")
    parser.add_argument("--source-config", default="configs/misconfiguration_sources.yaml")
    parser.add_argument("--max-records", type=int, default=50)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = collect_misconfiguration_candidates(
        output_dir=args.output,
        source_config=args.source_config,
        max_records=args.max_records,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("candidate_count", 0) else 2


if __name__ == "__main__":
    raise SystemExit(main())
