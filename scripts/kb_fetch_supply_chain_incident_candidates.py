#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cver.knowledge.collectors.supply_chain import collect_supply_chain_incident_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect curated container supply-chain incident Candidates.")
    parser.add_argument("--seed-config", default="configs/supply_chain_seed_sources.yaml")
    parser.add_argument("--max-records", type=int, default=20)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = collect_supply_chain_incident_candidates(
        output_dir=args.output,
        seed_config=args.seed_config,
        max_records=args.max_records,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("candidate_count", 0) else 2


if __name__ == "__main__":
    raise SystemExit(main())
