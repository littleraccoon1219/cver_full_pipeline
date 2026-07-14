#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cver.knowledge.collectors.attack_pattern import DEFAULT_ATTACK_STIX_URL, collect_attack_pattern_candidates


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect container-related ATT&CK/CAPEC attack-pattern Candidates.")
    parser.add_argument("--attack-stix", default=DEFAULT_ATTACK_STIX_URL)
    parser.add_argument("--capec")
    parser.add_argument("--max-records", type=int, default=20)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = collect_attack_pattern_candidates(
        output_dir=args.output,
        attack_stix=args.attack_stix,
        capec_csv_or_zip=args.capec,
        max_records=args.max_records,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("candidate_count", 0) else 2


if __name__ == "__main__":
    raise SystemExit(main())
