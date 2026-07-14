#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cver.knowledge.candidate_validation import validate_candidate_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate a Candidate bundle before database import.")
    parser.add_argument("--bundle", required=True)
    args = parser.parse_args()
    result = validate_candidate_bundle(args.bundle).to_dict()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
