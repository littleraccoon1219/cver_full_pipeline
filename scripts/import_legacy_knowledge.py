#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from cver.knowledge.migration import import_legacy_seed


def main() -> None:
    parser = argparse.ArgumentParser(description="Import legacy CVER seed data as trusted-KB candidates")
    parser.add_argument("--source", default="data/cve_knowledge/container_cves_seed.json")
    parser.add_argument("--db", default="data/trusted_knowledge.db")
    parser.add_argument("--annotator", required=True, help="human operator responsible for this migration")
    args = parser.parse_args()
    result = import_legacy_seed(args.source, args.db, args.annotator)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
