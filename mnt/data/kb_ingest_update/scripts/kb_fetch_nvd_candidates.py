#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import json

from cver.knowledge.nvd_ingest import DEFAULT_KEYWORDS, fetch_and_ingest_nvd_candidates


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Download container-related NVD records as immutable raw snapshots and "
            "store them as unverified Candidate records in the trusted knowledge base."
        )
    )
    parser.add_argument("--db", default="data/trusted_knowledge.db")
    parser.add_argument("--raw-dir", default="data/raw/nvd")
    parser.add_argument("--annotator", required=True)
    parser.add_argument("--years", nargs=2, type=int, default=[2016, dt.date.today().year])
    parser.add_argument("--max-records", type=int, default=100)
    parser.add_argument("--keyword", action="append", dest="keywords")
    parser.add_argument("--sleep", type=float, default=None)
    args = parser.parse_args()

    result = fetch_and_ingest_nvd_candidates(
        db_path=args.db,
        raw_dir=args.raw_dir,
        annotator=args.annotator,
        start_year=args.years[0],
        end_year=args.years[1],
        max_records=args.max_records,
        keywords=args.keywords or DEFAULT_KEYWORDS,
        sleep_seconds=args.sleep,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
