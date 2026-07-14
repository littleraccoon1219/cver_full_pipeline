#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cver.knowledge.formal_schema import schema_report


def main() -> int:
    parser = argparse.ArgumentParser(description='Report formal trusted-KB schema status.')
    parser.add_argument('--db', default='data/trusted_knowledge.db')
    args = parser.parse_args()
    report = schema_report(args.db)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not report['missing_tables'] and not report['foreign_key_errors'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
