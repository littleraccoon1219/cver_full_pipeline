#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cver.discovery.db import DiscoveryRepository


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize or upgrade the CVER discovery runtime database")
    parser.add_argument("--db", default="data/discovery_runtime.db")
    args = parser.parse_args()
    result = DiscoveryRepository(Path(args.db)).migrate()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
