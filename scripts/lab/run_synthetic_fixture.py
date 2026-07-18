#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: run_synthetic_fixture.py FIXTURE_DIR", file=sys.stderr)
        return 2
    fixture = Path(sys.argv[1]).resolve()
    if not (fixture / "go.mod").is_file() or not (fixture / "pathguard_test.go").is_file():
        print("invalid synthetic fixture", file=sys.stderr)
        return 2
    completed = subprocess.run(
        ["go", "test", "./...", "-count=1", "-v"],
        cwd=fixture,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    payload = {
        "reproduced": completed.returncode == 0,
        "security_invariant_violation": completed.returncode == 0,
        "fixture": "synthetic_pathguard",
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    print(json.dumps(payload, ensure_ascii=False))
    if completed.returncode == 0:
        print("CVER_SYNTHETIC_REPRODUCED")
        print("SECURITY_INVARIANT_VIOLATION_CONFIRMED")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
