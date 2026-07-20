from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def redact(x: Any) -> Any:
    if isinstance(x, dict):
        return {
            k: ("***REDACTED***" if any(t in k.lower() for t in ["key", "token", "secret", "password"]) else redact(v))
            for k, v in x.items()
        }
    if isinstance(x, list):
        return [redact(v) for v in x]
    return x


def hash_obj(x: Any) -> str:
    return hashlib.sha256(json.dumps(x, ensure_ascii=False, sort_keys=True, default=str).encode()).hexdigest()[:16]


class EventLogger:
    def __init__(self, path: str = "outputs/logs/pipeline.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, **kw: Any) -> None:
        record = {"ts": now_iso(), **kw}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(redact(record), ensure_ascii=False, default=str) + "\n")
