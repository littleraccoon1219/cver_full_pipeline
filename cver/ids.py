from __future__ import annotations
import hashlib, uuid, time

def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"

def stable_id(prefix: str, *parts: object) -> str:
    raw = "|".join(str(x) for x in parts)
    return f"{prefix}-{hashlib.sha1(raw.encode()).hexdigest()[:12]}"

def utc_ms() -> int:
    return int(time.time() * 1000)
