from __future__ import annotations

import hashlib
import json
import re
import uuid
from pathlib import Path
from typing import Any

from .models import CandidateLevel, CandidateRecord, asdict


SANITIZER_RE = re.compile(
    r"AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer|ThreadSanitizer|data race",
    re.IGNORECASE,
)
PANIC_RE = re.compile(r"thread .* panicked|panic at|fatal runtime error", re.IGNORECASE)
DEADLOCK_RE = re.compile(r"deadlock|all threads are asleep|lock order inversion", re.IGNORECASE)
RESOURCE_RE = re.compile(r"out of memory|resource exhausted|too many open files", re.IGNORECASE)


class CandidateTriage:
    def classify(self, run: dict[str, Any], *, guest_replay: dict[str, Any] | None = None) -> dict[str, Any]:
        text = "\n".join(
            str(run.get(key, "")) for key in ("stdout_tail", "stderr_tail", "log", "reason")
        )
        evidence = list(run.get("evidence", []))
        reproductions = int((run.get("reproducibility") or {}).get("successful_reproductions", 0))
        has_artifact = any(item.get("sha256") for item in evidence)
        sanitizer = bool(SANITIZER_RE.search(text)) or any(
            item.get("kind") in {"sanitizer", "data_race"} for item in evidence
        )
        deterministic_deadlock = bool(DEADLOCK_RE.search(text)) and reproductions >= 3
        repeatable_panic = bool(PANIC_RE.search(text)) and reproductions >= 2
        resource = bool(RESOURCE_RE.search(text)) and reproductions >= 2
        isolation = bool((guest_replay or {}).get("isolation_invariant_violated"))
        guest_reproduced = bool((guest_replay or {}).get("reproduced"))

        if guest_reproduced or isolation:
            level = CandidateLevel.VALIDATED
            reason = "non-destructive Kata Guest replay or an isolation invariant confirmed the defect"
        elif (sanitizer and has_artifact and reproductions >= 3) or deterministic_deadlock:
            level = CandidateLevel.STRONG
            reason = "sanitizer/data-race/deterministic-deadlock evidence reproduced at least three times"
        elif repeatable_panic or resource or reproductions >= 2:
            level = CandidateLevel.WEAK
            reason = "repeatable abnormal behavior exists but strong memory/race/boundary evidence is incomplete"
        else:
            level = CandidateLevel.OBSERVATION
            reason = "single or non-deterministic anomaly; retained as an observation only"

        candidate = CandidateRecord(
            candidate_id=f"m2cand-{uuid.uuid4().hex}",
            level=level,
            component=str(run.get("component", "kata-agent")),
            kata_version=str(run.get("kata_version", "unknown")),
            source_track=str(run.get("source_track", "unknown")),
            handler_id=str(run.get("handler_id", "unknown")),
            finding_type=self._finding_type(text, run),
            title=f"{level.value}: {run.get('handler_id', 'kata-agent handler')} anomaly",
            evidence=evidence,
            reproductions=reproductions,
            deterministic_seed=(run.get("reproducibility") or {}).get("seed"),
            state_sequence=list((run.get("reproducibility") or {}).get("state_sequence", [])),
            isolation_invariant=(guest_replay or {}).get("isolation_invariant"),
            source_commit=run.get("source_commit"),
            adapter_id=run.get("adapter_id"),
            status_reason=reason,
            metadata={
                "run_id": run.get("run_id"),
                "guest_replay": guest_replay or {},
                "promotion_policy": "LLM output and exit code alone cannot promote a candidate",
            },
        )
        payload = asdict(candidate)
        payload["dedup_key"] = self.dedup_key(payload)
        return payload

    @staticmethod
    def _finding_type(text: str, run: dict[str, Any]) -> str:
        if re.search(r"ThreadSanitizer|data race", text, re.I):
            return "data_race"
        if DEADLOCK_RE.search(text):
            return "deadlock"
        if re.search(r"AddressSanitizer|use-after-free|buffer-overflow", text, re.I):
            return "memory_safety"
        if re.search(r"UndefinedBehaviorSanitizer|runtime error", text, re.I):
            return "undefined_behavior"
        if PANIC_RE.search(text):
            return "panic"
        if RESOURCE_RE.search(text):
            return "resource_exhaustion"
        return str(run.get("classification", "unexpected_behavior"))

    @staticmethod
    def dedup_key(payload: dict[str, Any]) -> str:
        signature = {
            "component": payload.get("component"),
            "handler_id": payload.get("handler_id"),
            "finding_type": payload.get("finding_type"),
            "source_commit": payload.get("source_commit"),
            "artifact_hashes": sorted(
                item.get("sha256") for item in payload.get("evidence", []) if item.get("sha256")
            ),
        }
        return hashlib.sha256(json.dumps(signature, sort_keys=True).encode("utf-8")).hexdigest()

    @staticmethod
    def write(candidate: dict[str, Any], directory: str | Path) -> str:
        root = Path(directory).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{candidate['candidate_id']}.json"
        path.write_text(json.dumps(candidate, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)
