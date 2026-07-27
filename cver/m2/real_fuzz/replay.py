from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..config import M2Settings
from .models import CandidateLevel, ReplayLevel
from .runtime_assets import RuntimeAssetManager


ALLOWED_PROFILES = {
    "ReadStdout": {"rpc_only", "bounded_stdio"},
    "ReadStderr": {"rpc_only", "bounded_stdio"},
    "WriteStdin": {"rpc_only", "bounded_stdio"},
    "ExecProcess": {"rpc_only", "test_process"},
    "SignalProcess": {"rpc_only", "non_fatal_signal"},
    "WaitProcess": {"rpc_only", "bounded_wait"},
    "UpdateContainer": {"rpc_only", "bounded_resources"},
}

FORBIDDEN_ACTIONS = (
    "host filesystem access",
    "privileged device access",
    "external network access",
    "persistent host changes",
    "arbitrary root shell",
    "guest-to-host escape payload",
)


class GuestReplayPlanner:
    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings
        self.assets = RuntimeAssetManager(settings)

    def plan(
        self,
        *,
        candidate: dict[str, Any],
        version: str,
        level: str,
        input_artifact: str | Path,
        input_profile: str,
        confirm: bool = False,
    ) -> dict[str, Any]:
        replay_level = ReplayLevel(level)
        handler = str(candidate.get("handler_id", ""))
        if input_profile not in ALLOWED_PROFILES.get(handler, set()):
            raise ValueError(f"input profile {input_profile!r} is not allowed for {handler}")
        artifact = Path(input_artifact).expanduser().resolve()
        if not artifact.is_file():
            raise FileNotFoundError(artifact)
        candidate_level = CandidateLevel(str(candidate.get("level", CandidateLevel.OBSERVATION.value)))
        gates = self._gates(replay_level, candidate_level, confirm=confirm)
        runtime = self._runtime(version)
        runtime_ready = runtime["status"] in {"CURRENT_INSTALLED_READY", "READY"}
        ready = gates["ready"] and runtime_ready
        if ready:
            status = "REPLAY_PLAN_READY"
        elif not runtime_ready:
            status = "RUNTIME_NOT_REPRODUCED"
        else:
            status = "REPLAY_APPROVAL_REQUIRED"
        plan = {
            "schema_version": 1,
            "status": status,
            "version": version,
            "level": replay_level.value,
            "candidate_id": candidate.get("candidate_id"),
            "candidate_level": candidate_level.value,
            "handler_id": handler,
            "input": {
                "profile": input_profile,
                "sha256": self._sha256(artifact),
                "size_bytes": artifact.stat().st_size,
                "restricted": True,
                "path": str(artifact),
            },
            "runtime": runtime,
            "gates": gates,
            "sandbox": {
                "namespace": self.settings.namespace,
                "one_shot": True,
                "guest_tmp_only": True,
                "host_paths": [],
                "external_network": False,
                "privileged_devices": False,
                "destroy_after_run": True,
            },
            "expected_observations": [
                "typed RPC status and bounded response",
                "guest process state before and after the request",
                "agent/runtime logs with timestamps",
                "isolation and authorization invariants",
            ],
            "forbidden_actions": list(FORBIDDEN_ACTIONS),
            "execution": {
                "automatic": False,
                "reason": (
                    "A version-matched replay client and restricted root helper are required. "
                    "This planner never substitutes a mock result for Guest evidence."
                ),
            },
        }
        plan["plan_sha256"] = hashlib.sha256(
            json.dumps(plan, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return plan

    def _runtime(self, version: str) -> dict[str, Any]:
        if version == self.settings.current_kata_version:
            config_ready = self.settings.kata_config.is_file()
            return {
                "status": "CURRENT_INSTALLED_READY" if config_ready else "RUNTIME_NOT_REPRODUCED",
                "version": version,
                "runtime_root": "/opt/kata",
                "configuration": str(self.settings.kata_config),
                "system_overwrite": False,
                "reason": None if config_ready else "current Kata configuration file is missing",
            }
        return self.assets.readiness(version)

    def _gates(self, level: ReplayLevel, candidate_level: CandidateLevel, *, confirm: bool) -> dict[str, Any]:
        reasons = []
        if level in {ReplayLevel.GUEST_NON_DESTRUCTIVE, ReplayLevel.ISOLATION_INVARIANT}:
            if not (confirm and self.settings.allow_guest_replay):
                reasons.append("L2/L3 requires CVER_M2_ALLOW_GUEST_REPLAY=true and --confirm")
            if not self.settings.disposable_lab_ready:
                reasons.append("disposable Kata lab is not marked ready")
        if level is ReplayLevel.ISOLATION_INVARIANT and candidate_level not in {
            CandidateLevel.STRONG,
            CandidateLevel.VALIDATED,
        }:
            reasons.append("L3 requires a STRONG_CANDIDATE or VALIDATED_CANDIDATE")
        return {
            "ready": not reasons,
            "reasons": reasons,
            "human_approval_required": level is not ReplayLevel.RPC_ONLY,
            "minimum_candidate": (
                CandidateLevel.STRONG.value if level is ReplayLevel.ISOLATION_INVARIANT else CandidateLevel.OBSERVATION.value
            ),
        }

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
