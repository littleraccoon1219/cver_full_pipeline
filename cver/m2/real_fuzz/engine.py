from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable

from ..config import HARD_LIMITS, M2Settings
from ..runner import SafeCommandRunner
from .inspector import KataAgentInspector
from .manifests import AdapterRegistry
from .models import AdapterState
from .toolchain import RustFuzzToolchain
from .workspace import RealFuzzWorkspace


SANITIZER_PATTERNS = {
    "address": re.compile(r"AddressSanitizer|use-after-free|buffer-overflow", re.I),
    "undefined": re.compile(r"UndefinedBehaviorSanitizer|runtime error:", re.I),
    "thread": re.compile(r"ThreadSanitizer|data race", re.I),
    "memory": re.compile(r"MemorySanitizer", re.I),
    "leak": re.compile(r"LeakSanitizer", re.I),
}


class RealFuzzEngine:
    def __init__(self, settings: M2Settings, runner: SafeCommandRunner | None = None) -> None:
        self.settings = settings
        self.settings.ensure_directories()
        self.runner = runner or SafeCommandRunner(helper=settings.sudo_helper)
        assert settings.adapter_manifest_dir is not None
        assert settings.real_fuzz_root is not None
        self.registry = AdapterRegistry(settings.adapter_manifest_dir)
        self.workspace_manager = RealFuzzWorkspace(settings.real_fuzz_root)

    def inspect(self, source_root: str | Path, *, version: str, track: str) -> dict[str, Any]:
        inspection = KataAgentInspector().inspect(source_root, version=version)
        adapter = self.registry.check(inspection)
        return {
            "status": inspection.status,
            "track": track,
            "inspection": KataAgentInspector.to_payload(inspection),
            "adapter": adapter,
            "track_isolation": "evidence is stored and evaluated only within this source track",
        }

    def prepare(
        self,
        source_root: str | Path,
        *,
        version: str,
        track: str,
        propose_adapter: bool = False,
        seed: int = 1337,
    ) -> dict[str, Any]:
        inspection = KataAgentInspector().inspect(source_root, version=version)
        adapter = self.registry.check(inspection)
        proposal = None
        if propose_adapter and adapter.get("state") in {
            AdapterState.ADAPTER_REQUIRED.value,
            AdapterState.REVIEW_REQUIRED.value,
            AdapterState.SEMANTIC_DRIFT.value,
        }:
            proposal = self.registry.propose(inspection)
        workspace = self.workspace_manager.prepare(inspection, adapter, track=track, seed=seed)
        return {
            "status": "prepared",
            "inspection": KataAgentInspector.to_payload(inspection),
            "adapter": adapter,
            "adapter_proposal": proposal,
            "workspace": workspace,
        }

    def toolchain(self) -> dict[str, Any]:
        return RustFuzzToolchain(self.settings.rust_nightly).check()

    def build(self, workspace: str | Path, *, handler: str | None = None) -> dict[str, Any]:
        root, lock = self._validated_workspace(workspace)
        if lock.get("adapter_state") != AdapterState.APPROVED.value:
            return {
                "status": "SKIPPED_WITH_REASON",
                "reason": "real handler build requires an approved exact adapter",
                "adapter_state": lock.get("adapter_state"),
            }
        toolchain = self.toolchain()
        if toolchain["status"] != "ready":
            return {"status": "SKIPPED_WITH_REASON", "reason": toolchain["reasons"], "toolchain": toolchain}
        target = self._target_name(handler) if handler else None
        command = ["cargo", f"+{self.settings.rust_nightly}", "fuzz", "build"]
        if target:
            command.append(target)
        result = self.runner.run(command, cwd=root, timeout=900)
        return {
            "status": "built" if result.ok else "BUILD_FAILED",
            "command": result.argv,
            "exit_code": result.returncode,
            "duration_seconds": result.duration_seconds,
            "stdout_tail": result.stdout[-12000:],
            "stderr_tail": result.stderr[-12000:],
            "workspace_lock_sha256": self._sha256(root / "workspace-lock.json"),
        }

    def run(
        self,
        workspace: str | Path,
        *,
        handler: str,
        seconds: int | None = None,
        seed: int = 1337,
        confirm: bool = False,
        mode: str = "stateless",
    ) -> dict[str, Any]:
        if not confirm:
            raise PermissionError("real source fuzzing requires --confirm-native-fuzz")
        root, lock = self._validated_workspace(workspace)
        if lock.get("adapter_state") != AdapterState.APPROVED.value:
            return {
                "run_id": f"realfuzz-{uuid.uuid4().hex}",
                "status": "SKIPPED_WITH_REASON",
                "reason": "adapter is not approved for this exact source interface",
                "adapter_state": lock.get("adapter_state"),
                "handler_id": handler,
            }
        toolchain = self.toolchain()
        if toolchain["status"] != "ready":
            return {
                "run_id": f"realfuzz-{uuid.uuid4().hex}",
                "status": "SKIPPED_WITH_REASON",
                "reason": toolchain["reasons"],
                "toolchain": toolchain,
                "handler_id": handler,
            }
        fuzz_seconds = self.settings.resolve_fuzz_seconds(seconds)
        target = self._target_name(handler)
        corpus = root / "fuzz" / "corpus" / target
        artifacts = root / "artifacts" / target / str(int(time.time()))
        artifacts.mkdir(parents=True, exist_ok=True)
        before = {item.name for item in artifacts.iterdir()}
        command = [
            "cargo",
            f"+{self.settings.rust_nightly}",
            "fuzz",
            "run",
            target,
            str(corpus),
            "--",
            f"-max_total_time={fuzz_seconds}",
            "-timeout=15",
            "-max_len=262144",
            f"-rss_limit_mb={self.settings.budget.rss_limit_mb}",
            f"-artifact_prefix={artifacts}/",
            f"-seed={seed}",
            "-print_final_stats=1",
        ]
        result = self.runner.run(
            command,
            cwd=root,
            env={
                "RUST_BACKTRACE": "1",
                "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1:symbolize=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
            timeout=fuzz_seconds + 90,
        )
        new_artifacts = [item for item in artifacts.iterdir() if item.name not in before and item.is_file()]
        combined = f"{result.stdout}\n{result.stderr}"
        sanitizer = next((name for name, pattern in SANITIZER_PATTERNS.items() if pattern.search(combined)), None)
        evidence = [
            {
                "evidence_id": f"ev-{uuid.uuid4().hex}",
                "kind": "sanitizer" if sanitizer else "fuzz_artifact",
                "artifact_path": str(item),
                "sha256": self._sha256(item),
                "size_bytes": item.stat().st_size,
                "restricted": True,
            }
            for item in new_artifacts
        ]
        if new_artifacts and sanitizer:
            status = "CONFIRMED_SANITIZER_CRASH"
        elif result.timed_out:
            status = "TIMEOUT"
        elif result.returncode not in {0, 77}:
            status = "FAILED_WITHOUT_STRONG_EVIDENCE"
        else:
            status = "COMPLETED_NO_CRASH"
        source = lock.get("source") or {}
        adapter = lock.get("adapter") or {}
        return {
            "run_id": f"realfuzz-{uuid.uuid4().hex}",
            "component": "kata-agent",
            "source_track": lock.get("track"),
            "kata_version": source.get("version"),
            "source_commit": source.get("commit"),
            "source_sha256": source.get("rpc_sha256"),
            "adapter_id": adapter.get("adapter_id"),
            "handler_id": handler,
            "mode": mode,
            "status": status,
            "command": result.argv,
            "duration_seconds": result.duration_seconds,
            "exit_code": result.returncode,
            "corpus_dir": str(corpus),
            "artifact_dir": str(artifacts),
            "sanitizer_kind": sanitizer,
            "coverage": self._coverage(combined),
            "evidence": evidence,
            "reproducibility": {
                "seed": seed,
                "required_reproductions": 3,
                "successful_reproductions": 0,
                "state_sequence": [],
            },
            "stdout_tail": result.stdout[-12000:],
            "stderr_tail": result.stderr[-12000:],
            "safety_boundary": (
                "This run invokes only an approved real-handler adapter with bounded inputs. "
                "It does not generate or execute a guest-to-host escape payload."
            ),
        }

    def run_many(
        self,
        workspace: str | Path,
        *,
        handlers: Iterable[str],
        seconds: int | None = None,
        seed: int = 1337,
        confirm: bool = False,
    ) -> list[dict[str, Any]]:
        selected = list(dict.fromkeys(handlers))
        if not selected:
            raise ValueError("at least one handler is required")
        workers = min(self.settings.budget.parallel_harnesses, HARD_LIMITS["parallel_harnesses"], len(selected))
        results = []
        with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
            futures = {
                executor.submit(
                    self.run,
                    workspace,
                    handler=handler,
                    seconds=seconds,
                    seed=seed + index,
                    confirm=confirm,
                ): handler
                for index, handler in enumerate(selected)
            }
            for future in as_completed(futures):
                results.append(future.result())
        return sorted(results, key=lambda item: str(item.get("handler_id")))

    def reproduce(
        self,
        workspace: str | Path,
        *,
        handler: str,
        artifact: str | Path,
        attempts: int = 3,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if not confirm:
            raise PermissionError("crash reproduction requires --confirm-native-fuzz")
        root, lock = self._validated_workspace(workspace)
        if lock.get("adapter_state") != AdapterState.APPROVED.value:
            return {"status": "SKIPPED_WITH_REASON", "reason": "adapter not approved"}
        artifact_path = Path(artifact).expanduser().resolve()
        if not artifact_path.is_file() or root not in artifact_path.parents:
            raise PermissionError("artifact must be a file inside the selected workspace")
        count = max(1, min(int(attempts), HARD_LIMITS["replay_attempts"]))
        target = self._target_name(handler)
        outcomes = []
        successes = 0
        for index in range(count):
            result = self.runner.run(
                ["cargo", f"+{self.settings.rust_nightly}", "fuzz", "run", target, str(artifact_path)],
                cwd=root,
                env={"RUST_BACKTRACE": "1"},
                timeout=120,
            )
            text = f"{result.stdout}\n{result.stderr}"
            sanitizer = next((name for name, pattern in SANITIZER_PATTERNS.items() if pattern.search(text)), None)
            reproduced = sanitizer is not None
            successes += int(reproduced)
            outcomes.append(
                {
                    "attempt": index + 1,
                    "reproduced": reproduced,
                    "sanitizer_kind": sanitizer,
                    "exit_code": result.returncode,
                    "duration_seconds": result.duration_seconds,
                    "stderr_tail": result.stderr[-4000:],
                }
            )
        return {
            "status": "REPRODUCED" if successes >= 3 else "INSUFFICIENT_REPRODUCTIONS",
            "handler_id": handler,
            "artifact_sha256": self._sha256(artifact_path),
            "required_reproductions": 3,
            "successful_reproductions": successes,
            "attempts": outcomes,
        }

    @staticmethod
    def _target_name(handler: str | None) -> str:
        if not handler:
            raise ValueError("handler is required")
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", handler).lower()
        return snake if snake.startswith("fuzz_") else f"fuzz_{snake}"

    @staticmethod
    def _coverage(text: str) -> dict[str, Any]:
        def value(pattern: str) -> int | None:
            matches = re.findall(pattern, text)
            return int(matches[-1]) if matches else None

        return {
            "edges": value(r"cov:\s*(\d+)"),
            "features": value(r"ft:\s*(\d+)"),
            "corpus_units": value(r"corp:\s*(\d+)"),
            "source": "libFuzzer final statistics",
        }

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _validated_workspace(workspace: str | Path) -> tuple[Path, dict[str, Any]]:
        root = Path(workspace).expanduser().resolve()
        lock_path = root / "workspace-lock.json"
        if not lock_path.is_file():
            raise FileNotFoundError(f"workspace lock is missing: {lock_path}")
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        source = lock.get("source") or {}
        rpc_path = Path(str(source.get("rpc_path", ""))).expanduser().resolve()
        if not rpc_path.is_file():
            raise FileNotFoundError("locked kata-agent rpc source is unavailable")
        actual = RealFuzzEngine._sha256(rpc_path)
        if actual != source.get("rpc_sha256"):
            raise RuntimeError("locked kata-agent source hash changed; re-run adapter compatibility checks")
        return root, lock
