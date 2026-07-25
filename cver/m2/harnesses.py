from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import BUDGETS, M2Settings
from .runner import SafeCommandRunner


@dataclass(frozen=True, slots=True)
class HarnessSpec:
    harness_id: str
    source_name: str
    boundary: str
    description: str
    seeds: tuple[bytes, ...]


HARNESS_SPECS: tuple[HarnessSpec, ...] = (
    HarnessSpec(
        "oci-runtime-input",
        "oci_runtime_harness.cc",
        "runtime/shim OCI and annotation input",
        "Bounded JSON/OCI structural and annotation-boundary parser.",
        (
            b'{"ociVersion":"1.2.1","annotations":{"io.katacontainers.config.hypervisor.machine_type":"virt"}}',
            b'{"process":{"noNewPrivileges":true},"linux":{"namespaces":[]}}',
        ),
    ),
    HarnessSpec(
        "kata-agent-wire",
        "kata_agent_wire_harness.cc",
        "kata-agent ttrpc/protobuf message framing",
        "Length-prefixed protobuf wire parser; it never contacts a live agent.",
        (b"\x02\x00\x00\x00\x08\x01", b"\x03\x00\x00\x00\x12\x01A"),
    ),
    HarnessSpec(
        "virtiofs-vsock-boundary",
        "virtiofs_vsock_harness.cc",
        "virtio-fs FUSE and AF_VSOCK packet boundaries",
        "Bounded parser for representative FUSE/vsock headers.",
        (b"\x00" + b"\x00" * 40, b"\x01" + b"\x00" * 44),
    ),
)


_SANITIZER_PATTERNS = {
    "address": re.compile(r"AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|use-after-free", re.I),
    "undefined": re.compile(r"UndefinedBehaviorSanitizer|runtime error:", re.I),
    "memory": re.compile(r"MemorySanitizer", re.I),
    "leak": re.compile(r"LeakSanitizer", re.I),
}


class HarnessManager:
    def __init__(self, settings: M2Settings, runner: SafeCommandRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or SafeCommandRunner(helper=settings.sudo_helper)
        self.source_dir = Path(__file__).with_name("harnesses")
        self.build_dir = settings.artifacts_dir / "harnesses" / "build"
        self.corpus_root = settings.artifacts_dir / "harnesses" / "corpus"
        self.crash_root = settings.artifacts_dir / "harnesses" / "crashes"

    def _compiler(self) -> str | None:
        return shutil.which("clang-18") or shutil.which("clang")

    def build(self, harness_ids: Iterable[str] | None = None) -> list[dict[str, Any]]:
        selected = set(harness_ids or [spec.harness_id for spec in HARNESS_SPECS])
        unknown = selected - {spec.harness_id for spec in HARNESS_SPECS}
        if unknown:
            raise ValueError(f"unknown harnesses: {', '.join(sorted(unknown))}")
        compiler = self._compiler()
        if not compiler:
            return [
                {
                    "harness_id": spec.harness_id,
                    "status": "skipped_with_reason",
                    "reason": "clang/clang-18 is missing",
                }
                for spec in HARNESS_SPECS
                if spec.harness_id in selected
            ]
        self.build_dir.mkdir(parents=True, exist_ok=True)
        results = []
        for spec in HARNESS_SPECS:
            if spec.harness_id not in selected:
                continue
            source = self.source_dir / spec.source_name
            output = self.build_dir / spec.harness_id
            command = [
                compiler,
                "-std=c++17",
                "-O1",
                "-g",
                "-fno-omit-frame-pointer",
                "-fsanitize=fuzzer,address,undefined",
                str(source),
                "-o",
                str(output),
            ]
            result = self.runner.run(command, timeout=180)
            payload = {
                "run_id": f"harness-{uuid.uuid4().hex}",
                "harness_id": spec.harness_id,
                "boundary": spec.boundary,
                "status": "built" if result.ok else "failed",
                "compiler": compiler,
                "binary_path": str(output) if result.ok else None,
                "source_path": str(source),
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "exit_code": result.returncode,
                "stdout": result.stdout[-8000:],
                "stderr": result.stderr[-8000:],
                "command": result.argv,
            }
            results.append(payload)
            if result.ok:
                self._write_seeds(spec)
        return results

    def _write_seeds(self, spec: HarnessSpec) -> None:
        root = self.corpus_root / spec.harness_id
        root.mkdir(parents=True, exist_ok=True)
        for index, seed in enumerate(spec.seeds, start=1):
            path = root / f"seed-{index:02d}-{hashlib.sha256(seed).hexdigest()[:12]}"
            if not path.exists():
                path.write_bytes(seed)

    def fuzz(
        self,
        harness_ids: Iterable[str] | None = None,
        *,
        seconds: int | None = None,
        profile: str | None = None,
    ) -> list[dict[str, Any]]:
        selected = list(harness_ids or [spec.harness_id for spec in HARNESS_SPECS])
        budget = self.settings.budget if profile is None else BUDGETS[profile]
        fuzz_seconds = max(1, int(seconds if seconds is not None else budget.fuzz_seconds))
        build_results = {item["harness_id"]: item for item in self.build(selected)}
        jobs = []
        for harness_id in selected:
            build = build_results[harness_id]
            if build["status"] != "built":
                jobs.append(
                    {
                        "run_id": f"fuzz-{uuid.uuid4().hex}",
                        "harness_id": harness_id,
                        "status": "skipped_with_reason",
                        "reason": "harness build failed",
                        "duration_seconds": 0.0,
                        "exit_code": None,
                        "crash_count": 0,
                    }
                )
        runnable = [item for item in selected if build_results[item]["status"] == "built"]
        with ThreadPoolExecutor(max_workers=min(budget.parallel_harnesses, max(1, len(runnable)))) as executor:
            futures = {
                executor.submit(self._fuzz_one, harness_id, fuzz_seconds, budget.rss_limit_mb): harness_id
                for harness_id in runnable
            }
            for future in as_completed(futures):
                jobs.append(future.result())
        return sorted(jobs, key=lambda item: item["harness_id"])

    def _fuzz_one(self, harness_id: str, seconds: int, rss_limit_mb: int) -> dict[str, Any]:
        binary = self.build_dir / harness_id
        corpus = self.corpus_root / harness_id
        crash_dir = self.crash_root / harness_id / str(int(time.time()))
        crash_dir.mkdir(parents=True, exist_ok=True)
        before = {path.name for path in crash_dir.iterdir()}
        command = [
            str(binary),
            str(corpus),
            f"-max_total_time={seconds}",
            "-timeout=10",
            "-max_len=1048576",
            f"-rss_limit_mb={rss_limit_mb}",
            f"-artifact_prefix={str(crash_dir)}/",
            "-print_final_stats=1",
        ]
        started = time.monotonic()
        # The generated binary is itself an allowlisted artifact, so execute it through a
        # dedicated local subprocess rather than the general command runner.
        import subprocess

        env = {
            **os.environ,
            "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=1:symbolize=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
        try:
            process = subprocess.run(
                command,
                cwd=str(self.settings.project_root),
                env=env,
                capture_output=True,
                text=True,
                timeout=seconds + 30,
                check=False,
            )
            returncode = process.returncode
            stdout = process.stdout
            stderr = process.stderr
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            returncode = 124
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            timed_out = True
        duration = round(time.monotonic() - started, 4)
        after_paths = [path for path in crash_dir.iterdir() if path.name not in before]
        combined = f"{stdout}\n{stderr}"
        sanitizer_kind = next((name for name, pattern in _SANITIZER_PATTERNS.items() if pattern.search(combined)), None)
        confirmed = bool(after_paths and sanitizer_kind)
        status = "confirmed_sanitizer_crash" if confirmed else "completed_no_crash"
        if timed_out:
            status = "timeout"
        elif returncode not in {0, 77} and not confirmed:
            status = "failed_without_sanitizer_evidence"
        return {
            "run_id": f"fuzz-{uuid.uuid4().hex}",
            "harness_id": harness_id,
            "status": status,
            "duration_seconds": duration,
            "exit_code": returncode,
            "crash_count": len(after_paths) if confirmed else 0,
            "sanitizer_kind": sanitizer_kind,
            "crash_artifacts": [
                {
                    "name": path.name,
                    "artifact_path": str(path),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    "size_bytes": path.stat().st_size,
                    "restricted": True,
                }
                for path in after_paths
            ],
            "stdout_tail": stdout[-12000:],
            "stderr_tail": stderr[-12000:],
            "command": command,
            "claim_boundary": (
                "A finding is promoted only when a sanitizer signature and a newly created "
                "artifact are both present. Exit codes or output markers alone are insufficient."
            ),
        }

    def native_readiness(self, source_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        readiness = []
        for item in source_results:
            if item.get("status") not in {"present", "fetched"}:
                continue
            component = item["component"]
            path = Path(item["path"])
            if component == "kata-containers":
                indicators = [path / "src" / "runtime", path / "src" / "agent"]
            elif component == "virtiofsd":
                indicators = [path / "Cargo.toml"]
            elif component == "qemu":
                indicators = [path / "configure", path / "tests" / "qtest" / "fuzz"]
            else:
                indicators = [path]
            present = [str(candidate) for candidate in indicators if candidate.exists()]
            readiness.append(
                {
                    "component": component,
                    "track": item["track"],
                    "status": "ready_for_native_adapter" if present else "skipped_with_reason",
                    "indicators": present,
                    "reason": None if present else "expected source/build indicators were not found",
                    "execution_policy": (
                        "Native target fuzzing is opt-in, source-pinned and sandboxed. QEMU full-device "
                        "fuzz builds are not automatically started in the balanced profile."
                    ),
                }
            )
        return readiness
