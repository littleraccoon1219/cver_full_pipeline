from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from ..models import ExperimentKind, ToolResult
from .runner import CommandRunner

_SAFE_REF = re.compile(r"^[A-Za-z0-9._/-]{1,160}$")
_SAFE_GO_TARGET = re.compile(r"^[A-Za-z0-9_./-]{1,200}$")


class ToolRegistry:
    """Trusted adapters. No model-provided shell command is ever executed."""

    def __init__(self, runner: CommandRunner, *, project_root: str | Path = ".") -> None:
        self.runner = runner
        self.project_root = Path(project_root).resolve()

    @staticmethod
    def _resolve_target(target: str) -> Path:
        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(path)
        return path

    def inventory(self, target: str) -> dict[str, Any]:
        path = self._resolve_target(target)
        result: dict[str, Any] = {
            "path": str(path),
            "is_dir": path.is_dir(),
            "files": [],
            "git_commit": None,
            "go_module": None,
        }
        if path.is_dir():
            result["files"] = sorted(
                str(item.relative_to(path))
                for item in path.rglob("*")
                if item.is_file() and len(item.relative_to(path).parts) <= 4
            )[:2500]
            git = self.runner.run(["git", "rev-parse", "HEAD"], cwd=path, tool="git")
            if git.status == "succeeded":
                result["git_commit"] = git.stdout.strip()
            go_mod = path / "go.mod"
            if go_mod.is_file():
                first = go_mod.read_text(encoding="utf-8", errors="replace").splitlines()
                result["go_module"] = first[0] if first else ""
        else:
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            result["binary"] = {
                "size_bytes": path.stat().st_size,
                "sha256": digest.hexdigest(),
                "executable_bit": bool(path.stat().st_mode & 0o111),
            }
            file_result = self.runner.run(["file", "--brief", str(path)], tool="file-metadata")
            result["binary"]["file_type"] = (file_result.stdout or file_result.stderr).strip()[:4000]
            go_result = self.runner.run(["go", "version", "-m", str(path)], tool="go-binary-metadata")
            result["binary"]["go_build_info"] = (go_result.stdout + go_result.stderr).strip()[:12000]
            result["binary"]["inspection_policy"] = "static_only_binary_not_executed"
        return result

    def execute(self, kind: ExperimentKind, *, target: str, parameters: dict[str, Any] | None = None) -> ToolResult:
        parameters = parameters or {}
        path = self._resolve_target(target)
        if kind == ExperimentKind.VERSION_CHECK:
            if path.is_file():
                return self.runner.run(["go", "version", "-m", str(path)], tool="static-version-check")
            git = self.runner.run(["git", "describe", "--tags", "--always", "--dirty"], cwd=path, tool="version-check")
            if git.status == "succeeded":
                return git
            return self.runner.run(["git", "rev-parse", "HEAD"], cwd=path, tool="version-check")

        if kind == ExperimentKind.SEMGREP_SCAN:
            config = self.project_root / "data/benchmarks/semgrep-runc.yml"
            return self.runner.run(
                ["semgrep", "scan", "--config", str(config), "--json", "--metrics", "off", str(path)],
                tool="semgrep",
            )

        if kind == ExperimentKind.GO_TEST:
            package = str(parameters.get("package", "./..."))
            if not _SAFE_GO_TARGET.fullmatch(package) or ".." in Path(package).parts:
                raise ValueError("unsafe Go package selector")
            return self.runner.run(["go", "test", package, "-count=1"], cwd=path, tool="go-test")

        if kind == ExperimentKind.GO_FUZZ:
            package = str(parameters.get("package", "./..."))
            fuzz = str(parameters.get("fuzz", ""))
            seconds = max(1, min(int(parameters.get("seconds", 20)), 60))
            if not _SAFE_GO_TARGET.fullmatch(package) or not re.fullmatch(r"Fuzz[A-Za-z0-9_]{1,100}", fuzz):
                raise ValueError("invalid fuzz target")
            return self.runner.run(
                ["go", "test", package, "-run=^$", f"-fuzz=^{fuzz}$", f"-fuzztime={seconds}s"],
                cwd=path,
                tool="go-fuzz",
                timeout_seconds=seconds + 30,
            )

        if kind == ExperimentKind.PATCH_DIFF:
            base = str(parameters.get("base") or "HEAD^")
            head = str(parameters.get("head") or "HEAD")
            if not _SAFE_REF.fullmatch(base) or not _SAFE_REF.fullmatch(head):
                raise ValueError("invalid git ref")
            verify = self.runner.run(["git", "rev-parse", "--verify", base], cwd=path, tool="patch-diff-base")
            if verify.status != "succeeded":
                return ToolResult(
                    status="skipped_with_reason",
                    tool="patch-diff",
                    command=["git", "diff", "--stat", f"{base}..{head}"],
                    exit_code=None,
                    stdout="",
                    stderr=verify.stderr,
                    duration_ms=verify.duration_ms,
                    reason=f"base ref is unavailable: {base}",
                )
            return self.runner.run(["git", "diff", "--stat", f"{base}..{head}"], cwd=path, tool="patch-diff")

        if kind == ExperimentKind.SYNTHETIC_FIXTURE:
            fixture = self.project_root / "benchmarks/synthetic_pathguard"
            return self.runner.run(
                ["python", str(self.project_root / "scripts/lab/run_synthetic_fixture.py"), str(fixture)],
                cwd=self.project_root,
                tool="synthetic-fixture",
            )

        if kind == ExperimentKind.TRACEE_OBSERVE:
            return ToolResult(
                status="skipped_with_reason",
                tool="tracee",
                command=[],
                exit_code=None,
                stdout="",
                stderr="",
                duration_ms=0,
                reason="Tracee collection is executed by the sandbox smoke/observation controller, not from LLM plans",
            )

        if kind == ExperimentKind.HISTORICAL_POC:
            return ToolResult(
                status="skipped_with_reason",
                tool="historical-poc",
                command=[],
                exit_code=None,
                stdout="",
                stderr="",
                duration_ms=0,
                reason="BLOCKED_NO_DISPOSABLE_LAB: executor intentionally absent from first-stage package",
            )
        raise ValueError(f"unsupported experiment kind: {kind}")
