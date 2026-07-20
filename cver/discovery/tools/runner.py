from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from ..models import ToolResult


class CommandRunner:
    """Execute a trusted, pre-constructed argv vector without a shell.

    The discovery LLM never supplies this vector. The runner rejects malformed
    arguments, enforces timeouts and can terminate the whole process group when
    the operator emergency-stop marker becomes active.
    """

    def __init__(
        self,
        *,
        timeout_seconds: int = 600,
        output_limit: int = 200_000,
        cancel_check: Callable[[], bool] | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.output_limit = output_limit
        self.cancel_check = cancel_check

    @staticmethod
    def _terminate(process: subprocess.Popen[str]) -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()
        try:
            process.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        tool: str | None = None,
        timeout_seconds: int | None = None,
    ) -> ToolResult:
        argv = [str(value) for value in command]
        if not argv or any(not value or "\x00" in value for value in argv):
            raise ValueError("invalid command vector")
        if cwd is not None and not Path(cwd).exists():
            raise FileNotFoundError(cwd)
        if self.cancel_check and self.cancel_check():
            return ToolResult(
                status="cancelled_by_emergency_stop",
                tool=tool or Path(argv[0]).name,
                command=argv,
                exit_code=None,
                stdout="",
                stderr="",
                duration_ms=0,
                reason="emergency stop active before command start",
            )

        started = time.monotonic()
        deadline = started + max(1, timeout_seconds or self.timeout_seconds)
        merged_env = os.environ.copy()
        if env:
            merged_env.update({str(key): str(value) for key, value in env.items()})
        with (
            tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as stdout_file,
            tempfile.TemporaryFile(mode="w+t", encoding="utf-8", errors="replace") as stderr_file,
        ):
            try:
                process = subprocess.Popen(
                    argv,
                    cwd=str(cwd) if cwd is not None else None,
                    env=merged_env,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    start_new_session=True,
                )
            except FileNotFoundError:
                return ToolResult(
                    status="skipped_with_reason",
                    tool=tool or Path(argv[0]).name,
                    command=argv,
                    exit_code=None,
                    stdout="",
                    stderr="",
                    duration_ms=int((time.monotonic() - started) * 1000),
                    reason=f"executable not found: {argv[0]}",
                )

            status = "failed"
            reason: str | None = None
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timed_out"
                    reason = "timeout"
                    self._terminate(process)
                    break
                try:
                    process.wait(timeout=min(0.25, remaining))
                    status = "succeeded" if process.returncode == 0 else "failed"
                    break
                except subprocess.TimeoutExpired:
                    if self.cancel_check and self.cancel_check():
                        status = "cancelled_by_emergency_stop"
                        reason = "emergency stop activated during command execution"
                        self._terminate(process)
                        break

            stdout_file.flush()
            stderr_file.flush()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read()
            stderr = stderr_file.read()
            return ToolResult(
                status=status,
                tool=tool or Path(argv[0]).name,
                command=argv,
                exit_code=process.returncode,
                stdout=(stdout or "")[-self.output_limit :],
                stderr=(stderr or "")[-self.output_limit :],
                duration_ms=int((time.monotonic() - started) * 1000),
                reason=reason,
            )
