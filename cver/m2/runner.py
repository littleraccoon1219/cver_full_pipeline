from __future__ import annotations

import os
import shutil
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(slots=True)
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class SafeCommandRunner:
    """Executes argument-vector commands without a shell and with process-group cleanup."""

    ALLOWED_NAMES = {
        "git",
        "clang",
        "clang-18",
        "gcc",
        "go",
        "cargo",
        "rustc",
        "cmake",
        "ninja",
        "make",
        "pkg-config",
        "protoc",
        "grpc_cpp_plugin",
        "kata-runtime",
        "containerd",
        "ctr",
        "docker",
        "qemu-system-aarch64",
        "virtiofsd",
        "uname",
        "lsb_release",
        "file",
        "sha256sum",
        "journalctl",
        "systemctl",
        "ps",
        "df",
        "free",
        "nproc",
        "id",
        "python3",
    }

    def __init__(self, *, helper: str | Path | None = None, max_output_bytes: int = 2_000_000) -> None:
        self.helper = Path(helper).resolve() if helper else None
        self.max_output_bytes = max_output_bytes

    @classmethod
    def _allowed_name(cls, name: str) -> bool:
        return name in cls.ALLOWED_NAMES or bool(
            re.fullmatch(r"(?:clang|gcc|g\+\+|llvm-config)(?:-\d+)?", name)
        )

    def _resolve(self, executable: str) -> str:
        path = Path(executable)
        if path.is_absolute():
            original_name = path.name
            resolved = path.resolve()
            if self.helper and resolved == self.helper:
                return str(resolved)
            if not (self._allowed_name(original_name) and self._allowed_name(resolved.name)):
                raise ValueError(f"executable is not allowlisted: {resolved}")
            return str(resolved)
        if not self._allowed_name(executable):
            raise ValueError(f"executable is not allowlisted: {executable}")
        resolved = shutil.which(executable)
        if not resolved:
            raise FileNotFoundError(executable)
        return resolved

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float = 60.0,
        input_bytes: bytes | None = None,
    ) -> CommandResult:
        if not argv:
            raise ValueError("empty command")
        command = [self._resolve(str(argv[0])), *[str(item) for item in argv[1:]]]
        started = time.monotonic()
        process = subprocess.Popen(
            command,
            cwd=str(cwd) if cwd else None,
            env={**os.environ, **dict(env or {})},
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
        duration = time.monotonic() - started
        return CommandResult(
            argv=command,
            returncode=124 if timed_out else process.returncode,
            stdout=stdout[: self.max_output_bytes].decode("utf-8", errors="replace"),
            stderr=stderr[: self.max_output_bytes].decode("utf-8", errors="replace"),
            duration_seconds=round(duration, 4),
            timed_out=timed_out,
        )

    def run_helper(self, subcommand: str, *arguments: str, timeout: float = 180.0) -> CommandResult:
        if not self.helper or not self.helper.is_file():
            raise FileNotFoundError("CVER M2 privileged helper is not installed")
        sudo = shutil.which("sudo")
        if not sudo:
            raise FileNotFoundError("sudo")
        started = time.monotonic()
        command = [sudo, "-n", str(self.helper), subcommand, *arguments]
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
        return CommandResult(
            argv=command,
            returncode=124 if timed_out else process.returncode,
            stdout=stdout[: self.max_output_bytes].decode("utf-8", errors="replace"),
            stderr=stderr[: self.max_output_bytes].decode("utf-8", errors="replace"),
            duration_seconds=round(time.monotonic() - started, 4),
            timed_out=timed_out,
        )
