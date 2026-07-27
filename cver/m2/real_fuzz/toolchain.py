from __future__ import annotations

import shutil
import subprocess
from typing import Any

from .models import ToolchainStatus, asdict


def _capture(argv: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)
        text = (result.stdout or result.stderr).strip()
        return result.returncode == 0, text
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}"


class RustFuzzToolchain:
    def __init__(self, pinned_nightly: str) -> None:
        self.pinned_nightly = pinned_nightly

    def check(self) -> dict[str, Any]:
        _, rustc = _capture(["rustc", "--version"]) if shutil.which("rustc") else (False, "")
        _, cargo = _capture(["cargo", "--version"]) if shutil.which("cargo") else (False, "")
        nightly_ok, _ = (
            _capture(["rustc", f"+{self.pinned_nightly}", "--version"])
            if shutil.which("rustc")
            else (False, "")
        )
        cargo_fuzz_ok, _ = (
            _capture(["cargo", f"+{self.pinned_nightly}", "fuzz", "--help"])
            if shutil.which("cargo")
            else (False, "")
        )
        llvm_ok, _ = (
            _capture(["rustup", "component", "list", "--toolchain", self.pinned_nightly, "--installed"])
            if shutil.which("rustup")
            else (False, "")
        )
        reasons = []
        if not rustc:
            reasons.append("stable rustc is missing")
        if not cargo:
            reasons.append("stable cargo is missing")
        if not nightly_ok:
            reasons.append(f"pinned toolchain {self.pinned_nightly} is not installed")
        if not cargo_fuzz_ok:
            reasons.append(f"cargo-fuzz is unavailable for {self.pinned_nightly}")
        status = "ready" if not reasons else "SKIPPED_WITH_REASON"
        return asdict(
            ToolchainStatus(
                stable_rustc=rustc or None,
                stable_cargo=cargo or None,
                pinned_nightly=self.pinned_nightly,
                pinned_nightly_installed=nightly_ok,
                cargo_fuzz_installed=cargo_fuzz_ok,
                llvm_tools_installed=llvm_ok,
                status=status,
                reasons=reasons,
            )
        )
