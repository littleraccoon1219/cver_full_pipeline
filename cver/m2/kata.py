from __future__ import annotations

import json
from typing import Any

from .config import M2Settings
from .runner import SafeCommandRunner


class KataController:
    """Thin client for the root-owned, fixed-function helper."""

    def __init__(self, settings: M2Settings, runner: SafeCommandRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or SafeCommandRunner(helper=settings.sudo_helper)

    @staticmethod
    def _decode(stdout: str, stderr: str, returncode: int) -> dict[str, Any]:
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError:
            payload = {
                "ok": False,
                "status": "invalid_helper_response",
                "stdout": stdout[-8000:],
                "stderr": stderr[-8000:],
            }
        payload.setdefault("returncode", returncode)
        return payload

    def helper_status(self) -> dict[str, Any]:
        path = self.settings.sudo_helper
        return {
            "path": str(path),
            "installed": path.is_file(),
            "required_owner_uid": 0,
            "actual_owner_uid": path.stat().st_uid if path.is_file() else None,
            "mode": oct(path.stat().st_mode & 0o777) if path.is_file() else None,
        }

    def compatibility(self, action: str, *, confirm: bool = False) -> dict[str, Any]:
        mapping = {
            "check": "compat-check",
            "apply": "compat-apply",
            "restore": "compat-restore",
        }
        if action not in mapping:
            raise ValueError(f"unknown compatibility action: {action}")
        arguments = ["--confirm"] if confirm and action in {"apply", "restore"} else []
        result = self.runner.run_helper(mapping[action], *arguments, timeout=180)
        return self._decode(result.stdout, result.stderr, result.returncode)

    def prepare_smoke_image(self, namespace: str | None = None) -> dict[str, Any]:
        target = namespace or self.settings.namespace
        result = self.runner.run_helper("prepare-smoke-image", "--namespace", target, timeout=240)
        return self._decode(result.stdout, result.stderr, result.returncode)

    def smoke(self, namespace: str | None = None) -> dict[str, Any]:
        target = namespace or self.settings.namespace
        result = self.runner.run_helper("kata-smoke", "--namespace", target, timeout=120)
        return self._decode(result.stdout, result.stderr, result.returncode)

    def install_dependencies(self, *, confirm: bool = False) -> dict[str, Any]:
        arguments = ["--confirm"] if confirm else []
        result = self.runner.run_helper("install-deps", *arguments, timeout=2100)
        return self._decode(result.stdout, result.stderr, result.returncode)
