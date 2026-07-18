from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from .config import DiscoverySettings
from .db import DiscoveryRepository
from .sandbox import SandboxManager
from .tools import CommandRunner


def doctor(settings: DiscoverySettings, *, project_root: str | Path = ".") -> dict[str, Any]:
    settings.ensure_directories()
    repository = DiscoveryRepository(settings.runtime_db)
    migration = repository.migrate()
    runner = CommandRunner(timeout_seconds=min(settings.max_tool_seconds, 60))
    manager = SandboxManager(settings, runner, project_root=project_root)
    tools = {}
    for name in ["python", "git", "go", "semgrep", "trivy", "syft", "docker", "ctr", "kata-runtime", "firecracker", "jailer", "tracee-docker"]:
        tools[name] = shutil.which(name)
    return {
        "ok": True,
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "kvm_rw": os.access("/dev/kvm", os.R_OK | os.W_OK),
        "btf_readable": os.access("/sys/kernel/btf/vmlinux", os.R_OK),
        "runtime_db": migration,
        "trusted_kb": {"path": str(settings.trusted_kb_db), "exists": settings.trusted_kb_db.is_file()},
        "llm": {
            "api_key_configured": bool(settings.openai_api_key),
            "planner_model": settings.planner_model,
            "critic_model": settings.critic_model,
            "summary_model": settings.summary_model,
            "base_url_configured": bool(settings.openai_base_url),
            "store": settings.llm_store,
        },
        "policy": {
            "emergency_stop_active": settings.emergency_stop_active(),
            "emergency_stop_file": str(settings.emergency_stop_file),
            "disposable_lab_ready": settings.disposable_lab_ready,
            "historical_poc_enabled": settings.allow_historical_poc,
            "historical_poc_state": "ENABLED" if settings.allow_historical_poc and settings.disposable_lab_ready else "BLOCKED_NO_DISPOSABLE_LAB",
        },
        "tools": tools,
        "sandboxes": {name: item.to_dict() for name, item in manager.availability().items()},
    }
