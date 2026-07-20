from __future__ import annotations

import platform
import sys
from pathlib import Path
from typing import Any

from .config import DiscoverySettings
from .db import DiscoveryRepository
from .fullstack import CapabilityScanner, ComponentRegistry
from .sandbox import SandboxManager
from .taxonomy import TaxonomyCatalog
from .tools import CommandRunner


def doctor(settings: DiscoverySettings, *, project_root: str | Path = ".") -> dict[str, Any]:
    settings.ensure_directories()
    repository = DiscoveryRepository(settings.runtime_db)
    migration = repository.migrate()
    runner = CommandRunner(timeout_seconds=min(settings.max_tool_seconds, 60))
    registry = ComponentRegistry(settings.component_registry_path)
    capability_matrix = CapabilityScanner(runner, registry=registry).scan()
    snapshot_id = repository.add_capability_snapshot(capability_matrix)
    manager = SandboxManager(settings, runner, project_root=project_root)
    taxonomy = TaxonomyCatalog(settings.taxonomy_path, settings.security_properties_path)
    return {
        "ok": True,
        "milestone": "M1",
        "python": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "runtime_db": migration,
        "trusted_kb": {"path": str(settings.trusted_kb_db), "exists": settings.trusted_kb_db.is_file()},
        "taxonomy": {
            "version": taxonomy.version,
            "macro_categories": sorted(taxonomy.parents),
            "second_level_labels": len(taxonomy.root_labels),
            "security_properties": len(taxonomy.security_properties),
        },
        "llm": {
            "api_key_configured": bool(settings.openai_api_key),
            "planner_model": settings.planner_model,
            "critic_model": settings.critic_model,
            "summary_model": settings.summary_model,
            "remediation_model": settings.remediation_model,
            "base_url_configured": bool(settings.openai_base_url),
            "store": settings.llm_store,
        },
        "policy": {
            "emergency_stop_active": settings.emergency_stop_active(),
            "emergency_stop_file": str(settings.emergency_stop_file),
            "disposable_lab_ready": settings.disposable_lab_ready,
            "historical_poc_enabled": settings.allow_historical_poc,
            "historical_poc_state": "ENABLED"
            if settings.allow_historical_poc and settings.disposable_lab_ready
            else "BLOCKED_NO_DISPOSABLE_LAB",
            "zero_day_key_mode": settings.zero_day_key_mode,
        },
        "budget": {"default_profile": settings.default_budget_profile},
        "capability_snapshot_id": snapshot_id,
        "capability_matrix": capability_matrix,
        "sandboxes": {name: item.to_dict() for name, item in manager.availability().items()},
    }
