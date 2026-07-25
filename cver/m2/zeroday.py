from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import M2Settings


class ZeroDayGate:
    """Adapter to M1's encrypted zero-day vault.

    If the vault cannot be initialized, restricted trigger material is not copied
    into an ordinary M2 directory; the caller receives an explicit blocked result.
    """

    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings

    def seal_crash(
        self,
        *,
        files: list[str | Path],
        metadata: dict[str, Any],
        actor: str,
        job_id: str,
        hypothesis_id: str | None = None,
    ) -> dict[str, Any]:
        existing = [Path(item).expanduser().resolve() for item in files if Path(item).expanduser().is_file()]
        if not existing:
            return {"status": "skipped_with_reason", "reason": "no restricted crash artifacts were present"}
        try:
            from cver.discovery.config import DiscoverySettings
            from cver.discovery.db import DiscoveryRepository
            from cver.discovery.zeroday import ZeroDayVault, master_key_provider

            discovery = DiscoverySettings.from_env()
            discovery.ensure_directories()
            repository = DiscoveryRepository(discovery.runtime_db)
            repository.migrate()
            root = getattr(discovery, "zero_day_vault_dir", self.settings.state_root / "zero_day_vault")
            mode = getattr(discovery, "zero_day_key_mode", self.settings.zero_day_key_mode)
            vault = ZeroDayVault(repository, root=root, master_key=master_key_provider(mode))
            payload = vault.seal_case(
                files=existing,
                metadata={
                    **metadata,
                    "disclosure_state": "suspected_zero_day",
                    "web_visibility": "redacted_metadata_only",
                    "automatic_exploit_generation": False,
                },
                actor=actor,
                job_id=job_id,
                hypothesis_id=hypothesis_id,
            )
            return {"status": "sealed", **payload}
        except Exception as exc:
            return {
                "status": "blocked",
                "reason": f"encrypted zero-day vault unavailable: {type(exc).__name__}: {exc}",
                "plaintext_fallback": False,
                "artifact_hashes": [
                    {
                        "name": item.name,
                        "size_bytes": item.stat().st_size,
                    }
                    for item in existing
                ],
            }
