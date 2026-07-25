from __future__ import annotations

from pathlib import Path

import pytest

from cver.m2.config import M2Settings


@pytest.fixture
def m2_settings(tmp_path: Path) -> M2Settings:
    config = tmp_path / "configuration-qemu.toml"
    config.write_text(
        '[hypervisor.qemu]\ncpu_features = ""\ndisable_guest_seccomp = true\nenable_debug = false\n',
        encoding="utf-8",
    )
    settings = M2Settings(
        project_root=tmp_path,
        state_root=tmp_path / "state",
        runtime_db=tmp_path / "state" / "runtime.db",
        artifacts_dir=tmp_path / "state" / "artifacts",
        reports_dir=tmp_path / "state" / "reports",
        candidates_dir=tmp_path / "state" / "candidates",
        source_root=tmp_path / "sources",
        trusted_kb_db=tmp_path / "trusted.db",
        llm_enabled=False,
        kata_config=config,
        sudo_helper=tmp_path / "missing-helper",
        zero_day_key_mode="ephemeral",
    )
    settings.ensure_directories()
    return settings

@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[2]
