from __future__ import annotations

import pytest

from cver.discovery.config import DiscoverySettings
from cver.discovery.errors import ConfigurationError


def test_real_runtime_requires_key_and_planner_model(tmp_path):
    settings = DiscoverySettings(runtime_db=tmp_path / "runtime.db", test_mode=False)
    with pytest.raises(ConfigurationError):
        settings.validate_runtime(require_llm=True)


def test_historical_poc_requires_disposable_lab(tmp_path):
    settings = DiscoverySettings(
        runtime_db=tmp_path / "runtime.db",
        test_mode=True,
        allow_historical_poc=True,
        disposable_lab_ready=False,
    )
    with pytest.raises(ConfigurationError):
        settings.validate_runtime(require_llm=False)


def test_emergency_stop_marker_is_dynamic(tmp_path):
    marker = tmp_path / "STOP"
    settings = DiscoverySettings(runtime_db=tmp_path / "runtime.db", emergency_stop_file=marker, test_mode=True)
    assert settings.emergency_stop_active() is False
    marker.write_text("stop", encoding="utf-8")
    assert settings.emergency_stop_active() is True
