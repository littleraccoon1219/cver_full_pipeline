from __future__ import annotations

from pathlib import Path

from cver.discovery.historical import HistoricalReplay, _affected, _extract_runc_version
from cver.discovery.tools.runner import CommandRunner


def test_version_parsing_and_ranges():
    assert _extract_runc_version("runc version 1.1.11") == "1.1.11"
    assert _extract_runc_version("runc version 1.0.0-rc6") == "1.0.0-rc6"
    assert _affected("1.1.11", {"max_inclusive": "1.1.11"}) is True
    assert _affected("1.1.12", {"max_inclusive": "1.1.11"}) is False
    assert _affected("1.0.0-rc6", {"max_inclusive": "1.0.0rc6"}) is True


def test_manifest_contains_both_cases():
    manifest = Path(__file__).parents[2] / "data/benchmarks/historical_runc_cves.yaml"
    cases = HistoricalReplay(manifest, CommandRunner()).cases()
    assert {item["id"] for item in cases} == {"CVE-2024-21626", "CVE-2019-5736"}


def test_binary_replay_never_executes_target(tmp_path):
    marker = tmp_path / "executed"
    binary = tmp_path / "runc"
    binary.write_text(
        "#!/bin/sh\n"
        f"touch {marker}\n"
        "# runc version 1.1.11\n",
        encoding="utf-8",
    )
    binary.chmod(0o755)
    runner = CommandRunner(timeout_seconds=5)
    manifest = Path(__file__).parents[2] / "data/benchmarks/historical_runc_cves.yaml"
    replay = HistoricalReplay(manifest, runner)
    result = replay.replay("CVE-2024-21626", str(binary))
    assert result["detected_version"] == "1.1.11"
    assert result["version_appears_affected"] is True
    assert result["observations"]["binary_metadata"]["inspection_policy"] == "static_only_binary_not_executed"
    assert not marker.exists()
