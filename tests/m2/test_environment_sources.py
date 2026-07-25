from __future__ import annotations

from cver.m2.environment import EnvironmentCollector
from cver.m2.sources import SourceManager


def test_config_audit_reads_compatibility_override(m2_settings):
    collector = EnvironmentCollector(m2_settings)
    config = collector._kata_config()
    assert config["cpu_features"] == ""
    assert config["disable_guest_seccomp"] is True


def test_pmu_mismatch_is_blocking(monkeypatch):
    monkeypatch.setattr("cver.m2.environment.platform.machine", lambda: "aarch64")
    issues = EnvironmentCollector._issues(
        {"version": "3.32.0", "commit": "337b600"},
        {"version": "11.0.1"},
        {"cpu_features": "pmu=off"},
        {name: {"status": "ok"} for name in ["git", "clang", "go", "rustc", "cargo", "protoc", "containerd", "ctr"]},
    )
    assert any(item["code"] == "KATA_QEMU_ARM64_PMU_PROPERTY_MISMATCH" for item in issues)


def test_source_plan_has_two_separate_tracks(m2_settings, monkeypatch):
    manager = SourceManager(m2_settings)
    monkeypatch.setattr(
        manager,
        "_installed_refs",
        lambda: {
            "kata-containers": "337b6002681479fb6a605ca8a7a1138e81b6098c",
            "qemu": "v11.0.1",
            "virtiofsd": None,
            "cloud-hypervisor": None,
            "firecracker": None,
            "linux": "v6.8.0",
        },
    )
    plan = manager.plan(["kata-containers"])
    tracks = {item["track"] for item in plan["plans"]}
    assert tracks == {"installed-baseline", "research-head"}
    assert plan["automatic_fetch"] is False
