from __future__ import annotations

from cver.discovery import commands
from cver.discovery.config import DiscoverySettings
from cver.discovery.db import DiscoveryRepository


def test_submit_synthetic_benchmark_sets_explicit_benchmark_mode(tmp_path, monkeypatch):
    (tmp_path / "benchmarks" / "synthetic_pathguard").mkdir(parents=True)
    (tmp_path / "benchmarks" / "synthetic_pathguard" / "go.mod").write_text("module test\n", encoding="utf-8")
    settings = DiscoverySettings(
        runtime_db=tmp_path / "runtime.db",
        trusted_kb_db=tmp_path / "trusted.db",
        artifacts_dir=tmp_path / "artifacts",
        workspace_root=tmp_path / "workspaces",
        test_mode=True,
        api_auth_required=False,
    )
    monkeypatch.setattr(commands.DiscoverySettings, "from_env", classmethod(lambda cls: settings))
    result = commands.submit_synthetic_benchmark(project_root=str(tmp_path))
    job = DiscoveryRepository(settings.runtime_db).get_job(result["job_id"])
    assert job is not None
    assert job.payload["benchmark_mode"] == "synthetic_pathguard"
    assert job.requested_backend == "docker"
