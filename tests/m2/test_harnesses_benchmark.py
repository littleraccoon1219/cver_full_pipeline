from __future__ import annotations

import shutil

import pytest

from cver.m2.benchmark import M2Benchmark
from cver.m2.harnesses import HARNESS_SPECS, HarnessManager


def test_synthetic_benchmark(project_root):
    result = M2Benchmark(project_root).run()
    assert result["status"] == "completed"
    assert result["metrics"]["recall"] == 1.0


def test_all_three_harnesses_build_and_short_fuzz(m2_settings):
    if not (shutil.which("clang-18") or shutil.which("clang")):
        pytest.skip("clang unavailable")
    manager = HarnessManager(m2_settings)
    builds = manager.build()
    assert len(builds) == len(HARNESS_SPECS) == 3
    assert all(item["status"] == "built" for item in builds)
    runs = manager.fuzz(seconds=1, profile="quick")
    assert len(runs) == 3
    assert all(item["status"] in {"completed_no_crash", "timeout"} for item in runs)
    assert all(item["crash_count"] == 0 for item in runs)
