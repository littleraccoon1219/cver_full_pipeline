from __future__ import annotations

import sys
import time

from cver.discovery.tools.runner import CommandRunner


def test_runner_cancels_process_group_when_emergency_stop_activates(tmp_path):
    marker = tmp_path / "STOP"
    runner = CommandRunner(timeout_seconds=10, cancel_check=marker.exists)
    script = (
        "import pathlib,time; "
        f"time.sleep(0.5); pathlib.Path({str(marker)!r}).write_text('stop'); "
        "time.sleep(10)"
    )
    started = time.monotonic()
    result = runner.run([sys.executable, "-c", script], tool="cancellation-test")
    assert result.status == "cancelled_by_emergency_stop"
    assert time.monotonic() - started < 5
