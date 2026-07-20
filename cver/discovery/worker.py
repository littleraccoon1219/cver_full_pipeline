from __future__ import annotations

import argparse
import os
import socket
import sqlite3
import time
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Event, Thread

from .config import DiscoverySettings
from .db import DiscoveryRepository
from .errors import ConfigurationError, EmergencyStopActive, PolicyDenied
from .factory import build_workflow
from .models import JobStatus


def worker_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}"


def is_retryable_exception(exc: Exception) -> bool:
    if isinstance(exc, (ConfigurationError, EmergencyStopActive, PolicyDenied, ValueError, FileNotFoundError)):
        return False
    if isinstance(exc, (TimeoutError, ConnectionError, sqlite3.OperationalError)):
        return True
    text = str(exc).lower()
    return any(
        marker in text
        for marker in ["timeout", "timed out", "rate limit", "temporarily unavailable", "connection reset"]
    )


@contextmanager
def maintain_lease(
    repository: DiscoveryRepository,
    job_id: str,
    identity: str,
    lease_seconds: int,
) -> Iterator[None]:
    """Extend a running-job lease while synchronous LLM/tool work is in progress."""
    stop = Event()
    interval = max(1.0, min(float(lease_seconds) / 3.0, 30.0))

    def pulse() -> None:
        while not stop.wait(interval):
            if not repository.heartbeat(job_id, identity, lease_seconds=lease_seconds):
                return

    thread = Thread(target=pulse, name=f"cver-lease-{job_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=min(interval + 1.0, 5.0))


def run_worker(*, once: bool = False, project_root: str = ".") -> int:
    settings = DiscoverySettings.from_env()
    settings.validate_runtime(require_llm=True)
    repository = DiscoveryRepository(settings.runtime_db)
    workflow = build_workflow(settings, project_root=project_root)
    identity = worker_id()

    while True:
        if settings.emergency_stop_active():
            print(f"CVER emergency stop is active: {settings.emergency_stop_file}")
            return 3
        job = repository.claim_next(identity, lease_seconds=settings.worker_lease_seconds)
        if job is None:
            if once:
                return 0
            time.sleep(settings.worker_poll_seconds)
            continue
        try:
            with maintain_lease(
                repository,
                job.job_id,
                identity,
                settings.worker_lease_seconds,
            ):
                result = workflow.process(job)
            terminal = (
                JobStatus.WAITING_APPROVAL
                if result.get("workflow_status") == "waiting_approval"
                else JobStatus.SUCCEEDED
            )
            repository.finish_job(job.job_id, result, status=terminal)
        except Exception as exc:  # worker boundary: persist the complete failure
            detail = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()}"
            repository.fail_job(job.job_id, detail, retryable=is_retryable_exception(exc))
        if once:
            return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="cver-discovery-worker")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--project-root", default=".")
    args = parser.parse_args()
    raise SystemExit(run_worker(once=args.once, project_root=args.project_root))


if __name__ == "__main__":
    main()
