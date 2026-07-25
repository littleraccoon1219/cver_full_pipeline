from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from .benchmark import M2Benchmark
from .config import BUDGETS, M2Settings
from .db import M2Repository
from .environment import EnvironmentCollector
from .harnesses import HarnessManager
from .kata import KataController
from .sources import SOURCES, SourceManager
from .workflow import M2Workflow


def output(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="cver m2", description="CVER M2 Kata vulnerability discovery")
    root.add_argument("--project-root", default=".")
    sub = root.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="initialize M2 directories and runtime database")
    sub.add_parser("doctor", help="check M2, Kata, QEMU and fuzz toolchain readiness")

    install = sub.add_parser("install-deps", help="install the fixed dependency allowlist through the root helper")
    install.add_argument("--confirm", action="store_true")

    sub.add_parser("environment", help="collect the current Kata/QEMU environment snapshot")

    source = sub.add_parser("source", help="manage dual-track source checkouts")
    source_sub = source.add_subparsers(dest="source_command", required=True)
    source_plan = source_sub.add_parser("plan")
    source_plan.add_argument(
        "--component", action="append", choices=sorted(SOURCES)
    )
    source_sync = source_sub.add_parser("sync")
    source_sync.add_argument(
        "--component", action="append", choices=sorted(SOURCES)
    )
    source_sync.add_argument("--fetch", action="store_true")
    source_sync.add_argument("--confirm", action="store_true")

    compat = sub.add_parser(
        "kata-compat",
        help="check/apply/restore the verified Kata/QEMU ARM64 compatibility setting",
    )
    compat.add_argument("action", choices=["check", "apply", "restore"])
    compat.add_argument("--confirm", action="store_true")

    prepare = sub.add_parser("prepare-smoke-image", help="copy the fixed ARM64 smoke image to the M2 namespace")
    prepare.add_argument("--namespace")

    smoke = sub.add_parser("kata-smoke", help="run a fixed, non-destructive Kata guest acceptance test")
    smoke.add_argument("--namespace")

    harness = sub.add_parser("harness", help="build or fuzz the three bounded M2 harnesses")
    harness_sub = harness.add_subparsers(dest="harness_command", required=True)
    harness_build = harness_sub.add_parser("build")
    harness_build.add_argument("--harness", action="append")
    harness_fuzz = harness_sub.add_parser("fuzz")
    harness_fuzz.add_argument("--harness", action="append")
    harness_fuzz.add_argument("--seconds", type=int)
    harness_fuzz.add_argument("--profile", choices=sorted(BUDGETS))

    run = sub.add_parser("run", help="execute the evidence-gated M2 Kata workflow")
    run.add_argument("--profile", default=None, choices=sorted(BUDGETS))
    run.add_argument("--component", action="append")
    run.add_argument("--fetch-sources", action="store_true")
    run.add_argument("--confirm-source-fetch", action="store_true")
    run.add_argument("--collect-external-candidates", action="store_true")
    run.add_argument("--confirm-external-collection", action="store_true")
    run.add_argument("--external-max-per-component", type=int, default=20)
    run.add_argument("--no-fuzz", action="store_true")
    run.add_argument("--fuzz-seconds", type=int)
    run.add_argument("--no-kata-smoke", action="store_true")
    run.add_argument("--namespace")
    run.add_argument("--actor", default="m2-operator")
    run.add_argument("--max-static-findings", type=int, default=1000)

    resume = sub.add_parser("resume", help="resume only unfinished or failed M2 phases")
    resume.add_argument("job_id")

    jobs = sub.add_parser("jobs", help="list or show M2 jobs")
    jobs_sub = jobs.add_subparsers(dest="jobs_command", required=True)
    jobs_list = jobs_sub.add_parser("list")
    jobs_list.add_argument("--limit", type=int, default=50)
    jobs_list.add_argument("--status")
    jobs_show = jobs_sub.add_parser("show")
    jobs_show.add_argument("job_id")

    sub.add_parser("benchmark", help="run the synthetic M2 evidence-gating benchmark")

    web = sub.add_parser("web", help="run the M2 REST API and redacted Web console")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8090)
    web.add_argument("--reload", action="store_true")
    return root


def _request(args: argparse.Namespace, settings: M2Settings) -> dict[str, Any]:
    return {
        "profile": args.profile or settings.budget_profile,
        "components": args.component,
        "fetch_sources": args.fetch_sources,
        "confirm_source_fetch": args.confirm_source_fetch,
        "collect_external_candidates": args.collect_external_candidates,
        "confirm_external_collection": args.confirm_external_collection,
        "external_max_per_component": args.external_max_per_component,
        "run_fuzz": not args.no_fuzz,
        "fuzz_seconds": args.fuzz_seconds,
        "kata_smoke": not args.no_kata_smoke,
        "namespace": args.namespace or settings.namespace,
        "actor": args.actor,
        "max_static_findings": args.max_static_findings,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    settings = M2Settings.from_env(args.project_root)
    settings.ensure_directories()
    repository = M2Repository(settings.runtime_db)

    try:
        if args.command == "init":
            output({"directories": settings.redacted(), "database": repository.migrate()})
        elif args.command == "doctor":
            output(EnvironmentCollector(settings).doctor())
        elif args.command == "install-deps":
            output(KataController(settings).install_dependencies(confirm=args.confirm))
        elif args.command == "environment":
            payload = EnvironmentCollector(settings).collect()
            payload["snapshot_id"] = repository.add_environment_snapshot(None, payload["digest"], payload)
            output(payload)
        elif args.command == "source":
            manager = SourceManager(settings)
            if args.source_command == "plan":
                output(manager.plan(args.component))
            else:
                output(manager.sync(args.component, fetch=args.fetch, confirm=args.confirm))
        elif args.command == "kata-compat":
            output(KataController(settings).compatibility(args.action, confirm=args.confirm))
        elif args.command == "prepare-smoke-image":
            output(KataController(settings).prepare_smoke_image(args.namespace))
        elif args.command == "kata-smoke":
            output(KataController(settings).smoke(args.namespace))
        elif args.command == "harness":
            manager = HarnessManager(settings)
            if args.harness_command == "build":
                payload = manager.build(args.harness)
                for item in payload:
                    repository.add_harness_run(None, item)
                output(payload)
            else:
                payload = manager.fuzz(args.harness, seconds=args.seconds, profile=args.profile)
                for item in payload:
                    repository.add_fuzz_run(None, item)
                output(payload)
        elif args.command == "run":
            output(M2Workflow(settings).run_new(_request(args, settings)))
        elif args.command == "resume":
            output(M2Workflow(settings).run(args.job_id, resume=True))
        elif args.command == "jobs":
            if args.jobs_command == "list":
                output(repository.list_jobs(args.limit, args.status))
            else:
                job = repository.get_job(args.job_id)
                if job is None:
                    raise KeyError(f"job not found: {args.job_id}")
                output(job)
        elif args.command == "benchmark":
            output(M2Benchmark(settings.project_root).run())
        elif args.command == "web":
            if args.host not in {"127.0.0.1", "localhost", "::1"} and not settings.api_token:
                raise RuntimeError("CVER_M2_API_TOKEN is required when binding the M2 API beyond loopback")
            import uvicorn

            uvicorn.run("cver.m2.api:app", host=args.host, port=args.port, reload=args.reload)
        return 0
    except (ValueError, PermissionError, FileNotFoundError, RuntimeError, KeyError) as exc:
        output({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
