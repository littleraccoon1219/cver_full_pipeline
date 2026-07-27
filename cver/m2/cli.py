from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from .benchmark import M2Benchmark
from .config import BUDGETS, M2Settings
from .dataset import DatasetBuilder
from .db import M2Repository
from .environment import EnvironmentCollector
from .evaluation import evaluate_predictions
from .harnesses import HarnessManager
from .knowledge_bridge import M2CandidateBundleExporter
from .kata import KataController
from .real_fuzz.engine import RealFuzzEngine
from .real_fuzz.inspector import KataAgentInspector
from .real_fuzz.manifests import AdapterRegistry
from .real_fuzz.replay import GuestReplayPlanner
from .real_fuzz.runtime_assets import REQUIRED_ASSETS, RuntimeAssetManager
from .real_fuzz.triage import CandidateTriage
from .sources import SOURCES, SourceManager
from .workflow import M2Workflow


def output(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def _json(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).expanduser().read_text(encoding="utf-8"))


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
    source_plan.add_argument("--component", action="append", choices=sorted(SOURCES))
    source_sync = source_sub.add_parser("sync")
    source_sync.add_argument("--component", action="append", choices=sorted(SOURCES))
    source_sync.add_argument("--fetch", action="store_true")
    source_sync.add_argument("--confirm", action="store_true")

    compat = sub.add_parser("kata-compat", help="check/apply/restore the verified Kata/QEMU setting")
    compat.add_argument("action", choices=["check", "apply", "restore"])
    compat.add_argument("--confirm", action="store_true")

    prepare = sub.add_parser("prepare-smoke-image", help="copy the fixed ARM64 smoke image to M2 namespace")
    prepare.add_argument("--namespace")
    smoke = sub.add_parser("kata-smoke", help="run a fixed, non-destructive Kata guest acceptance test")
    smoke.add_argument("--namespace")

    harness = sub.add_parser("harness", help="build or fuzz the bounded protocol-model harnesses")
    harness_sub = harness.add_subparsers(dest="harness_command", required=True)
    harness_build = harness_sub.add_parser("build")
    harness_build.add_argument("--harness", action="append")
    harness_fuzz = harness_sub.add_parser("fuzz")
    harness_fuzz.add_argument("--harness", action="append")
    harness_fuzz.add_argument("--seconds", type=int)
    harness_fuzz.add_argument("--profile", choices=sorted(BUDGETS))

    real = sub.add_parser("real-fuzz", help="inspect, prepare and run source-pinned real kata-agent fuzzing")
    real_sub = real.add_subparsers(dest="real_command", required=True)
    real_sub.add_parser("toolchain")
    inspect = real_sub.add_parser("inspect")
    inspect.add_argument("--source", required=True)
    inspect.add_argument("--version", required=True)
    inspect.add_argument("--track", required=True, choices=["installed-baseline", "research-head"])
    prepare_real = real_sub.add_parser("prepare")
    prepare_real.add_argument("--source", required=True)
    prepare_real.add_argument("--version", required=True)
    prepare_real.add_argument("--track", required=True, choices=["installed-baseline", "research-head"])
    prepare_real.add_argument("--propose-adapter", action="store_true")
    prepare_real.add_argument("--seed", type=int, default=1337)
    adapter = real_sub.add_parser("adapter")
    adapter_sub = adapter.add_subparsers(dest="adapter_command", required=True)
    adapter_check = adapter_sub.add_parser("check")
    adapter_check.add_argument("--source", required=True)
    adapter_check.add_argument("--version", required=True)
    adapter_propose = adapter_sub.add_parser("propose")
    adapter_propose.add_argument("--source", required=True)
    adapter_propose.add_argument("--version", required=True)
    adapter_approve = adapter_sub.add_parser("approve")
    adapter_approve.add_argument("--candidate", required=True)
    adapter_approve.add_argument("--actor", required=True)
    adapter_approve.add_argument("--compilation-test", action="store_true")
    adapter_approve.add_argument("--interface-test", action="store_true")
    adapter_approve.add_argument("--semantic-differential-test", action="store_true")
    adapter_approve.add_argument("--confirm", action="store_true")
    real_build = real_sub.add_parser("build")
    real_build.add_argument("--workspace", required=True)
    real_build.add_argument("--handler")
    real_run = real_sub.add_parser("run")
    real_run.add_argument("--workspace", required=True)
    real_run.add_argument("--handler", action="append", required=True)
    real_run.add_argument("--seconds", type=int)
    real_run.add_argument("--seed", type=int, default=1337)
    real_run.add_argument("--confirm-native-fuzz", action="store_true")
    reproduce = real_sub.add_parser("reproduce")
    reproduce.add_argument("--workspace", required=True)
    reproduce.add_argument("--handler", required=True)
    reproduce.add_argument("--artifact", required=True)
    reproduce.add_argument("--attempts", type=int, default=3)
    reproduce.add_argument("--confirm-native-fuzz", action="store_true")
    triage = real_sub.add_parser("triage")
    triage.add_argument("--run-json", required=True)
    triage.add_argument("--guest-replay-json")
    export_kb = real_sub.add_parser("export-kb")
    export_kb.add_argument("--output-dir", required=True)
    export_kb.add_argument("--candidate-json", action="append")
    export_kb.add_argument("--level")
    export_kb.add_argument("--limit", type=int, default=100)

    runtime = sub.add_parser("runtime-assets", help="manage isolated versioned Kata runtime assets")
    runtime_sub = runtime.add_subparsers(dest="runtime_command", required=True)
    runtime_sub.add_parser("list")
    readiness = runtime_sub.add_parser("readiness")
    readiness.add_argument("--version", required=True)
    register = runtime_sub.add_parser("register")
    register.add_argument("--version", required=True)
    register.add_argument("--source", default="user-provided")
    for asset_name in REQUIRED_ASSETS:
        register.add_argument(f"--{asset_name.replace('_', '-')}")
    register.add_argument("--copy-assets", action="store_true")
    register.add_argument("--confirm", action="store_true")
    fetch = runtime_sub.add_parser("fetch-official")
    fetch.add_argument("--version", required=True)
    fetch.add_argument("--url", required=True)
    fetch.add_argument("--sha256", required=True)
    fetch.add_argument("--asset-name", required=True, choices=REQUIRED_ASSETS)
    fetch.add_argument("--confirm", action="store_true")
    build_runtime = runtime_sub.add_parser("build")
    build_runtime.add_argument("--version", required=True)
    build_runtime.add_argument("--source", required=True)
    build_runtime.add_argument("--recipe", required=True)
    build_runtime.add_argument("--confirm", action="store_true")

    replay = sub.add_parser("replay-plan", help="create a gated, non-destructive Kata Guest replay plan")
    replay.add_argument("--candidate", required=True)
    replay.add_argument("--version", required=True)
    replay.add_argument("--level", required=True, choices=["L1_RPC_ONLY", "L2_GUEST_NON_DESTRUCTIVE", "L3_ISOLATION_INVARIANT"])
    replay.add_argument("--input-artifact", required=True)
    replay.add_argument("--input-profile", required=True)
    replay.add_argument("--confirm", action="store_true")

    dataset = sub.add_parser("dataset", help="build time-aware, group-isolated paper datasets")
    dataset_sub = dataset.add_subparsers(dest="dataset_command", required=True)
    split = dataset_sub.add_parser("split")
    split.add_argument("--input", required=True)
    split.add_argument("--release-id", required=True)
    split.add_argument("--output-dir")
    evaluate = sub.add_parser("evaluate", help="evaluate classification and exploitability predictions")
    evaluate.add_argument("--predictions", required=True)

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
    run.add_argument("--real-source-fuzz", action="store_true")
    run.add_argument("--real-fuzz-source")
    run.add_argument("--real-fuzz-version")
    run.add_argument("--real-fuzz-track", default="installed-baseline", choices=["installed-baseline", "research-head"])
    run.add_argument("--real-fuzz-handler", action="append")
    run.add_argument("--confirm-native-fuzz", action="store_true")

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
        "real_source_fuzz": args.real_source_fuzz,
        "real_fuzz_source": args.real_fuzz_source,
        "real_fuzz_version": args.real_fuzz_version,
        "real_fuzz_track": args.real_fuzz_track,
        "real_fuzz_handlers": args.real_fuzz_handler,
        "confirm_native_fuzz": args.confirm_native_fuzz,
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
            payload = EnvironmentCollector(settings).doctor()
            payload["real_fuzz_toolchain"] = RealFuzzEngine(settings).toolchain()
            output(payload)
        elif args.command == "install-deps":
            output(KataController(settings).install_dependencies(confirm=args.confirm))
        elif args.command == "environment":
            payload = EnvironmentCollector(settings).collect()
            payload["snapshot_id"] = repository.add_environment_snapshot(None, payload["digest"], payload)
            output(payload)
        elif args.command == "source":
            manager = SourceManager(settings)
            output(manager.plan(args.component) if args.source_command == "plan" else manager.sync(args.component, fetch=args.fetch, confirm=args.confirm))
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
            else:
                payload = manager.fuzz(args.harness, seconds=args.seconds, profile=args.profile)
                for item in payload:
                    repository.add_fuzz_run(None, item)
            output(payload)
        elif args.command == "real-fuzz":
            engine = RealFuzzEngine(settings)
            if args.real_command == "toolchain":
                output(engine.toolchain())
            elif args.real_command == "inspect":
                output(engine.inspect(args.source, version=args.version, track=args.track))
            elif args.real_command == "prepare":
                output(engine.prepare(args.source, version=args.version, track=args.track, propose_adapter=args.propose_adapter, seed=args.seed))
            elif args.real_command == "adapter":
                inspection = None
                registry = AdapterRegistry(settings.adapter_manifest_dir)
                if args.adapter_command in {"check", "propose"}:
                    inspection = KataAgentInspector().inspect(args.source, version=args.version)
                if args.adapter_command == "check":
                    output(registry.check(inspection))
                elif args.adapter_command == "propose":
                    output(registry.propose(inspection))
                else:
                    output(
                        registry.approve(
                            args.candidate,
                            actor=args.actor,
                            compilation_test=args.compilation_test,
                            interface_test=args.interface_test,
                            semantic_differential_test=args.semantic_differential_test,
                            confirm=args.confirm,
                        )
                    )
            elif args.real_command == "build":
                output(engine.build(args.workspace, handler=args.handler))
            elif args.real_command == "run":
                runs = engine.run_many(
                    args.workspace,
                    handlers=args.handler,
                    seconds=args.seconds,
                    seed=args.seed,
                    confirm=args.confirm_native_fuzz,
                )
                for item in runs:
                    repository.add_real_fuzz_run(None, item)
                output(runs)
            elif args.real_command == "reproduce":
                output(
                    engine.reproduce(
                        args.workspace,
                        handler=args.handler,
                        artifact=args.artifact,
                        attempts=args.attempts,
                        confirm=args.confirm_native_fuzz,
                    )
                )
            elif args.real_command == "triage":
                candidate = CandidateTriage().classify(
                    _json(args.run_json),
                    guest_replay=_json(args.guest_replay_json) if args.guest_replay_json else None,
                )
                candidate["artifact_path"] = CandidateTriage.write(candidate, settings.candidates_dir)
                repository.add_candidate_v2(None, candidate)
                output(candidate)
            else:
                candidates = (
                    [_json(path) for path in args.candidate_json]
                    if args.candidate_json
                    else repository.list_candidates_v2(limit=args.limit, level=args.level)
                )
                if not candidates:
                    raise ValueError("no M2 candidates are available for Candidate-bundle export")
                output(
                    M2CandidateBundleExporter().export(
                        candidates,
                        output_dir=args.output_dir,
                        query_config={
                            "candidate_count": len(candidates),
                            "level_filter": args.level,
                            "direct_trusted_db_write": False,
                        },
                    )
                )
        elif args.command == "runtime-assets":
            manager = RuntimeAssetManager(settings)
            if args.runtime_command == "list":
                output(manager.list())
            elif args.runtime_command == "readiness":
                output(manager.readiness(args.version))
            elif args.runtime_command == "register":
                assets = {name: getattr(args, name) for name in REQUIRED_ASSETS if getattr(args, name)}
                payload = manager.register(
                    args.version,
                    assets,
                    source=args.source,
                    copy_assets=args.copy_assets,
                    confirm=args.confirm,
                )
                repository.add_runtime_asset_manifest(payload)
                output(payload)
            elif args.runtime_command == "fetch-official":
                output(
                    manager.fetch_official(
                        args.version,
                        url=args.url,
                        expected_sha256=args.sha256,
                        asset_name=args.asset_name,
                        confirm=args.confirm,
                    )
                )
            else:
                output(
                    manager.build_from_recipe(
                        args.version,
                        source_root=args.source,
                        recipe_path=args.recipe,
                        confirm=args.confirm,
                    )
                )
        elif args.command == "replay-plan":
            output(
                GuestReplayPlanner(settings).plan(
                    candidate=_json(args.candidate),
                    version=args.version,
                    level=args.level,
                    input_artifact=args.input_artifact,
                    input_profile=args.input_profile,
                    confirm=args.confirm,
                )
            )
        elif args.command == "dataset":
            builder = DatasetBuilder()
            payload = builder.split(builder.read_jsonl(args.input))
            release = builder.write_release(
                payload,
                args.output_dir or settings.state_root / "datasets",
                args.release_id,
            )
            repository.add_dataset_release(release)
            output(release)
        elif args.command == "evaluate":
            output(evaluate_predictions(DatasetBuilder.read_jsonl(args.predictions)))
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
    except (ValueError, PermissionError, FileNotFoundError, RuntimeError, KeyError, json.JSONDecodeError) as exc:
        output({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
