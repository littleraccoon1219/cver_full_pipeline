from __future__ import annotations

import argparse
import json
from typing import Any


def out(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cver")
    parser.add_argument("--profile", default=None)
    sub = parser.add_subparsers(dest="cmd")

    for command in ["doctor", "init-db", "demo", "benchmark"]:
        item = sub.add_parser(command)
        item.add_argument("--profile", default=None)

    for command in ["full-pipeline", "scan-only", "reason-only", "redteam-only"]:
        item = sub.add_parser(command)
        item.add_argument("--profile", default=None)
        item.add_argument("--target", default="demo/nginx:lab")
        item.add_argument("--target-kind", default="image")
        item.add_argument("--namespace")
        item.add_argument("--runtime-class")
        item.add_argument("--lab-label", default="true")

    web = sub.add_parser("web")
    web.add_argument("--profile", default=None)
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8000)
    web.add_argument("--reload", action="store_true")

    kb_init = sub.add_parser("kb-init", help="initialize the trusted knowledge base schema")
    kb_init.add_argument("--db", default="data/trusted_knowledge.db")

    kb_validate = sub.add_parser("kb-validate", help="validate Gold admission for one record")
    kb_validate.add_argument("record_id")
    kb_validate.add_argument("--db", default="data/trusted_knowledge.db")

    kb_export = sub.add_parser("kb-export", help="export one evidence-grounded record bundle")
    kb_export.add_argument("record_id")
    kb_export.add_argument("--db", default="data/trusted_knowledge.db")
    kb_export.add_argument("--output", required=True)

    kb_schema = sub.add_parser("kb-schema-report", help="report formal trusted-KB schema status")
    kb_schema.add_argument("--db", default="data/trusted_knowledge.db")

    sub.add_parser("discovery-init", help="initialize the durable autonomous-discovery runtime database")

    discovery_doctor = sub.add_parser("discovery-doctor", help="report discovery, tool and sandbox readiness")
    discovery_doctor.add_argument("--project-root", default=".")

    submit = sub.add_parser("discovery-submit", help="enqueue an autonomous discovery job")
    submit.add_argument("--target", required=True)
    submit.add_argument("--target-kind", default="source", choices=["source", "binary"])
    submit.add_argument("--risk", default="low", choices=["low", "medium", "high", "critical"])
    submit.add_argument("--backend", default="auto", choices=["auto", "docker", "kata", "firecracker"])
    submit.add_argument(
        "--data-class",
        default="internal",
        choices=["public", "internal", "confidential", "restricted"],
    )

    benchmark_submit = sub.add_parser(
        "discovery-benchmark",
        help="enqueue the reviewed synthetic evidence-gating benchmark",
    )
    benchmark_submit.add_argument(
        "--name",
        default="synthetic_pathguard",
        choices=["synthetic_pathguard"],
    )
    benchmark_submit.add_argument("--project-root", default=".")

    status_parser = sub.add_parser("discovery-status", help="show one discovery job and its events")
    status_parser.add_argument("job_id")

    list_parser = sub.add_parser("discovery-list", help="list discovery jobs")
    list_parser.add_argument("--limit", type=int, default=50)
    list_parser.add_argument("--status", default=None)

    approval = sub.add_parser("discovery-approve", help="record a scoped human decision")
    approval.add_argument("job_id")
    approval.add_argument("--scope", required=True, help="for example experiment:go_fuzz")
    approval.add_argument("--actor", required=True)
    approval.add_argument("--reason", default="")
    approval.add_argument("--decision", default="approve", choices=["approve", "deny"])


    stop = sub.add_parser("discovery-stop", help="activate the non-bypassable emergency-stop marker")
    stop.add_argument("--actor", required=True)
    stop.add_argument("--reason", required=True)

    resume = sub.add_parser("discovery-resume", help="remove the emergency-stop marker")
    resume.add_argument("--actor", required=True)
    resume.add_argument("--reason", required=True)

    worker = sub.add_parser("discovery-worker", help="run the durable queue worker")
    worker.add_argument("--once", action="store_true")
    worker.add_argument("--project-root", default=".")

    api = sub.add_parser("discovery-api", help="run the authenticated discovery FastAPI service")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)
    api.add_argument("--reload", action="store_true")

    smoke = sub.add_parser("sandbox-smoke", help="run fixed, non-destructive backend acceptance checks")
    smoke.add_argument("--backend", action="append", choices=["docker", "kata", "firecracker"], default=[])
    smoke.add_argument("--project-root", default=".")

    replay = sub.add_parser("historical-replay", help="run non-destructive runc CVE prerequisite/patch validation")
    replay.add_argument(
        "case_id",
        nargs="?",
        default="CVE-2024-21626",
        choices=["CVE-2024-21626", "CVE-2019-5736"],
    )
    replay.add_argument("--target", required=True, help="runc binary or source checkout")
    replay.add_argument("--project-root", default=".")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    command = args.cmd or "doctor"

    if command in {
        "discovery-init", "discovery-doctor", "discovery-submit", "discovery-benchmark",
        "discovery-status", "discovery-list", "discovery-approve", "discovery-stop",
        "discovery-resume", "sandbox-smoke", "historical-replay",
    }:
        from .discovery import commands

        if command == "discovery-init":
            out(commands.init_runtime())
        elif command == "discovery-doctor":
            out(commands.discovery_doctor(args.project_root))
        elif command == "discovery-submit":
            out(
                commands.submit(
                    target=args.target,
                    target_kind=args.target_kind,
                    risk=args.risk,
                    backend=args.backend,
                    data_class=args.data_class,
                )
            )
        elif command == "discovery-benchmark":
            out(commands.submit_synthetic_benchmark(name=args.name, project_root=args.project_root))
        elif command == "discovery-status":
            out(commands.status(args.job_id))
        elif command == "discovery-list":
            out(commands.list_jobs(args.limit, args.status))
        elif command == "discovery-approve":
            out(commands.approve(args.job_id, scope=args.scope, actor=args.actor, reason=args.reason, decision=args.decision))
        elif command == "discovery-stop":
            out(commands.emergency_stop(actor=args.actor, reason=args.reason))
        elif command == "discovery-resume":
            out(commands.emergency_resume(actor=args.actor, reason=args.reason))
        elif command == "sandbox-smoke":
            out(commands.sandbox_smoke(args.backend, args.project_root))
        else:
            out(commands.historical_replay(args.case_id, args.target, args.project_root))
        return

    if command == "discovery-worker":
        from .discovery.worker import run_worker

        raise SystemExit(run_worker(once=args.once, project_root=args.project_root))

    if command == "discovery-api":
        from .discovery.config import DiscoverySettings

        settings = DiscoverySettings.from_env()
        settings.validate_runtime(require_llm=False, require_api_token=True)
        import uvicorn

        uvicorn.run("cver.discovery.api:app", host=args.host, port=args.port, reload=args.reload)
        return

    if command in {"kb-init", "kb-validate", "kb-export", "kb-schema-report"}:
        from .knowledge.cli import export_bundle_command, init_command, schema_report_command, validate_command

        if command == "kb-init":
            out(init_command(args.db))
        elif command == "kb-validate":
            out(validate_command(args.db, args.record_id))
        elif command == "kb-export":
            out(export_bundle_command(args.db, args.record_id, args.output))
        else:
            out(schema_report_command(args.db))
        return

    from .models import Target
    from .legacy.pipeline import CVERPipeline

    pipe = CVERPipeline(args.profile or "demo")
    if command == "doctor":
        out(pipe.doctor())
    elif command == "init-db":
        out(pipe.init_db())
    elif command == "demo":
        result = pipe.demo()
        out({"ok": True, "scan_id": result["scan"]["scan_id"], "defense_score": result["defense_score"]["total_score"], "report": result["report"]})
    elif command == "benchmark":
        out(pipe.benchmark())
    elif command in ("full-pipeline", "scan-only", "reason-only", "redteam-only"):
        result = pipe.run(
            Target(
                args.target,
                args.target_kind,
                labels={"cver-lab": args.lab_label},
                namespace=args.namespace,
                runtime_class=args.runtime_class,
            ),
            command,
        )
        out({"ok": True, "scan_id": result["scan"]["scan_id"], "defense_score": result.get("defense_score", {}).get("total_score"), "report": result.get("report")})
    elif command == "web":
        import uvicorn

        uvicorn.run("cver.api:app", host=args.host, port=args.port, reload=args.reload)
