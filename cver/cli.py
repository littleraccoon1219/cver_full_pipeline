from __future__ import annotations

import argparse
import json
from typing import Any

from .models import Target
from .pipeline import CVERPipeline


def out(x: Any) -> None:
    print(json.dumps(x, ensure_ascii=False, indent=2, default=str))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cver")
    p.add_argument("--profile", default=None)
    sub = p.add_subparsers(dest="cmd")

    for command in ["doctor", "init-db", "demo", "benchmark"]:
        parser = sub.add_parser(command)
        parser.add_argument("--profile", default=None)

    for command in ["full-pipeline", "scan-only", "reason-only", "redteam-only"]:
        parser = sub.add_parser(command)
        parser.add_argument("--profile", default=None)
        parser.add_argument("--target", default="demo/nginx:lab")
        parser.add_argument("--target-kind", default="image")
        parser.add_argument("--namespace")
        parser.add_argument("--runtime-class")
        parser.add_argument("--lab-label", default="true")

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
    return p


def main() -> None:
    args = build_parser().parse_args()
    command = args.cmd or "doctor"

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

    pipe = CVERPipeline(args.profile or "demo")
    if command == "doctor":
        out(pipe.doctor())
    elif command == "init-db":
        out(pipe.init_db())
    elif command == "demo":
        result = pipe.demo()
        out({
            "ok": True,
            "scan_id": result["scan"]["scan_id"],
            "defense_score": result["defense_score"]["total_score"],
            "report": result["report"],
        })
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
        out({
            "ok": True,
            "scan_id": result["scan"]["scan_id"],
            "defense_score": result.get("defense_score", {}).get("total_score"),
            "report": result.get("report"),
        })
    elif command == "web":
        try:
            import uvicorn
        except Exception:
            raise SystemExit("uvicorn is not installed. Run: pip install -r requirements.txt")
        uvicorn.run("cver.api:app", host=args.host, port=args.port, reload=args.reload)
