from __future__ import annotations
import argparse, json
from typing import Any
from .models import Target
from .pipeline import CVERPipeline

def out(x: Any) -> None:
    print(json.dumps(x, ensure_ascii=False, indent=2, default=str))

def build_parser() -> argparse.ArgumentParser:
    p=argparse.ArgumentParser(prog="cver")
    p.add_argument("--profile", default=None)
    sub=p.add_subparsers(dest="cmd")
    for c in ["doctor","init-db","demo","benchmark"]:
        sp0=sub.add_parser(c); sp0.add_argument("--profile", default=None)
    for c in ["full-pipeline","scan-only","reason-only","redteam-only"]:
        sp=sub.add_parser(c); sp.add_argument("--profile", default=None); sp.add_argument("--target", default="demo/nginx:lab"); sp.add_argument("--target-kind", default="image"); sp.add_argument("--namespace"); sp.add_argument("--runtime-class"); sp.add_argument("--lab-label", default="true")
    web=sub.add_parser("web"); web.add_argument("--profile", default=None); web.add_argument("--host", default="127.0.0.1"); web.add_argument("--port", type=int, default=8000); web.add_argument("--reload", action="store_true")
    return p

def main() -> None:
    args=build_parser().parse_args()
    pipe=CVERPipeline(args.profile or "demo")
    cmd=args.cmd or "doctor"
    if cmd=="doctor": out(pipe.doctor())
    elif cmd=="init-db": out(pipe.init_db())
    elif cmd=="demo":
        r=pipe.demo(); out({"ok":True,"scan_id":r["scan"]["scan_id"],"defense_score":r["defense_score"]["total_score"],"report":r["report"]})
    elif cmd=="benchmark": out(pipe.benchmark())
    elif cmd in ("full-pipeline","scan-only","reason-only","redteam-only"):
        r=pipe.run(Target(args.target,args.target_kind,labels={"cver-lab":args.lab_label},namespace=args.namespace,runtime_class=args.runtime_class),cmd)
        out({"ok":True,"scan_id":r["scan"]["scan_id"],"defense_score":r.get("defense_score",{}).get("total_score"),"report":r.get("report")})
    elif cmd=="web":
        try:
            import uvicorn
        except Exception:
            raise SystemExit("uvicorn is not installed. Run: pip install -r requirements.txt")
        uvicorn.run("cver.api:app", host=args.host, port=args.port, reload=args.reload)
