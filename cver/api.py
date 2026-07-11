from __future__ import annotations
from typing import Any
try:
    from fastapi import FastAPI, Form, Request
    from fastapi.responses import HTMLResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
except Exception:
    FastAPI = None  # type: ignore
from .models import Target
from .pipeline import CVERPipeline

if FastAPI is None:
    app = None
else:
    app=FastAPI(title="CVER Full Pipeline", version="0.1.0")
    app.mount("/static", StaticFiles(directory="cver/web/static"), name="static")
    templates=Jinja2Templates(directory="cver/web/templates")

    @app.get("/health")
    def health() -> dict[str,Any]:
        return {"status":"ok"}

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        return templates.TemplateResponse("dashboard.html", {"request":request, "doctor":CVERPipeline("demo").doctor()})

    @app.get("/scan", response_class=HTMLResponse)
    def scan_page(request: Request):
        return templates.TemplateResponse("scan.html", {"request":request})

    @app.post("/scan", response_class=HTMLResponse)
    def scan_submit(request: Request, target: str=Form("demo/nginx:lab"), target_kind: str=Form("image"), mode: str=Form("full-pipeline"), profile: str=Form("demo")):
        payload=CVERPipeline(profile).run(Target(target,target_kind,labels={"cver-lab":"true"}),mode)
        return templates.TemplateResponse("report.html", {"request":request, "payload":payload})

    @app.post("/api/pipeline")
    def api_pipeline(payload: dict[str,Any]) -> dict[str,Any]:
        r=CVERPipeline(payload.get("profile","demo")).run(Target(payload.get("target","demo/nginx:lab"),payload.get("target_kind","image"),labels={"cver-lab":str(payload.get("lab_label","true")).lower()}), payload.get("mode","full-pipeline"))
        return {"ok":True,"scan_id":r["scan"]["scan_id"],"report":r["report"],"defense_score":r["defense_score"]}

    @app.get("/benchmark", response_class=HTMLResponse)
    def benchmark_page(request: Request):
        return templates.TemplateResponse("benchmark.html", {"request":request, "benchmark":CVERPipeline("benchmark").benchmark()})
