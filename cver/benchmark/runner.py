from __future__ import annotations

from pathlib import Path

from ..ids import new_id
from ..models import BenchmarkRun
from ..storage import read_json, write_json
from .metrics import set_metrics


class BenchmarkRunner:
    def run(
        self, report: dict, profile: str = "benchmark", labels_path: str = "data/demo/labels_demo.json"
    ) -> BenchmarkRun:
        labels = read_json(labels_path)
        exp = labels.get("cases", [{}])[0].get("expected", {})
        pred_macro = sorted({f.get("macro_type") for f in report.get("findings", []) if f.get("macro_type")})
        pred_fine = sorted({f.get("fine_type") for f in report.get("findings", []) if f.get("fine_type")})
        pred_expl = sorted(
            {
                r.get("exploitability_label")
                for r in report.get("exploitability_results", [])
                if r.get("exploitability_label")
            }
        )
        pred_scen = sorted(
            {
                r.get("scenario_id")
                for r in report.get("redteam_campaign", {}).get("results", [])
                if r.get("scenario_id")
            }
        )
        pred_repair = sorted(
            {
                p.get("template_id")
                for p in report.get("repair_plan", {}).get("patch_proposals", [])
                if p.get("template_id")
            }
        )
        metrics = {
            "macro_classification": set_metrics(pred_macro, exp.get("macro_types", [])),
            "fine_classification": set_metrics(pred_fine, exp.get("fine_types", [])),
            "exploitability_label": set_metrics(pred_expl, exp.get("exploitability_labels", [])),
            "redteam_trigger": set_metrics(pred_scen, exp.get("redteam_scenarios", [])),
            "repair_recommendation": set_metrics(pred_repair, exp.get("repair_expected", [])),
            "runtime_ms": report.get("runtime_ms", 0),
            "llm_cost_estimate": 0.0,
            "groups": {"runtime": "mock", "llm_mode": "hybrid", "target_class": report.get("target", {}).get("kind")},
        }
        out = Path("outputs/benchmarks")
        out.mkdir(parents=True, exist_ok=True)
        bid = new_id("bench")
        path = write_json(
            out / f"{bid}.json", {"benchmark_id": bid, "metrics": metrics, "case": labels.get("cases", [None])[0]}
        )
        return BenchmarkRun(bid, profile, labels.get("cases", []), metrics, path)
