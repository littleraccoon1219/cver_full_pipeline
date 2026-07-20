from __future__ import annotations

import html
from pathlib import Path

from ..ids import new_id
from ..models import Report
from ..storage import write_json, write_text


class ReportGenerator:
    def generate(self, run_dir: str | Path, payload: dict) -> Report:
        p = Path(run_dir)
        p.mkdir(parents=True, exist_ok=True)
        rid = new_id("report")
        jp = write_json(p / "report.json", payload)
        mp = write_text(p / "report.md", self.markdown(payload))
        hp = write_text(p / "report.html", self.html(payload))
        return Report(rid, payload["scan"]["scan_id"], payload["target"]["target_id"], jp, mp, hp)

    def markdown(self, p: dict) -> str:
        lines = [
            f"# CVER Report: {p['target']['name']}",
            "",
            f"- Scan ID: `{p['scan']['scan_id']}`",
            f"- Defense Score: **{p['defense_score']['total_score']} / 100**",
            "",
            "## Findings",
        ]
        for f in p["findings"]:
            lines += [
                f"### {f['severity']} - {f['title']}",
                f"- Type: `{f.get('macro_type')}/{f.get('fine_type')}`",
                f"- Root Cause: `{f.get('root_cause')}`",
                f"- Evidence: `{', '.join(f.get('evidence_refs', []))}`",
            ]
        lines += ["", "## Exploitability"]
        for r in p["exploitability_results"]:
            lines.append(
                f"- `{r['finding_id']}` -> "
                f"**{r['exploitability_label']}** "
                f"score={r['exploitability_score']} "
                f"confidence={r['confidence']}"
            )
            if r.get("reasoning_trace"):
                lines.append("  - Trace: " + "; ".join(r["reasoning_trace"][:3]))
        lines += ["", "## EscapeGraph", "```mermaid", p["escape_graph"]["mermaid"], "```", "", "## RedTeam"]
        for r in p["redteam_campaign"]["results"]:
            lines.append(f"- `{r.get('scenario_id')}`: {r.get('status')} / no real PoC")
        lines += ["", "## Repair"]
        for rp in p["repair_plan"]["patch_proposals"]:
            lines.append(
                f"- `{rp['template_id']}`: {rp['summary']} human_confirm_required={rp['human_confirm_required']}"
            )
        return "\n".join(lines) + "\n"

    def html(self, p: dict) -> str:
        md = html.escape(self.markdown(p))
        return f"<!doctype html><html><head><meta charset='utf-8'><title>CVER Report</title><style>body{{font-family:Arial,sans-serif;max-width:1180px;margin:30px auto;line-height:1.55}}pre{{background:#f6f8fa;padding:12px;border-radius:8px;overflow:auto}}.score{{font-size:28px;font-weight:700}}</style></head><body><h1>CVER Report</h1><p>Target: <code>{html.escape(p['target']['name'])}</code></p><p class='score'>Defense Score: {p['defense_score']['total_score']} / 100</p><pre>{md}</pre></body></html>"  # noqa: E501
