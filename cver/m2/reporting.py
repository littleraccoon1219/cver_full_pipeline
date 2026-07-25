from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path
from typing import Any

from .config import M2Settings


RESTRICTED_KEYS = {
    "context",
    "trigger_input",
    "corpus",
    "crash_artifacts",
    "output_tail",
    "stdout_tail",
    "stderr_tail",
    "env_raw",
}


def redact(value: Any, *, reveal_restricted: bool = False) -> Any:
    if reveal_restricted:
        return value
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        restricted = bool(value.get("restricted"))
        for key, item in value.items():
            if restricted and key in {"artifact_path", "path", "name"}:
                output[key] = "[sealed]"
            elif key in RESTRICTED_KEYS:
                if key == "crash_artifacts" and isinstance(item, list):
                    output[key] = [
                        {
                            "sha256": candidate.get("sha256"),
                            "size_bytes": candidate.get("size_bytes"),
                            "restricted": True,
                        }
                        for candidate in item
                        if isinstance(candidate, dict)
                    ]
                else:
                    output[key] = "[redacted]"
            else:
                output[key] = redact(item, reveal_restricted=False)
        return output
    if isinstance(value, list):
        return [redact(item, reveal_restricted=False) for item in value]
    return value


class ReportWriter:
    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings

    def write(self, job_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        root = self.settings.reports_dir / job_id
        root.mkdir(parents=True, exist_ok=True)
        safe = redact(payload)
        json_path = root / "report.json"
        md_path = root / "report.md"
        html_path = root / "report.html"
        json_path.write_text(json.dumps(safe, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        md_path.write_text(self._markdown(safe), encoding="utf-8")
        html_path.write_text(self._html(safe), encoding="utf-8")
        return {
            "json": str(json_path),
            "markdown": str(md_path),
            "html": str(html_path),
            "sha256": {
                "json": hashlib.sha256(json_path.read_bytes()).hexdigest(),
                "markdown": hashlib.sha256(md_path.read_bytes()).hexdigest(),
                "html": hashlib.sha256(html_path.read_bytes()).hexdigest(),
            },
        }

    @staticmethod
    def _markdown(payload: dict[str, Any]) -> str:
        findings = payload.get("findings", [])
        phases = payload.get("phases", {})
        lines = [
            "# CVER M2 Kata Vulnerability Discovery Report",
            "",
            f"- Job: `{payload.get('job_id', '')}`",
            f"- Status: `{payload.get('status', '')}`",
            f"- Profile: `{payload.get('profile', '')}`",
            f"- Safety boundary: `{payload.get('safety_boundary', '')}`",
            "",
            "## Phase status",
            "",
        ]
        for name, item in phases.items():
            status = item.get("status") if isinstance(item, dict) else "unknown"
            lines.append(f"- `{name}`: `{status}`")
        lines.extend(["", "## Findings", ""])
        if not findings:
            lines.append("No findings were recorded.")
        for item in findings:
            lines.extend(
                [
                    f"### {item.get('title', 'Untitled')}",
                    "",
                    f"- Component: `{item.get('component')}`",
                    f"- Severity: `{item.get('severity')}`",
                    f"- Status: `{item.get('status')}`",
                    f"- Confidence: `{item.get('confidence')}`",
                    f"- Location: `{item.get('file') or '-'}:{item.get('line') or '-'}`",
                    "",
                    str(item.get("description", "")),
                    "",
                ]
            )
        lines.extend(
            [
                "## Evidence policy",
                "",
                (
                    "LLM output is review assistance, not ground truth. A sanitizer crash "
                    "must include a fresh artifact and sanitizer signature. Suspected zero-day "
                    "trigger material is sealed and omitted from this report."
                ),
                "",
            ]
        )
        return "\n".join(lines)

    @classmethod
    def _html(cls, payload: dict[str, Any]) -> str:
        markdown = cls._markdown(payload)
        body = "\n".join(f"<p>{html.escape(line)}</p>" for line in markdown.splitlines())
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>CVER M2 Report</title>"
            "<style>body{font:15px system-ui;max-width:1100px;margin:40px auto;padding:0 20px;}"
            "p{white-space:pre-wrap;margin:.35rem 0;}code{background:#eee;padding:2px 4px}</style>"
            f"</head><body>{body}</body></html>"
        )
