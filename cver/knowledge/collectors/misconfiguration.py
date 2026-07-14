from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .common import CandidateBundleBuilder, CollectorError, html_to_text, load_yaml, now_iso, read_source_bytes

COLLECTOR_VERSION = "1.0.0"
_CONTROL_HEADING = re.compile(
    r"(?im)^\s*(?P<id>\d+(?:\.\d+){1,5})\s+(?P<title>(?:Ensure|Verify|Set|Do not|Do Not|Use|Restrict|Configure|Disable|Enable)\b[^\n]{8,300})"
)
_MARKDOWN_HEADING = re.compile(r"(?im)^#{1,6}\s+(?P<id>[A-Za-z0-9_.-]+)\s*[-:]?\s*(?P<title>[^\n]{8,300})")


def _extract_text(content: bytes, media_type: str, source_name: str) -> str:
    suffix = Path(source_name).suffix.lower()
    if media_type == "application/pdf" or suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise CollectorError("PDF collection requires pypdf; run pip install -r requirements.txt") from exc
        import io

        reader = PdfReader(io.BytesIO(content))
        return "\n\n".join((page.extract_text() or "") for page in reader.pages)
    if media_type in {"text/html", "application/xhtml+xml"} or suffix in {".html", ".htm"}:
        return html_to_text(content)[0]
    if suffix in {".json", ".yaml", ".yml"}:
        try:
            if suffix == ".json":
                return json.dumps(json.loads(content.decode("utf-8")), ensure_ascii=False, indent=2)
            import yaml

            return yaml.safe_dump(yaml.safe_load(content.decode("utf-8")), allow_unicode=True, sort_keys=False)
        except Exception:
            pass
    return content.decode("utf-8", errors="replace")


def _sections(text: str, max_records: int) -> list[dict[str, str]]:
    matches = list(_CONTROL_HEADING.finditer(text)) or list(_MARKDOWN_HEADING.finditer(text))
    output: list[dict[str, str]] = []
    for index, match in enumerate(matches[:max_records]):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else min(len(text), start + 5000)
        excerpt = " ".join(text[start:end].split())[:4000]
        output.append({"control_id": match.group("id"), "title": match.group("title").strip(), "excerpt": excerpt})
    return output


def collect_misconfiguration_candidates(
    *,
    output_dir: str | Path,
    source_config: str | Path,
    max_records: int = 50,
) -> dict[str, Any]:
    config = load_yaml(source_config)
    sources = config.get("sources") or []
    if not sources:
        raise CollectorError("misconfiguration source config contains no sources")
    builder = CandidateBundleBuilder(
        output_dir,
        "misconfiguration",
        COLLECTOR_VERSION,
        "CIS and official container/cloud-native security guidance",
        {"source_config": str(source_config), "max_records": max_records},
    )
    remaining = max_records
    for source in sources:
        if remaining <= 0:
            break
        source_id = str(source.get("source_id") or "").strip()
        if not source_id:
            builder.add_error("source_config", "source_id is required", source=source)
            continue
        try:
            content, media_type, origin = read_source_bytes(source)
            snapshot = builder.store_raw(source_id, content, suffix=Path(origin).suffix, media_type=media_type)
            text = _extract_text(content, media_type, origin)
            controls = _sections(text, remaining)
            if not controls:
                builder.add_error("parse", "no control headings found", source_id=source_id, origin=origin)
                continue
            for control in controls:
                external_id = f"MISCONF-{source_id}-{control['control_id']}"
                candidate = {
                    "record_type": "misconfiguration",
                    "external_id": external_id,
                    "title_en": control["title"],
                    "summary_en": control["excerpt"][:1000],
                    "technology_bucket_candidate": source.get("technology_bucket", "container_security_configuration"),
                    "candidate_source": source_id,
                    "attributes": {
                        "control_id": control["control_id"],
                        "document_origin": origin,
                        "document_version": source.get("version"),
                        "technology_bucket_candidate": source.get("technology_bucket"),
                        "requires_independent_source": True,
                        "requires_local_experiment": True,
                    },
                    "source": {
                        "source_key": source_id,
                        "name": source.get("name") or source_id,
                        "source_type": source.get("source_type", "security_benchmark"),
                        "authority_level": source.get("authority_level", "E0"),
                        "url": source.get("url"),
                        "publisher": source.get("publisher"),
                        "license_name": source.get("license_name"),
                        "retrieved_at": now_iso(),
                    },
                    "snapshot": snapshot,
                    "evidence": {
                        "locator": f"control:{control['control_id']}",
                        "excerpt": control["excerpt"],
                        "language": source.get("language", "en"),
                        "evidence_level": source.get("authority_level", "E0"),
                        "fragment_type": "document_section",
                    },
                    "assertions": [
                        {"predicate": "configuration_control", "object": control["title"], "verification_status": "moderate"},
                        {"predicate": "source_control_id", "object": control["control_id"], "verification_status": "moderate"},
                    ],
                }
                if builder.add_candidate(candidate):
                    remaining -= 1
                    builder.add_source_candidate(
                        {
                            "external_id": external_id,
                            "source_role_candidate": "independent_validation_required",
                            "query_hint": f"{control['title']} Docker Kubernetes security research",
                            "requires_human_confirmation": True,
                        }
                    )
                    if remaining <= 0:
                        break
        except Exception as exc:
            builder.add_error("source", str(exc), source_id=source_id)
    return builder.finalize()
