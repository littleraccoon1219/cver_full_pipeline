from __future__ import annotations

import re
import urllib.parse
from pathlib import Path
from typing import Any

from ..source_discovery import classify_reference_url
from .common import CandidateBundleBuilder, CollectorError, html_to_text, load_yaml, now_iso, read_source_bytes

COLLECTOR_VERSION = "1.0.0"


def collect_supply_chain_incident_candidates(
    *,
    output_dir: str | Path,
    seed_config: str | Path,
    max_records: int = 20,
) -> dict[str, Any]:
    config = load_yaml(seed_config)
    incidents = config.get("incidents") or []
    if not incidents:
        raise CollectorError("supply-chain seed config contains no incidents")
    builder = CandidateBundleBuilder(
        output_dir,
        "supply_chain_incident",
        COLLECTOR_VERSION,
        "Curated official incident reports and independent research",
        {"seed_config": str(seed_config), "max_records": max_records},
    )
    for incident in incidents[:max_records]:
        external_id = str(incident.get("external_id") or "").strip()
        title = str(incident.get("title") or "").strip()
        if not external_id or not title:
            builder.add_error("seed", "external_id and title are required", incident=incident)
            continue
        try:
            content, media_type, origin = read_source_bytes(incident)
            snapshot = builder.store_raw(external_id, content, suffix=Path(origin).suffix, media_type=media_type)
            if media_type in {"text/html", "application/xhtml+xml"} or origin.endswith((".html", ".htm")):
                text, links = html_to_text(content)
            else:
                text = content.decode("utf-8", errors="replace")
                links = []
            clean = re.sub(r"\s+", " ", text).strip()
            query_terms = [str(value).lower() for value in incident.get("match_terms") or []]
            if query_terms and not any(term in clean.lower() for term in query_terms):
                builder.add_error("relevance", "seed document does not contain match terms", external_id=external_id)
                continue
            excerpt = clean[:4000]
            candidate = {
                "record_type": "supply_chain_incident",
                "external_id": external_id,
                "title_en": title,
                "summary_en": incident.get("summary") or excerpt[:1500],
                "technology_bucket_candidate": incident.get("technology_bucket", "container_supply_chain"),
                "candidate_source": incident.get("source_id") or external_id,
                "attributes": {
                    "event_date": incident.get("event_date"),
                    "incident_type_candidate": incident.get("incident_type"),
                    "affected_projects": incident.get("affected_projects") or [],
                    "document_origin": origin,
                    "requires_independent_source": True,
                },
                "source": {
                    "source_key": incident.get("source_id") or external_id,
                    "name": incident.get("source_name") or title,
                    "source_type": incident.get("source_type", "incident_report"),
                    "authority_level": incident.get("authority_level", "E0"),
                    "url": incident.get("url"),
                    "publisher": incident.get("publisher"),
                    "license_name": incident.get("license_name"),
                    "retrieved_at": now_iso(),
                },
                "snapshot": snapshot,
                "evidence": {
                    "locator": incident.get("locator", "document"),
                    "excerpt": excerpt or title,
                    "language": incident.get("language", "en"),
                    "evidence_level": incident.get("authority_level", "E0"),
                    "fragment_type": "incident_document",
                },
                "assertions": [
                    {"predicate": "incident_title", "object": title, "verification_status": "moderate"},
                    {"predicate": "event_date", "object": incident.get("event_date"), "verification_status": "moderate"},
                    {"predicate": "incident_type_candidate", "object": incident.get("incident_type"), "verification_status": "moderate"},
                ],
            }
            builder.add_candidate(candidate)
            for url in links:
                absolute = urllib.parse.urljoin(str(incident.get("url") or ""), url)
                if absolute.startswith(("http://", "https://")):
                    source = classify_reference_url(absolute, component_hint="container_supply_chain")
                    source["external_id"] = external_id
                    builder.add_source_candidate(source)
            for url in incident.get("related_urls") or []:
                source = classify_reference_url(str(url), component_hint="container_supply_chain")
                source["external_id"] = external_id
                builder.add_source_candidate(source)
        except Exception as exc:
            builder.add_error("incident", str(exc), external_id=external_id)
    return builder.finalize()
