from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from ..source_discovery import classify_reference_url
from .common import CandidateBundleBuilder, CollectorError, fetch_bytes, now_iso

COLLECTOR_VERSION = "1.0.0"
DEFAULT_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)
_CONTAINER_TERMS = {
    "container",
    "docker",
    "kubernetes",
    "kubelet",
    "cloud native",
    "escape to host",
    "container administration",
    "deploy container",
    "exposed docker",
}


def _text_matches(text: str) -> bool:
    low = text.lower()
    return any(term in low for term in _CONTAINER_TERMS)


def _attack_object_matches(obj: dict[str, Any]) -> bool:
    platforms = {str(value).strip().lower() for value in obj.get("x_mitre_platforms") or []}
    if "containers" in platforms:
        return True
    text = " ".join(
        [
            str(obj.get("name") or ""),
            str(obj.get("description") or ""),
            " ".join(obj.get("x_mitre_data_sources") or []),
        ]
    )
    return _text_matches(text)


def _read_origin(path_or_url: str) -> tuple[bytes, str]:
    if path_or_url.startswith(("http://", "https://")):
        return fetch_bytes(path_or_url)[0], path_or_url
    path = Path(path_or_url)
    if not path.is_file():
        raise CollectorError(f"attack-pattern source not found: {path}")
    return path.read_bytes(), str(path)


def _attack_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references") or []:
        external_id = str(ref.get("external_id") or "")
        if external_id.startswith("T"):
            return external_id
    return None


def _collect_attack_stix(builder: CandidateBundleBuilder, origin: str, max_records: int) -> int:
    content, resolved = _read_origin(origin)
    snapshot = builder.store_raw("MITRE-ATTACK-STIX", content, suffix=".json", media_type="application/json")
    payload = json.loads(content.decode("utf-8"))
    count = 0
    for obj in payload.get("objects") or []:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        attack_id = _attack_id(obj)
        if not attack_id:
            continue
        if not _attack_object_matches(obj):
            continue
        description = re.sub(r"\s+", " ", str(obj.get("description") or "")).strip()
        candidate = {
            "record_type": "attack_pattern",
            "external_id": f"ATTACK-{attack_id}",
            "title_en": str(obj.get("name") or attack_id),
            "summary_en": description[:1500],
            "technology_bucket_candidate": "container_attack_pattern",
            "candidate_source": "MITRE ATT&CK STIX 2.1",
            "attributes": {
                "attack_id": attack_id,
                "stix_id": obj.get("id"),
                "platforms": obj.get("x_mitre_platforms") or [],
                "kill_chain_phases": obj.get("kill_chain_phases") or [],
                "external_references": obj.get("external_references") or [],
                "requires_real_case": True,
            },
            "source": {
                "source_key": "MITRE-ATTACK-STIX",
                "name": "MITRE ATT&CK Enterprise STIX 2.1",
                "source_type": "attack_taxonomy",
                "authority_level": "E0",
                "url": origin if origin.startswith("http") else None,
                "publisher": "MITRE",
                "license_name": "MITRE ATT&CK terms apply",
                "retrieved_at": now_iso(),
            },
            "snapshot": snapshot,
            "evidence": {
                "locator": f"stix:{obj.get('id')}",
                "excerpt": description or str(obj.get("name") or attack_id),
                "language": "en",
                "evidence_level": "E0",
                "fragment_type": "stix_object",
            },
            "assertions": [
                {"predicate": "attack_pattern_name", "object": obj.get("name"), "verification_status": "moderate"},
                {
                    "predicate": "attack_platforms",
                    "object": obj.get("x_mitre_platforms") or [],
                    "verification_status": "moderate",
                },
            ],
        }
        if builder.add_candidate(candidate):
            count += 1
            for ref in obj.get("external_references") or []:
                url = ref.get("url")
                if url:
                    source = classify_reference_url(str(url), component_hint="container_attack_pattern")
                    source["external_id"] = f"ATTACK-{attack_id}"
                    builder.add_source_candidate(source)
        if count >= max_records:
            break
    return count


def _capec_rows(content: bytes, origin: str) -> list[dict[str, str]]:
    if origin.lower().endswith(".zip") or content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith(".csv")]
            if not names:
                raise CollectorError("CAPEC ZIP contains no CSV")
            content = archive.read(names[0])
    text = content.decode("utf-8-sig", errors="replace")
    return [dict(row) for row in csv.DictReader(io.StringIO(text))]


def _collect_capec(builder: CandidateBundleBuilder, origin: str, max_records: int) -> int:
    content, _ = _read_origin(origin)
    is_zip = origin.lower().endswith(".zip") or content[:2] == b"PK"
    snapshot = builder.store_raw(
        "CAPEC",
        content,
        suffix=Path(origin).suffix or (".zip" if is_zip else ".csv"),
        media_type="application/zip" if is_zip else "text/csv",
    )
    count = 0
    for row in _capec_rows(content, origin):
        row_text = " ".join(str(value or "") for value in row.values())
        if not _text_matches(row_text):
            continue
        capec_id = str(row.get("ID") or row.get("Id") or row.get("id") or "").strip()
        name = str(row.get("Name") or row.get("name") or f"CAPEC-{capec_id}").strip()
        description = str(row.get("Description") or row.get("description") or "").strip()
        if not capec_id:
            continue
        candidate = {
            "record_type": "attack_pattern",
            "external_id": f"CAPEC-{capec_id}",
            "title_en": name,
            "summary_en": re.sub(r"\s+", " ", description)[:1500],
            "technology_bucket_candidate": "container_attack_pattern",
            "candidate_source": "CAPEC",
            "attributes": {"capec_id": capec_id, "raw_row": row, "requires_real_case": True},
            "source": {
                "source_key": "MITRE-CAPEC",
                "name": "MITRE CAPEC Dictionary",
                "source_type": "attack_taxonomy",
                "authority_level": "E0",
                "url": origin if origin.startswith("http") else None,
                "publisher": "MITRE",
                "license_name": "CAPEC terms apply",
                "retrieved_at": now_iso(),
            },
            "snapshot": snapshot,
            "evidence": {
                "locator": f"csv:CAPEC-{capec_id}",
                "excerpt": description or name,
                "language": "en",
                "evidence_level": "E0",
                "fragment_type": "csv_row",
            },
            "assertions": [
                {"predicate": "attack_pattern_name", "object": name, "verification_status": "moderate"},
                {"predicate": "capec_id", "object": f"CAPEC-{capec_id}", "verification_status": "moderate"},
            ],
        }
        if builder.add_candidate(candidate):
            count += 1
            builder.add_source_candidate(
                {
                    "external_id": f"CAPEC-{capec_id}",
                    "source_role_candidate": "real_case_or_independent_research_required",
                    "query_hint": f"{name} container Kubernetes Docker incident",
                }
            )
        if count >= max_records:
            break
    return count


def collect_attack_pattern_candidates(
    *,
    output_dir: str | Path,
    attack_stix: str = DEFAULT_ATTACK_STIX_URL,
    capec_csv_or_zip: str | None = None,
    max_records: int = 20,
) -> dict[str, Any]:
    builder = CandidateBundleBuilder(
        output_dir,
        "attack_pattern",
        COLLECTOR_VERSION,
        "MITRE ATT&CK and CAPEC",
        {"attack_stix": attack_stix, "capec": capec_csv_or_zip, "max_records": max_records},
    )
    try:
        attack_count = _collect_attack_stix(builder, attack_stix, max_records)
    except Exception as exc:
        attack_count = 0
        builder.add_error("attack_stix", str(exc), source=attack_stix)
    remaining = max(0, max_records - attack_count)
    if capec_csv_or_zip and remaining:
        try:
            _collect_capec(builder, capec_csv_or_zip, remaining)
        except Exception as exc:
            builder.add_error("capec", str(exc), source=capec_csv_or_zip)
    return builder.finalize()
