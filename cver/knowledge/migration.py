from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import KnowledgeRecord, RecordStatus, RecordType
from .repository import TrustedKnowledgeRepository


def _record_type(raw: dict[str, Any]) -> RecordType | None:
    facts = raw.get("facts", {})
    explicit = facts.get("record_type") or raw.get("record_type")
    if explicit:
        try:
            return RecordType(str(explicit))
        except ValueError:
            return None
    external_id = str(facts.get("cve_id") or "")
    if external_id.upper().startswith("CVE-"):
        return RecordType.VULNERABILITY
    return None


def import_legacy_seed(
    source_path: str | Path,
    db_path: str | Path,
    changed_by: str,
) -> dict[str, Any]:
    """Import old seed records as unverified candidates only.

    The migration deliberately does not copy legacy root-cause labels into the
    trusted taxonomy fields. They are retained under attributes for later human
    review, preventing keyword-derived labels from becoming Gold facts.
    """

    path = Path(source_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    repository = TrustedKnowledgeRepository(db_path)
    imported = 0
    skipped: list[dict[str, str]] = []

    for index, raw in enumerate(payload.get("records", []), start=1):
        facts = raw.get("facts", {})
        record_type = _record_type(raw)
        external_id = str(facts.get("cve_id") or "").strip()
        if record_type is None or not external_id:
            skipped.append({"index": str(index), "reason": "record_type_or_external_id_not_explicit"})
            continue

        record_id = "REC-" + hashlib.sha256(f"{record_type.value}:{external_id}".encode()).hexdigest()[:20]
        title_en = str(facts.get("title") or facts.get("description") or external_id).strip()
        record = KnowledgeRecord(
            record_id=record_id,
            record_type=record_type,
            external_id=external_id,
            title_en=title_en[:500],
            status=RecordStatus.CANDIDATE,
            summary_en=str(facts.get("description") or ""),
            attributes={
                "legacy_source_path": str(path),
                "legacy_facts": facts,
                "legacy_semantic_annotations": raw.get("semantic_annotations", {}),
                "legacy_evidence_sources": raw.get("evidence_sources", []),
                "migration_warning": "Legacy labels are unverified and were not promoted to trusted root-cause fields.",
            },
        )
        repository.upsert_record(
            record,
            changed_by=changed_by,
            change_reason="legacy seed imported as candidate",
        )
        imported += 1

    return {
        "source": str(path),
        "database": str(db_path),
        "imported_candidates": imported,
        "skipped": skipped,
    }
