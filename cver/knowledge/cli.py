from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .repository import TrustedKnowledgeRepository
from .validation import GoldAdmissionValidator


def init_command(db_path: str) -> dict[str, Any]:
    TrustedKnowledgeRepository(db_path)
    return {"ok": True, "db_path": str(Path(db_path)), "schema": "trusted-kb-0.1.0"}


def validate_command(db_path: str, record_id: str) -> dict[str, Any]:
    repository = TrustedKnowledgeRepository(db_path)
    bundle = repository.get_gold_bundle(record_id)
    return GoldAdmissionValidator().validate(bundle).to_dict()


def export_bundle_command(db_path: str, record_id: str, output: str) -> dict[str, Any]:
    repository = TrustedKnowledgeRepository(db_path)
    bundle = repository.get_gold_bundle(record_id)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bundle, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return {"ok": True, "record_id": record_id, "output": str(path)}
