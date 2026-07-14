from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collectors.common import BUNDLE_SCHEMA_VERSION, ALLOWED_RECORD_TYPES, read_jsonl, sha256_file

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")


@dataclass(slots=True)
class CandidateBundleValidation:
    valid: bool
    errors: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": self.errors, "warnings": self.warnings, "stats": self.stats}


def validate_candidate_bundle(bundle_dir: str | Path) -> CandidateBundleValidation:
    root = Path(bundle_dir).resolve()
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    manifest_path = root / "manifest.json"
    candidates_path = root / "candidates.jsonl"
    if not manifest_path.is_file():
        return CandidateBundleValidation(False, [{"code": "MANIFEST_MISSING"}], [], {})
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return CandidateBundleValidation(False, [{"code": "MANIFEST_INVALID", "message": str(exc)}], [], {})
    if manifest.get("bundle_schema_version") != BUNDLE_SCHEMA_VERSION:
        errors.append({"code": "SCHEMA_VERSION", "value": manifest.get("bundle_schema_version")})
    if not candidates_path.is_file():
        errors.append({"code": "CANDIDATES_MISSING"})
        candidates: list[dict[str, Any]] = []
    else:
        try:
            candidates = read_jsonl(candidates_path)
        except Exception as exc:
            errors.append({"code": "CANDIDATES_INVALID", "message": str(exc)})
            candidates = []
    for entry in manifest.get("files") or []:
        rel = str(entry.get("path") or "")
        candidate_path = (root / rel).resolve()
        if root not in candidate_path.parents and candidate_path != root:
            errors.append({"code": "PATH_ESCAPE", "path": rel})
            continue
        if not candidate_path.is_file():
            errors.append({"code": "FILE_MISSING", "path": rel})
        elif sha256_file(candidate_path) != entry.get("sha256"):
            errors.append({"code": "FILE_HASH_MISMATCH", "path": rel})
    seen: set[tuple[str, str]] = set()
    counts: dict[str, int] = {}
    for index, item in enumerate(candidates, start=1):
        record_type = item.get("record_type")
        external_id = str(item.get("external_id") or "")
        prefix = {"row": index, "external_id": external_id}
        if record_type not in ALLOWED_RECORD_TYPES:
            errors.append({"code": "RECORD_TYPE", **prefix})
        if not external_id:
            errors.append({"code": "EXTERNAL_ID", **prefix})
        if record_type == "vulnerability" and not _CVE_ID.match(external_id):
            errors.append({"code": "CVE_ID", **prefix})
        key = (str(record_type), external_id)
        if key in seen:
            errors.append({"code": "DUPLICATE", **prefix})
        seen.add(key)
        counts[str(record_type)] = counts.get(str(record_type), 0) + 1
        if item.get("status") != "candidate":
            errors.append({"code": "STATUS_NOT_CANDIDATE", **prefix})
        if item.get("root_cause_l1") not in (None, "") or item.get("root_cause_l2") not in (None, ""):
            errors.append({"code": "AUTO_ROOT_CAUSE_FORBIDDEN", **prefix})
        if item.get("generated_by_model") is not False:
            errors.append({"code": "MODEL_FLAG", **prefix})
        snapshot = item.get("snapshot") or {}
        rel = str(snapshot.get("relative_path") or "")
        raw_path = (root / rel).resolve()
        if not rel or not raw_path.is_file():
            errors.append({"code": "RAW_SNAPSHOT_MISSING", **prefix})
        elif sha256_file(raw_path) != snapshot.get("sha256"):
            errors.append({"code": "RAW_SNAPSHOT_HASH", **prefix})
        source = item.get("source") or {}
        if source.get("authority_level") not in {"E0", "E1", "E2", "E3", "E4"}:
            errors.append({"code": "EVIDENCE_LEVEL", **prefix})
        if not item.get("assertions"):
            warnings.append({"code": "NO_ASSERTIONS", **prefix})
    if manifest.get("candidate_count") != len(candidates):
        errors.append({"code": "COUNT_MISMATCH", "manifest": manifest.get("candidate_count"), "actual": len(candidates)})
    stats = {"candidate_count": len(candidates), "record_type_counts": counts, "manifest": manifest}
    return CandidateBundleValidation(not errors, errors, warnings, stats)
