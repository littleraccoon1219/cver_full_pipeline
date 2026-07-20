from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .collectors.common import (
    ALLOWED_RECORD_TYPES,
    BUNDLE_SCHEMA_VERSION,
    canonical_json,
    read_jsonl,
    sha256_bytes,
    sha256_file,
)

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_EVIDENCE_LEVELS = {"E0", "E1", "E2", "E3", "E4"}
_ALLOWED_VERIFICATION_STATUSES = {
    "verified",
    "strong",
    "moderate",
    "inferred",
    "unknown",
    "rejected",
    "conflicted",
}
_REQUIRED_MANIFEST_FIELDS = {
    "bundle_schema_version",
    "ingestion_run_id",
    "collector_name",
    "collector_version",
    "source_family",
    "candidate_count",
    "query_config",
    "query_config_hash",
    "files",
}
_REQUIRED_BUNDLE_FILES = {"candidates.jsonl", "source_candidates.jsonl", "errors.jsonl"}


@dataclass(slots=True)
class CandidateBundleValidation:
    valid: bool
    errors: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": self.errors, "warnings": self.warnings, "stats": self.stats}


def _required_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


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
    if not isinstance(manifest, dict):
        return CandidateBundleValidation(False, [{"code": "MANIFEST_NOT_OBJECT"}], [], {})

    for field in sorted(_REQUIRED_MANIFEST_FIELDS):
        if field not in manifest:
            errors.append({"code": "MANIFEST_FIELD_MISSING", "field": field})
    if manifest.get("bundle_schema_version") != BUNDLE_SCHEMA_VERSION:
        errors.append({"code": "SCHEMA_VERSION", "value": manifest.get("bundle_schema_version")})
    expected_query_hash = sha256_bytes(canonical_json(manifest.get("query_config") or {}).encode("utf-8"))
    if manifest.get("query_config_hash") != expected_query_hash:
        errors.append({"code": "QUERY_CONFIG_HASH_MISMATCH"})

    files = manifest.get("files") or []
    if not isinstance(files, list):
        errors.append({"code": "MANIFEST_FILES_NOT_LIST"})
        files = []
    file_entries: dict[str, dict[str, Any]] = {}
    for entry in files:
        if not isinstance(entry, dict):
            errors.append({"code": "MANIFEST_FILE_ENTRY_INVALID"})
            continue
        rel = str(entry.get("path") or "")
        if not rel:
            errors.append({"code": "MANIFEST_FILE_PATH_MISSING"})
            continue
        if rel in file_entries:
            errors.append({"code": "MANIFEST_FILE_DUPLICATE", "path": rel})
            continue
        file_entries[rel] = entry
        candidate_path = (root / rel).resolve()
        if root not in candidate_path.parents and candidate_path != root:
            errors.append({"code": "PATH_ESCAPE", "path": rel})
            continue
        if not candidate_path.is_file():
            errors.append({"code": "FILE_MISSING", "path": rel})
        elif sha256_file(candidate_path) != entry.get("sha256"):
            errors.append({"code": "FILE_HASH_MISMATCH", "path": rel})
    for required_file in sorted(_REQUIRED_BUNDLE_FILES):
        if required_file not in file_entries:
            errors.append({"code": "BUNDLE_FILE_UNLISTED", "path": required_file})

    if not candidates_path.is_file():
        errors.append({"code": "CANDIDATES_MISSING"})
        candidates: list[dict[str, Any]] = []
    else:
        try:
            candidates = read_jsonl(candidates_path)
        except Exception as exc:
            errors.append({"code": "CANDIDATES_INVALID", "message": str(exc)})
            candidates = []

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
        if not _required_string(item.get("title_en")):
            errors.append({"code": "TITLE_REQUIRED", **prefix})
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

        source = item.get("source")
        if not isinstance(source, dict):
            errors.append({"code": "SOURCE_REQUIRED", **prefix})
            source = {}
        for field in ("source_key", "name", "source_type"):
            if not _required_string(source.get(field)):
                errors.append({"code": "SOURCE_FIELD_REQUIRED", "field": field, **prefix})
        if source.get("authority_level") not in _ALLOWED_EVIDENCE_LEVELS:
            errors.append({"code": "EVIDENCE_LEVEL", "field": "source.authority_level", **prefix})

        snapshot = item.get("snapshot")
        if not isinstance(snapshot, dict):
            errors.append({"code": "SNAPSHOT_REQUIRED", **prefix})
            snapshot = {}
        rel = str(snapshot.get("relative_path") or "")
        raw_path = (root / rel).resolve()
        if not rel or not raw_path.is_file():
            errors.append({"code": "RAW_SNAPSHOT_MISSING", **prefix})
        elif root not in raw_path.parents:
            errors.append({"code": "RAW_SNAPSHOT_PATH_ESCAPE", **prefix})
        else:
            if not rel.startswith("raw/"):
                errors.append({"code": "RAW_SNAPSHOT_NOT_UNDER_RAW", "path": rel, **prefix})
            if sha256_file(raw_path) != snapshot.get("sha256"):
                errors.append({"code": "RAW_SNAPSHOT_HASH", **prefix})
            manifest_entry = file_entries.get(rel)
            if manifest_entry is None:
                errors.append({"code": "RAW_SNAPSHOT_UNLISTED", "path": rel, **prefix})
            elif manifest_entry.get("sha256") != snapshot.get("sha256"):
                errors.append({"code": "RAW_SNAPSHOT_MANIFEST_HASH", "path": rel, **prefix})
        if not _SHA256.match(str(snapshot.get("sha256") or "")):
            errors.append({"code": "RAW_SNAPSHOT_SHA256_FORMAT", **prefix})

        evidence = item.get("evidence")
        if not isinstance(evidence, dict):
            errors.append({"code": "EVIDENCE_REQUIRED", **prefix})
            evidence = {}
        for field in ("locator", "excerpt", "language", "fragment_type"):
            if not _required_string(evidence.get(field)):
                errors.append({"code": "EVIDENCE_FIELD_REQUIRED", "field": field, **prefix})
        if evidence.get("evidence_level") not in _ALLOWED_EVIDENCE_LEVELS:
            errors.append({"code": "EVIDENCE_LEVEL", "field": "evidence.evidence_level", **prefix})

        assertions = item.get("assertions")
        if not isinstance(assertions, list):
            errors.append({"code": "ASSERTIONS_NOT_LIST", **prefix})
            assertions = []
        if not assertions:
            warnings.append({"code": "NO_ASSERTIONS", **prefix})
        for assertion_index, assertion in enumerate(assertions, start=1):
            assertion_prefix = {**prefix, "assertion": assertion_index}
            if not isinstance(assertion, dict):
                errors.append({"code": "ASSERTION_INVALID", **assertion_prefix})
                continue
            if not _required_string(assertion.get("predicate")):
                errors.append({"code": "ASSERTION_PREDICATE_REQUIRED", **assertion_prefix})
            if assertion.get("verification_status", "moderate") not in _ALLOWED_VERIFICATION_STATUSES:
                errors.append({"code": "ASSERTION_VERIFICATION_STATUS", **assertion_prefix})
            if assertion.get("object") in (None, "", []):
                warnings.append({"code": "EMPTY_ASSERTION_OBJECT", **assertion_prefix})

    if manifest.get("candidate_count") != len(candidates):
        errors.append(
            {"code": "COUNT_MISMATCH", "manifest": manifest.get("candidate_count"), "actual": len(candidates)}
        )
    stats = {"candidate_count": len(candidates), "record_type_counts": counts, "manifest": manifest}
    return CandidateBundleValidation(not errors, errors, warnings, stats)
