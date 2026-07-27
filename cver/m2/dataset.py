from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


VALID_LAYERS = {"public_vulnerability", "hard_negative", "controlled_synthetic", "fuzz_candidate"}


def _date(value: Any) -> datetime:
    text = str(value or "1970-01-01")[:10]
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return datetime(1970, 1, 1)


def group_key(record: dict[str, Any]) -> str:
    if record.get("cve_id"):
        return f"cve:{record['cve_id']}"
    if record.get("fix_commit"):
        return f"commit:{record['fix_commit']}"
    if record.get("crash_cluster"):
        return f"crash:{record['crash_cluster']}"
    fields = {
        "component": record.get("component"),
        "handler": record.get("handler_id"),
        "source_commit": record.get("source_commit"),
        "label": record.get("label"),
    }
    return "derived:" + hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:24]


class DatasetBuilder:
    """Builds time-aware, group-isolated paper splits with explicit leakage audits."""

    def validate(self, records: Iterable[dict[str, Any]]) -> dict[str, Any]:
        errors = []
        values = list(records)
        for index, record in enumerate(values):
            layer = record.get("dataset_layer")
            if layer not in VALID_LAYERS:
                errors.append({"index": index, "field": "dataset_layer", "value": layer})
            if not record.get("record_id"):
                errors.append({"index": index, "field": "record_id", "value": None})
            if not record.get("label"):
                errors.append({"index": index, "field": "label", "value": None})
        return {"valid": not errors, "record_count": len(values), "errors": errors}

    def split(
        self,
        records: Iterable[dict[str, Any]],
        *,
        train_ratio: float = 0.70,
        validation_ratio: float = 0.15,
    ) -> dict[str, Any]:
        values = list(records)
        validation = self.validate(values)
        if not validation["valid"]:
            raise ValueError(f"dataset validation failed: {validation['errors'][:5]}")
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in values:
            groups[group_key(record)].append(record)
        ordered = sorted(
            groups.items(),
            key=lambda item: min(_date(record.get("published_at")) for record in item[1]),
        )
        total = len(values)
        train_target = total * train_ratio
        validation_target = total * (train_ratio + validation_ratio)
        assignments: dict[str, str] = {}
        count = 0
        for key, items in ordered:
            if count < train_target:
                split = "train"
            elif count < validation_target:
                split = "validation"
            else:
                split = "test"
            assignments[key] = split
            count += len(items)
        output = {"train": [], "validation": [], "test": []}
        for key, items in ordered:
            for record in items:
                enriched = dict(record)
                enriched["split_group"] = key
                enriched["split"] = assignments[key]
                output[assignments[key]].append(enriched)
        audit = self.leakage_audit(output)
        summary = {
            split: {
                "records": len(items),
                "groups": len({item["split_group"] for item in items}),
                "layers": dict(Counter(item["dataset_layer"] for item in items)),
                "labels": dict(Counter(str(item["label"]) for item in items)),
                "versions": sorted({str(item.get("kata_version")) for item in items if item.get("kata_version")}),
                "handlers": sorted({str(item.get("handler_id")) for item in items if item.get("handler_id")}),
            }
            for split, items in output.items()
        }
        return {
            "schema_version": 1,
            "strategy": "time_ordered_group_isolated",
            "splits": output,
            "summary": summary,
            "leakage_audit": audit,
            "reporting_policy": "real vulnerabilities and controlled synthetic samples must be reported separately",
        }

    @staticmethod
    def leakage_audit(splits: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        seen: dict[str, str] = {}
        leaks = []
        derived_hashes: dict[str, str] = {}
        for split, items in splits.items():
            for record in items:
                key = str(record.get("split_group") or group_key(record))
                if key in seen and seen[key] != split:
                    leaks.append({"type": "group", "key": key, "splits": sorted({seen[key], split})})
                seen[key] = split
                payload_hash = str(record.get("source_payload_sha256") or record.get("artifact_sha256") or "")
                if payload_hash:
                    if payload_hash in derived_hashes and derived_hashes[payload_hash] != split:
                        leaks.append(
                            {
                                "type": "payload",
                                "sha256": payload_hash,
                                "splits": sorted({derived_hashes[payload_hash], split}),
                            }
                        )
                    derived_hashes[payload_hash] = split
        return {"passed": not leaks, "leak_count": len(leaks), "leaks": leaks}

    @staticmethod
    def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
        records = []
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        return records

    @staticmethod
    def write_release(payload: dict[str, Any], directory: str | Path, release_id: str) -> dict[str, Any]:
        root = Path(directory).expanduser().resolve() / release_id
        root.mkdir(parents=True, exist_ok=True)
        files = {}
        for split, records in payload["splits"].items():
            path = root / f"{split}.jsonl"
            path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records), encoding="utf-8")
            files[split] = str(path)
        manifest = {
            "schema_version": 1,
            "release_id": release_id,
            "strategy": payload["strategy"],
            "summary": payload["summary"],
            "leakage_audit": payload["leakage_audit"],
            "files": files,
        }
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"manifest_path": str(manifest_path), **manifest}
