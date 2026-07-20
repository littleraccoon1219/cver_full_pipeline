from __future__ import annotations

import hashlib
import json
import mimetypes
import re
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import ValidationError, validate

from .db import DiscoveryRepository, utc_now
from .taxonomy import TaxonomyCatalog

_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_split_group(component_id: str, external_id: str | None, title: str) -> str:
    family = f"{component_id}\0{(external_id or title).strip().lower()}"
    return "grp-" + hashlib.sha256(family.encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class CandidateArtifactInput:
    path: Path
    kind: str
    metadata: dict[str, Any] | None = None


class CandidateBundleBuilder:
    """Stages untrusted collection output without admitting it to the trusted KB.

    The builder copies raw files into a content-addressed candidate directory,
    computes hashes, creates a manifest, and stores only CANDIDATE state. Root
    cause labels are deliberately absent until a human annotation is submitted.
    """

    def __init__(
        self,
        repository: DiscoveryRepository,
        *,
        root: str | Path = "data/candidates",
    ) -> None:
        self.repository = repository
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def build(
        self,
        *,
        source_type: str,
        component_id: str,
        title: str,
        data_class: str,
        artifacts: Iterable[CandidateArtifactInput],
        external_id: str | None = None,
        source_url: str | None = None,
        discovered_at: str | None = None,
        split_group_id: str | None = None,
        source_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if data_class not in {"public", "internal", "confidential", "restricted"}:
            raise ValueError(f"unsupported data class: {data_class}")
        artifact_inputs = list(artifacts)
        if not artifact_inputs:
            raise ValueError("candidate bundle requires at least one raw artifact")

        prepared: list[dict[str, Any]] = []
        aggregate = hashlib.sha256()
        for item in artifact_inputs:
            source = item.path.expanduser().resolve()
            if not source.is_file():
                raise FileNotFoundError(source)
            digest = sha256_file(source)
            aggregate.update(item.kind.encode())
            aggregate.update(digest.encode())
            prepared.append(
                {
                    "source": source,
                    "kind": item.kind,
                    "sha256": digest,
                    "size_bytes": source.stat().st_size,
                    "mime_type": mimetypes.guess_type(source.name)[0] or "application/octet-stream",
                    "metadata": item.metadata or {},
                }
            )
        content_sha256 = aggregate.hexdigest()
        split_group = split_group_id or stable_split_group(component_id, external_id, title)
        manifest = {
            "schema_version": "1.0.0",
            "source_type": source_type,
            "component_id": component_id,
            "external_id": external_id,
            "title": title,
            "data_class": data_class,
            "source_url": source_url,
            "discovered_at": discovered_at,
            "content_sha256": content_sha256,
            "split_group_id": split_group,
            "source_metadata": source_metadata or {},
            "artifacts": [
                {key: value for key, value in item.items() if key not in {"source"}}
                | {"original_name": item["source"].name}
                for item in prepared
            ],
            "admission": {
                "status": "candidate",
                "root_cause": None,
                "generated_by_model": False,
                "requires_human_annotation": True,
            },
        }
        candidate_id = self.repository.add_candidate(
            source_type=source_type,
            component_id=component_id,
            external_id=external_id,
            title=title,
            status="candidate",
            data_class=data_class,
            source_url=source_url,
            discovered_at=discovered_at,
            content_sha256=content_sha256,
            split_group_id=split_group,
            manifest=manifest,
        )
        safe = _SAFE_ID.sub("-", candidate_id).strip("-")
        bundle_dir = self.root / safe
        raw_dir = bundle_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        for index, item in enumerate(prepared, start=1):
            destination = raw_dir / f"{index:03d}-{item['sha256'][:12]}-{item['source'].name}"
            if not destination.exists():
                shutil.copy2(item["source"], destination)
            self.repository.add_candidate_artifact(
                candidate_id,
                kind=item["kind"],
                path=str(destination),
                sha256=item["sha256"],
                size_bytes=item["size_bytes"],
                mime_type=item["mime_type"],
                metadata=item["metadata"],
            )
        manifest_path = bundle_dir / "manifest.json"
        manifest["candidate_id"] = candidate_id
        manifest["created_at"] = utc_now()
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"candidate_id": candidate_id, "manifest_path": str(manifest_path), "manifest": manifest}


class AnnotationService:
    def __init__(
        self,
        repository: DiscoveryRepository,
        catalog: TaxonomyCatalog,
        *,
        schema_path: str | Path = "schemas/discovery/annotation.schema.json",
    ) -> None:
        self.repository = repository
        self.catalog = catalog
        self.schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))

    def submit(self, candidate_id: str, payload: dict[str, Any], *, annotator: str) -> dict[str, Any]:
        if self.repository.get_candidate(candidate_id) is None:
            raise KeyError(f"candidate not found: {candidate_id}")
        payload = dict(payload)
        payload.setdefault("taxonomy_version", self.catalog.version)
        try:
            validate(instance=payload, schema=self.schema)
        except ValidationError as exc:
            path = ".".join(str(value) for value in exc.absolute_path) or "annotation"
            raise ValueError(f"annotation schema violation at {path}: {exc.message}") from exc
        if payload["taxonomy_version"] != self.catalog.version:
            raise ValueError("annotation taxonomy version does not match the active fixed taxonomy")
        evidence_ids = payload.get("evidence_ids", [])
        errors = self.catalog.validate_decision(payload, evidence_ids)
        if errors:
            raise ValueError("invalid annotation: " + "; ".join(errors))
        if not payload.get("rationale", "").strip():
            raise ValueError("human annotation requires a rationale")
        annotation_id = self.repository.add_annotation(candidate_id, payload, annotator=annotator)
        candidate_status = "human_annotated_gold" if payload.get("status") == "gold" else "human_annotated"
        self.repository.update_candidate_status(candidate_id, candidate_status)
        return {
            "annotation_id": annotation_id,
            "candidate_id": candidate_id,
            "status": payload.get("status", "draft"),
            "candidate_status": candidate_status,
        }
