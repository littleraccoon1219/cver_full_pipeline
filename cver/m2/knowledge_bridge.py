from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


class M2CandidateBundleExporter:
    """Exports M2 candidates into the formal trusted-KB Candidate pipeline.

    This class never inserts directly into trusted_knowledge.db and never assigns a
    root cause or Gold status. Restricted trigger bytes remain in the encrypted vault;
    the bundle contains hashes and redacted experiment metadata only.
    """

    def export(
        self,
        candidates: Iterable[dict[str, Any]],
        *,
        output_dir: str | Path,
        query_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            from cver.knowledge.collectors.common import CandidateBundleBuilder
        except ImportError as exc:  # pragma: no cover - only the M2 overlay lacks the full repository
            raise RuntimeError("formal CandidateBundleBuilder is unavailable in this checkout") from exc

        builder = CandidateBundleBuilder(
            output_dir,
            "cver-m2-kata-real-fuzz",
            "2.0.0",
            "CVER M2 source-pinned experiment",
            query_config or {},
        )
        for candidate in candidates:
            redacted = self._redact(candidate)
            external_id = str(candidate.get("candidate_id"))
            raw = (json.dumps(redacted, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            snapshot = builder.store_raw(external_id, raw, suffix=".json", media_type="application/json")
            evidence_hashes = sorted(
                item.get("sha256")
                for item in candidate.get("evidence", [])
                if item.get("sha256")
            )
            summary = (
                f"{candidate.get('level')} from source-pinned kata-agent handler "
                f"{candidate.get('handler_id')} on Kata {candidate.get('kata_version')}; "
                f"reproductions={candidate.get('reproductions', 0)}."
            )
            builder.add_candidate(
                {
                    "record_type": "vulnerability",
                    "external_id": external_id,
                    "title_en": str(candidate.get("title") or external_id),
                    "summary_en": summary,
                    "technology_bucket_candidate": "kata-agent",
                    "candidate_source": "CVER M2 source-pinned experiment",
                    "attributes": {
                        "candidate_level": candidate.get("level"),
                        "component": candidate.get("component"),
                        "kata_version": candidate.get("kata_version"),
                        "source_track": candidate.get("source_track"),
                        "source_commit": candidate.get("source_commit"),
                        "adapter_id": candidate.get("adapter_id"),
                        "handler_id": candidate.get("handler_id"),
                        "finding_type": candidate.get("finding_type"),
                        "reproductions": candidate.get("reproductions", 0),
                        "evidence_hashes": evidence_hashes,
                        "experiment_only": True,
                        "restricted_trigger_material_in_bundle": False,
                        "review_notice": (
                            "This is an experiment Candidate. Human root-cause annotation, independent "
                            "source review, version-range review and Gold admission are still required."
                        ),
                    },
                    "source": {
                        "source_key": f"CVER-M2:{external_id}",
                        "name": f"CVER M2 experiment for {external_id}",
                        "source_type": "experiment",
                        "authority_level": "E3",
                        "url": None,
                        "publisher": "CVER authorized research lab",
                        "license_name": "local research evidence",
                    },
                    "snapshot": snapshot,
                    "evidence": {
                        "locator": "$.status_reason",
                        "excerpt": str(candidate.get("status_reason") or summary)[:2000],
                        "language": "en",
                        "evidence_level": "E3",
                        "fragment_type": "json",
                    },
                    "assertions": [
                        {
                            "predicate": "candidate_level",
                            "object": candidate.get("level"),
                            "verification_status": "moderate",
                        },
                        {
                            "predicate": "handler_id",
                            "object": candidate.get("handler_id"),
                            "verification_status": "moderate",
                        },
                        {
                            "predicate": "source_commit",
                            "object": candidate.get("source_commit"),
                            "verification_status": "moderate",
                        },
                        {
                            "predicate": "reproduction_count",
                            "object": candidate.get("reproductions", 0),
                            "verification_status": "moderate",
                        },
                        {
                            "predicate": "evidence_hashes",
                            "object": evidence_hashes,
                            "verification_status": "moderate",
                        },
                    ],
                }
            )
        manifest = builder.finalize()
        manifest["admission_policy"] = {
            "direct_trusted_db_write": False,
            "automatic_root_cause": False,
            "automatic_gold": False,
            "restricted_trigger_material": "encrypted_vault_only",
        }
        manifest_path = Path(output_dir) / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {"manifest_path": str(manifest_path), **manifest}

    @staticmethod
    def _redact(candidate: dict[str, Any]) -> dict[str, Any]:
        payload = copy.deepcopy(candidate)
        for evidence in payload.get("evidence", []):
            if evidence.get("restricted"):
                evidence.pop("artifact_path", None)
                evidence.pop("content", None)
        metadata = payload.get("metadata") or {}
        metadata.pop("raw_input", None)
        metadata.pop("full_call_path", None)
        payload["metadata"] = metadata
        payload["bundle_payload_sha256"] = hashlib.sha256(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return payload
