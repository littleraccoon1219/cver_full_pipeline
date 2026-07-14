from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .candidate_validation import validate_candidate_bundle
from .collectors.common import canonical_json, now_iso, read_jsonl, sha256_bytes, stable_id
from .schema import connect, init_trusted_kb


def import_candidate_bundle(
    *,
    db_path: str | Path,
    bundle_dir: str | Path,
    actor_id: str,
    actor_name: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    report = validate_candidate_bundle(bundle_dir)
    if not report.valid:
        return {"ok": False, "dry_run": dry_run, "validation": report.to_dict()}
    root = Path(bundle_dir).resolve()
    manifest = report.stats["manifest"]
    candidates = read_jsonl(root / "candidates.jsonl")
    if dry_run:
        return {"ok": True, "dry_run": True, "would_import": len(candidates), "validation": report.to_dict()}
    init_trusted_kb(db_path, now_iso())
    now = now_iso()
    imported = 0
    with connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO kb_actors(actor_id,actor_type,display_name,metadata_json,active,created_at,updated_at)
            VALUES(?, 'human', ?, '{}', 1, ?, ?)
            ON CONFLICT(actor_id) DO UPDATE SET display_name=excluded.display_name, active=1, updated_at=excluded.updated_at
            """,
            (actor_id, actor_name or actor_id, now, now),
        )
        run_id = str(manifest["ingestion_run_id"])
        connection.execute(
            """
            INSERT INTO kb_ingestion_runs(
              ingestion_run_id,collector_name,collector_version,source_family,query_json,
              started_at,finished_at,status,requested_by,stats_json,error_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                run_id,
                manifest["collector_name"],
                manifest["collector_version"],
                manifest["source_family"],
                canonical_json(manifest.get("query_config") or {}),
                manifest.get("created_at") or now,
                now,
                "completed",
                actor_id,
                canonical_json({"candidate_count": len(candidates)}),
                canonical_json({"error_count": manifest.get("error_count", 0)}),
            ),
        )
        for item in candidates:
            record_type = str(item["record_type"])
            external_id = str(item["external_id"])
            record_id = stable_id("REC", record_type, external_id, length=20)
            source = item["source"]
            source_id = stable_id("SRC", str(source["source_key"]), length=20)
            snapshot = item["snapshot"]
            snapshot_id = stable_id("SNAP", source_id, snapshot["sha256"], length=20)
            evidence = item["evidence"]
            evidence_id = stable_id("EV", snapshot_id, str(evidence["locator"]), length=20)
            attributes = dict(item.get("attributes") or {})
            attributes.update(
                {
                    "candidate_source": item.get("candidate_source"),
                    "technology_bucket_candidate": item.get("technology_bucket_candidate"),
                    "bundle_ingestion_run_id": run_id,
                    "raw_snapshot_relative_path": snapshot.get("relative_path"),
                }
            )
            content_hash = sha256_bytes(canonical_json(item).encode("utf-8"))
            existing_record = connection.execute(
                "SELECT record_id,status FROM kb_records WHERE record_type=? AND external_id=?",
                (record_type, external_id),
            ).fetchone()
            if existing_record:
                actual_record = existing_record["record_id"]
                if existing_record["status"] == "gold":
                    raise ValueError(f"refusing to overwrite Gold record: {external_id}")
                connection.execute(
                    """
                    UPDATE kb_records SET
                      title_en=?,title_zh=?,summary_en=?,summary_zh=?,attributes_json=?,content_hash=?,
                      status='candidate',root_cause_l1=NULL,root_cause_l2=NULL,
                      root_cause_confidence='unknown',review_status='unreviewed',generated_by_model=0,updated_at=?
                    WHERE record_id=?
                    """,
                    (
                        item.get("title_en") or external_id,
                        item.get("title_zh"),
                        item.get("summary_en"),
                        item.get("summary_zh"),
                        canonical_json(attributes),
                        content_hash,
                        now,
                        actual_record,
                    ),
                )
            else:
                actual_record = record_id
                connection.execute(
                    """
                    INSERT INTO kb_records(
                      record_id,record_type,external_id,canonical_key,title_en,title_zh,status,
                      root_cause_l1,root_cause_l2,root_cause_confidence,summary_en,summary_zh,
                      attributes_json,content_hash,schema_version,taxonomy_version,review_status,
                      generated_by_model,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,'candidate',NULL,NULL,'unknown',?,?,?,?,'1.0.0',NULL,'unreviewed',0,?,?)
                    """,
                    (
                        actual_record,
                        record_type,
                        external_id,
                        f"{record_type}:{external_id}",
                        item.get("title_en") or external_id,
                        item.get("title_zh"),
                        item.get("summary_en"),
                        item.get("summary_zh"),
                        canonical_json(attributes),
                        content_hash,
                        now,
                        now,
                    ),
                )
            connection.execute(
                """
                INSERT INTO kb_record_identifiers(identifier_id,record_id,scheme,identifier_value,is_primary,metadata_json)
                VALUES(?,?,?,?,1,'{}') ON CONFLICT(scheme,identifier_value) DO UPDATE SET record_id=excluded.record_id
                """,
                (stable_id("ID", record_type, external_id), actual_record, record_type, external_id),
            )
            connection.execute(
                """
                INSERT INTO kb_sources(source_id,name,source_type,authority_level,url,publisher,license_name,retrieved_at,metadata_json,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?, '{}',?,?)
                ON CONFLICT(source_id) DO UPDATE SET url=excluded.url,retrieved_at=excluded.retrieved_at,updated_at=excluded.updated_at
                """,
                (
                    source_id,
                    source.get("name") or source["source_key"],
                    source.get("source_type") or "unknown",
                    source.get("authority_level") or "E4",
                    source.get("url"),
                    source.get("publisher"),
                    source.get("license_name"),
                    source.get("retrieved_at") or now,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO kb_source_snapshots(snapshot_id,source_id,content_hash,storage_path,media_type,captured_at,metadata_json)
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    snapshot_id,
                    source_id,
                    snapshot["sha256"],
                    str((root / snapshot["relative_path"]).resolve()),
                    snapshot.get("media_type"),
                    now,
                    canonical_json({"bundle": str(root), "size_bytes": snapshot.get("size_bytes")}),
                ),
            )
            excerpt = str(evidence.get("excerpt") or external_id)
            evidence_hash = sha256_bytes(excerpt.encode("utf-8"))
            connection.execute(
                """
                INSERT OR IGNORE INTO kb_evidence_fragments(
                  evidence_id,source_id,snapshot_id,locator,excerpt,evidence_level,content_hash,
                  language,fragment_type,metadata_json,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,'{}',?)
                """,
                (
                    evidence_id,
                    source_id,
                    snapshot_id,
                    evidence.get("locator") or "document",
                    excerpt,
                    evidence.get("evidence_level") or source.get("authority_level") or "E4",
                    evidence_hash,
                    evidence.get("language") or "en",
                    evidence.get("fragment_type") or "text",
                    now,
                ),
            )
            for assertion in item.get("assertions") or []:
                if assertion.get("object") in (None, "", []):
                    continue
                predicate = str(assertion["predicate"])
                assertion_id = stable_id("AST", actual_record, predicate, canonical_json(assertion.get("object")), length=20)
                object_json = canonical_json(assertion.get("object"))
                connection.execute(
                    """
                    INSERT OR IGNORE INTO kb_assertions(
                      assertion_id,record_id,predicate,object_json,assertion_type,verification_status,
                      asserted_by,generated_by_model,content_hash,notes,created_at,updated_at
                    ) VALUES(?,?,?,?, 'fact',?,?,0,?,?,?,?)
                    """,
                    (
                        assertion_id,
                        actual_record,
                        predicate,
                        object_json,
                        assertion.get("verification_status", "moderate"),
                        f"system:{manifest['collector_name']}",
                        sha256_bytes(object_json.encode("utf-8")),
                        "Candidate import only; human verification required before Gold admission.",
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT OR IGNORE INTO kb_assertion_evidence(assertion_id,evidence_id,support_type) VALUES(?,?, 'supports')",
                    (assertion_id, evidence_id),
                )
            connection.execute(
                """
                INSERT INTO kb_ingestion_items(
                  ingestion_item_id,ingestion_run_id,external_key,source_id,record_id,status,reason,raw_hash,created_at,updated_at
                ) VALUES(?,?,?,?,?,'imported',?,?,?,?)
                """,
                (
                    stable_id("ITEM", run_id, record_type, external_id),
                    run_id,
                    external_id,
                    source_id,
                    actual_record,
                    "Validated Candidate bundle import",
                    snapshot["sha256"],
                    now,
                    now,
                ),
            )
            imported += 1
        connection.execute(
            "INSERT INTO kb_audit_events(occurred_at,actor_id,action,object_type,object_id,reason,metadata_json) VALUES(?,?,?,?,?,?,?)",
            (now, actor_id, "candidate_bundle_import", "ingestion_run", run_id, "Separated collection/validation/import workflow", canonical_json({"imported": imported})),
        )
        connection.commit()
    return {"ok": True, "dry_run": False, "imported": imported, "ingestion_run_id": manifest["ingestion_run_id"], "validation": report.to_dict()}
