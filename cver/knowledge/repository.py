from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import Assertion, EnvironmentProfile, EvidenceFragment, KnowledgeRecord, RuleDefinition, Source
from .rules import evaluate_rule
from .schema import connect, init_trusted_kb


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


class TrustedKnowledgeRepository:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        init_trusted_kb(self.db_path, _now_iso())

    def upsert_record(self, record: KnowledgeRecord, changed_by: str, change_reason: str) -> None:
        payload = record.to_dict()
        content_hash = _hash(payload)
        now = _now_iso()
        with connect(self.db_path) as connection:
            current = connection.execute(
                "SELECT * FROM kb_records WHERE record_id=?", (record.record_id,)
            ).fetchone()
            if current and current["content_hash"] == content_hash:
                return
            if current:
                revision_no = connection.execute(
                    "SELECT COALESCE(MAX(revision_no), 0) + 1 AS next_no FROM kb_record_revisions WHERE record_id=?",
                    (record.record_id,),
                ).fetchone()["next_no"]
                snapshot = dict(current)
                connection.execute(
                    """
                    INSERT INTO kb_record_revisions(
                        record_id, revision_no, content_hash, snapshot_json, changed_by, change_reason, created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        record.record_id,
                        revision_no,
                        current["content_hash"],
                        _json(snapshot),
                        changed_by,
                        change_reason,
                        now,
                    ),
                )
                created_at = current["created_at"]
            else:
                created_at = now

            connection.execute(
                """
                INSERT INTO kb_records(
                    record_id, record_type, external_id, title_en, title_zh, status,
                    root_cause_l1, root_cause_l2, root_cause_confidence,
                    summary_en, summary_zh, attributes_json, content_hash, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(record_id) DO UPDATE SET
                    record_type=excluded.record_type,
                    external_id=excluded.external_id,
                    title_en=excluded.title_en,
                    title_zh=excluded.title_zh,
                    status=excluded.status,
                    root_cause_l1=excluded.root_cause_l1,
                    root_cause_l2=excluded.root_cause_l2,
                    root_cause_confidence=excluded.root_cause_confidence,
                    summary_en=excluded.summary_en,
                    summary_zh=excluded.summary_zh,
                    attributes_json=excluded.attributes_json,
                    content_hash=excluded.content_hash,
                    updated_at=excluded.updated_at
                """,
                (
                    record.record_id,
                    record.record_type.value,
                    record.external_id,
                    record.title_en,
                    record.title_zh,
                    record.status.value,
                    record.root_cause_l1,
                    record.root_cause_l2,
                    record.root_cause_confidence.value,
                    record.summary_en,
                    record.summary_zh,
                    _json(record.attributes),
                    content_hash,
                    created_at,
                    now,
                ),
            )
            connection.commit()

    def add_source(self, source: Source) -> None:
        payload = source.to_dict()
        now = _now_iso()
        with connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO kb_sources(
                    source_id, name, source_type, authority_level, url, publisher,
                    license_name, retrieved_at, metadata_json, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(source_id) DO UPDATE SET
                    name=excluded.name,
                    source_type=excluded.source_type,
                    authority_level=excluded.authority_level,
                    url=excluded.url,
                    publisher=excluded.publisher,
                    license_name=excluded.license_name,
                    retrieved_at=excluded.retrieved_at,
                    metadata_json=excluded.metadata_json,
                    updated_at=excluded.updated_at
                """,
                (
                    source.source_id,
                    source.name,
                    source.source_type,
                    source.authority_level.value,
                    source.url,
                    source.publisher,
                    source.license_name,
                    source.retrieved_at,
                    _json(source.metadata),
                    now,
                    now,
                ),
            )
            connection.commit()

    def add_source_snapshot(
        self,
        snapshot_id: str,
        source_id: str,
        content_hash: str,
        storage_path: str,
        media_type: str = "text/html",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO kb_source_snapshots(
                    snapshot_id, source_id, content_hash, storage_path, media_type, captured_at, metadata_json
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (snapshot_id, source_id, content_hash, storage_path, media_type, _now_iso(), _json(metadata or {})),
            )
            connection.commit()

    def add_evidence(self, evidence: EvidenceFragment) -> None:
        with connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO kb_evidence_fragments(
                    evidence_id, source_id, snapshot_id, locator, excerpt, evidence_level,
                    content_hash, language, metadata_json, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    evidence.evidence_id,
                    evidence.source_id,
                    evidence.snapshot_id,
                    evidence.locator,
                    evidence.excerpt,
                    evidence.evidence_level.value,
                    evidence.content_hash,
                    evidence.language,
                    _json(evidence.metadata),
                    _now_iso(),
                ),
            )
            connection.commit()

    def add_assertion(self, assertion: Assertion) -> None:
        now = _now_iso()
        with connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO kb_assertions(
                    assertion_id, record_id, predicate, object_json, verification_status,
                    asserted_by, notes, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(assertion_id) DO UPDATE SET
                    predicate=excluded.predicate,
                    object_json=excluded.object_json,
                    verification_status=excluded.verification_status,
                    asserted_by=excluded.asserted_by,
                    notes=excluded.notes,
                    updated_at=excluded.updated_at
                """,
                (
                    assertion.assertion_id,
                    assertion.record_id,
                    assertion.predicate,
                    _json(assertion.object_value),
                    assertion.verification_status.value,
                    assertion.asserted_by,
                    assertion.notes,
                    now,
                    now,
                ),
            )
            connection.execute("DELETE FROM kb_assertion_evidence WHERE assertion_id=?", (assertion.assertion_id,))
            for evidence_id in sorted(set(assertion.evidence_ids)):
                connection.execute(
                    "INSERT INTO kb_assertion_evidence(assertion_id, evidence_id) VALUES(?,?)",
                    (assertion.assertion_id, evidence_id),
                )
            connection.commit()

    def upsert_environment(self, environment: EnvironmentProfile) -> None:
        now = _now_iso()
        payload = {
            "name": environment.name,
            "architecture": environment.architecture,
            "runtime": environment.runtime,
            "description": environment.description,
            "facts": environment.facts,
            "metadata": environment.metadata,
        }
        with connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO kb_environments(
                    environment_id, name, architecture, runtime, description,
                    facts_json, metadata_json, content_hash, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(environment_id) DO UPDATE SET
                    name=excluded.name,
                    architecture=excluded.architecture,
                    runtime=excluded.runtime,
                    description=excluded.description,
                    facts_json=excluded.facts_json,
                    metadata_json=excluded.metadata_json,
                    content_hash=excluded.content_hash,
                    updated_at=excluded.updated_at
                """,
                (
                    environment.environment_id,
                    environment.name,
                    environment.architecture,
                    environment.runtime,
                    environment.description,
                    _json(environment.facts),
                    _json(environment.metadata),
                    _hash(payload),
                    now,
                    now,
                ),
            )
            connection.commit()

    def add_rule(self, rule: RuleDefinition) -> None:
        payload = {
            "rule_id": rule.rule_id,
            "record_id": rule.record_id,
            "version": rule.version,
            "expression": rule.expression,
            "evidence_ids": rule.evidence_ids,
            "description_zh": rule.description_zh,
            "description_en": rule.description_en,
        }
        with connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO kb_rules(
                    rule_id, version, record_id, expression_json, evidence_ids_json,
                    description_zh, description_en, content_hash, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    rule.rule_id,
                    rule.version,
                    rule.record_id,
                    _json(rule.expression),
                    _json(rule.evidence_ids),
                    rule.description_zh,
                    rule.description_en,
                    _hash(payload),
                    _now_iso(),
                ),
            )
            connection.commit()

    def evaluate(self, rule_id: str, version: str, environment_id: str) -> dict[str, Any]:
        with connect(self.db_path) as connection:
            rule_row = connection.execute(
                "SELECT * FROM kb_rules WHERE rule_id=? AND version=?", (rule_id, version)
            ).fetchone()
            env_row = connection.execute(
                "SELECT * FROM kb_environments WHERE environment_id=?", (environment_id,)
            ).fetchone()
            if not rule_row:
                raise KeyError(f"rule not found: {rule_id}@{version}")
            if not env_row:
                raise KeyError(f"environment not found: {environment_id}")

            result = evaluate_rule(
                rule_id=rule_id,
                environment_id=environment_id,
                expression=json.loads(rule_row["expression_json"]),
                facts=json.loads(env_row["facts_json"]),
            )
            evaluation_id = hashlib.sha256(
                f"{rule_id}:{version}:{environment_id}:{result.input_hash}".encode("utf-8")
            ).hexdigest()[:24]
            connection.execute(
                """
                INSERT OR REPLACE INTO kb_rule_evaluations(
                    evaluation_id, rule_id, rule_version, environment_id, result,
                    trace_json, evaluator_version, input_hash, evaluated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    evaluation_id,
                    rule_id,
                    version,
                    environment_id,
                    result.result.value,
                    _json(result.trace),
                    result.evaluator_version,
                    result.input_hash,
                    _now_iso(),
                ),
            )
            connection.commit()
            return {
                "evaluation_id": evaluation_id,
                "rule_id": rule_id,
                "rule_version": version,
                "environment_id": environment_id,
                "result": result.result.value,
                "trace": result.trace,
                "evaluator_version": result.evaluator_version,
                "input_hash": result.input_hash,
            }

    def get_gold_bundle(self, record_id: str) -> dict[str, Any]:
        with connect(self.db_path) as connection:
            record = connection.execute("SELECT * FROM kb_records WHERE record_id=?", (record_id,)).fetchone()
            if not record:
                raise KeyError(record_id)
            assertions = connection.execute(
                "SELECT * FROM kb_assertions WHERE record_id=? ORDER BY predicate", (record_id,)
            ).fetchall()
            source_rows = connection.execute(
                """
                SELECT DISTINCT s.*
                FROM kb_sources s
                JOIN kb_evidence_fragments e ON e.source_id=s.source_id
                JOIN kb_assertion_evidence ae ON ae.evidence_id=e.evidence_id
                JOIN kb_assertions a ON a.assertion_id=ae.assertion_id
                WHERE a.record_id=?
                """,
                (record_id,),
            ).fetchall()
            experiments = connection.execute(
                "SELECT * FROM kb_experiments WHERE record_id=?", (record_id,)
            ).fetchall()

        record_dict = dict(record)
        record_dict["attributes"] = json.loads(record_dict.pop("attributes_json"))
        assertion_dicts = []
        for row in assertions:
            item = dict(row)
            item["object_value"] = json.loads(item.pop("object_json"))
            with connect(self.db_path) as connection:
                item["evidence_ids"] = [
                    evidence_row["evidence_id"]
                    for evidence_row in connection.execute(
                        "SELECT evidence_id FROM kb_assertion_evidence WHERE assertion_id=?",
                        (item["assertion_id"],),
                    ).fetchall()
                ]
            assertion_dicts.append(item)
        sources = []
        for row in source_rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            sources.append(item)
        return {
            "record": record_dict,
            "sources": sources,
            "assertions": assertion_dicts,
            "experiments": [dict(row) for row in experiments],
            "unresolved_conflicts": [],
        }
