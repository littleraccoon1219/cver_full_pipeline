from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import Assertion, EnvironmentProfile, EvidenceFragment, KnowledgeRecord, RuleDefinition, Source
from .rules import evaluate_rule
from .schema import FORMAL_TABLES, SCHEMA_VERSION, connect, init_trusted_kb


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *parts: str, length: int = 24) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}"


def _flatten_facts(value: Any, prefix: str = "") -> Iterable[tuple[str, Any, str]]:
    """Flatten an environment manifest into auditable fact_path/value rows."""
    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_facts(value[key], child)
        return
    if isinstance(value, list):
        yield prefix, value, "array"
    elif isinstance(value, bool):
        yield prefix, value, "boolean"
    elif isinstance(value, int):
        yield prefix, value, "integer"
    elif isinstance(value, float):
        yield prefix, value, "number"
    elif value is None:
        yield prefix, None, "null"
    else:
        yield prefix, str(value), "string"


class TrustedKnowledgeRepository:
    """Compatibility repository plus formal-schema provenance behavior.

    Existing MVP callers continue to use the same methods.  Each environment update also
    creates an immutable snapshot, assertions preserve revisions, rule evidence is
    normalized, and Gold bundles include real conflict/assessment/attack/repair context.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        init_trusted_kb(self.db_path, _now_iso())

    def schema_summary(self) -> dict[str, Any]:
        with connect(self.db_path) as connection:
            names = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'kb_%'"
                ).fetchall()
            }
            missing = sorted(set(FORMAL_TABLES) - names)
            fk_errors = [dict(row) for row in connection.execute("PRAGMA foreign_key_check").fetchall()]
        return {
            "schema_version": SCHEMA_VERSION,
            "expected_tables": len(FORMAL_TABLES),
            "present_tables": len(set(FORMAL_TABLES) & names),
            "missing_tables": missing,
            "foreign_key_errors": fk_errors,
        }

    def upsert_record(self, record: KnowledgeRecord, changed_by: str, change_reason: str) -> None:
        payload = record.to_dict()
        content_hash = _hash(payload)
        now = _now_iso()
        with connect(self.db_path) as connection:
            current = connection.execute("SELECT * FROM kb_records WHERE record_id=?", (record.record_id,)).fetchone()
            if current and current["content_hash"] == content_hash:
                return
            if current:
                revision_no = connection.execute(
                    "SELECT COALESCE(MAX(revision_no), 0) + 1 AS next_no FROM kb_record_revisions WHERE record_id=?",
                    (record.record_id,),
                ).fetchone()["next_no"]
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
                        _json(dict(current)),
                        changed_by,
                        change_reason,
                        now,
                    ),
                )
                created_at = current["created_at"]
            else:
                created_at = now

            generated_by_model = int(bool(record.attributes.get("generated_by_model", False)))
            canonical_key = record.attributes.get("canonical_key") or (
                f"{record.record_type.value}:{record.external_id}" if record.external_id else record.record_id
            )
            connection.execute(
                """
                INSERT INTO kb_records(
                    record_id, record_type, external_id, canonical_key, title_en, title_zh, status,
                    root_cause_l1, root_cause_l2, root_cause_confidence,
                    summary_en, summary_zh, attributes_json, content_hash, schema_version,
                    taxonomy_version, review_status, generated_by_model, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(record_id) DO UPDATE SET
                    record_type=excluded.record_type,
                    external_id=excluded.external_id,
                    canonical_key=excluded.canonical_key,
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
                    schema_version=excluded.schema_version,
                    taxonomy_version=excluded.taxonomy_version,
                    review_status=excluded.review_status,
                    generated_by_model=excluded.generated_by_model,
                    updated_at=excluded.updated_at
                """,
                (
                    record.record_id,
                    record.record_type.value,
                    record.external_id,
                    canonical_key,
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
                    SCHEMA_VERSION,
                    record.attributes.get("taxonomy_version"),
                    record.attributes.get("review_status", "unreviewed"),
                    generated_by_model,
                    created_at,
                    now,
                ),
            )
            if record.external_id:
                identifier_id = _stable_id("ID", record.record_type.value, record.external_id)
                connection.execute(
                    """
                    INSERT INTO kb_record_identifiers(
                        identifier_id, record_id, scheme, identifier_value, is_primary, metadata_json
                    ) VALUES(?,?,?,?,1,'{}')
                    ON CONFLICT(scheme, identifier_value) DO UPDATE SET record_id=excluded.record_id
                    """,
                    (identifier_id, record.record_id, record.record_type.value, record.external_id),
                )
            connection.commit()

    def add_source(self, source: Source) -> None:
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
                INSERT INTO kb_evidence_fragments(
                    evidence_id, source_id, snapshot_id, locator, excerpt, evidence_level,
                    content_hash, language, metadata_json, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(evidence_id) DO UPDATE SET
                    source_id=excluded.source_id,
                    snapshot_id=excluded.snapshot_id,
                    locator=excluded.locator,
                    excerpt=excluded.excerpt,
                    evidence_level=excluded.evidence_level,
                    content_hash=excluded.content_hash,
                    language=excluded.language,
                    metadata_json=excluded.metadata_json
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
        object_json = _json(assertion.object_value)
        payload = {
            "record_id": assertion.record_id,
            "predicate": assertion.predicate,
            "object": assertion.object_value,
            "verification_status": assertion.verification_status.value,
            "asserted_by": assertion.asserted_by,
            "notes": assertion.notes,
            "evidence_ids": sorted(set(assertion.evidence_ids)),
        }
        content_hash = _hash(payload)
        with connect(self.db_path) as connection:
            current = connection.execute(
                "SELECT * FROM kb_assertions WHERE assertion_id=?", (assertion.assertion_id,)
            ).fetchone()
            current_evidence = []
            if current:
                current_evidence = [
                    row["evidence_id"]
                    for row in connection.execute(
                        "SELECT evidence_id FROM kb_assertion_evidence WHERE assertion_id=? ORDER BY evidence_id",
                        (assertion.assertion_id,),
                    ).fetchall()
                ]
                old_hash = current["content_hash"] or _hash({**dict(current), "evidence_ids": current_evidence})
                if old_hash == content_hash:
                    return
                revision_no = connection.execute(
                    "SELECT COALESCE(MAX(revision_no),0)+1 AS n FROM kb_assertion_revisions WHERE assertion_id=?",
                    (assertion.assertion_id,),
                ).fetchone()["n"]
                connection.execute(
                    """
                    INSERT INTO kb_assertion_revisions(
                        assertion_id, revision_no, content_hash, snapshot_json, changed_by, change_reason, created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        assertion.assertion_id,
                        revision_no,
                        old_hash,
                        _json({**dict(current), "evidence_ids": current_evidence}),
                        assertion.asserted_by,
                        "assertion content or evidence changed",
                        now,
                    ),
                )
            connection.execute(
                """
                INSERT INTO kb_assertions(
                    assertion_id, record_id, predicate, object_json, verification_status,
                    asserted_by, notes, content_hash, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(assertion_id) DO UPDATE SET
                    predicate=excluded.predicate,
                    object_json=excluded.object_json,
                    verification_status=excluded.verification_status,
                    asserted_by=excluded.asserted_by,
                    notes=excluded.notes,
                    content_hash=excluded.content_hash,
                    updated_at=excluded.updated_at
                """,
                (
                    assertion.assertion_id,
                    assertion.record_id,
                    assertion.predicate,
                    object_json,
                    assertion.verification_status.value,
                    assertion.asserted_by,
                    assertion.notes,
                    content_hash,
                    now,
                    now,
                ),
            )
            connection.execute("DELETE FROM kb_assertion_evidence WHERE assertion_id=?", (assertion.assertion_id,))
            for evidence_id in sorted(set(assertion.evidence_ids)):
                connection.execute(
                    "INSERT INTO kb_assertion_evidence(assertion_id, evidence_id, support_type) VALUES(?,?,'supports')",
                    (assertion.assertion_id, evidence_id),
                )
            connection.commit()

    def upsert_environment(self, environment: EnvironmentProfile) -> str:
        now = _now_iso()
        payload = {
            "name": environment.name,
            "architecture": environment.architecture,
            "runtime": environment.runtime,
            "description": environment.description,
            "facts": environment.facts,
            "metadata": environment.metadata,
        }
        content_hash = _hash(payload)
        snapshot_id = _stable_id("ENVSNAP", environment.environment_id, content_hash)
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
                    content_hash,
                    now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO kb_environment_snapshots(
                    environment_snapshot_id, environment_id, snapshot_role, manifest_json,
                    content_hash, collector_name, collector_version, captured_at, metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    snapshot_id,
                    environment.environment_id,
                    environment.metadata.get("snapshot_role", "observed"),
                    _json(environment.facts),
                    content_hash,
                    environment.metadata.get("collector_name", "repository-upsert"),
                    environment.metadata.get("collector_version", "1.0.0"),
                    now,
                    _json(environment.metadata),
                ),
            )
            for fact_path, value, value_type in _flatten_facts(environment.facts):
                if not fact_path:
                    continue
                fact_id = _stable_id("ENVFACT", snapshot_id, fact_path)
                connection.execute(
                    """
                    INSERT OR IGNORE INTO kb_environment_facts(
                        environment_fact_id, environment_snapshot_id, fact_path, value_json,
                        value_type, truth_state, collection_method, confidence_status, observed_at, metadata_json
                    ) VALUES(?,?,?,?,?,'known',?,'verified',?,'{}')
                    """,
                    (
                        fact_id,
                        snapshot_id,
                        fact_path,
                        _json(value),
                        value_type,
                        environment.metadata.get("collection_method", "structured_import"),
                        now,
                    ),
                )
            connection.commit()
        return snapshot_id

    def add_rule(self, rule: RuleDefinition) -> None:
        payload = {
            "rule_id": rule.rule_id,
            "record_id": rule.record_id,
            "version": rule.version,
            "expression": rule.expression,
            "evidence_ids": sorted(set(rule.evidence_ids)),
            "description_zh": rule.description_zh,
            "description_en": rule.description_en,
        }
        with connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO kb_rules(
                    rule_id, version, record_id, expression_json, evidence_ids_json,
                    description_zh, description_en, content_hash, created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(rule_id, version) DO UPDATE SET
                    record_id=excluded.record_id,
                    expression_json=excluded.expression_json,
                    evidence_ids_json=excluded.evidence_ids_json,
                    description_zh=excluded.description_zh,
                    description_en=excluded.description_en,
                    content_hash=excluded.content_hash
                """,
                (
                    rule.rule_id,
                    rule.version,
                    rule.record_id,
                    _json(rule.expression),
                    _json(sorted(set(rule.evidence_ids))),
                    rule.description_zh,
                    rule.description_en,
                    _hash(payload),
                    _now_iso(),
                ),
            )
            connection.execute(
                "DELETE FROM kb_rule_evidence WHERE rule_id=? AND rule_version=?",
                (rule.rule_id, rule.version),
            )
            for evidence_id in sorted(set(rule.evidence_ids)):
                connection.execute(
                    "INSERT INTO kb_rule_evidence(rule_id, rule_version, evidence_id) VALUES(?,?,?)",
                    (rule.rule_id, rule.version, evidence_id),
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
            snapshot = connection.execute(
                """
                SELECT * FROM kb_environment_snapshots
                WHERE environment_id=? ORDER BY captured_at DESC LIMIT 1
                """,
                (environment_id,),
            ).fetchone()
            facts = json.loads(snapshot["manifest_json"] if snapshot else env_row["facts_json"])
            result = evaluate_rule(
                rule_id=rule_id,
                environment_id=environment_id,
                expression=json.loads(rule_row["expression_json"]),
                facts=facts,
            )
            snapshot_id = snapshot["environment_snapshot_id"] if snapshot else None
            evaluation_id = hashlib.sha256(
                f"{rule_id}:{version}:{environment_id}:{snapshot_id}:{result.input_hash}".encode()
            ).hexdigest()[:24]
            connection.execute(
                """
                INSERT INTO kb_rule_evaluations(
                    evaluation_id, rule_id, rule_version, environment_id, environment_snapshot_id,
                    result, trace_json, evaluator_version, input_hash, error_json, evaluated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,'{}',?)
                ON CONFLICT(evaluation_id) DO UPDATE SET
                    result=excluded.result,
                    trace_json=excluded.trace_json,
                    evaluator_version=excluded.evaluator_version,
                    input_hash=excluded.input_hash,
                    evaluated_at=excluded.evaluated_at
                """,
                (
                    evaluation_id,
                    rule_id,
                    version,
                    environment_id,
                    snapshot_id,
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
                "environment_snapshot_id": snapshot_id,
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
                "SELECT * FROM kb_experiments WHERE record_id=? ORDER BY executed_at", (record_id,)
            ).fetchall()
            conflicts = connection.execute(
                "SELECT * FROM kb_v_unresolved_conflicts WHERE record_id=?", (record_id,)
            ).fetchall()
            assessments = connection.execute(
                "SELECT * FROM kb_exploitability_assessments WHERE record_id=? ORDER BY assessed_at",
                (record_id,),
            ).fetchall()
            taxonomy = connection.execute(
                """
                SELECT a.*, n.taxonomy_name, n.code, n.name_en, n.name_zh
                FROM kb_record_taxonomy_assignments a
                JOIN kb_taxonomy_nodes n ON n.taxonomy_node_id=a.taxonomy_node_id
                WHERE a.record_id=?
                """,
                (record_id,),
            ).fetchall()
            rules = connection.execute(
                "SELECT * FROM kb_rules WHERE record_id=? ORDER BY rule_id, version", (record_id,)
            ).fetchall()
            attack_chains = connection.execute(
                """
                SELECT DISTINCT c.*
                FROM kb_attack_chains c
                JOIN kb_attack_steps s ON s.attack_chain_id=c.attack_chain_id
                JOIN kb_attack_step_records sr ON sr.attack_step_id=s.attack_step_id
                WHERE sr.record_id=?
                """,
                (record_id,),
            ).fetchall()
            mitigations = connection.execute(
                """
                SELECT DISTINCT m.*
                FROM kb_mitigations m
                JOIN kb_mitigation_targets t ON t.mitigation_id=m.mitigation_id
                WHERE t.target_type='record' AND t.target_id=?
                """,
                (record_id,),
            ).fetchall()
            retests = connection.execute(
                "SELECT * FROM kb_retest_runs WHERE record_id=? ORDER BY executed_at", (record_id,)
            ).fetchall()
            assertion_dicts = []
            for row in assertions:
                item = dict(row)
                item["object_value"] = json.loads(item.pop("object_json"))
                item["evidence_ids"] = [
                    evidence_row["evidence_id"]
                    for evidence_row in connection.execute(
                        "SELECT evidence_id FROM kb_assertion_evidence WHERE assertion_id=? ORDER BY evidence_id",
                        (item["assertion_id"],),
                    ).fetchall()
                ]
                assertion_dicts.append(item)

        record_dict = dict(record)
        record_dict["attributes"] = json.loads(record_dict.pop("attributes_json"))
        sources = []
        for row in source_rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            sources.append(item)
        return {
            "record": record_dict,
            "sources": sources,
            "assertions": assertion_dicts,
            "taxonomy_assignments": [dict(row) for row in taxonomy],
            "rules": [dict(row) for row in rules],
            "experiments": [dict(row) for row in experiments],
            "assessments": [dict(row) for row in assessments],
            "attack_chains": [dict(row) for row in attack_chains],
            "mitigations": [dict(row) for row in mitigations],
            "retests": [dict(row) for row in retests],
            "unresolved_conflicts": [dict(row) for row in conflicts],
        }
