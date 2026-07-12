from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = "0.1.0"

DDL = [
    """
    CREATE TABLE IF NOT EXISTS kb_schema_migrations(
        version TEXT PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_records(
        record_id TEXT PRIMARY KEY,
        record_type TEXT NOT NULL,
        external_id TEXT,
        title_en TEXT NOT NULL,
        title_zh TEXT,
        status TEXT NOT NULL,
        root_cause_l1 TEXT,
        root_cause_l2 TEXT,
        root_cause_confidence TEXT,
        summary_en TEXT,
        summary_zh TEXT,
        attributes_json TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_kb_records_external ON kb_records(record_type, external_id) WHERE external_id <> ''",
    "CREATE INDEX IF NOT EXISTS idx_kb_records_taxonomy ON kb_records(root_cause_l1, root_cause_l2)",
    """
    CREATE TABLE IF NOT EXISTS kb_record_revisions(
        revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id TEXT NOT NULL,
        revision_no INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        changed_by TEXT NOT NULL,
        change_reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(record_id, revision_no),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_sources(
        source_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        authority_level TEXT NOT NULL,
        url TEXT,
        publisher TEXT,
        license_name TEXT,
        retrieved_at TEXT,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_source_snapshots(
        snapshot_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        storage_path TEXT NOT NULL,
        media_type TEXT,
        captured_at TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        UNIQUE(source_id, content_hash),
        FOREIGN KEY(source_id) REFERENCES kb_sources(source_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_evidence_fragments(
        evidence_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        locator TEXT NOT NULL,
        excerpt TEXT NOT NULL,
        evidence_level TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        language TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(source_id) REFERENCES kb_sources(source_id),
        FOREIGN KEY(snapshot_id) REFERENCES kb_source_snapshots(snapshot_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_assertions(
        assertion_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        predicate TEXT NOT NULL,
        object_json TEXT NOT NULL,
        verification_status TEXT NOT NULL,
        asserted_by TEXT NOT NULL,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_assertion_evidence(
        assertion_id TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        PRIMARY KEY(assertion_id, evidence_id),
        FOREIGN KEY(assertion_id) REFERENCES kb_assertions(assertion_id) ON DELETE CASCADE,
        FOREIGN KEY(evidence_id) REFERENCES kb_evidence_fragments(evidence_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_environments(
        environment_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        architecture TEXT NOT NULL,
        runtime TEXT NOT NULL,
        description TEXT,
        facts_json TEXT NOT NULL,
        metadata_json TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_rules(
        rule_id TEXT NOT NULL,
        version TEXT NOT NULL,
        record_id TEXT NOT NULL,
        expression_json TEXT NOT NULL,
        evidence_ids_json TEXT NOT NULL,
        description_zh TEXT,
        description_en TEXT,
        content_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY(rule_id, version),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_rule_evaluations(
        evaluation_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        rule_version TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        result TEXT NOT NULL,
        trace_json TEXT NOT NULL,
        evaluator_version TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        evaluated_at TEXT NOT NULL,
        FOREIGN KEY(environment_id) REFERENCES kb_environments(environment_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_experiments(
        experiment_id TEXT PRIMARY KEY,
        record_id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        validation_level TEXT NOT NULL,
        outcome TEXT NOT NULL,
        protocol_version TEXT NOT NULL,
        artifacts_json TEXT NOT NULL,
        observations_json TEXT NOT NULL,
        executed_by TEXT NOT NULL,
        executed_at TEXT NOT NULL,
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id),
        FOREIGN KEY(environment_id) REFERENCES kb_environments(environment_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_dataset_releases(
        release_id TEXT PRIMARY KEY,
        schema_version TEXT NOT NULL,
        taxonomy_version TEXT NOT NULL,
        released_at TEXT NOT NULL,
        manifest_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kb_dataset_memberships(
        release_id TEXT NOT NULL,
        record_id TEXT NOT NULL,
        split_name TEXT NOT NULL,
        family_group TEXT,
        PRIMARY KEY(release_id, record_id),
        FOREIGN KEY(release_id) REFERENCES kb_dataset_releases(release_id),
        FOREIGN KEY(record_id) REFERENCES kb_records(record_id)
    )
    """,
]


@contextmanager
def connect(db_path: str | Path) -> Iterator[sqlite3.Connection]:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        yield connection
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_trusted_kb(db_path: str | Path, applied_at: str) -> None:
    with connect(db_path) as connection:
        for statement in DDL:
            connection.execute(statement)
        connection.execute(
            "INSERT OR IGNORE INTO kb_schema_migrations(version, applied_at) VALUES(?, ?)",
            (SCHEMA_VERSION, applied_at),
        )
        connection.commit()
