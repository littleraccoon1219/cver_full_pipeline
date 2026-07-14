from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from .schema import FORMAL_TABLES, SCHEMA_VERSION, connect, init_trusted_kb


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode('utf-8')).hexdigest()


def seed_actor(db_path: str | Path, actor_id: str, display_name: str, actor_type: str = 'human') -> None:
    now = _now_iso()
    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO kb_actors(actor_id, actor_type, display_name, metadata_json, active, created_at, updated_at)
            VALUES(?,?,?,'{}',1,?,?)
            ON CONFLICT(actor_id) DO UPDATE SET
                actor_type=excluded.actor_type,
                display_name=excluded.display_name,
                active=1,
                updated_at=excluded.updated_at
            """,
            (actor_id, actor_type, display_name, now, now),
        )
        connection.commit()


def seed_root_cause_taxonomy(
    db_path: str | Path,
    taxonomy_path: str | Path,
    created_by: str | None = None,
) -> dict[str, Any]:
    path = Path(taxonomy_path)
    payload = yaml.safe_load(path.read_text(encoding='utf-8'))
    taxonomy_version = str(payload['version'])
    taxonomy_name = str(payload['taxonomy_id'])
    now = _now_iso()
    content_hash = _hash(payload)
    node_count = 0
    with connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO kb_taxonomy_versions(
                taxonomy_version, name, description, status, content_hash, released_at, created_by, created_at
            ) VALUES(?,?,?,?,?,?,?,?)
            ON CONFLICT(taxonomy_version) DO UPDATE SET
                name=excluded.name,
                description=excluded.description,
                content_hash=excluded.content_hash,
                status=excluded.status
            """,
            (
                taxonomy_version,
                taxonomy_name,
                'Container-security root-cause taxonomy used by the formal trusted KB.',
                'active',
                content_hash,
                now,
                created_by,
                now,
            ),
        )
        for parent_order, category in enumerate(payload.get('categories') or [], start=1):
            parent_code = str(category['code'])
            parent_id = f"TAX-{taxonomy_version}-{parent_code}"
            connection.execute(
                """
                INSERT INTO kb_taxonomy_nodes(
                    taxonomy_node_id, taxonomy_version, taxonomy_name, code, node_type,
                    parent_node_id, level, name_en, name_zh, definition_zh,
                    inclusion_json, exclusion_json, status, sort_order, metadata_json
                ) VALUES(?,?,?,?,?,NULL,1,?,?,?,?,?,'active',?,'{}')
                ON CONFLICT(taxonomy_node_id) DO UPDATE SET
                    name_en=excluded.name_en,
                    name_zh=excluded.name_zh,
                    definition_zh=excluded.definition_zh,
                    sort_order=excluded.sort_order
                """,
                (
                    parent_id,
                    taxonomy_version,
                    taxonomy_name,
                    parent_code,
                    'root_cause_l1',
                    category['name_en'],
                    category.get('name_zh'),
                    category.get('definition'),
                    '[]',
                    '[]',
                    parent_order,
                ),
            )
            node_count += 1
            for child_order, child in enumerate(category.get('children') or [], start=1):
                child_code = str(child['code'])
                child_id = f"TAX-{taxonomy_version}-{child_code}"
                connection.execute(
                    """
                    INSERT INTO kb_taxonomy_nodes(
                        taxonomy_node_id, taxonomy_version, taxonomy_name, code, node_type,
                        parent_node_id, level, name_en, name_zh, definition_zh,
                        inclusion_json, exclusion_json, status, sort_order, metadata_json
                    ) VALUES(?,?,?,?,?,?,2,?,?,?,?,?,'active',?,'{}')
                    ON CONFLICT(taxonomy_node_id) DO UPDATE SET
                        parent_node_id=excluded.parent_node_id,
                        name_en=excluded.name_en,
                        name_zh=excluded.name_zh,
                        definition_zh=excluded.definition_zh,
                        inclusion_json=excluded.inclusion_json,
                        exclusion_json=excluded.exclusion_json,
                        sort_order=excluded.sort_order
                    """,
                    (
                        child_id,
                        taxonomy_version,
                        taxonomy_name,
                        child_code,
                        'root_cause_l2',
                        parent_id,
                        child['name_en'],
                        child.get('name_zh'),
                        child.get('definition'),
                        _canonical_json(child.get('include') or []),
                        _canonical_json(child.get('exclude') or []),
                        parent_order * 100 + child_order,
                    ),
                )
                node_count += 1
        connection.commit()
    return {
        'taxonomy_version': taxonomy_version,
        'taxonomy_name': taxonomy_name,
        'content_hash': content_hash,
        'nodes': node_count,
    }


def schema_report(db_path: str | Path) -> dict[str, Any]:
    init_trusted_kb(db_path, _now_iso())
    with connect(db_path) as connection:
        objects = connection.execute(
            """
            SELECT type, name FROM sqlite_master
            WHERE name LIKE 'kb_%' AND type IN ('table','view','trigger')
            ORDER BY type, name
            """
        ).fetchall()
        tables = [row['name'] for row in objects if row['type'] == 'table']
        views = [row['name'] for row in objects if row['type'] == 'view']
        triggers = [row['name'] for row in objects if row['type'] == 'trigger']
        row_counts = {}
        for table in FORMAL_TABLES:
            if table in tables:
                row_counts[table] = connection.execute(f'SELECT COUNT(*) AS n FROM {table}').fetchone()['n']
        foreign_key_errors = [dict(row) for row in connection.execute('PRAGMA foreign_key_check').fetchall()]
        migration_versions = [
            dict(row)
            for row in connection.execute(
                'SELECT * FROM kb_schema_migrations ORDER BY applied_at, version'
            ).fetchall()
        ]
    return {
        'schema_version': SCHEMA_VERSION,
        'expected_table_count': len(FORMAL_TABLES),
        'present_formal_table_count': len(set(tables) & set(FORMAL_TABLES)),
        'missing_tables': sorted(set(FORMAL_TABLES) - set(tables)),
        'extra_kb_tables': sorted(set(tables) - set(FORMAL_TABLES)),
        'views': views,
        'triggers': triggers,
        'foreign_key_errors': foreign_key_errors,
        'migrations': migration_versions,
        'row_counts': row_counts,
    }
