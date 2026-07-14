from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cver.knowledge import (
    Assertion,
    EnvironmentProfile,
    EvidenceFragment,
    EvidenceLevel,
    KnowledgeRecord,
    RecordStatus,
    RecordType,
    RuleDefinition,
    Source,
    TrustedKnowledgeRepository,
    VerificationStatus,
)
from cver.knowledge.formal_schema import schema_report, seed_actor, seed_root_cause_taxonomy
from cver.knowledge.schema import FORMAL_TABLES, connect


class FormalSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / 'formal.db'
        self.repo = TrustedKnowledgeRepository(self.db_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_all_formal_tables_and_views_exist(self) -> None:
        report = schema_report(self.db_path)
        self.assertEqual([], report['missing_tables'])
        self.assertEqual(len(FORMAL_TABLES), report['present_formal_table_count'])
        self.assertEqual([], report['foreign_key_errors'])
        self.assertIn('kb_v_gold_readiness', report['views'])
        self.assertIn('kb_v_unresolved_conflicts', report['views'])

    def test_taxonomy_is_seeded_into_relational_tables(self) -> None:
        seed_actor(self.db_path, 'researcher', 'Researcher')
        taxonomy = Path(__file__).resolve().parents[1] / 'taxonomy' / 'root_causes.yaml'
        result = seed_root_cause_taxonomy(self.db_path, taxonomy, 'researcher')
        self.assertEqual('0.1.0', result['taxonomy_version'])
        self.assertGreaterEqual(result['nodes'], 30)
        with connect(self.db_path) as connection:
            l1 = connection.execute(
                "SELECT COUNT(*) AS n FROM kb_taxonomy_nodes WHERE node_type='root_cause_l1'"
            ).fetchone()['n']
            l2 = connection.execute(
                "SELECT COUNT(*) AS n FROM kb_taxonomy_nodes WHERE node_type='root_cause_l2'"
            ).fetchone()['n']
        self.assertEqual(5, l1)
        self.assertGreaterEqual(l2, 25)

    def test_environment_upsert_creates_immutable_snapshot_and_facts(self) -> None:
        snapshot_id = self.repo.upsert_environment(
            EnvironmentProfile(
                environment_id='ENV-1',
                name='ARM64 runc vulnerable',
                architecture='aarch64',
                runtime='runc',
                facts={
                    'runtime': {'runc': {'version': '1.1.10'}},
                    'container': {'privileged': False},
                },
            )
        )
        with connect(self.db_path) as connection:
            snapshot = connection.execute(
                'SELECT * FROM kb_environment_snapshots WHERE environment_snapshot_id=?',
                (snapshot_id,),
            ).fetchone()
            fact_count = connection.execute(
                'SELECT COUNT(*) AS n FROM kb_environment_facts WHERE environment_snapshot_id=?',
                (snapshot_id,),
            ).fetchone()['n']
            self.assertIsNotNone(snapshot)
            self.assertEqual(2, fact_count)
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE kb_environment_snapshots SET manifest_json='{}' WHERE environment_snapshot_id=?",
                    (snapshot_id,),
                )

    def test_assertion_changes_create_revision(self) -> None:
        self.repo.upsert_record(
            KnowledgeRecord('REC-1', RecordType.VULNERABILITY, 'Test', external_id='CVE-TEST-1'),
            'tester',
            'create',
        )
        self.repo.add_source(Source('SRC-1', 'Vendor', 'official_advisory', EvidenceLevel.E0_PRIMARY))
        snap_hash = hashlib.sha256(b'snapshot').hexdigest()
        self.repo.add_source_snapshot('SNAP-1', 'SRC-1', snap_hash, 'raw/vendor.json')
        self.repo.add_evidence(
            EvidenceFragment(
                'EV-1', 'SRC-1', 'SNAP-1', '$.affected', 'before 1.2.3',
                EvidenceLevel.E0_PRIMARY, hashlib.sha256(b'fragment').hexdigest(),
            )
        )
        first = Assertion(
            'AST-1', 'REC-1', 'affected_versions', '<1.2.3', ['EV-1'],
            VerificationStatus.MODERATE, 'tester',
        )
        self.repo.add_assertion(first)
        corrected = Assertion(
            'AST-1', 'REC-1', 'affected_versions', '<1.2.4', ['EV-1'],
            VerificationStatus.VERIFIED, 'tester',
        )
        self.repo.add_assertion(corrected)
        with connect(self.db_path) as connection:
            count = connection.execute(
                "SELECT COUNT(*) AS n FROM kb_assertion_revisions WHERE assertion_id='AST-1'"
            ).fetchone()['n']
        self.assertEqual(1, count)

    def test_model_generated_record_cannot_be_promoted_to_gold(self) -> None:
        record = KnowledgeRecord(
            'REC-MODEL', RecordType.VULNERABILITY, 'Generated', external_id='CVE-TEST-MODEL',
            status=RecordStatus.GOLD,
            attributes={'generated_by_model': True},
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.upsert_record(record, 'model', 'attempted promotion')

    def test_rule_evaluation_has_rule_and_snapshot_provenance(self) -> None:
        self.repo.upsert_record(
            KnowledgeRecord('REC-RULE', RecordType.VULNERABILITY, 'Rule'), 'tester', 'create'
        )
        self.repo.upsert_environment(
            EnvironmentProfile(
                'ENV-RULE', 'runc', 'aarch64', 'runc',
                facts={'runtime': {'runc': {'version': '1.1.10'}}},
            )
        )
        self.repo.add_rule(
            RuleDefinition(
                'RULE-1', 'REC-RULE', '1.0.0',
                {'fact': 'runtime.runc.version', 'operator': 'version_in_range', 'value': '<1.1.12'},
            )
        )
        result = self.repo.evaluate('RULE-1', '1.0.0', 'ENV-RULE')
        self.assertEqual('true', result['result'])
        self.assertTrue(result['environment_snapshot_id'])
        with connect(self.db_path) as connection:
            row = connection.execute(
                'SELECT * FROM kb_rule_evaluations WHERE evaluation_id=?',
                (result['evaluation_id'],),
            ).fetchone()
        self.assertEqual('1.0.0', row['rule_version'])
        self.assertEqual(result['environment_snapshot_id'], row['environment_snapshot_id'])


if __name__ == '__main__':
    unittest.main()
