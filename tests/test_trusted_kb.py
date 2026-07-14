from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from cver.knowledge import (
    Assertion,
    EnvironmentProfile,
    EvidenceFragment,
    EvidenceLevel,
    GoldAdmissionValidator,
    KnowledgeRecord,
    RecordStatus,
    RecordType,
    RuleDefinition,
    Source,
    TrustedKnowledgeRepository,
    VerificationStatus,
)
from cver.knowledge.migration import import_legacy_seed
from cver.knowledge.rules import evaluate_expression, version_in_range
from cver.knowledge.schema import connect
from cver.knowledge.taxonomy import load_taxonomy


class TrustedKnowledgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "trusted.db"
        self.repo = TrustedKnowledgeRepository(self.db_path)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_schema_created(self) -> None:
        with connect(self.db_path) as connection:
            names = {
                row["name"]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
        self.assertIn("kb_records", names)
        self.assertIn("kb_assertions", names)
        self.assertIn("kb_rule_evaluations", names)

    def test_record_revision_is_preserved(self) -> None:
        record = KnowledgeRecord(
            record_id="REC-1",
            record_type=RecordType.VULNERABILITY,
            external_id="CVE-TEST-1",
            title_en="Initial title",
        )
        self.repo.upsert_record(record, changed_by="tester", change_reason="initial import")
        record.title_en = "Corrected title"
        self.repo.upsert_record(record, changed_by="tester", change_reason="evidence correction")
        with connect(self.db_path) as connection:
            revisions = connection.execute(
                "SELECT * FROM kb_record_revisions WHERE record_id='REC-1'"
            ).fetchall()
        self.assertEqual(1, len(revisions))
        self.assertEqual("evidence correction", revisions[0]["change_reason"])

    def test_three_valued_rule_evaluation(self) -> None:
        expression = {
            "logic": "and",
            "conditions": [
                {"fact": "runtime.runc.version", "operator": "version_in_range", "value": ">=1.0.0,<1.1.12"},
                {"fact": "container.privileged", "operator": "equals", "value": True},
                {"fact": "kernel.CONFIG_USER_NS", "operator": "kernel_config_enabled", "value": True},
            ],
        }
        result, _ = evaluate_expression(
            expression,
            {"runtime": {"runc": {"version": "1.1.10"}}, "container": {"privileged": True}},
        )
        self.assertEqual("unknown", result.value)

    def test_version_range(self) -> None:
        self.assertTrue(version_in_range("1.1.10", ">=1.0.0,<1.1.12"))
        self.assertFalse(version_in_range("1.1.12", ">=1.0.0,<1.1.12"))
        self.assertTrue(version_in_range("6.8.0-134", ">=5.15,<6.9"))

    def test_repository_rule_execution(self) -> None:
        record = KnowledgeRecord(
            record_id="REC-RULE",
            record_type=RecordType.VULNERABILITY,
            external_id="CVE-TEST-RULE",
            title_en="Rule test",
            status=RecordStatus.ANNOTATED,
            root_cause_l1="RC-1",
            root_cause_l2="RC-1.5",
            root_cause_confidence=VerificationStatus.STRONG,
        )
        self.repo.upsert_record(record, "tester", "create")
        self.repo.upsert_environment(
            EnvironmentProfile(
                environment_id="ENV-1",
                name="vulnerable-runc",
                architecture="aarch64",
                runtime="runc",
                facts={"runtime": {"runc": {"version": "1.1.10"}}},
            )
        )
        self.repo.add_rule(
            RuleDefinition(
                rule_id="RULE-1",
                record_id="REC-RULE",
                version="1.0.0",
                expression={"fact": "runtime.runc.version", "operator": "version_in_range", "value": "<1.1.12"},
            )
        )
        result = self.repo.evaluate("RULE-1", "1.0.0", "ENV-1")
        self.assertEqual("true", result["result"])
        self.assertTrue(result["input_hash"])

    def test_gold_validator_for_vulnerability(self) -> None:
        bundle = {
            "record": {
                "record_type": "vulnerability",
                "root_cause_l1": "RC-1",
                "root_cause_l2": "RC-1.5",
                "root_cause_confidence": "verified",
                "generated_by_model": False,
            },
            "sources": [
                {"authority_level": "E0", "source_type": "official_advisory"},
                {"authority_level": "E0", "source_type": "patch"},
                {"authority_level": "E2", "source_type": "peer_reviewed_paper"},
            ],
            "assertions": [
                {"predicate": "affected_versions", "evidence_ids": ["EV-1"]},
                {"predicate": "fixed_versions", "evidence_ids": ["EV-2"]},
                {"predicate": "root_cause", "evidence_ids": ["EV-3"]},
            ],
            "experiments": [{"experiment_id": "EXP-1", "validation_level": "L1", "outcome": "confirmed"}],
            "unresolved_conflicts": [],
        }
        report = GoldAdmissionValidator().validate(bundle)
        self.assertTrue(report.eligible, report.to_dict())

    def test_evidence_chain_foreign_keys(self) -> None:
        record = KnowledgeRecord(
            record_id="REC-EV",
            record_type=RecordType.VULNERABILITY,
            external_id="CVE-TEST-EV",
            title_en="Evidence test",
        )
        self.repo.upsert_record(record, "tester", "create")
        self.repo.add_source(Source("SRC-1", "Vendor", "official_advisory", EvidenceLevel.E0_PRIMARY))
        content_hash = hashlib.sha256(b"snapshot").hexdigest()
        self.repo.add_source_snapshot("SNAP-1", "SRC-1", content_hash, "data/raw/vendor/test.html")
        self.repo.add_evidence(
            EvidenceFragment(
                evidence_id="EV-1",
                source_id="SRC-1",
                snapshot_id="SNAP-1",
                locator="section affected versions",
                excerpt="Versions before 1.2.3 are affected.",
                evidence_level=EvidenceLevel.E0_PRIMARY,
                content_hash=hashlib.sha256(b"fragment").hexdigest(),
            )
        )
        self.repo.add_assertion(
            Assertion(
                assertion_id="AST-1",
                record_id="REC-EV",
                predicate="affected_versions",
                object_value="<1.2.3",
                evidence_ids=["EV-1"],
                verification_status=VerificationStatus.VERIFIED,
                asserted_by="tester",
            )
        )
        bundle = self.repo.get_gold_bundle("REC-EV")
        self.assertEqual(["EV-1"], bundle["assertions"][0]["evidence_ids"])


    def test_legacy_migration_never_promotes_unverified_labels(self) -> None:
        source = Path(self.tmp.name) / "legacy.json"
        source.write_text(
            '{"records":[{"facts":{"cve_id":"CVE-TEST-LEGACY","title":"Legacy"},"semantic_annotations":{"root_cause":"runtime_isolation","fine_type":"escape"}}]}',
            encoding="utf-8",
        )
        result = import_legacy_seed(source, self.db_path, "tester")
        self.assertEqual(1, result["imported_candidates"])
        with connect(self.db_path) as connection:
            row = connection.execute("SELECT * FROM kb_records WHERE external_id='CVE-TEST-LEGACY'").fetchone()
        self.assertEqual("candidate", row["status"])
        self.assertEqual("", row["root_cause_l1"])
        self.assertEqual("", row["root_cause_l2"])

    def test_taxonomy_is_valid(self) -> None:
        taxonomy_path = Path(__file__).resolve().parents[1] / "taxonomy" / "root_causes.yaml"
        payload = load_taxonomy(taxonomy_path)
        self.assertEqual(5, len(payload["categories"]))


if __name__ == "__main__":
    unittest.main()
