from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from cver.knowledge.candidate_importer import import_candidate_bundle
from cver.knowledge.candidate_validation import validate_candidate_bundle
from cver.knowledge.collectors.common import CandidateBundleBuilder
from cver.knowledge.collectors.nvd import date_chunks, stratified_date_chunks
from cver.knowledge.validation import GoldAdmissionValidator


class CandidatePipelineTests(unittest.TestCase):
    def _bundle(self, root: Path) -> Path:
        bundle = root / "bundle"
        builder = CandidateBundleBuilder(bundle, "unit-test", "1.0.0", "test")
        raw = builder.store_raw(
            "CVE-2024-21626", b'{"id":"CVE-2024-21626"}\n', suffix=".json", media_type="application/json"
        )
        builder.add_candidate(
            {
                "record_type": "vulnerability",
                "external_id": "CVE-2024-21626",
                "title_en": "CVE-2024-21626",
                "summary_en": "runc container candidate",
                "technology_bucket_candidate": "runc",
                "candidate_source": "NVD API 2.0",
                "attributes": {"published": "2024-01-31"},
                "source": {
                    "source_key": "NVD:CVE-2024-21626",
                    "name": "NVD record",
                    "source_type": "nvd_record",
                    "authority_level": "E1",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
                },
                "snapshot": raw,
                "evidence": {
                    "locator": "$.id",
                    "excerpt": "CVE-2024-21626",
                    "language": "en",
                    "evidence_level": "E1",
                    "fragment_type": "json",
                },
                "assertions": [
                    {"predicate": "description", "object": "runc candidate", "verification_status": "moderate"}
                ],
            }
        )
        builder.finalize()
        return bundle

    @staticmethod
    def _rewrite_manifest_hash(bundle: Path, relative_path: str) -> None:
        target = bundle / relative_path
        manifest_path = bundle / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest["files"]:
            if entry["path"] == relative_path:
                entry["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
                entry["size_bytes"] = target.stat().st_size
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_bundle_is_valid_and_imports_as_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root)
            validation = validate_candidate_bundle(bundle)
            self.assertTrue(validation.valid, validation.to_dict())
            db_path = root / "trusted.db"
            result = import_candidate_bundle(
                db_path=db_path,
                bundle_dir=bundle,
                actor_id="researcher",
                actor_name="Researcher",
            )
            self.assertTrue(result["ok"], result)
            with closing(sqlite3.connect(db_path)) as connection:
                record = connection.execute(
                    "SELECT status,root_cause_l1,root_cause_l2,generated_by_model FROM kb_records"
                ).fetchone()
                self.assertEqual(("candidate", None, None, 0), record)
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM kb_ingestion_runs").fetchone()[0])
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM kb_source_snapshots").fetchone()[0])

    def test_same_bundle_import_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root)
            db_path = root / "trusted.db"
            first = import_candidate_bundle(db_path=db_path, bundle_dir=bundle, actor_id="researcher")
            second = import_candidate_bundle(db_path=db_path, bundle_dir=bundle, actor_id="researcher")
            self.assertTrue(first["ok"])
            self.assertTrue(second["ok"])
            self.assertTrue(second["already_imported"])
            with closing(sqlite3.connect(db_path)) as connection:
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM kb_ingestion_runs").fetchone()[0])
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM kb_records").fetchone()[0])

    def test_candidate_import_does_not_downgrade_verified_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self._bundle(root)
            db_path = root / "trusted.db"
            import_candidate_bundle(db_path=db_path, bundle_dir=bundle, actor_id="researcher")
            with closing(sqlite3.connect(db_path)) as connection:
                connection.execute(
                    "UPDATE kb_records SET status='verified',"
                    "root_cause_l1='RC-1', "
                    "root_cause_l2='RC-1.1', "
                    "review_status='approved'"
                )
                connection.commit()
            second_bundle = self._bundle(root / "second")
            result = import_candidate_bundle(db_path=db_path, bundle_dir=second_bundle, actor_id="researcher")
            self.assertEqual(0, result["imported"])
            self.assertEqual(1, result["skipped"])
            with closing(sqlite3.connect(db_path)) as connection:
                record = connection.execute(
                    "SELECT status,root_cause_l1,root_cause_l2,review_status FROM kb_records"
                ).fetchone()
            self.assertEqual(("verified", "RC-1", "RC-1.1", "approved"), record)

    def test_bundle_rejects_automatic_root_cause(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(Path(directory))
            path = bundle / "candidates.jsonl"
            row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            row["root_cause_l1"] = "RC-1"
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            self._rewrite_manifest_hash(bundle, "candidates.jsonl")
            result = validate_candidate_bundle(bundle)
            self.assertFalse(result.valid)
            self.assertIn("AUTO_ROOT_CAUSE_FORBIDDEN", {item["code"] for item in result.errors})

    def test_bundle_rejects_missing_evidence_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(Path(directory))
            path = bundle / "candidates.jsonl"
            row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            row.pop("evidence")
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            self._rewrite_manifest_hash(bundle, "candidates.jsonl")
            result = validate_candidate_bundle(bundle)
            self.assertFalse(result.valid)
            self.assertIn("EVIDENCE_REQUIRED", {item["code"] for item in result.errors})

    def test_vulnerability_gold_requires_validated_experiment(self) -> None:
        bundle = {
            "record": {
                "record_type": "vulnerability",
                "root_cause_l1": "RC-1",
                "root_cause_l2": "RC-1.1",
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
            "experiments": [
                {
                    "experiment_id": "EXP-PLANNED",
                    "status": "planned",
                    "validation_level": "L0",
                    "outcome": "unknown",
                }
            ],
            "unresolved_conflicts": [],
        }
        report = GoldAdmissionValidator().validate(bundle)
        self.assertFalse(report.eligible)
        self.assertIn("HAS_VALIDATED_EXPERIMENT", {issue.code for issue in report.issues})

    def test_vulnerability_gold_accepts_completed_l1_experiment(self) -> None:
        bundle = {
            "record": {
                "record_type": "vulnerability",
                "root_cause_l1": "RC-1",
                "root_cause_l2": "RC-1.1",
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
            "experiments": [
                {
                    "experiment_id": "EXP-1",
                    "status": "completed",
                    "validation_level": "L1",
                    "outcome": "preconditions_confirmed",
                    "environment_snapshot_id": "ENV-SNAP-1",
                    "observations": [{"type": "precondition_verified"}],
                }
            ],
            "unresolved_conflicts": [],
        }
        report = GoldAdmissionValidator().validate(bundle)
        self.assertTrue(report.eligible, report.to_dict())

    def test_nvd_chunks_are_at_most_120_days_and_interleave_years(self) -> None:
        chunks = list(date_chunks(2020, 2020))
        self.assertTrue(chunks)
        self.assertTrue(all((end - start).days <= 119 for start, end in chunks))
        stratified = list(stratified_date_chunks(2020, 2022))
        self.assertGreaterEqual(len(stratified), 3)
        self.assertEqual([2020, 2021, 2022], [start.year for start, _ in stratified[:3]])


if __name__ == "__main__":
    unittest.main()
