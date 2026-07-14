from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cver.knowledge.candidate_importer import import_candidate_bundle
from cver.knowledge.candidate_validation import validate_candidate_bundle
from cver.knowledge.collectors.common import CandidateBundleBuilder
from cver.knowledge.validation import GoldAdmissionValidator


class CandidatePipelineTests(unittest.TestCase):
    def _bundle(self, root: Path) -> Path:
        bundle = root / "bundle"
        builder = CandidateBundleBuilder(bundle, "unit-test", "1.0.0", "test")
        raw = builder.store_raw("CVE-2024-21626", b'{"id":"CVE-2024-21626"}\n', suffix=".json", media_type="application/json")
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
            with sqlite3.connect(db_path) as connection:
                record = connection.execute(
                    "SELECT status,root_cause_l1,root_cause_l2,generated_by_model FROM kb_records"
                ).fetchone()
                self.assertEqual(("candidate", None, None, 0), record)
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM kb_ingestion_runs").fetchone()[0])
                self.assertEqual(1, connection.execute("SELECT COUNT(*) FROM kb_source_snapshots").fetchone()[0])

    def test_bundle_rejects_automatic_root_cause(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = self._bundle(Path(directory))
            path = bundle / "candidates.jsonl"
            row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
            row["root_cause_l1"] = "RC-1"
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            result = validate_candidate_bundle(bundle)
            self.assertFalse(result.valid)
            self.assertIn("AUTO_ROOT_CAUSE_FORBIDDEN", {item["code"] for item in result.errors})

    def test_vulnerability_gold_requires_experiment(self) -> None:
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
            "experiments": [],
            "unresolved_conflicts": [],
        }
        report = GoldAdmissionValidator().validate(bundle)
        self.assertFalse(report.eligible)
        self.assertIn("HAS_EXPERIMENT", {issue.code for issue in report.issues})


if __name__ == "__main__":
    unittest.main()
