from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cver.knowledge.nvd_ingest import NVDCandidateIngestor, _reference_urls


class TestNVDIngest(unittest.TestCase):
    def test_references_are_parsed_from_api_v2_list(self) -> None:
        cve = {"references": [{"url": "https://example.test/a"}, {"url": "https://example.test/b"}]}
        self.assertEqual(
            _reference_urls(cve),
            ["https://example.test/a", "https://example.test/b"],
        )

    def test_candidate_ingest_does_not_assign_root_cause_or_gold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "trusted.db"
            raw_dir = Path(directory) / "raw"
            ingestor = NVDCandidateIngestor(db_path, raw_dir, "tester")
            cve = {
                "id": "CVE-2026-0001",
                "sourceIdentifier": "security@example.test",
                "published": "2026-01-01T00:00:00.000",
                "lastModified": "2026-01-02T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "A vulnerability in runc may affect containers."}],
                "references": [{"url": "https://example.test/advisory"}],
                "metrics": {},
                "weaknesses": [],
                "configurations": [],
            }
            self.assertTrue(ingestor.ingest_cve(cve, "runc"))
            with sqlite3.connect(str(db_path)) as connection:
                row = connection.execute(
                    "SELECT status, root_cause_l1, root_cause_l2, attributes_json FROM kb_records"
                ).fetchone()
                self.assertEqual(row[0], "candidate")
                self.assertIn(row[1], (None, ""))
                self.assertIn(row[2], (None, ""))
                attributes = json.loads(row[3])
                self.assertEqual(attributes["candidate_source"], "NVD API 2.0")
                self.assertTrue(list(raw_dir.rglob("*.json")))


if __name__ == "__main__":
    unittest.main()
