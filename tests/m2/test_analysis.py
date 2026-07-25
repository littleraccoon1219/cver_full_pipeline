from __future__ import annotations

from cver.m2.exploitability import ExploitabilityEvaluator
from cver.m2.static_analysis import AttackSurfaceScanner, KataConfigAuditor


def test_static_scanner_emits_candidates_not_confirmed(tmp_path):
    source = tmp_path / "sample.go"
    source.write_text(
        'package p\n// AF_VSOCK ttrpc virtiofs FUSE_INIT\n// annotations oci.spec\n// filepath.Clean ioctl unsafe {\n',
        encoding="utf-8",
    )
    result = AttackSurfaceScanner().scan("test", tmp_path)
    assert result["finding_count"] >= 5
    assert all(item["status"] == "needs_dynamic_evidence" for item in result["findings"])
    assert all(
        item["metadata"]["claim_boundary"] == "candidate_only_not_a_confirmed_vulnerability"
        for item in result["findings"]
    )


def test_exploitability_stops_at_non_weaponized_boundary():
    result = ExploitabilityEvaluator().evaluate(
        {"file": "boundary.rs"},
        version_match=True,
        prerequisites=True,
        reachable=True,
        controlled_trigger=True,
        boundary_impact=True,
    )
    assert result["exploitability_level"] == "E5"
    assert result["attack_chain_level"] == "L4"
    assert result["evidence"]["weaponized_escape"] is False


def test_kata_config_auditor_records_guest_seccomp():
    findings = KataConfigAuditor().audit({"disable_guest_seccomp": True, "cpu_features": ""})
    titles = {item["title"] for item in findings}
    assert "Guest seccomp is disabled" in titles
    assert "ARM64 PMU compatibility override is active" in titles
