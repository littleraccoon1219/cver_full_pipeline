from __future__ import annotations

import sqlite3

import pytest

from cver.discovery.budget import DEFAULT_BUDGETS, resolve_budget
from cver.discovery.candidates import AnnotationService, CandidateArtifactInput, CandidateBundleBuilder
from cver.discovery.db import SCHEMA_VERSION, DiscoveryRepository
from cver.discovery.fullstack import ComponentRegistry
from cver.discovery.models import ExperimentKind, RiskLevel
from cver.discovery.policy import DiscoveryPolicy, PolicyContext
from cver.discovery.retrieval import HybridDocument, HybridRetriever
from cver.discovery.taxonomy import TaxonomyCatalog
from cver.discovery.zeroday import EphemeralMasterKeyProvider, ZeroDayVault


def _annotation() -> dict:
    return {
        "taxonomy_version": "1.0.0",
        "security_status": "SECURITY_VULNERABILITY",
        "primary_root_cause": "RC-2",
        "primary_secondary_root_cause": "RC-2.2",
        "primary_causal_role": "The first failed invariant exposes a host mount to the isolated workload.",
        "primary_counterfactual_changes_outcome": True,
        "secondary_root_causes": [
            {
                "code": "RC-5.2",
                "evidence_ids": ["ev-source", "ev-runtime"],
                "causal_role": "Host and runtime interpreted the mount path differently.",
                "counterfactual_changes_outcome": True,
            }
        ],
        "primary_security_property": "SP6",
        "secondary_security_properties": ["SP1"],
        "evidence_ids": ["ev-source", "ev-runtime"],
        "rationale": "Source and runtime evidence independently establish the boundary violation.",
        "classification_status": "ACCEPTED",
        "status": "gold",
    }


def test_fixed_taxonomy_is_machine_decidable():
    catalog = TaxonomyCatalog()
    assert set(catalog.parents) == {"RC-1", "RC-2", "RC-3", "RC-4", "RC-5"}
    assert len(catalog.root_labels) == 29
    assert set(catalog.security_properties) == {f"SP{i}" for i in range(1, 14)}
    for label in catalog.root_labels.values():
        assert label.positive_examples
        assert label.negative_examples
        assert label.machine_signals["static"]
        assert label.machine_signals["dynamic"]
        assert label.evidence_gate["minimum_independent_evidence"] >= 2
        assert label.evidence_gate["allows_text_only_classification"] is False
        assert label.causal_test


def test_primary_and_secondary_labels_require_causal_evidence():
    catalog = TaxonomyCatalog()
    valid = _annotation()
    assert catalog.validate_decision(valid, valid["evidence_ids"]) == []

    invalid = dict(valid)
    invalid["evidence_ids"] = ["ev-source"]
    invalid["primary_counterfactual_changes_outcome"] = False
    errors = catalog.validate_decision(invalid, invalid["evidence_ids"])
    assert any("at least two" in item for item in errors)
    assert any("counterfactual" in item for item in errors)


def test_fullstack_registry_covers_required_components():
    registry = ComponentRegistry()
    expected = {
        "application-dependencies",
        "image-supply-chain",
        "moby",
        "runc",
        "containerd",
        "crio-conmon",
        "kubernetes",
        "buildkit",
        "linux-ebpf",
        "gvisor",
        "kata",
        "firecracker",
        "rust-shyper",
    }
    assert expected == set(registry.components)
    assert registry.get("rust-shyper").integration_stage == "M3"


def test_candidate_is_deduplicated_and_requires_human_annotation(tmp_path):
    repository = DiscoveryRepository(tmp_path / "runtime.db")
    repository.migrate()
    source = tmp_path / "advisory.txt"
    source.write_text("host mount boundary evidence", encoding="utf-8")
    builder = CandidateBundleBuilder(repository, root=tmp_path / "candidates")
    first = builder.build(
        source_type="vendor_advisory",
        component_id="runc",
        title="candidate",
        data_class="public",
        artifacts=[CandidateArtifactInput(source, "advisory")],
        external_id="TEST-1",
    )
    second = builder.build(
        source_type="vendor_advisory",
        component_id="runc",
        title="candidate",
        data_class="public",
        artifacts=[CandidateArtifactInput(source, "advisory")],
        external_id="TEST-1",
    )
    assert first["candidate_id"] == second["candidate_id"]
    candidate = repository.get_candidate(first["candidate_id"])
    assert candidate is not None
    assert len(candidate["artifacts"]) == 1
    assert candidate["manifest"]["admission"]["root_cause"] is None
    assert candidate["manifest"]["admission"]["requires_human_annotation"] is True

    result = AnnotationService(repository, TaxonomyCatalog()).submit(
        first["candidate_id"], _annotation(), annotator="human-researcher"
    )
    assert result["annotation_id"].startswith("ann-")
    assert result["candidate_status"] == "human_annotated_gold"
    assert repository.get_candidate(first["candidate_id"])["status"] == "human_annotated_gold"
    with repository.connect() as connection:
        row = connection.execute("SELECT * FROM discovery_annotations").fetchone()
    assert row["annotator"] == "human-researcher"
    assert row["primary_counterfactual_changes_outcome"] == 1


def test_annotation_rejects_unknown_candidate(tmp_path):
    repository = DiscoveryRepository(tmp_path / "runtime.db")
    repository.migrate()
    with pytest.raises(KeyError):
        AnnotationService(repository, TaxonomyCatalog()).submit("missing", _annotation(), annotator="human")


def test_hybrid_retrieval_enforces_split_leakage_and_metadata():
    documents = [
        HybridDocument("a", "runc mount host path boundary", {"component_id": "runc", "split_group_id": "g1"}, 1, 1),
        HybridDocument(
            "b", "runc mount namespace boundary", {"component_id": "runc", "split_group_id": "g2"}, 0.9, 0.9
        ),
        HybridDocument("c", "kubernetes rbac permission", {"component_id": "kubernetes", "split_group_id": "g3"}, 1, 1),
    ]
    results = HybridRetriever(documents).search(
        "runc mount boundary", metadata_filters={"component_id": "runc"}, excluded_split_groups={"g1"}
    )
    assert [item["document_id"] for item in results] == ["b"]
    assert results[0]["embedding_backend"] == "local-hashing-v1"


def test_zero_day_vault_encrypts_each_case_and_audits(tmp_path):
    repository = DiscoveryRepository(tmp_path / "runtime.db")
    repository.migrate()
    secret = tmp_path / "crash.bin"
    plaintext = b"unpublished crash input and source fragment"
    secret.write_bytes(plaintext)
    provider = EphemeralMasterKeyProvider.generate()
    vault = ZeroDayVault(repository, root=tmp_path / "vault", master_key=provider)
    sealed = vault.seal_case(files=[secret], metadata={"component": "runc"}, actor="researcher")
    manifest = vault.read_manifest(sealed["case_id"], actor="researcher")
    assert manifest["data_class"] == "restricted"
    assert manifest["metadata"]["component"] == "runc"
    case_files = list((tmp_path / "vault" / sealed["case_id"]).iterdir())
    assert not any(plaintext in path.read_bytes() for path in case_files)
    with repository.connect() as connection:
        cases = connection.execute("SELECT COUNT(*) AS n FROM discovery_zero_day_cases").fetchone()["n"]
        audits = connection.execute("SELECT COUNT(*) AS n FROM discovery_audit_log").fetchone()["n"]
    assert cases == 1
    assert audits == 2


def test_immutable_approval_digest_changes_with_experiment(settings):
    policy = DiscoveryPolicy(settings)
    base = PolicyContext(
        "job",
        "/tmp/target",
        "source",
        ExperimentKind.GO_FUZZ,
        job_risk=RiskLevel.HIGH,
        experiment_spec={"source_commit": "abc", "network": "online-audited"},
    )
    changed = PolicyContext(
        "job",
        "/tmp/target",
        "source",
        ExperimentKind.GO_FUZZ,
        job_risk=RiskLevel.HIGH,
        experiment_spec={"source_commit": "def", "network": "online-audited"},
    )
    first = policy.decide(base)
    second = policy.decide(changed)
    assert first.risk == RiskLevel.HIGH
    assert first.backend == "firecracker"
    assert first.decision == "await_approval"
    assert first.experiment_digest != second.experiment_digest


def test_budget_profiles_match_approved_defaults():
    assert DEFAULT_BUDGETS["quick"].max_duration_seconds == 3600
    assert DEFAULT_BUDGETS["balanced"].max_llm_calls == 50
    assert DEFAULT_BUDGETS["deep"].fuzz_budget_seconds == 4 * 3600
    assert resolve_budget("balanced", {"max_experiments": 12}).max_experiments == 12


def test_migrate_old_schema_to_v2(tmp_path):
    path = tmp_path / "runtime.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE discovery_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE discovery_jobs(
          job_id TEXT PRIMARY KEY,kind TEXT,target TEXT,target_kind TEXT,status TEXT,risk TEXT,
          requested_backend TEXT,selected_backend TEXT,payload_json TEXT,result_json TEXT,error TEXT,
          attempts INTEGER DEFAULT 0,max_attempts INTEGER DEFAULT 3,leased_by TEXT,lease_expires_at TEXT,
          created_at TEXT,updated_at TEXT
        );
        CREATE TABLE discovery_approvals(
          approval_id TEXT PRIMARY KEY,job_id TEXT,scope TEXT,decision TEXT,actor TEXT,reason TEXT,created_at TEXT
        );
        """
    )
    connection.close()
    result = DiscoveryRepository(path).migrate()
    assert result["schema_version"] == SCHEMA_VERSION
    connection = sqlite3.connect(path)
    job_columns = {row[1] for row in connection.execute("PRAGMA table_info(discovery_jobs)")}
    approval_columns = {row[1] for row in connection.execute("PRAGMA table_info(discovery_approvals)")}
    annotation_columns = {row[1] for row in connection.execute("PRAGMA table_info(discovery_annotations)")}
    connection.close()
    assert "next_attempt_at" in job_columns
    assert {"experiment_digest", "expires_at"} <= approval_columns
    assert {"primary_causal_role", "primary_counterfactual_changes_outcome"} <= annotation_columns
