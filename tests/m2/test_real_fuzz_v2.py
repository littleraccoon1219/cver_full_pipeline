from __future__ import annotations

import json
from pathlib import Path

import pytest

from cver.m2.agents import DeepSeekMultiAgent
from cver.m2.dataset import DatasetBuilder
from cver.m2.evaluation import classification_metrics, evaluate_predictions, fuzz_metrics
from cver.m2.real_fuzz.inspector import KataAgentInspector
from cver.m2.real_fuzz.manifests import AdapterRegistry
from cver.m2.real_fuzz.replay import GuestReplayPlanner
from cver.m2.real_fuzz.runtime_assets import REQUIRED_ASSETS, RuntimeAssetManager
from cver.m2.real_fuzz.triage import CandidateTriage
from cver.m2.real_fuzz.workspace import RealFuzzWorkspace
from cver.m2.rules_engine import ExploitabilityLadder, ThreeValuedRuleEngine, TriState


HANDLERS = {
    "read_stdout": "ReadStreamRequest",
    "read_stderr": "ReadStreamRequest",
    "write_stdin": "WriteStreamRequest",
    "exec_process": "ExecProcessRequest",
    "signal_process": "SignalProcessRequest",
    "wait_process": "WaitProcessRequest",
    "update_container": "UpdateContainerRequest",
}


def _kata_source(root: Path, *, changed_write_type: bool = False) -> Path:
    rpc = root / "src" / "agent" / "src" / "rpc.rs"
    rpc.parent.mkdir(parents=True, exist_ok=True)
    methods = []
    for method, request in HANDLERS.items():
        if method == "write_stdin" and changed_write_type:
            request = "ChangedWriteStreamRequest"
        methods.append(
            "#[async_trait]\n"
            f"async fn {method}(&self, _ctx: &TtrpcContext, req: {request}) "
            "-> ttrpc::Result<Empty> { let _ = req; todo!() }\n"
        )
    rpc.write_text("\n".join(methods), encoding="utf-8")
    return root


def _approved_adapter(source: Path, registry: AdapterRegistry) -> tuple[dict, Path]:
    inspection = KataAgentInspector().inspect(source, version="3.32.0")
    proposal = registry.propose(inspection)
    approved = registry.approve(
        proposal["manifest_path"],
        actor="tester",
        compilation_test=True,
        interface_test=True,
        semantic_differential_test=True,
        confirm=True,
    )
    return registry.check(inspection), Path(approved["manifest_path"])


def test_inspector_finds_seven_real_rpc_boundaries(tmp_path: Path):
    inspection = KataAgentInspector().inspect(_kata_source(tmp_path / "kata"), version="3.32.0")
    assert inspection.status == "COMPATIBLE"
    assert not inspection.missing_handlers
    assert {item.handler_id for item in inspection.handlers} == {
        "ReadStdout",
        "ReadStderr",
        "WriteStdin",
        "ExecProcess",
        "SignalProcess",
        "WaitProcess",
        "UpdateContainer",
    }
    assert all(item.signature_sha256 for item in inspection.handlers)
    assert inspection.interface_fingerprint


def test_adapter_requires_review_then_exact_approval_and_detects_drift(tmp_path: Path):
    source = _kata_source(tmp_path / "kata")
    registry = AdapterRegistry(tmp_path / "adapters")
    inspection = KataAgentInspector().inspect(source, version="3.32.0")
    assert registry.check(inspection)["state"] == "ADAPTER_REQUIRED"
    proposal = registry.propose(inspection)
    assert proposal["state"] == "REVIEW_REQUIRED"
    # Candidate manifests are not executable adapters.
    assert registry.check(inspection)["state"] == "ADAPTER_REQUIRED"
    approved = registry.approve(
        proposal["manifest_path"],
        actor="tester",
        compilation_test=True,
        interface_test=True,
        semantic_differential_test=True,
        confirm=True,
    )
    assert Path(approved["manifest_path"]).is_file()
    assert registry.check(inspection)["state"] == "APPROVED"

    _kata_source(source, changed_write_type=True)
    changed = KataAgentInspector().inspect(source, version="3.32.0")
    assert registry.check(changed)["state"] == "ADAPTER_SEMANTIC_DRIFT"


def test_adapter_approval_requires_all_hard_gates(tmp_path: Path):
    source = _kata_source(tmp_path / "kata")
    registry = AdapterRegistry(tmp_path / "adapters")
    proposal = registry.propose(KataAgentInspector().inspect(source, version="3.32.0"))
    with pytest.raises(PermissionError):
        registry.approve(
            proposal["manifest_path"],
            actor="tester",
            compilation_test=True,
            interface_test=True,
            semantic_differential_test=True,
            confirm=False,
        )
    with pytest.raises(ValueError):
        registry.approve(
            proposal["manifest_path"],
            actor="tester",
            compilation_test=True,
            interface_test=True,
            semantic_differential_test=False,
            confirm=True,
        )


def test_independent_workspace_preserves_evidence_gate(tmp_path: Path):
    source = _kata_source(tmp_path / "kata")
    inspection = KataAgentInspector().inspect(source, version="3.32.0")
    adapter = {"state": "REVIEW_REQUIRED", "adapter": None}
    payload = RealFuzzWorkspace(tmp_path / "workspaces").prepare(
        inspection, adapter, track="installed-baseline", seed=7
    )
    workspace = Path(payload["workspace"])
    assert workspace.is_dir()
    assert source not in workspace.parents
    assert payload["real_build_ready"] is False
    assert "compile_error!" in (workspace / "bridge" / "src" / "lib.rs").read_text()
    lock = json.loads((workspace / "workspace-lock.json").read_text())
    assert lock["workspace_policy"]["mock_results_are_interface_tests_only"] is True
    concurrency = json.loads((workspace / "plans" / "controlled-concurrency.json").read_text())
    assert concurrency["max_branches"] == 2
    assert concurrency["required_reproductions"] == 3


def test_triage_levels_use_reproduction_and_evidence_not_exit_code():
    base = {
        "run_id": "run-1",
        "component": "kata-agent",
        "kata_version": "3.32.0",
        "source_track": "installed-baseline",
        "handler_id": "WaitProcess",
        "source_commit": "abc",
        "adapter_id": "adapter",
        "exit_code": 1,
        "reproducibility": {"seed": 3, "successful_reproductions": 0, "state_sequence": []},
        "evidence": [],
        "stderr_tail": "ordinary nonzero exit",
    }
    assert CandidateTriage().classify(base)["level"] == "OBSERVATION"

    strong = dict(base)
    strong["stderr_tail"] = "ERROR: AddressSanitizer: heap-buffer-overflow"
    strong["evidence"] = [{"kind": "sanitizer", "sha256": "deadbeef", "restricted": True}]
    strong["reproducibility"] = {
        "seed": 3,
        "successful_reproductions": 3,
        "state_sequence": [],
    }
    assert CandidateTriage().classify(strong)["level"] == "STRONG_CANDIDATE"
    validated = CandidateTriage().classify(
        strong,
        guest_replay={"reproduced": True, "isolation_invariant_violated": False},
    )
    assert validated["level"] == "VALIDATED_CANDIDATE"


def test_versioned_runtime_assets_are_hash_checked_and_isolated(m2_settings, tmp_path: Path):
    manager = RuntimeAssetManager(m2_settings)
    assets = {}
    for name in REQUIRED_ASSETS:
        path = tmp_path / f"{name}.bin"
        path.write_bytes(name.encode())
        assets[name] = path
    registered = manager.register("3.31.0", assets, source="test")
    assert registered["status"] == "READY"
    assert registered["system_kata_overwrite"] is False
    assert not registered["asset_root"].startswith("/opt/kata")
    assert manager.readiness("3.31.0")["status"] == "READY"
    Path(assets["agent"]).write_bytes(b"changed")
    assert manager.readiness("3.31.0")["status"] == "RUNTIME_NOT_REPRODUCED"


def test_guest_replay_is_planned_but_never_automatic(m2_settings, tmp_path: Path):
    artifact = tmp_path / "input.bin"
    artifact.write_bytes(b"bounded")
    candidate = {
        "candidate_id": "cand-1",
        "handler_id": "WaitProcess",
        "level": "STRONG_CANDIDATE",
    }
    planner = GuestReplayPlanner(m2_settings)
    l1 = planner.plan(
        candidate=candidate,
        version="3.32.0",
        level="L1_RPC_ONLY",
        input_artifact=artifact,
        input_profile="rpc_only",
    )
    assert l1["status"] == "REPLAY_PLAN_READY"
    assert l1["execution"]["automatic"] is False
    assert "guest-to-host escape payload" in l1["forbidden_actions"]

    l3 = planner.plan(
        candidate=candidate,
        version="3.32.0",
        level="L3_ISOLATION_INVARIANT",
        input_artifact=artifact,
        input_profile="bounded_wait",
        confirm=False,
    )
    assert l3["status"] == "REPLAY_APPROVAL_REQUIRED"
    assert l3["gates"]["ready"] is False


def test_three_valued_rules_and_ladder_preserve_unknown():
    result = ThreeValuedRuleEngine().evaluate(
        "runc-prerequisites",
        {
            "logic": "and",
            "conditions": [
                {"fact": "runtime.version", "operator": "version_in_range", "value": "<1.1.12"},
                {"fact": "container.privileged", "operator": "equals", "value": True},
            ],
        },
        {"runtime": {"version": "1.1.10"}},
    )
    assert result["outcome"] == "UNKNOWN"
    assert result["missing_facts"] == ["container.privileged"]
    ladder = ExploitabilityLadder().assess(
        affected_version=TriState.TRUE,
        prerequisites=TriState.UNKNOWN,
        reachable=TriState.TRUE,
        controlled_trigger=TriState.TRUE,
        boundary_impact=TriState.UNKNOWN,
    )
    assert ladder["level"] == "E1"
    assert ladder["agent_override_allowed"] is False


def test_dataset_split_is_time_ordered_group_isolated():
    records = []
    for index in range(12):
        cve = f"CVE-202{index // 4}-{1000 + index // 2}"
        records.append(
            {
                "record_id": f"r-{index}",
                "dataset_layer": "public_vulnerability" if index < 8 else "hard_negative",
                "label": "runtime_escape" if index % 2 else "fixed",
                "cve_id": cve,
                "published_at": f"202{index // 4}-0{(index % 4) + 1}-01",
                "kata_version": "3.32.0",
                "handler_id": "WaitProcess",
            }
        )
    payload = DatasetBuilder().split(records, train_ratio=0.5, validation_ratio=0.25)
    assert payload["leakage_audit"]["passed"] is True
    locations = {}
    for split, items in payload["splits"].items():
        for item in items:
            previous = locations.setdefault(item["split_group"], split)
            assert previous == split
    assert set(payload["splits"]) == {"train", "validation", "test"}


def test_evaluation_reports_layer_separated_metrics():
    records = [
        {
            "truth_macro": "runtime",
            "predicted_macro": "runtime",
            "truth_fine": "escape",
            "predicted_fine": "escape",
            "truth_exploitability": "E3",
            "predicted_exploitability": "E3",
            "truth_exploitable_binary": 1,
            "predicted_probability": 0.9,
            "dataset_layer": "public_vulnerability",
        },
        {
            "truth_macro": "runtime",
            "predicted_macro": "runtime",
            "truth_fine": "fixed",
            "predicted_fine": "escape",
            "truth_exploitability": "E0",
            "predicted_exploitability": "E2",
            "truth_exploitable_binary": 0,
            "predicted_probability": 0.3,
            "dataset_layer": "hard_negative",
        },
    ]
    report = evaluate_predictions(records)
    assert report["macro_classification"]["accuracy"] == 1.0
    assert set(report["by_dataset_layer"]) == {"public_vulnerability", "hard_negative"}
    assert classification_metrics([], [])["support"] == 0
    fuzz = fuzz_metrics(
        [
            {
                "duration_seconds": 2,
                "evidence": [{"sha256": "a"}],
                "reproducibility": {"successful_reproductions": 3},
                "coverage": {"edges": 10},
            }
        ]
    )
    assert fuzz["unique_crash_artifacts"] == 1
    assert fuzz["reproduction_rate"] == 1.0


def test_six_agents_degrade_without_key_and_cannot_promote(m2_settings):
    payload = DeepSeekMultiAgent(m2_settings).run(
        candidate={"candidate_id": "c", "level": "WEAK_CANDIDATE"},
        evidence_graph={"nodes": [], "edges": []},
        environment={},
    )
    assert payload["status"] == "SKIPPED_WITH_REASON"
    assert payload["hard_gate"]["candidate_level_after"] == "WEAK_CANDIDATE"
    assert payload["hard_gate"]["promotion_allowed"] is False
