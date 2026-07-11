from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any
from .ids import stable_id
from .logging_utils import now_iso

def to_dict(x: Any) -> Any:
    if hasattr(x, "__dataclass_fields__"):
        return asdict(x)
    if isinstance(x, list):
        return [to_dict(v) for v in x]
    if isinstance(x, dict):
        return {k: to_dict(v) for k,v in x.items()}
    return x

@dataclass
class Target:
    name: str
    kind: str = "image"
    target_id: str = ""
    labels: dict[str,str] = field(default_factory=dict)
    namespace: str | None = None
    runtime_class: str | None = None
    backend_hint: str = "auto"
    def __post_init__(self) -> None:
        if not self.target_id:
            self.target_id = stable_id("target", self.kind, self.name)

@dataclass
class Scan:
    scan_id: str
    target_id: str
    mode: str
    profile: str
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    status: str = "created"
    correlation_id: str = ""

@dataclass
class Finding:
    finding_id: str
    source: str
    type: str
    title: str
    description: str
    severity: str
    cve_id: str = ""
    component: str = "unknown"
    package_name: str = ""
    installed_version: str = "unknown"
    fixed_version: str = "unknown"
    evidence_refs: list[str] = field(default_factory=list)
    provenance: dict[str,Any] = field(default_factory=dict)
    confidence: float = 0.5
    dedup_key: str = ""
    scan_id: str = ""
    target_id: str = ""
    correlation_id: str = ""
    macro_type: str = "unknown"
    fine_type: str = "unknown"
    root_cause: str = "unknown"
    attack_surface: str = "unknown"
    impact_boundary: str = "unknown"
    required_capability: str = "unknown"
    escape_primitives: list[str] = field(default_factory=list)
    mitigation_class: str = "unknown"

@dataclass
class Evidence:
    evidence_id: str
    source: str
    category: str
    key: str
    value: Any
    evidence_snippet: str = ""
    confidence: float = 0.8
    scan_id: str = ""
    target_id: str = ""
    campaign_id: str = ""
    scenario_id: str = ""
    correlation_id: str = ""

@dataclass
class Precondition:
    name: str
    expr: str
    source_type: str = "rule_inferred"
    evidence_snippet: str = ""
    confidence: float = 0.5
    human_confirmed: bool = False

@dataclass
class CVEKnowledge:
    cve_id: str
    facts: dict[str,Any]
    semantic_annotations: dict[str,Any]
    evidence_sources: list[dict[str,Any]] = field(default_factory=list)
    redteam_mapping: list[dict[str,Any]] = field(default_factory=list)

@dataclass
class EvidenceBundle:
    scan_id: str
    target_id: str
    evidences: list[Evidence]
    summary: dict[str,Any]
    correlation_id: str = ""

@dataclass
class ExploitabilityResult:
    finding_id: str
    exploitability_label: str
    exploitability_score: float
    confidence: float
    matched_preconditions: list[dict[str,Any]]
    missing_preconditions: list[dict[str,Any]]
    blocking_conditions: list[dict[str,Any]]
    required_capability: str
    environment_gap: list[str]
    human_confirm_required: bool
    reasoning_trace: list[str]
    scan_id: str = ""
    target_id: str = ""
    correlation_id: str = ""

@dataclass
class GraphNode:
    node_id: str
    node_type: str
    label: str
    data: dict[str,Any] = field(default_factory=dict)

@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    data: dict[str,Any] = field(default_factory=dict)

@dataclass
class EscapeGraph:
    graph_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    mermaid: str
    scan_id: str = ""
    target_id: str = ""
    correlation_id: str = ""

@dataclass
class RedTeamCampaign:
    campaign_id: str
    scan_id: str
    target_id: str
    planned_scenarios: list[dict[str,Any]]
    results: list[dict[str,Any]]
    execution_level: str
    policy_decisions: list[dict[str,Any]]
    correlation_id: str = ""

@dataclass
class DefenseScore:
    total_score: float
    dimensions: dict[str,float]
    deductions: list[dict[str,Any]]
    evidence_refs: list[str]
    shared_kernel_score: float
    microvm_score: float
    scan_id: str = ""
    target_id: str = ""
    correlation_id: str = ""

@dataclass
class RepairPlan:
    repair_plan_id: str
    scan_id: str
    target_id: str
    patch_proposals: list[dict[str,Any]]
    retest_plan: list[dict[str,Any]]
    safe_apply_allowed: bool
    rollback_plan: list[dict[str,Any]]
    correlation_id: str = ""

@dataclass
class Report:
    report_id: str
    scan_id: str
    target_id: str
    json_path: str
    markdown_path: str
    html_path: str
    created_at: str = field(default_factory=now_iso)

@dataclass
class BenchmarkRun:
    benchmark_id: str
    profile: str
    cases: list[dict[str,Any]]
    metrics: dict[str,Any]
    output_path: str
    created_at: str = field(default_factory=now_iso)
