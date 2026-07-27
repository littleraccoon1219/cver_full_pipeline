from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class EvidenceNode:
    node_id: str
    node_type: str
    label: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceEdge:
    source: str
    target: str
    relation: str
    payload: dict[str, Any] = field(default_factory=dict)


class ExploitabilityEvidenceGraph:
    """A deterministic evidence graph; agents may annotate but never rewrite hard facts."""

    def __init__(self) -> None:
        self.nodes: dict[str, EvidenceNode] = {}
        self.edges: list[EvidenceEdge] = []

    def add_node(self, node_id: str, node_type: str, label: str, **payload: Any) -> str:
        existing = self.nodes.get(node_id)
        if existing and existing.node_type != node_type:
            raise ValueError(f"node type conflict for {node_id}")
        self.nodes[node_id] = EvidenceNode(node_id, node_type, label, payload)
        return node_id

    def add_edge(self, source: str, target: str, relation: str, **payload: Any) -> None:
        if source not in self.nodes or target not in self.nodes:
            raise KeyError("both graph nodes must exist before an edge is added")
        self.edges.append(EvidenceEdge(source, target, relation, payload))

    def add_candidate(self, candidate: dict[str, Any]) -> str:
        candidate_id = str(candidate["candidate_id"])
        self.add_node(
            candidate_id,
            "candidate",
            str(candidate.get("title", candidate_id)),
            level=candidate.get("level"),
            handler_id=candidate.get("handler_id"),
            source_commit=candidate.get("source_commit"),
            source_track=candidate.get("source_track"),
        )
        for index, evidence in enumerate(candidate.get("evidence", [])):
            evidence_id = str(evidence.get("evidence_id") or f"{candidate_id}:evidence:{index}")
            self.add_node(
                evidence_id,
                "evidence",
                str(evidence.get("kind", "evidence")),
                sha256=evidence.get("sha256"),
                restricted=bool(evidence.get("restricted")),
                source=evidence.get("source"),
            )
            self.add_edge(evidence_id, candidate_id, "supports")
        return candidate_id

    def add_environment_facts(self, facts: dict[str, Any]) -> list[str]:
        values = []
        for path, value in sorted(_flatten(facts).items()):
            node_id = f"fact:{hashlib.sha256(path.encode('utf-8')).hexdigest()[:20]}"
            self.add_node(node_id, "environment_fact", path, value=value)
            values.append(node_id)
        return values

    def add_rule_result(self, candidate_id: str, result: dict[str, Any]) -> str:
        node_id = f"rule:{result.get('rule_id', 'unknown')}:{candidate_id}"
        self.add_node(
            node_id,
            "rule_evaluation",
            str(result.get("rule_id", "rule")),
            outcome=result.get("outcome"),
            missing_facts=result.get("missing_facts", []),
            trace=result.get("trace", []),
        )
        self.add_edge(node_id, candidate_id, "evaluates")
        return node_id

    def add_agent_annotation(self, candidate_id: str, role: str, annotation: dict[str, Any]) -> str:
        digest = hashlib.sha256(
            json.dumps(annotation, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        node_id = f"agent:{role}:{digest}"
        self.add_node(
            node_id,
            "agent_annotation",
            role,
            advisory_only=True,
            payload=annotation,
        )
        self.add_edge(node_id, candidate_id, "advises")
        return node_id

    def payload(self) -> dict[str, Any]:
        data = {
            "schema_version": 1,
            "nodes": [
                {
                    "node_id": item.node_id,
                    "node_type": item.node_type,
                    "label": item.label,
                    "payload": item.payload,
                }
                for item in sorted(self.nodes.values(), key=lambda value: value.node_id)
            ],
            "edges": [
                {
                    "source": item.source,
                    "target": item.target,
                    "relation": item.relation,
                    "payload": item.payload,
                }
                for item in self.edges
            ],
        }
        data["graph_sha256"] = hashlib.sha256(
            json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return data


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten(item, path))
        return output
    return {prefix: value}
