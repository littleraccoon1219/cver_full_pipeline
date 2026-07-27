from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .config import M2Settings


@dataclass(frozen=True, slots=True)
class AgentRole:
    role_id: str
    purpose: str
    required_output: tuple[str, ...]


ROLES: tuple[AgentRole, ...] = (
    AgentRole("triage", "deduplicate, classify and prioritize the candidate", ("priority", "duplicate_keys", "reason")),
    AgentRole(
        "exploitability",
        "identify environment prerequisites, missing evidence and a non-weaponized attack-chain hypothesis",
        ("prerequisites", "missing_evidence", "chain_hypothesis"),
    ),
    AgentRole(
        "experiment",
        "propose bounded harness, corpus, state-sequence and Kata Guest validation steps",
        ("safe_experiments", "expected_observations", "stop_conditions"),
    ),
    AgentRole(
        "critic",
        "challenge unsupported claims, detect evidence conflicts and enforce hard-gate limits",
        ("conflicts", "unsupported_claims", "gate_decision"),
    ),
    AgentRole(
        "remediation",
        "propose minimal source or configuration remediation and a regression plan",
        ("remediation_options", "regression_tests", "rollback"),
    ),
    AgentRole(
        "evaluation",
        "map the case to paper metrics, baselines and ablation evidence",
        ("metrics", "baseline_comparisons", "ablation_tags"),
    ),
)

FORBIDDEN_OUTPUT_TERMS = (
    "reverse shell",
    "bind shell",
    "credential theft",
    "persistence payload",
    "disable validation",
    "remove authorization",
    "escape payload",
)


class DeepSeekMultiAgent:
    """Six advisory agents with deterministic hard-gate enforcement.

    Agent output is stored as annotation only. It cannot approve adapters, promote
    evidence levels, execute generated patches or trigger Guest replay.
    """

    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings
        self.client: Any | None = None
        self.error: str | None = None
        if not settings.llm_enabled:
            self.error = "CVER_M2_LLM_ENABLED is false"
        elif not settings.llm_api_key:
            self.error = "DEEPSEEK_API_KEY is not configured"
        else:
            try:
                from openai import OpenAI

                self.client = OpenAI(
                    api_key=settings.llm_api_key,
                    base_url=settings.llm_base_url,
                    timeout=settings.llm_timeout_seconds,
                    max_retries=2,
                )
            except Exception as exc:  # pragma: no cover - environment specific
                self.error = f"{type(exc).__name__}: {exc}"

    def run(
        self,
        *,
        candidate: dict[str, Any],
        evidence_graph: dict[str, Any],
        environment: dict[str, Any],
        experiment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.client is None:
            return {
                "status": "SKIPPED_WITH_REASON",
                "reason": self.error,
                "model": self.settings.llm_model,
                "agents": [],
                "hard_gate": self._hard_gate(candidate, []),
            }
        history: list[dict[str, Any]] = []
        total_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        for role in ROLES:
            response = self._invoke(
                role,
                candidate=candidate,
                evidence_graph=evidence_graph,
                environment=environment,
                experiment=experiment or {},
                prior_agents=history,
            )
            history.append(response)
            for key in total_usage:
                total_usage[key] += int((response.get("usage") or {}).get(key) or 0)
        return {
            "status": "completed",
            "provider": "deepseek-openai-compatible",
            "model": self.settings.llm_model,
            "agents": history,
            "usage": total_usage,
            "hard_gate": self._hard_gate(candidate, history),
            "provenance_sha256": hashlib.sha256(
                json.dumps(history, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest(),
        }

    def _invoke(
        self,
        role: AgentRole,
        *,
        candidate: dict[str, Any],
        evidence_graph: dict[str, Any],
        environment: dict[str, Any],
        experiment: dict[str, Any],
        prior_agents: list[dict[str, Any]],
    ) -> dict[str, Any]:
        system = (
            f"You are the {role.role_id} agent in an authorized defensive Kata Containers research lab. "
            f"Your purpose is to {role.purpose}. Return one JSON object only. "
            "Do not provide exploit code, guest-to-host escape payloads, persistence, credential theft, "
            "arbitrary commands, or instructions that weaken security checks. Treat LLM output as advisory. "
            "Do not claim a vulnerability is validated without deterministic dynamic evidence."
        )
        request = {
            "required_fields": list(role.required_output),
            "candidate": self._compact(candidate),
            "evidence_graph": self._compact_graph(evidence_graph),
            "environment": self._compact(environment),
            "experiment": self._compact(experiment),
            "prior_agent_annotations": [
                {"role": item.get("role"), "output": item.get("output")} for item in prior_agents
            ],
            "policy": {
                "may_promote_candidate": False,
                "may_execute_patch": False,
                "may_trigger_guest_replay": False,
                "must_list_missing_evidence": True,
            },
        }
        try:
            response = self.client.chat.completions.create(
                model=self.settings.llm_model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(request, ensure_ascii=False)},
                ],
                response_format={"type": "json_object"},
                max_tokens=self.settings.llm_max_tokens,
                extra_body={"thinking": {"type": "enabled"}},
                stream=False,
            )
            content = response.choices[0].message.content or "{}"
            output = json.loads(content)
            violations = self._violations(output)
            missing = [field for field in role.required_output if field not in output]
            status = "accepted_annotation" if not violations and not missing else "rejected_annotation"
            return {
                "role": role.role_id,
                "status": status,
                "output": output if status == "accepted_annotation" else {},
                "violations": violations,
                "missing_fields": missing,
                "usage": self._usage(response),
            }
        except Exception as exc:  # pragma: no cover - remote API behavior
            return {
                "role": role.role_id,
                "status": "SKIPPED_WITH_REASON",
                "reason": f"{type(exc).__name__}: {exc}",
                "output": {},
                "usage": {},
            }

    @staticmethod
    def _compact(value: dict[str, Any]) -> dict[str, Any]:
        encoded = json.dumps(value, ensure_ascii=False, default=str)
        if len(encoded) <= 20_000:
            return value
        return {"truncated": True, "sha256": hashlib.sha256(encoded.encode()).hexdigest(), "preview": encoded[:18_000]}

    @staticmethod
    def _compact_graph(graph: dict[str, Any]) -> dict[str, Any]:
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        return {
            "graph_sha256": graph.get("graph_sha256"),
            "nodes": nodes[:120],
            "edges": edges[:240],
            "truncated": len(nodes) > 120 or len(edges) > 240,
        }

    @staticmethod
    def _violations(output: dict[str, Any]) -> list[str]:
        text = json.dumps(output, ensure_ascii=False).lower()
        return [term for term in FORBIDDEN_OUTPUT_TERMS if term in text]

    @staticmethod
    def _usage(response: Any) -> dict[str, Any]:
        usage = getattr(response, "usage", None)
        if usage is None:
            return {}
        if hasattr(usage, "model_dump"):
            return usage.model_dump()
        return {
            "prompt_tokens": getattr(usage, "prompt_tokens", None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "total_tokens": getattr(usage, "total_tokens", None),
        }

    @staticmethod
    def _hard_gate(candidate: dict[str, Any], annotations: list[dict[str, Any]]) -> dict[str, Any]:
        critic = next((item for item in annotations if item.get("role") == "critic"), None)
        return {
            "candidate_level_before": candidate.get("level"),
            "candidate_level_after": candidate.get("level"),
            "promotion_allowed": False,
            "adapter_approval_allowed": False,
            "guest_replay_approval_allowed": False,
            "knowledge_gold_admission_allowed": False,
            "critic_annotation_status": critic.get("status") if critic else None,
            "decision_authority": "deterministic rules plus human review",
        }
