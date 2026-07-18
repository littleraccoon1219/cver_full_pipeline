from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import DiscoverySettings
from .errors import EmergencyStopActive
from .db import DiscoveryRepository
from .knowledge import TrustedKnowledgeReader
from .llm import LLMGateway
from .llm.redaction import DataClass
from .models import ExperimentKind, Job, PromotionStage, ToolResult
from .policy import DiscoveryPolicy, PolicyContext
from .sandbox import SandboxManager
from .tools import CommandRunner, ToolRegistry

_STATIC_KINDS = {ExperimentKind.VERSION_CHECK, ExperimentKind.SEMGREP_SCAN, ExperimentKind.PATCH_DIFF}
_TRUSTED_FIXTURE_KINDS = {ExperimentKind.SYNTHETIC_FIXTURE}


class DiscoveryWorkflow:
    def __init__(
        self,
        settings: DiscoverySettings,
        repository: DiscoveryRepository,
        gateway: LLMGateway,
        *,
        project_root: str | Path = ".",
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.gateway = gateway
        self.project_root = Path(project_root).resolve()
        self.runner = CommandRunner(
            timeout_seconds=settings.max_tool_seconds,
            cancel_check=settings.emergency_stop_active,
        )
        self.tools = ToolRegistry(self.runner, project_root=self.project_root)
        self.sandboxes = SandboxManager(settings, self.runner, project_root=self.project_root)
        self.policy = DiscoveryPolicy(settings)
        self.knowledge = TrustedKnowledgeReader(settings.trusted_kb_db)

    def _assert_not_stopped(self) -> None:
        if self.settings.emergency_stop_active():
            raise EmergencyStopActive(f"emergency stop is active: {self.settings.emergency_stop_file}")

    def process(self, job: Job) -> dict[str, Any]:
        self._assert_not_stopped()
        self.settings.validate_runtime(require_llm=True)
        classification = DataClass(job.payload.get("data_class", DataClass.INTERNAL.value))
        if classification == DataClass.RESTRICTED:
            raise ValueError("restricted data cannot be sent to the cloud LLM")
        inventory = self.tools.inventory(job.target)
        synthetic_benchmark = job.payload.get("benchmark_mode") == "synthetic_pathguard"
        kb_context = self.knowledge.search("runc container runtime file descriptor namespace mount")
        planner_input = {
            "job": {
                "job_id": job.job_id,
                "kind": job.kind,
                "target_kind": job.target_kind,
                "risk": job.risk.value,
            },
            "inventory": inventory,
            "trusted_knowledge": kb_context,
            "constraints": {
                "no_arbitrary_shell": True,
                "no_exploit_payload": True,
                "allowed_experiments": [
                    kind.value
                    for kind in ExperimentKind
                    if kind != ExperimentKind.HISTORICAL_POC
                    and (synthetic_benchmark or kind != ExperimentKind.SYNTHETIC_FIXTURE)
                ],
                "synthetic_benchmark": synthetic_benchmark,
                "promotion_chain": [stage.value for stage in PromotionStage],
            },
        }
        self._assert_not_stopped()
        plan = self.gateway.plan(job.job_id, planner_input, classification=classification)
        hypothesis_reports: list[dict[str, Any]] = []
        waiting_for_approval = False

        for hypothesis in plan.get("hypotheses", []):
            self._assert_not_stopped()
            linked = self.knowledge.find_cves(hypothesis.get("known_cve_candidates", []))
            trusted_ids = [item["record_id"] for item in linked]
            hypothesis_id = self.repository.add_hypothesis(
                job.job_id,
                hypothesis,
                stage=PromotionStage.CANDIDATE_DEFECT.value,
                trusted_record_ids=trusted_ids,
            )
            experiments: list[dict[str, Any]] = []
            for raw_kind in hypothesis.get("experiment_kinds", [])[:5]:
                self._assert_not_stopped()
                try:
                    kind = ExperimentKind(raw_kind)
                except ValueError:
                    experiments.append({"kind": raw_kind, "status": "skipped_with_reason", "reason": "unknown experiment kind"})
                    continue
                if kind == ExperimentKind.SYNTHETIC_FIXTURE and not synthetic_benchmark:
                    result = {
                        "status": "skipped_with_reason",
                        "reason": "synthetic fixture is pipeline-validation evidence, not target evidence",
                    }
                    experiments.append({"kind": kind.value, **result})
                    continue
                approved = self.repository.has_approval(job.job_id, f"experiment:{kind.value}")
                decision = self.policy.decide(
                    PolicyContext(
                        job_id=job.job_id,
                        target=job.target,
                        target_kind=job.target_kind,
                        experiment_kind=kind,
                        requested_backend=job.requested_backend,
                        human_approved=approved,
                    )
                )
                experiment_id = self.repository.add_experiment(
                    job.job_id,
                    hypothesis_id,
                    kind=kind.value,
                    risk=decision.risk.value,
                    backend=decision.backend,
                    policy=decision.to_dict(),
                    status="planned",
                )
                if not decision.allowed:
                    if decision.decision == "await_approval":
                        waiting_for_approval = True
                    result = {
                        "status": "waiting_approval" if decision.decision == "await_approval" else "blocked_by_policy",
                        "reason": "; ".join(decision.reasons),
                        "policy": decision.to_dict(),
                    }
                    self.repository.finish_experiment(experiment_id, status=result["status"], result=result)
                    experiments.append({"experiment_id": experiment_id, "kind": kind.value, **result})
                    continue

                backend = self.sandboxes.require(decision.backend or "docker")
                if kind not in _STATIC_KINDS and kind not in _TRUSTED_FIXTURE_KINDS and not backend.available:
                    result = {
                        "status": "skipped_with_reason",
                        "reason": f"sandbox {backend.name} unavailable: {backend.reason}",
                        "backend": backend.to_dict(),
                    }
                    self.repository.finish_experiment(experiment_id, status=result["status"], result=result)
                    experiments.append({"experiment_id": experiment_id, "kind": kind.value, **result})
                    continue

                if kind in _STATIC_KINDS or kind in _TRUSTED_FIXTURE_KINDS:
                    tool_result = self.tools.execute(kind, target=job.target)
                else:
                    tool_result = ToolResult(
                        "skipped_with_reason",
                        kind.value,
                        [],
                        None,
                        "",
                        "",
                        0,
                        reason=(
                            f"active adapter for {kind.value} on {decision.backend} is not enabled in v1; "
                            "run the backend acceptance suite and add a reviewed adapter"
                        ),
                    )
                result = {"backend": decision.backend, "tool_result": tool_result.to_dict()}
                self.repository.finish_experiment(experiment_id, status=tool_result.status, result=result)
                experiments.append({"experiment_id": experiment_id, "kind": kind.value, **result})

            critic_input = {
                "hypothesis": hypothesis,
                "trusted_matches": linked,
                "experiments": experiments,
                "promotion_rules": {
                    "candidate_defect": "hypothesis plus at least one concrete observation",
                    "reproducible_bug": "deterministic reproduction in a controlled test",
                    "security_vulnerability": "reproduced bug plus violated security invariant and boundary impact",
                    "exploitable_zero_day": "not available to the model; requires novelty assessment, disposable lab and human review",
                },
            }
            self._assert_not_stopped()
            critique = self.gateway.critique(job.job_id, critic_input, classification=classification)
            adjudicated_stage = self._adjudicate_stage(
                experiments, critique, allow_synthetic=synthetic_benchmark
            )
            if adjudicated_stage != PromotionStage.CANDIDATE_DEFECT:
                self.repository.update_hypothesis_stage(hypothesis_id, adjudicated_stage.value)
            hypothesis_reports.append(
                {
                    "hypothesis_id": hypothesis_id,
                    "hypothesis": hypothesis,
                    "trusted_matches": linked,
                    "experiments": experiments,
                    "critique": critique,
                    "adjudicated_stage": adjudicated_stage.value,
                }
            )

        report_payload = {
            "job_id": job.job_id,
            "target": job.target,
            "inventory": inventory,
            "plan_coverage_gaps": plan.get("coverage_gaps", []),
            "hypotheses": hypothesis_reports,
            "benchmark_mode": job.payload.get("benchmark_mode"),
            "hard_limit": "No finding can be promoted to exploitable_zero_day in this environment.",
        }
        self._assert_not_stopped()
        summary = self.gateway.summarize(job.job_id, report_payload, classification=classification)
        result = {
            **report_payload,
            "summary": summary,
            "workflow_status": "waiting_approval" if waiting_for_approval else "succeeded",
        }
        artifact = self.settings.artifacts_dir / job.job_id / "report.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text(json.dumps(result, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        result["report_artifact"] = str(artifact)
        return result

    @staticmethod
    def _adjudicate_stage(
        experiments: list[dict[str, Any]],
        critique: dict[str, Any],
        *,
        allow_synthetic: bool = False,
    ) -> PromotionStage:
        reproduced = False
        invariant_evidence = False
        for experiment in experiments:
            if experiment.get("kind") == ExperimentKind.SYNTHETIC_FIXTURE.value and not allow_synthetic:
                continue
            tool = experiment.get("tool_result", {})
            stdout = tool.get("stdout", "") if isinstance(tool, dict) else ""
            if '"reproduced": true' in stdout.lower() or "CVER_SYNTHETIC_REPRODUCED" in stdout:
                reproduced = True
            if "SECURITY_INVARIANT_VIOLATION_CONFIRMED" in stdout:
                invariant_evidence = True
        recommended = critique.get("recommended_stage")
        if reproduced and invariant_evidence and recommended == PromotionStage.SECURITY_VULNERABILITY.value:
            return PromotionStage.SECURITY_VULNERABILITY
        if reproduced and recommended in {
            PromotionStage.REPRODUCIBLE_BUG.value,
            PromotionStage.SECURITY_VULNERABILITY.value,
        }:
            return PromotionStage.REPRODUCIBLE_BUG
        return PromotionStage.CANDIDATE_DEFECT
