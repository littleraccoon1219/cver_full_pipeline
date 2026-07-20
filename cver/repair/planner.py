from __future__ import annotations

from ..ids import new_id
from ..models import DefenseScore, Finding, RepairPlan, Target
from ..storage import read_json


class RepairPlanner:
    def __init__(self, path: str = "data/repair/repair_templates.json") -> None:
        self.templates = read_json(path).get("templates", [])

    def plan(
        self,
        target: Target,
        scan_id: str,
        findings: list[Finding],
        score: DefenseScore,
        safe_apply_allowed: bool,
        corr: str,
    ) -> RepairPlan:
        props = []
        retests = []
        rollback = []
        for f in findings:
            matches = [t for t in self.templates if t.get("match_fine_type") == f.fine_type]
            if not matches and f.fine_type in ("dangerous_capability", "privileged_container"):
                matches = [t for t in self.templates if t.get("template_id") == "drop-cap-sys-admin"]
            for t in matches:
                pid = new_id("patch")
                props.append(
                    {
                        "patch_id": pid,
                        "template_id": t.get("template_id"),
                        "finding_id": f.finding_id,
                        "repair_class": t.get("repair_class"),
                        "summary": t.get("summary"),
                        "docker_hint": t.get("docker_hint"),
                        "k8s_patch_hint": t.get("k8s_patch_hint"),
                        "safe_apply_default": bool(
                            safe_apply_allowed and t.get("repair_class") in ("configuration", "k8s_policy")
                        ),
                        "human_confirm_required": True,
                        "source": "template",
                    }
                )
                retests.append({"patch_id": pid, "finding_id": f.finding_id, "retest": t.get("retest")})
                rollback.append(
                    {
                        "patch_id": pid,
                        "rollback": "Restore original Docker/K8s manifest from captured evidence snapshot.",
                    }
                )
        return RepairPlan(
            new_id("repair"), scan_id, target.target_id, props, retests, safe_apply_allowed, rollback, corr
        )
