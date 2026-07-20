from __future__ import annotations

from ..models import RepairPlan, Target
from ..policy.guard import PolicyGuard


class SafeRepairApplier:
    def __init__(self, guard: PolicyGuard) -> None:
        self.guard = guard

    def apply(self, target: Target, plan: RepairPlan, human_confirm: bool = False) -> dict:
        out = []
        for p in plan.patch_proposals:
            level = "safe-exec" if p.get("safe_apply_default") else "dry-run"
            d = self.guard.decide(
                target=target,
                action={"scenario_id": p.get("patch_id"), "execution_level": level, "patch": p},
                campaign_id=plan.repair_plan_id,
                scan_id=plan.scan_id,
                human_confirm=human_confirm,
            )
            out.append(
                {
                    "patch_id": p.get("patch_id"),
                    "status": "simulated_apply"
                    if d["allowed"] and p.get("safe_apply_default") and human_confirm
                    else "proposal_only",
                    "policy_decision": d,
                }
            )
        return {"repair_plan_id": plan.repair_plan_id, "applied": out}
