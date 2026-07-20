from __future__ import annotations

from ..models import RepairPlan


class RetestPlanner:
    def retest(self, plan: RepairPlan) -> dict:
        return {
            "repair_plan_id": plan.repair_plan_id,
            "status": "planned",
            "steps": plan.retest_plan,
            "note": "Run full-pipeline again after approved patches; compare Finding diff and DefenseScore diff.",
        }
