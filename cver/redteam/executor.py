from __future__ import annotations
from ..ids import new_id
from ..models import RedTeamCampaign, Target
from ..policy.guard import PolicyGuard

class RedTeamExecutor:
    def __init__(self, guard: PolicyGuard) -> None:
        self.guard = guard
    def execute(self, target: Target, scan_id: str, planned: list[dict], execution_level: str, corr: str) -> RedTeamCampaign:
        cid = new_id("campaign"); results=[]; decisions=[]
        for p in planned:
            s = p["scenario"]
            action={"scenario_id":s["scenario_id"],"execution_level":execution_level,"forbidden_actions":s.get("forbidden_actions",[])}
            d = self.guard.decide(target=target, action=action, campaign_id=cid, scan_id=scan_id, human_confirm=False)
            decisions.append(d)
            if not d["allowed"]:
                results.append({"scenario_id":s["scenario_id"],"status":"blocked_by_policy","blocked":True,"defense_observed":True,"evidence":d["reason"]})
            else:
                results.append({"scenario_id":s["scenario_id"],"status":"dry_run_triggered" if execution_level=="dry-run" else "safe_exec_simulated","blocked":False,"defense_observed":False,"finding_id":p.get("finding_id"),"expected_defense_points":s.get("expected_defense_points",[]),"retest_logic":s.get("retest_logic"),"poc_policy":"no_real_poc"})
        return RedTeamCampaign(cid, scan_id, target.target_id, planned, results, execution_level, decisions, corr)
