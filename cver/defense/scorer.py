from __future__ import annotations
from ..models import DefenseScore, EvidenceBundle, ExploitabilityResult, Finding, RedTeamCampaign

class DefenseScorer:
    def score(self, findings: list[Finding], results: list[ExploitabilityResult], bundle: EvidenceBundle, campaign: RedTeamCampaign) -> DefenseScore:
        sev=0; exp=0; red=0; deductions=[]
        for f in findings:
            pts={"CRITICAL":18,"HIGH":12,"MEDIUM":7,"LOW":3}.get(f.severity.upper(),5)
            sev += pts; deductions.append({"dimension":"vulnerability_severity","points":pts,"reason":f"{f.severity} {f.title}","evidence_refs":f.evidence_refs})
        for key,pts,reason in [("has_docker_socket",20,"Docker socket exposed"),("has_privileged_or_cap_sys_admin",15,"Privileged/CAP_SYS_ADMIN"),("has_hostpath",10,"Host filesystem exposure"),("has_seccomp_unconfined",8,"Seccomp unconfined")]:
            if bundle.summary.get(key):
                exp += pts; deductions.append({"dimension":"environment_exposure","points":pts,"reason":reason,"evidence_refs":[]})
        for r in campaign.results:
            if r.get("status") in ("dry_run_triggered","safe_exec_simulated") and not r.get("defense_observed"):
                red += 8; deductions.append({"dimension":"redteam_result","points":8,"reason":f"Scenario {r.get('scenario_id')} triggered without observed block","evidence_refs":[]})
        bonus = 8 if bundle.summary.get("has_kata_runtimeclass") else 0
        trust = min(5, bundle.summary.get("evidence_count",0))
        total=max(0,min(100,100-sev-exp-red+bonus+trust))
        dims={"vulnerability_severity":max(0,100-sev),"environment_exposure":max(0,100-exp),"isolation_strength":88 if bundle.summary.get("has_kata_runtimeclass") else 55,"runtime_protection":35 if bundle.summary.get("has_seccomp_unconfined") else 60,"k8s_policy":60,"redteam_blocking":max(0,100-red),"evidence_trust":min(100,50+trust*10)}
        return DefenseScore(round(total,2), dims, deductions, [e.evidence_id for e in bundle.evidences], round(max(0,total-(5 if bundle.summary.get("has_kata_runtimeclass") else 0)),2), round(min(100,total+(10 if bundle.summary.get("has_kata_runtimeclass") else 0)),2), bundle.scan_id, bundle.target_id, bundle.correlation_id)
