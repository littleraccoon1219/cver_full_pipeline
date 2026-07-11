from __future__ import annotations
from .scenario import load_scenarios
from ..models import EscapeGraph, ExploitabilityResult, Finding

class RedTeamPlanner:
    def plan(self, findings: list[Finding], results: list[ExploitabilityResult], graph: EscapeGraph) -> list[dict]:
        scenarios = {s["scenario_id"]: s for s in load_scenarios()}
        planned=[]
        for f in findings:
            cands=[]
            if f.fine_type == "docker_socket_mount": cands.append("docker_sock_mount")
            if f.fine_type in ("dangerous_capability","privileged_container") or "CAP_SYS_ADMIN" in f.required_capability:
                cands += ["privileged_container","ebpf_load_probe"]
            if f.fine_type in ("container_runtime_escape",): cands.append("runtime_version_exposure")
            if f.fine_type in ("hostpath_mount","k8s_volume_hostpath_or_subpath"): cands.append("hostpath_mount")
            if f.macro_type == "microvm": cands.append("kata_runtimeclass_probe")
            for sid in dict.fromkeys(cands):
                if sid in scenarios:
                    planned.append({"scenario":scenarios[sid],"finding_id":f.finding_id,"triggered_by":{"fine_type":f.fine_type,"macro_type":f.macro_type,"severity":f.severity},"execution_level":"dry-run"})
        return planned
