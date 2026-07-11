from __future__ import annotations
from typing import Any
from .ids import stable_id
from .models import Evidence, Finding, Target
from .scanners import ScanArtifact

def sev_rank(s: str) -> int:
    return {"UNKNOWN":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}.get((s or "UNKNOWN").upper(),0)

class FindingNormalizer:
    def normalize(self, artifacts: list[ScanArtifact], target: Target, scan_id: str, correlation_id: str) -> tuple[list[Finding], list[Evidence]]:
        findings: list[Finding] = []
        evidences: list[Evidence] = []
        for a in artifacts:
            if a.source == "mock-composite":
                findings.extend(self._mock(a.data, target, scan_id, correlation_id))
            elif a.source == "trivy":
                findings.extend(self._trivy(a.data, target, scan_id, correlation_id))
            elif a.source == "docker-inspect":
                evidences.extend(self._docker_evidence(a.data, target, scan_id, correlation_id))
                findings.extend(self._docker_findings(a.data, target, scan_id, correlation_id))
            elif a.source == "k8s-inspect":
                evidences.extend(self._k8s_evidence(a.data, target, scan_id, correlation_id))
            elif a.source == "kata-inspect":
                evidences.append(Evidence("evidence-kata-runtimeclass", a.source, "kata", "runtimeclass", a.data, "Kata RuntimeClass detected or demo evidence", .8, scan_id, target.target_id, correlation_id=correlation_id))
            elif a.source == "syft":
                evidences.append(Evidence("evidence-sbom", a.source, "sbom", "packages", a.data, "SBOM packages extracted", .8, scan_id, target.target_id, correlation_id=correlation_id))
        evidences.extend(self._generic_evidence(target, scan_id, correlation_id))
        return self._dedup_findings(findings), self._dedup_evidences(evidences)

    def _mock(self, data: dict[str,Any], target: Target, scan_id: str, corr: str) -> list[Finding]:
        out=[]
        for f in data.get("findings", []):
            out.append(Finding(f.get("finding_id") or stable_id("finding", f.get("dedup_key", f.get("title"))), f.get("source","mock"), f.get("type","unknown"), f.get("title",""), f.get("description",""), f.get("severity","UNKNOWN"), f.get("cve_id",""), f.get("component","unknown"), f.get("package_name",""), f.get("installed_version","unknown"), f.get("fixed_version","unknown"), f.get("evidence_refs",[]), {"raw_source":"data/demo/findings_demo.json"}, float(f.get("confidence",.7)), f.get("dedup_key",""), scan_id, target.target_id, corr))
        return out

    def _trivy(self, data: dict[str,Any], target: Target, scan_id: str, corr: str) -> list[Finding]:
        out=[]
        for r in data.get("Results",[]) or []:
            for v in r.get("Vulnerabilities",[]) or []:
                cve=v.get("VulnerabilityID",""); pkg=v.get("PkgName","")
                out.append(Finding(stable_id("finding",cve,pkg,v.get("InstalledVersion")), "trivy", "vulnerability", v.get("Title") or cve, v.get("Description",""), v.get("Severity","UNKNOWN"), cve, pkg or r.get("Target","unknown"), pkg, v.get("InstalledVersion","unknown"), v.get("FixedVersion","unknown"), [], {"scanner":"trivy"}, .85, f"{cve}:{pkg}", scan_id, target.target_id, corr))
        return out

    def _docker_evidence(self, data: dict[str,Any], target: Target, scan_id: str, corr: str) -> list[Evidence]:
        out=[]
        hc=data.get("HostConfig",{}) or {}; mounts=data.get("Mounts",[]) or {}; labels=(data.get("Config",{}) or {}).get("Labels",{}) or {}
        out.append(Evidence("evidence-docker-hostconfig","docker-inspect","docker","HostConfig",hc,"Docker HostConfig",.85,scan_id,target.target_id,correlation_id=corr))
        if labels: out.append(Evidence("evidence-target-labels","docker-inspect","target","labels",labels,str(labels),.9,scan_id,target.target_id,correlation_id=corr))
        for m in mounts:
            if m.get("Destination")=="/var/run/docker.sock" or m.get("Source")=="/var/run/docker.sock":
                out.append(Evidence("evidence-docker-sock-mount","docker-inspect","mount","docker.sock",m,"Docker socket is mounted",.95,scan_id,target.target_id,correlation_id=corr))
            if m.get("Source")=="/" or m.get("Destination")=="/host":
                out.append(Evidence("evidence-hostpath","docker-inspect","mount","host_filesystem",m,"Host filesystem mount detected",.85,scan_id,target.target_id,correlation_id=corr))
        caps=hc.get("CapAdd") or []
        if hc.get("Privileged") or "SYS_ADMIN" in caps or "CAP_SYS_ADMIN" in caps:
            out.append(Evidence("evidence-capabilities","docker-inspect","capability","dangerous_capabilities",{"privileged":hc.get("Privileged"),"cap_add":caps},"Privileged or CAP_SYS_ADMIN detected",.9,scan_id,target.target_id,correlation_id=corr))
        if any("seccomp=unconfined" in str(x) for x in hc.get("SecurityOpt") or []):
            out.append(Evidence("evidence-seccomp","docker-inspect","lsm","seccomp","unconfined","Seccomp unconfined",.9,scan_id,target.target_id,correlation_id=corr))
        return out

    def _docker_findings(self, data: dict[str,Any], target: Target, scan_id: str, corr: str) -> list[Finding]:
        out=[]; hc=data.get("HostConfig",{}) or {}; mounts=data.get("Mounts",[]) or []
        if any(m.get("Destination")=="/var/run/docker.sock" or m.get("Source")=="/var/run/docker.sock" for m in mounts):
            out.append(Finding("finding-docker-sock","docker-inspect","misconfiguration","Docker socket mounted","Docker socket is exposed to container.","CRITICAL","CONFIG-DOCKER-SOCK","docker","docker-runtime","unknown","not_applicable",["evidence-docker-sock-mount"],{"scanner":"docker-inspect"},.98,"CONFIG-DOCKER-SOCK:/var/run/docker.sock",scan_id,target.target_id,corr))
        caps=hc.get("CapAdd") or []
        if hc.get("Privileged") or "SYS_ADMIN" in caps or "CAP_SYS_ADMIN" in caps:
            out.append(Finding("finding-cap-sys-admin","docker-inspect","misconfiguration","Dangerous capability CAP_SYS_ADMIN","Container is privileged or has CAP_SYS_ADMIN.","HIGH","CONFIG-CAP-SYS-ADMIN","docker","container-config","unknown","not_applicable",["evidence-capabilities"],{"scanner":"docker-inspect"},.9,"CONFIG-CAP-SYS-ADMIN",scan_id,target.target_id,corr))
        return out

    def _k8s_evidence(self, data: dict[str,Any], target: Target, scan_id: str, corr: str) -> list[Evidence]:
        out=[]; meta=data.get("metadata",{}) or {}; spec=data.get("spec",{}) or {}
        if meta.get("labels"): out.append(Evidence("evidence-target-labels","k8s-inspect","target","labels",meta.get("labels"),str(meta.get("labels")),.9,scan_id,target.target_id,correlation_id=corr))
        if spec: out.append(Evidence("evidence-k8s-security-context","k8s-inspect","k8s","pod_spec",spec,"Kubernetes Pod spec security context",.85,scan_id,target.target_id,correlation_id=corr))
        if spec.get("runtimeClassName") == "kata": out.append(Evidence("evidence-kata-runtimeclass","k8s-inspect","kata","runtimeclass","kata","Kata RuntimeClass selected",.9,scan_id,target.target_id,correlation_id=corr))
        return out

    def _generic_evidence(self, target: Target, scan_id: str, corr: str) -> list[Evidence]:
        return [Evidence("evidence-runtime-runc-version","runtime-inspect","runtime","runc.version","1.1.10","runc version 1.1.10 from demo evidence",.85,scan_id,target.target_id,correlation_id=corr), Evidence("evidence-host-kernel","host-inspect","host","kernel","demo-kernel","Host kernel demo evidence",.6,scan_id,target.target_id,correlation_id=corr)]

    def _dedup_findings(self, fs: list[Finding]) -> list[Finding]:
        by={}
        for f in fs:
            k=f.dedup_key or f.finding_id
            if k not in by or sev_rank(f.severity) > sev_rank(by[k].severity):
                by[k]=f
        return list(by.values())

    def _dedup_evidences(self, es: list[Evidence]) -> list[Evidence]:
        by={e.evidence_id:e for e in es}
        return list(by.values())
