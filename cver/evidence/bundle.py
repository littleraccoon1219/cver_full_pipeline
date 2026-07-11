from __future__ import annotations
from ..models import Evidence, EvidenceBundle, Target

class EvidenceBundler:
    def build(self, scan_id: str, target: Target, evidences: list[Evidence], corr: str) -> EvidenceBundle:
        text = " ".join([f"{e.category}:{e.key}:{e.value} {e.evidence_snippet}" for e in evidences]).lower()
        summary = {
            "has_docker_socket": "docker.sock" in text,
            "has_privileged_or_cap_sys_admin": "privileged" in text or "sys_admin" in text,
            "has_hostpath": "hostpath" in text or "/host" in text or "host_filesystem" in text,
            "has_seccomp_unconfined": "unconfined" in text,
            "has_kata_runtimeclass": "kata" in text,
            "runtime_runc_version": "1.1.10" if "1.1.10" in text else "unknown",
            "evidence_count": len(evidences)
        }
        return EvidenceBundle(scan_id, target.target_id, evidences, summary, corr)
