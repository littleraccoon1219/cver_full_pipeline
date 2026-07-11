from __future__ import annotations
from ..models import Evidence

def expr_matches(expr: str, evidences: list[Evidence]) -> tuple[bool,str]:
    text = " ".join([f"{e.key}={e.value} {e.evidence_snippet}" for e in evidences]).lower()
    e = expr.lower()
    checks = [
      ("mounts contains /var/run/docker.sock", "docker.sock"),
      ("docker.sock", "docker.sock"),
      ("cap_sys_admin", "sys_admin"),
      ("sys_admin", "sys_admin"),
      ("privileged", "privileged"),
      ("runtime.runc.version < 1.1.12", "1.1.10"),
      ("runtime.name contains runc", "runc"),
      ("hostpath", "hostpath"),
      ("subpath", "subpath"),
      ("runtime.kind == kata", "kata"),
      ("runtime.is_microvm == true", "kata"),
      ("seccomp", "seccomp"),
    ]
    for needle, token in checks:
        if needle in e and token in text:
            return True, f"matched heuristic: {needle}"
    if "not contains /var/run/docker.sock" in e and "docker.sock" not in text:
        return True, "docker.sock absent"
    if "component_version >= fixed_version" in e or "patched" in e:
        return False, "patched/fixed condition not confirmed from environment"
    return False, "no matching evidence"
