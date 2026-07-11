from __future__ import annotations
from typing import Any
from .. import db
from ..models import Target

FORBIDDEN = {"arbitrary_shell","real_escape_poc","exploit_generation","destructive_write","kernel_exploit","vm_escape_poc","host_file_write","load_untrusted_bpf"}

class PolicyGuard:
    def __init__(self, profile: dict[str,Any], db_path: str) -> None:
        self.profile = profile; self.db_path = db_path
    def decide(self, *, target: Target, action: dict[str,Any], campaign_id: str="", scan_id: str="", human_confirm: bool=False) -> dict[str,Any]:
        allowed=True; reasons=[]; level=action.get("execution_level","dry-run")
        if self.profile.get("policy",{}).get("require_lab_label", True) and target.labels.get("cver-lab") != "true":
            allowed=False; reasons.append("target lacks cver-lab=true")
        if target.name.startswith(("http://","https://")):
            allowed=False; reasons.append("public URL targets are not allowed")
        if action.get("requested_forbidden_actions") and (set(action["requested_forbidden_actions"]) & FORBIDDEN):
            allowed=False; reasons.append("requested forbidden action")
        if level not in ("dry-run","safe-exec","lab-emulation"):
            allowed=False; reasons.append(f"execution level {level} is not allowed")
        if level != "dry-run" and self.profile.get("redteam",{}).get("require_human_confirm", True) and not human_confirm:
            allowed=False; reasons.append("human confirmation required for non-dry-run")
        record={"allowed":allowed,"decision":"allow" if allowed else "deny","reason":"; ".join(reasons) if reasons else "policy passed","action":action,"target_id":target.target_id,"scan_id":scan_id,"campaign_id":campaign_id}
        db.audit(self.db_path, record)
        return record
