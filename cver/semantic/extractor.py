from __future__ import annotations
from ..models import CVEKnowledge, Finding, Precondition
from .taxonomy import infer_fine_type, macro_from_root

class SemanticExtractor:
    def extract(self, finding: Finding, knowledge: CVEKnowledge | None) -> Finding:
        if knowledge:
            sem = knowledge.semantic_annotations
            finding.root_cause = sem.get("root_cause","unknown")
            finding.fine_type = sem.get("fine_type", finding.fine_type)
            finding.macro_type = macro_from_root(finding.root_cause, finding.type)
            finding.attack_surface = sem.get("attack_surface", finding.component)
            finding.impact_boundary = sem.get("impact_boundary","unknown")
            finding.required_capability = sem.get("required_capability","unknown")
            finding.escape_primitives = list(sem.get("escape_primitives", []))
            finding.mitigation_class = sem.get("mitigation_class","unknown")
            finding.confidence = max(float(finding.confidence), float(sem.get("confidence", .5)))
            return finding
        text = f"{finding.title} {finding.description} {finding.component} {finding.cve_id}"
        finding.fine_type = infer_fine_type(text)
        if finding.type == "misconfiguration":
            finding.macro_type = "misconfiguration"; finding.root_cause = "misconfiguration_privilege"
        elif "kubernetes" in text.lower() or "k8s" in text.lower():
            finding.macro_type = "orchestration"; finding.root_cause = "orchestration_config"
        elif any(x in text.lower() for x in ["runc","containerd","docker"]):
            finding.macro_type = "runtime"; finding.root_cause = "runtime_isolation"
        return finding

    def preconditions(self, knowledge: CVEKnowledge | None, finding: Finding) -> tuple[list[Precondition], list[Precondition]]:
        if knowledge:
            req = [Precondition(**{k:v for k,v in x.items() if k in Precondition.__dataclass_fields__}) for x in knowledge.semantic_annotations.get("required_conditions", [])]
            blk = [Precondition(**{k:v for k,v in x.items() if k in Precondition.__dataclass_fields__}) for x in knowledge.semantic_annotations.get("blocking_conditions", [])]
            return req, blk
        if finding.fine_type in ("dangerous_capability","privileged_container"):
            return [Precondition("dangerous_capability","CAP_SYS_ADMIN in container.capabilities OR privileged == true","rule_inferred",finding.description,.7,False)], [Precondition("drop_cap_sys_admin","CAP_SYS_ADMIN not in capabilities AND privileged == false","rule_inferred","",.7,False)]
        return [Precondition("affected_component_present",f"component == {finding.component}","rule_inferred",finding.description,.5,False)], []
