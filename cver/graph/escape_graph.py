from __future__ import annotations
from ..ids import stable_id
from ..models import EscapeGraph, ExploitabilityResult, Finding, GraphEdge, GraphNode

class EscapeGraphBuilder:
    def build(self, findings: list[Finding], results: list[ExploitabilityResult], scan_id: str, target_id: str, corr: str) -> EscapeGraph:
        nodes=[GraphNode("node-runtime-boundary","RuntimeBoundary","Container/Host Boundary",{"boundary":"shared_kernel_or_microvm"})]
        edges=[]; by={r.finding_id:r for r in results}
        for f in findings:
            fn = f"node-{f.finding_id}"
            nodes.append(GraphNode(fn,"Finding",f.title,{"severity":f.severity,"macro_type":f.macro_type,"fine_type":f.fine_type}))
            if f.cve_id:
                cn=f"node-cve-{f.cve_id}"
                nodes.append(GraphNode(cn,"CVEKnowledge",f.cve_id,{"component":f.component}))
                edges.append(GraphEdge(fn,cn,"maps_to",{}))
            for ep in f.escape_primitives or []:
                pn=stable_id("node-primitive",f.finding_id,ep)
                nodes.append(GraphNode(pn,"Capability",ep,{})); edges.append(GraphEdge(fn,pn,"requires",{}))
                if "host" in (f.impact_boundary or ""):
                    edges.append(GraphEdge(pn,"node-runtime-boundary","crosses_boundary",{"impact_boundary":f.impact_boundary}))
            r=by.get(f.finding_id)
            if r:
                rn=f"node-exploit-{f.finding_id}"
                nodes.append(GraphNode(rn,"ExploitabilityResult",r.exploitability_label,{"score":r.exploitability_score}))
                edges.append(GraphEdge(fn,rn,"evaluated_as",{}))
                for m in r.matched_preconditions:
                    pn=stable_id("node-precondition",f.finding_id,m.get("name"))
                    nodes.append(GraphNode(pn,"Precondition",m.get("name","precondition"),{"matched":True,"expr":m.get("expr")}))
                    edges.append(GraphEdge(pn,fn,"matches",{}))
        return EscapeGraph(stable_id("graph",scan_id,target_id),nodes,edges,self.mermaid(nodes,edges),scan_id,target_id,corr)

    def safe(self, s: str) -> str:
        return "".join(c if c.isalnum() else "_" for c in s)

    def mermaid(self, nodes, edges) -> str:
        lines=["flowchart TD"]; seen=set()
        for n in nodes:
            if n.node_id in seen: continue
            seen.add(n.node_id)
            label=n.label.replace('"',"'")[:60]
            lines.append(f'  {self.safe(n.node_id)}["{n.node_type}: {label}"]')
        for e in edges:
            lines.append(f"  {self.safe(e.source)} -- {e.relation} --> {self.safe(e.target)}")
        return "\n".join(lines)
