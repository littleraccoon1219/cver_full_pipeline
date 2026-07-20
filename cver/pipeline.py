from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from . import db
from .benchmark.runner import BenchmarkRunner
from .config import load_profile
from .defense.scorer import DefenseScorer
from .evidence.bundle import EvidenceBundler
from .graph.escape_graph import EscapeGraphBuilder
from .ids import new_id, stable_id
from .logging_utils import EventLogger, now_iso
from .models import Scan, Target, to_dict
from .normalizer import FindingNormalizer
from .policy.guard import PolicyGuard
from .reasoner.exploitability import ExploitabilityReasoner
from .redteam.executor import RedTeamExecutor
from .redteam.planner import RedTeamPlanner
from .repair.applier import SafeRepairApplier
from .repair.planner import RepairPlanner
from .repair.retest import RetestPlanner
from .report.generator import ReportGenerator
from .scanners import ScannerManager
from .semantic.extractor import SemanticExtractor
from .storage import write_json
from .vulndb import VulnDB


class CVERPipeline:
    def __init__(self, profile_name: str = "demo") -> None:
        self.profile = load_profile(profile_name)
        self.profile_name = self.profile.get("profile", profile_name)
        self.db_path = self.profile["storage"]["db_path"]
        db.init_db(self.db_path)
        self.logger = EventLogger()
        self.vulndb = VulnDB(self.db_path)
        self.vulndb.import_seed()

    def doctor(self) -> dict[str, Any]:
        import shutil
        import sys

        return {
            "python": sys.version.split()[0],
            "profile": self.profile_name,
            "db_path": self.db_path,
            "tools": {t: bool(shutil.which(t)) for t in ["docker", "trivy", "syft", "kubectl", "kata-runtime"]},
            "policy": self.profile.get("policy", {}),
        }

    def init_db(self) -> dict[str, Any]:
        db.init_db(self.db_path)
        n = self.vulndb.import_seed()
        return {"ok": True, "db_path": self.db_path, "imported_cve_records": n}

    def run(self, target: Target, mode: str = "full-pipeline") -> dict[str, Any]:
        t0 = time.time()
        scan_id = new_id("scan")
        corr = stable_id("corr", scan_id, target.target_id)
        scan = Scan(scan_id, target.target_id, mode, self.profile_name, status="running", correlation_id=corr)
        db.upsert_json(self.db_path, "targets", target.target_id, to_dict(target))
        db.upsert_json(self.db_path, "scans", scan.scan_id, to_dict(scan))
        self.logger.emit(
            stage="start",
            status="running",
            scan_id=scan_id,
            target_id=target.target_id,
            correlation_id=corr,
            input_hash=stable_id("in", target.name),
        )

        artifacts = []
        findings = []
        evidences = []
        bundle = None
        expl = []
        graph = None
        campaign = None
        score = None
        repair = None
        apply = None
        retest = None

        if mode in ("scan-only", "full-pipeline"):
            artifacts = ScannerManager().scan(target, self.profile)
            findings, evidences = FindingNormalizer().normalize(artifacts, target, scan_id, corr)
            for f in findings:
                db.upsert_json(self.db_path, "findings", f.finding_id, to_dict(f))
            for e in evidences:
                db.upsert_json(self.db_path, "evidences", e.evidence_id, to_dict(e))
            self.logger.emit(
                stage="scan",
                status="ok",
                scan_id=scan_id,
                target_id=target.target_id,
                correlation_id=corr,
                output={"findings": len(findings), "evidences": len(evidences)},
            )
        if mode == "scan-only":
            return self._finish(
                scan,
                target,
                artifacts,
                findings,
                evidences,
                bundle,
                expl,
                graph,
                campaign,
                score,
                repair,
                apply,
                retest,
                t0,
            )

        if not findings:
            artifacts = ScannerManager().scan(target, self.profile)
            findings, evidences = FindingNormalizer().normalize(artifacts, target, scan_id, corr)

        extractor = SemanticExtractor()
        required = {}
        blocking = {}
        for f in findings:
            k = self.vulndb.get(f.cve_id) if f.cve_id else None
            extractor.extract(f, k)
            req, blk = extractor.preconditions(k, f)
            required[f.finding_id] = req
            blocking[f.finding_id] = blk
        bundle = EvidenceBundler().build(scan_id, target, evidences, corr)

        if mode in ("reason-only", "full-pipeline", "redteam-only"):
            reasoner = ExploitabilityReasoner()
            expl = [
                reasoner.evaluate(f, required.get(f.finding_id, []), blocking.get(f.finding_id, []), bundle)
                for f in findings
            ]
            graph = EscapeGraphBuilder().build(findings, expl, scan_id, target.target_id, corr)
            self.logger.emit(
                stage="reason",
                status="ok",
                scan_id=scan_id,
                target_id=target.target_id,
                correlation_id=corr,
                output={"results": len(expl)},
            )
        if mode == "reason-only":
            return self._finish(
                scan,
                target,
                artifacts,
                findings,
                evidences,
                bundle,
                expl,
                graph,
                campaign,
                score,
                repair,
                apply,
                retest,
                t0,
            )

        planned = RedTeamPlanner().plan(findings, expl, graph)
        guard = PolicyGuard(self.profile, self.db_path)
        campaign = RedTeamExecutor(guard).execute(
            target, scan_id, planned, self.profile.get("redteam", {}).get("execution_level", "dry-run"), corr
        )
        self.logger.emit(
            stage="redteam",
            status="ok",
            scan_id=scan_id,
            target_id=target.target_id,
            campaign_id=campaign.campaign_id,
            correlation_id=corr,
            output={"planned": len(planned)},
        )
        if mode == "redteam-only":
            return self._finish(
                scan,
                target,
                artifacts,
                findings,
                evidences,
                bundle,
                expl,
                graph,
                campaign,
                score,
                repair,
                apply,
                retest,
                t0,
            )

        score = DefenseScorer().score(findings, expl, bundle, campaign)
        repair = RepairPlanner().plan(
            target, scan_id, findings, score, self.profile.get("repair", {}).get("safe_apply", False), corr
        )
        apply = SafeRepairApplier(guard).apply(target, repair, human_confirm=False)
        retest = RetestPlanner().retest(repair)
        return self._finish(
            scan,
            target,
            artifacts,
            findings,
            evidences,
            bundle,
            expl,
            graph,
            campaign,
            score,
            repair,
            apply,
            retest,
            t0,
        )

    def _finish(
        self,
        scan,
        target,
        artifacts,
        findings,
        evidences,
        bundle,
        expl,
        graph,
        campaign,
        score,
        repair,
        apply,
        retest,
        t0: float,
    ) -> dict[str, Any]:
        scan.finished_at = now_iso()
        scan.status = "finished"
        payload = {
            "target": to_dict(target),
            "scan": to_dict(scan),
            "artifacts": [a.__dict__ for a in artifacts],
            "findings": to_dict(findings),
            "evidences": to_dict(evidences),
            "evidence_bundle": to_dict(bundle) if bundle else None,
            "exploitability_results": to_dict(expl),
            "escape_graph": to_dict(graph) if graph else {"nodes": [], "edges": [], "mermaid": "flowchart TD"},
            "redteam_campaign": to_dict(campaign)
            if campaign
            else {"planned_scenarios": [], "results": [], "policy_decisions": []},
            "defense_score": to_dict(score) if score else {"total_score": None, "dimensions": {}, "deductions": []},
            "repair_plan": to_dict(repair) if repair else {"patch_proposals": [], "retest_plan": []},
            "repair_apply": apply,
            "retest": retest,
            "runtime_ms": int((time.time() - t0) * 1000),
            "safety_notice": "No real escape PoC executed. RedTeam actions are dry-run/safe-exec/lab-emulation only.",
        }
        run_dir = Path(self.profile["storage"]["output_dir"]) / scan.scan_id
        report = ReportGenerator().generate(run_dir, payload)
        payload["report"] = to_dict(report)
        write_json(run_dir / "report.json", payload)
        db.upsert_json(self.db_path, "scans", scan.scan_id, to_dict(scan))
        db.upsert_json(self.db_path, "reports", report.report_id, to_dict(report))
        self.logger.emit(
            stage="finish",
            status="ok",
            scan_id=scan.scan_id,
            target_id=target.target_id,
            correlation_id=scan.correlation_id,
            output={"report": to_dict(report)},
        )
        return payload

    def demo(self) -> dict[str, Any]:
        return self.run(
            Target("demo/nginx:lab", "image", labels={"cver-lab": "true"}, backend_hint="mock"), "full-pipeline"
        )

    def benchmark(self) -> dict[str, Any]:
        report = self.demo()
        bench = BenchmarkRunner().run(report, self.profile_name)
        db.upsert_json(self.db_path, "benchmark_runs", bench.benchmark_id, to_dict(bench))
        return {"benchmark": to_dict(bench), "source_scan_id": report["scan"]["scan_id"]}
