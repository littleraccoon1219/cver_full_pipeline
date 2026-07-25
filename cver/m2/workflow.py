from __future__ import annotations

import copy
import hashlib
import json
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable

from .config import M2Settings
from .db import M2Repository
from .environment import EnvironmentCollector
from .exploitability import ExploitabilityEvaluator
from .harnesses import HarnessManager
from .kata import KataController
from .knowledge import ExternalCandidateCollector, TrustedKnowledgeMatcher
from .llm import DeepSeekReviewer
from .models import Finding, FindingStatus, Severity, to_dict
from .reporting import ReportWriter
from .sources import SOURCES, SourceManager
from .static_analysis import AttackSurfaceScanner, KataConfigAuditor
from .zeroday import ZeroDayGate


class M2Workflow:
    PHASES = (
        "environment",
        "sources",
        "knowledge",
        "static_analysis",
        "llm_review",
        "harness_build",
        "fuzzing",
        "kata_validation",
        "exploitability",
        "zero_day_gate",
        "report",
    )

    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings
        self.settings.ensure_directories()
        self.repository = M2Repository(settings.runtime_db)
        self.repository.migrate()

    def submit(self, request: dict[str, Any]) -> str:
        profile = str(request.get("profile") or self.settings.budget_profile)
        return self.repository.create_job("kata-discovery", profile, request)

    def run_new(self, request: dict[str, Any]) -> dict[str, Any]:
        job_id = self.submit(request)
        return self.run(job_id)

    def run(self, job_id: str, *, resume: bool = False) -> dict[str, Any]:
        job = self.repository.get_job(job_id)
        if job is None:
            raise KeyError(f"M2 job not found: {job_id}")
        request = dict(job["request"])
        result = copy.deepcopy(job.get("result") or {}) if resume else {}
        result.setdefault("job_id", job_id)
        result.setdefault("profile", job["profile"])
        result.setdefault(
            "safety_boundary",
            "non-weaponized evidence only; no automatic guest-to-host escape payload generation or execution",
        )
        result.setdefault("phases", {})
        result.setdefault("findings", [])
        result.setdefault("evidence", [])
        self.repository.update_job(job_id, status="running", phase="starting", result=result, error="")
        self.repository.audit(str(request.get("actor", "m2-operator")), "m2.job.started", "job", job_id, request)

        handlers: dict[str, Callable[[str, dict[str, Any], dict[str, Any]], dict[str, Any]]] = {
            "environment": self._environment,
            "sources": self._sources,
            "knowledge": self._knowledge,
            "static_analysis": self._static,
            "llm_review": self._llm,
            "harness_build": self._harness_build,
            "fuzzing": self._fuzz,
            "kata_validation": self._kata,
            "exploitability": self._exploitability,
            "zero_day_gate": self._zero_day,
            "report": self._report,
        }
        try:
            for phase in self.PHASES:
                existing = result["phases"].get(phase)
                if resume and isinstance(existing, dict) and existing.get("status") in {
                    "ok",
                    "completed",
                    "passed",
                    "sealed",
                    "skipped_with_reason",
                }:
                    continue
                self.repository.update_job(job_id, phase=phase, result=result)
                self.repository.event(job_id, "info", "phase.started", f"M2 phase started: {phase}")
                phase_result = handlers[phase](job_id, request, result)
                result["phases"][phase] = phase_result
                self.repository.update_job(job_id, phase=phase, result=result)
                self.repository.event(
                    job_id,
                    "info",
                    "phase.finished",
                    f"M2 phase finished: {phase}",
                    {"status": phase_result.get("status")},
                )
            status = self._final_status(result)
            result["status"] = status
            self.repository.update_job(job_id, status=status, phase="finished", result=result)
            self.repository.audit(
                str(request.get("actor", "m2-operator")),
                "m2.job.finished",
                "job",
                job_id,
                {"status": status},
            )
            return self.repository.get_job(job_id) or result
        except Exception as exc:
            result["status"] = "failed"
            result["failure"] = {"type": type(exc).__name__, "message": str(exc)}
            self.repository.event(
                job_id,
                "error",
                "job.failed",
                f"{type(exc).__name__}: {exc}",
                {"traceback": traceback.format_exc()[-12000:]},
            )
            self.repository.update_job(job_id, status="failed", phase="failed", result=result, error=str(exc))
            return self.repository.get_job(job_id) or result

    @staticmethod
    def _final_status(result: dict[str, Any]) -> str:
        statuses = {
            item.get("status")
            for item in result.get("phases", {}).values()
            if isinstance(item, dict)
        }
        if "failed" in statuses or "blocked" in statuses:
            return "partial"
        if "skipped_with_reason" in statuses:
            return "partial"
        return "completed"

    def _environment(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        payload = EnvironmentCollector(self.settings).collect()
        snapshot = self.repository.add_environment_snapshot(job_id, payload["digest"], payload)
        result["environment"] = payload
        return {"status": "ok", "snapshot_id": snapshot, "digest": payload["digest"], "issues": payload["issues"]}

    def _components(self, request: dict[str, Any]) -> list[str]:
        selected = request.get("components") or self.settings.component_filter or list(SOURCES)
        unknown = set(selected) - set(SOURCES)
        if unknown:
            raise ValueError(f"unknown M2 components: {', '.join(sorted(unknown))}")
        return list(selected)

    def _sources(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        fetch = bool(request.get("fetch_sources", False))
        payload = SourceManager(self.settings).sync(
            self._components(request),
            fetch=fetch,
            confirm=bool(request.get("confirm_source_fetch", False)),
        )
        for item in payload["results"]:
            self.repository.add_source_snapshot(job_id, item)
        result["sources"] = payload
        return {
            "status": (
                "ok"
                if any(item.get("status") in {"present", "fetched"} for item in payload["results"])
                else "skipped_with_reason"
            ),
            "manifest_path": payload.get("manifest_path"),
            "available": sum(item.get("status") in {"present", "fetched"} for item in payload["results"]),
            "total": len(payload["results"]),
        }

    def _knowledge(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        environment = result.get("environment", {})
        versions = {
            "kata-containers": environment.get("kata", {}).get("version"),
            "qemu": environment.get("qemu", {}).get("version"),
            "virtiofsd": environment.get("virtiofsd", {}).get("version"),
            "linux": environment.get("host", {}).get("kernel"),
            "containerd": environment.get("tools", {}).get("containerd", {}).get("version"),
        }
        components = self._components(request)
        trusted = TrustedKnowledgeMatcher(self.settings).match(components, versions)
        external: dict[str, Any] = {"status": "not_requested"}
        if request.get("collect_external_candidates"):
            external = ExternalCandidateCollector(self.settings).collect_nvd(
                components,
                confirm=bool(request.get("confirm_external_collection", False)),
                max_per_component=int(request.get("external_max_per_component", 20)),
            )
        result["knowledge"] = {"trusted": trusted, "external": external}
        status = "ok" if trusted.get("status") == "ok" else "skipped_with_reason"
        return {
            "status": status,
            "trusted_matches": trusted.get("match_count", 0),
            "external": external.get("status"),
        }

    def _static(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        scanner = AttackSurfaceScanner(max_findings=int(request.get("max_static_findings", 1000)))
        scans = []
        findings: list[dict[str, Any]] = []
        for item in result.get("sources", {}).get("results", []):
            if item.get("status") not in {"present", "fetched"}:
                continue
            scan = scanner.scan(f"{item['component']}:{item['track']}", item["path"])
            scans.append(scan)
            findings.extend(scan.get("findings", []))
        config_findings = KataConfigAuditor().audit(result.get("environment", {}).get("configuration", {}))
        findings.extend(config_findings)
        for finding in findings:
            self.repository.add_finding(job_id, finding)
        result["findings"].extend(findings)
        result["static_scans"] = scans
        return {"status": "ok", "scan_count": len(scans), "finding_count": len(findings)}

    def _llm(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        review = DeepSeekReviewer(self.settings).review_findings(
            result.get("findings", []), result.get("environment", {})
        )
        by_id = {item.get("finding_id"): item for item in result.get("findings", [])}
        for item in review.get("reviews", []):
            finding = by_id.get(item.get("finding_id"))
            if not finding:
                continue
            decision = item.get("decision")
            if decision == "REJECTED":
                finding["status"] = FindingStatus.REJECTED.value
            else:
                # Model output alone cannot promote a candidate to supported.
                finding["status"] = FindingStatus.NEEDS_DYNAMIC_EVIDENCE.value
            finding.setdefault("metadata", {})["llm_review"] = item
            self.repository.add_finding(job_id, finding)
        result["llm_review"] = review
        return {
            "status": review.get("status", "skipped_with_reason"),
            "reviews": len(review.get("reviews", [])),
            "reason": review.get("reason"),
        }

    def _harness_build(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        manager = HarnessManager(self.settings)
        builds = manager.build(request.get("harnesses"))
        for item in builds:
            self.repository.add_harness_run(job_id, item)
        readiness = manager.native_readiness(result.get("sources", {}).get("results", []))
        result["harness_builds"] = builds
        result["native_readiness"] = readiness
        status = "ok" if any(item.get("status") == "built" for item in builds) else "skipped_with_reason"
        return {
            "status": status,
            "built": sum(item.get("status") == "built" for item in builds),
            "total": len(builds),
        }

    def _fuzz(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        if not request.get("run_fuzz", True):
            return {"status": "skipped_with_reason", "reason": "fuzzing was disabled by request"}
        seconds = request.get("fuzz_seconds")
        fuzz_runs = HarnessManager(self.settings).fuzz(
            request.get("harnesses"),
            seconds=int(seconds) if seconds is not None else None,
            profile=str(request.get("profile") or self.settings.budget_profile),
        )
        for item in fuzz_runs:
            self.repository.add_fuzz_run(job_id, item)
        result["fuzz_runs"] = fuzz_runs
        return {
            "status": "completed",
            "runs": len(fuzz_runs),
            "confirmed_sanitizer_crashes": sum(
                item.get("status") == "confirmed_sanitizer_crash" for item in fuzz_runs
            ),
        }

    def _kata(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        if not request.get("kata_smoke", True):
            return {"status": "skipped_with_reason", "reason": "Kata validation disabled by request"}
        controller = KataController(self.settings)
        if not controller.helper_status()["installed"]:
            return {"status": "skipped_with_reason", "reason": "restricted sudo helper is not installed"}
        compatibility = controller.compatibility("check")
        if compatibility.get("status") == "blocked_qemu_arm64_pmu_property_mismatch":
            return {
                "status": "blocked",
                "compatibility": compatibility,
                "reason": "run explicit kata-compat apply --confirm",
            }
        smoke = controller.smoke(str(request.get("namespace") or self.settings.namespace))
        result["kata_validation"] = {"compatibility": compatibility, "smoke": smoke}
        return {
            "status": "passed" if smoke.get("ok") else "failed",
            "compatibility": compatibility,
            "smoke": smoke,
        }

    def _exploitability(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        evaluator = ExploitabilityEvaluator()
        trusted_matches = result.get("knowledge", {}).get("trusted", {}).get("matches", [])
        kata_ok = result.get("kata_validation", {}).get("smoke", {}).get("ok", False)
        crash_by_harness = {
            item.get("harness_id"): item
            for item in result.get("fuzz_runs", [])
            if item.get("status") == "confirmed_sanitizer_crash"
        }
        for finding in result.get("findings", []):
            component = str(finding.get("component", ""))
            version_match = any(match.get("component_query") in component for match in trusted_matches)
            tags = set(finding.get("tags", []))
            controlled = any(tag in component for tag in crash_by_harness) or bool(
                crash_by_harness and "sanitizer_required" in tags
            )
            boundary = controlled and bool({"boundary", "virtio-fs", "vsock"} & tags)
            finding["exploitability"] = evaluator.evaluate(
                finding,
                version_match=version_match,
                prerequisites=kata_ok,
                reachable=bool(finding.get("file")),
                controlled_trigger=controlled,
                boundary_impact=boundary,
                weaponized_escape=False,
            )
            self.repository.add_finding(job_id, finding)
        return {"status": "completed", "evaluated": len(result.get("findings", []))}

    def _zero_day(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        crashes = [
            item
            for item in result.get("fuzz_runs", [])
            if item.get("status") == "confirmed_sanitizer_crash"
        ]
        if not crashes:
            return {
                "status": "skipped_with_reason",
                "reason": "no sanitizer-confirmed crash crossed the sealing threshold",
            }
        sealed = []
        gate = ZeroDayGate(self.settings)
        for crash in crashes:
            files = [
                item.get("artifact_path")
                for item in crash.get("crash_artifacts", [])
                if item.get("artifact_path")
            ]
            payload = gate.seal_crash(
                files=files,
                metadata={
                    "harness_id": crash.get("harness_id"),
                    "sanitizer_kind": crash.get("sanitizer_kind"),
                    "artifact_hashes": [item.get("sha256") for item in crash.get("crash_artifacts", [])],
                },
                actor=str(request.get("actor", "m2-operator")),
                job_id=job_id,
                hypothesis_id=f"hyp-{uuid.uuid4().hex}",
            )
            sealed.append(payload)
        result["zero_day_cases"] = sealed
        status = "sealed" if any(item.get("status") == "sealed" for item in sealed) else "blocked"
        return {"status": status, "cases": sealed}

    def _report(self, job_id: str, request: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        # Store a digest before adding file paths to avoid a self-referential report hash.
        result["result_digest"] = hashlib.sha256(
            json.dumps(result, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        paths = ReportWriter(self.settings).write(job_id, result)
        result["report"] = paths
        return {"status": "completed", **paths}
