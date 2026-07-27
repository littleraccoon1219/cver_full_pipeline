from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AdapterManifest, AdapterState, SourceInspection, asdict


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AdapterRegistry:
    def __init__(self, manifest_dir: str | Path) -> None:
        self.manifest_dir = Path(manifest_dir).expanduser().resolve()
        self.manifest_dir.mkdir(parents=True, exist_ok=True)

    def list(self) -> list[AdapterManifest]:
        manifests: list[AdapterManifest] = []
        for path in sorted(self.manifest_dir.glob("*.json")):
            if path.name.endswith(".candidate.json"):
                continue
            try:
                manifests.append(AdapterManifest(**json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return manifests

    def select(self, version: str) -> AdapterManifest | None:
        for manifest in self.list():
            try:
                if re.fullmatch(manifest.version_selector, version):
                    return manifest
            except re.error:
                continue
        return None

    def check(self, inspection: SourceInspection) -> dict[str, Any]:
        manifest = self.select(inspection.version)
        if manifest is None:
            return {
                "state": AdapterState.ADAPTER_REQUIRED.value,
                "reason": f"no adapter manifest matches Kata {inspection.version}",
                "inspection": asdict(inspection),
            }
        expected = {item["handler_id"]: item for item in manifest.handlers}
        actual = {item.handler_id: item for item in inspection.handlers}
        missing = sorted(set(expected) - set(actual))
        mismatches = []
        for handler_id in sorted(set(expected) & set(actual)):
            item = expected[handler_id]
            observed = actual[handler_id]
            if item.get("request_type") and item["request_type"] != observed.request_type:
                mismatches.append(
                    {
                        "handler_id": handler_id,
                        "field": "request_type",
                        "expected": item["request_type"],
                        "actual": observed.request_type,
                    }
                )
            if item.get("signature_sha256") and item["signature_sha256"] != observed.signature_sha256:
                mismatches.append(
                    {
                        "handler_id": handler_id,
                        "field": "signature_sha256",
                        "expected": item["signature_sha256"],
                        "actual": observed.signature_sha256,
                    }
                )
        if missing or mismatches:
            state = AdapterState.SEMANTIC_DRIFT
            reason = "handler interface differs from the approved adapter manifest"
        elif inspection.interface_fingerprint not in manifest.approved_interface_fingerprints:
            state = AdapterState.REVIEW_REQUIRED
            reason = "source layout is recognized but its exact interface fingerprint is not approved"
        elif not manifest.approved:
            state = AdapterState.REVIEW_REQUIRED
            reason = "manifest exists but has not passed human, compilation and interface approval"
        else:
            state = AdapterState.APPROVED
            reason = "exact source interface is approved"
        return {
            "state": state.value,
            "reason": reason,
            "adapter": asdict(manifest),
            "inspection": asdict(inspection),
            "missing_handlers": missing,
            "mismatches": mismatches,
        }

    def propose(self, inspection: SourceInspection, *, adapter_id: str | None = None) -> dict[str, Any]:
        safe_version = re.sub(r"[^A-Za-z0-9_.-]+", "-", inspection.version)
        identifier = adapter_id or f"kata-agent-{safe_version}-{inspection.interface_fingerprint[:12]}"
        manifest = AdapterManifest(
            schema_version=1,
            adapter_id=identifier,
            component="kata-agent",
            version_selector=re.escape(inspection.version),
            source_path="src/agent/src/rpc.rs",
            approved_interface_fingerprints=[inspection.interface_fingerprint],
            handlers=[
                {
                    "handler_id": item.handler_id,
                    "method": item.rust_method,
                    "request_type": item.request_type,
                    "response_type": item.response_type,
                    "signature_sha256": item.signature_sha256,
                    "group": item.group,
                }
                for item in inspection.handlers
            ],
            patch_policy={
                "feature": "cver-fuzz",
                "allowed_changes": [
                    "test-only visibility",
                    "deterministic mock injection",
                    "adapter construction",
                ],
                "forbidden_changes": [
                    "validation removal",
                    "authorization bypass",
                    "security logic modification",
                    "production default feature change",
                ],
                "automatic_execution": False,
                "required_gates": [
                    "human_approval",
                    "stable_compilation_test",
                    "interface_test",
                    "semantic_differential_test",
                ],
            },
            approved=False,
            source_commit=inspection.commit,
            source_sha256=inspection.rpc_sha256,
        )
        path = self.manifest_dir / f"{identifier}.candidate.json"
        path.write_text(json.dumps(asdict(manifest), ensure_ascii=False, indent=2), encoding="utf-8")
        return {
            "state": AdapterState.REVIEW_REQUIRED.value,
            "manifest_path": str(path),
            "manifest": asdict(manifest),
            "reason": "candidate manifest generated; it is not executable until approval gates pass",
        }

    def approve(
        self,
        candidate_path: str | Path,
        *,
        actor: str,
        compilation_test: bool,
        interface_test: bool,
        semantic_differential_test: bool,
        confirm: bool,
    ) -> dict[str, Any]:
        if not confirm:
            raise PermissionError("adapter approval requires --confirm")
        if not all((compilation_test, interface_test, semantic_differential_test)):
            raise ValueError("all three adapter gates must pass before approval")
        path = Path(candidate_path).expanduser().resolve()
        if path.parent != self.manifest_dir:
            raise PermissionError("candidate manifest must be inside the configured adapter directory")
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["approved"] = True
        payload["approved_by"] = actor
        payload["approved_at"] = utc_now()
        target = self.manifest_dir / path.name.replace(".candidate.json", ".json")
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"state": AdapterState.APPROVED.value, "manifest_path": str(target), "adapter": payload}
