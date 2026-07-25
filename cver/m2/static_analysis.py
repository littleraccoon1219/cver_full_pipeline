from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, FindingStatus, Severity, to_dict


@dataclass(frozen=True, slots=True)
class Pattern:
    code: str
    category: str
    regex: re.Pattern[str]
    severity: Severity
    confidence: float
    summary: str
    tags: tuple[str, ...]


PATTERNS: tuple[Pattern, ...] = (
    Pattern(
        "M2-BOUNDARY-VSOCK",
        "guest_host_message_boundary",
        re.compile(r"\b(vsock|VMADDR_CID|AF_VSOCK|ttrpc)\b", re.I),
        Severity.MEDIUM,
        0.42,
        "Guest/host message boundary code should be reviewed for framing, size and authorization invariants.",
        ("vsock", "boundary", "needs_dynamic_evidence"),
    ),
    Pattern(
        "M2-BOUNDARY-VIRTIOFS",
        "shared_filesystem_boundary",
        re.compile(r"\b(virtiofs|virtio-fs|vhost[_-]user|fuse_(?:in|out)_header|FUSE_[A-Z_]+)\b", re.I),
        Severity.MEDIUM,
        0.44,
        "Shared-filesystem boundary code should be reviewed for length, path and state-machine invariants.",
        ("virtio-fs", "fuse", "boundary"),
    ),
    Pattern(
        "M2-OCI-ANNOTATION",
        "oci_input_boundary",
        re.compile(r"\b(annotations?|oci\.spec|Spec\s*\{|runtimeConfig|sandboxConfig)\b", re.I),
        Severity.LOW,
        0.35,
        "OCI/configuration input reaches runtime logic and needs schema, normalization and policy checks.",
        ("oci", "configuration", "input"),
    ),
    Pattern(
        "M2-UNSAFE-MEMORY",
        "memory_safety_candidate",
        re.compile(r"\b(unsafe\s*\{|memcpy\s*\(|memmove\s*\(|from_raw_parts|set_len\s*\()", re.I),
        Severity.HIGH,
        0.58,
        "Unsafe memory operation near an untrusted boundary is a candidate, not a confirmed vulnerability.",
        ("memory", "candidate", "sanitizer_required"),
    ),
    Pattern(
        "M2-PATH-BOUNDARY",
        "path_resolution_candidate",
        re.compile(r"\b(filepath\.(?:Join|Clean|EvalSymlinks)|openat2?|O_NOFOLLOW|canonicalize\s*\()", re.I),
        Severity.MEDIUM,
        0.48,
        "Path handling across guest, shared filesystem or host boundaries needs race and canonicalization evidence.",
        ("path", "race", "boundary"),
    ),
    Pattern(
        "M2-IOCTL-BOUNDARY",
        "device_control_candidate",
        re.compile(r"\b(ioctl|Ioctl|KVM_[A-Z_]+|VHOST_[A-Z_]+)\b"),
        Severity.MEDIUM,
        0.4,
        "Device-control operation should be linked to a reachable untrusted input before promotion.",
        ("ioctl", "device", "reachability_required"),
    ),
    Pattern(
        "M2-SECURITY-DISABLE",
        "security_control_configuration",
        re.compile(
            r"\b(disable_guest_seccomp|disable_seccomp|"
            r"no_new_privileges\s*=\s*false|enable_debug\s*=\s*true)\b",
            re.I,
        ),
        Severity.MEDIUM,
        0.72,
        "A security control appears disabled or debug behavior enabled.",
        ("configuration", "hardening"),
    ),
)


class AttackSurfaceScanner:
    EXTENSIONS = {
        ".go", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
        ".proto", ".toml", ".json", ".yaml", ".yml",
    }
    IGNORE_DIRS = {".git", "target", "vendor", "node_modules", "build", "dist", ".venv"}

    def __init__(self, *, max_file_bytes: int = 2_000_000, max_findings: int = 2000) -> None:
        self.max_file_bytes = max_file_bytes
        self.max_findings = max_findings

    def scan(self, component: str, root: str | Path) -> dict[str, Any]:
        root_path = Path(root).resolve()
        if not root_path.is_dir():
            return {
                "component": component,
                "status": "skipped_with_reason",
                "reason": "source directory missing",
                "findings": [],
            }
        findings: list[dict[str, Any]] = []
        scanned_files = 0
        for path in sorted(root_path.rglob("*")):
            if len(findings) >= self.max_findings:
                break
            if not path.is_file() or path.suffix.lower() not in self.EXTENSIONS:
                continue
            relative_parts = path.relative_to(root_path).parts
            if any(part in self.IGNORE_DIRS for part in relative_parts):
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned_files += 1
            findings.extend(self._scan_text(component, root_path, path, text))
        return {
            "component": component,
            "status": "ok",
            "root": str(root_path),
            "scanned_files": scanned_files,
            "finding_count": len(findings),
            "findings": findings,
        }

    def _scan_text(self, component: str, root: Path, path: Path, text: str) -> list[dict[str, Any]]:
        lines = text.splitlines()
        output: list[dict[str, Any]] = []
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                start = max(0, line - 3)
                end = min(len(lines), line + 2)
                context = "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, end))
                relative = str(path.relative_to(root))
                finding = Finding(
                    finding_id=f"m2f-{uuid.uuid4().hex}",
                    component=component,
                    title=f"{pattern.code}: {pattern.category}",
                    category=pattern.category,
                    severity=pattern.severity,
                    status=FindingStatus.NEEDS_DYNAMIC_EVIDENCE,
                    confidence=pattern.confidence,
                    file=relative,
                    line=line,
                    description=pattern.summary,
                    tags=list(pattern.tags),
                    metadata={
                        "pattern_code": pattern.code,
                        "matched_text": match.group(0)[:200],
                        "context_sha256": hashlib.sha256(context.encode("utf-8")).hexdigest(),
                        "context": context,
                        "claim_boundary": "candidate_only_not_a_confirmed_vulnerability",
                    },
                )
                output.append(to_dict(finding))
        return output


class KataConfigAuditor:
    def audit(self, configuration: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        if configuration.get("disable_guest_seccomp") is True:
            findings.append(
                self._finding(
                    "Guest seccomp is disabled",
                    "security_control_configuration",
                    Severity.MEDIUM,
                    0.95,
                    "Enable guest seccomp after checking workload compatibility.",
                    ["kata", "seccomp", "configuration"],
                )
            )
        cpu_features = configuration.get("cpu_features")
        if cpu_features == "":
            findings.append(
                self._finding(
                    "ARM64 PMU compatibility override is active",
                    "compatibility_configuration",
                    Severity.INFO,
                    1.0,
                    (
                        "cpu_features is empty to avoid the verified QEMU property mismatch. "
                        "Treat PMU availability as an explicit security/performance review item."
                    ),
                    ["kata", "qemu", "arm64", "compatibility"],
                )
            )
        if configuration.get("enable_debug") is True:
            findings.append(
                self._finding(
                    "Kata debug mode is enabled",
                    "security_control_configuration",
                    Severity.LOW,
                    0.9,
                    "Disable debug mode outside an isolated research host.",
                    ["kata", "debug", "configuration"],
                )
            )
        return findings

    @staticmethod
    def _finding(
        title: str,
        category: str,
        severity: Severity,
        confidence: float,
        description: str,
        tags: Iterable[str],
    ) -> dict[str, Any]:
        return to_dict(
            Finding(
                finding_id=f"m2f-{uuid.uuid4().hex}",
                component="kata-configuration",
                title=title,
                category=category,
                severity=severity,
                status=FindingStatus.SUPPORTED,
                confidence=confidence,
                description=description,
                tags=list(tags),
            )
        )
