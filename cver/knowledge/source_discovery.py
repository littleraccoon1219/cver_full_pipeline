from __future__ import annotations

import re
import urllib.parse
from typing import Any

_PATCH_MARKERS = ("commit", "pull", "compare", "patch", "diff", "changeset")
_ADVISORY_MARKERS = ("advisory", "security", "cve", "vulnerability", "bulletin", "notice")
_RESEARCH_MARKERS = ("blog", "research", "analysis", "writeup", "report", "paper")
_OFFICIAL_DOMAINS = {
    "kubernetes.io",
    "github.com",
    "docs.docker.com",
    "docker.com",
    "containerd.io",
    "opencontainers.org",
    "kata-containers.io",
    "gvisor.dev",
    "firecracker-microvm.github.io",
    "kernel.org",
    "cisa.gov",
    "nist.gov",
    "nvd.nist.gov",
    "mitre.org",
    "attack.mitre.org",
    "capec.mitre.org",
}


def classify_reference_url(url: str, *, component_hint: str | None = None) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    text = f"{host} {path}"
    source_role = "unknown"
    if any(marker in path for marker in _PATCH_MARKERS):
        source_role = "patch_or_source"
    elif any(marker in text for marker in _ADVISORY_MARKERS):
        source_role = "official_advisory_candidate" if host in _OFFICIAL_DOMAINS else "independent_report_candidate"
    elif any(marker in text for marker in _RESEARCH_MARKERS):
        source_role = "independent_report_candidate"
    elif host in _OFFICIAL_DOMAINS:
        source_role = "official_source_candidate"
    return {
        "url": url,
        "host": host,
        "source_role_candidate": source_role,
        "component_hint": component_hint,
        "requires_human_confirmation": True,
        "classification_reason": "URL/domain heuristic only; no authority claim is made automatically.",
    }


def extract_cve_ids(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", text, flags=re.IGNORECASE)))
