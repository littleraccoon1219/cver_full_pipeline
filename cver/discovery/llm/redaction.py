from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import DataClass

_SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|password|passwd|secret)\s*[:=]\s*[^\s,;]+"),
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
        r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"(?i)authorization:\s*bearer\s+[^\s]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"(?i)(client[_-]?secret|private[_-]?token|access[_-]?token)\s*[:=]\s*[^\s,;]+"),
)

_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])")
_INTERNAL_HOST = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:internal|local|lan|corp|cluster\.local)\b", re.IGNORECASE)
_ABSOLUTE_PATH = re.compile(
    r'(?<![A-Za-z0-9_.-])/(?:home|Users|srv|opt|var/lib|etc/cver|workspace|workspaces)/[^\s"\'<>]{2,}'
)
_URL_CREDENTIAL = re.compile(r"(?i)(https?://)([^/@\s:]+):([^/@\s]+)@")


@dataclass(frozen=True, slots=True)
class SanitizedPayload:
    text: str
    classification: DataClass
    redactions: int


def _replace_private_ips(text: str) -> tuple[str, int]:
    count = 0
    parts: list[str] = []
    for token in re.split(r"(\s+)", text):
        stripped = token.strip("[](){}<>,;\"'")
        try:
            address = ipaddress.ip_address(stripped)
        except ValueError:
            parts.append(token)
            continue
        if address.is_private or address.is_loopback or address.is_link_local:
            parts.append(token.replace(stripped, "<PRIVATE_IP>"))
            count += 1
        else:
            parts.append(token)
    return "".join(parts), count


def sanitize_text(text: str, classification: DataClass) -> SanitizedPayload:
    if classification == DataClass.RESTRICTED:
        raise ValueError("restricted data must never be sent to a cloud LLM")

    if classification == DataClass.CONFIDENTIAL:
        lines = [line for line in text.splitlines() if line.strip()]
        extensions: dict[str, int] = {}
        for match in re.findall(r"\b[\w./-]+\.[A-Za-z0-9]{1,8}\b", text):
            suffix = Path(match).suffix.lower() or "<none>"
            extensions[suffix] = extensions.get(suffix, 0) + 1
        abstract = {
            "nonempty_line_count": len(lines),
            "character_count": len(text),
            "file_extension_histogram": extensions,
            "note": "raw confidential content withheld by policy",
        }
        return SanitizedPayload(
            json.dumps(abstract, ensure_ascii=False, sort_keys=True),
            classification,
            max(1, len(lines)),
        )

    value = text
    redactions = 0
    if classification == DataClass.INTERNAL:
        for pattern in _SECRET_PATTERNS:
            value, replaced = pattern.subn("<REDACTED_SECRET>", value)
            redactions += replaced
        value, replaced = _replace_private_ips(value)
        redactions += replaced
        value, replaced = _EMAIL.subn("<REDACTED_EMAIL>", value)
        redactions += replaced
        value, replaced = _INTERNAL_HOST.subn("<INTERNAL_HOST>", value)
        redactions += replaced
        value, replaced = _ABSOLUTE_PATH.subn("<INTERNAL_PATH>", value)
        redactions += replaced
        value, replaced = _URL_CREDENTIAL.subn(r"\1<REDACTED_CREDENTIALS>@", value)
        redactions += replaced
        home = str(Path.home())
        if home and home != "/":
            replaced = value.count(home)
            value = value.replace(home, "<HOME>")
            redactions += replaced
    return SanitizedPayload(value, classification, redactions)


def compact_json(value: Any, *, max_chars: int = 80_000) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n<TRUNCATED>"
