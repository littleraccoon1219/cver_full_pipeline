from __future__ import annotations

import datetime as dt
import hashlib
import json
import mimetypes
import re
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import yaml

BUNDLE_SCHEMA_VERSION = "candidate-bundle-1.0"
ALLOWED_RECORD_TYPES = {
    "vulnerability",
    "misconfiguration",
    "attack_pattern",
    "supply_chain_incident",
}


class CollectorError(RuntimeError):
    pass


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_id(prefix: str, *parts: str, length: int = 24) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}"  # 生成确定性 ID


def safe_name(value: str, fallback: str = "item") -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._")
    return normalized[:160] or fallback


def load_yaml(path: str | Path) -> dict[str, Any]:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CollectorError(f"YAML root must be an object: {path}")
    return payload


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CollectorError(f"invalid JSONL at {path}:{line_no}: {exc}") from exc
        if not isinstance(value, dict):
            raise CollectorError(f"JSONL row must be an object at {path}:{line_no}")
        rows.append(value)
    return rows


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> None:
    values = list(rows)
    text = "\n".join(canonical_json(row) for row in values)
    Path(path).write_text(text + ("\n" if values else ""), encoding="utf-8")


class _HTMLTextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.links: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip += 1
        if tag == "a":
            for key, value in attrs:
                if key == "href" and value:
                    self.links.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip:
            value = " ".join(data.split())
            if value:
                self.text.append(value)


def html_to_text(content: bytes) -> tuple[str, list[str]]:
    parser = _HTMLTextExtractor()
    parser.feed(content.decode("utf-8", errors="replace"))
    return "\n".join(parser.text), parser.links


def fetch_bytes(
    url: str,
    *,
    timeout: int = 60,
    retries: int = 4,
    headers: dict[str, str] | None = None,
    min_interval: float = 0.0,
    state: dict[str, float] | None = None,
) -> tuple[bytes, str]:
    request_headers = {
        "User-Agent": "cver-trusted-kb-collector/1.0",
        "Accept": "*/*",
        **(headers or {}),
    }
    last_error: Exception | None = None
    for attempt in range(retries):
        if state is not None and min_interval > 0:
            elapsed = time.monotonic() - state.get("last_request", 0.0)
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
        try:
            request = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content = response.read()
                media_type = response.headers.get_content_type() or "application/octet-stream"
            if state is not None:
                state["last_request"] = time.monotonic()
            return content, media_type
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if state is not None:
                state["last_request"] = time.monotonic()
            if attempt + 1 < retries:
                time.sleep(min(60.0, 2.0**attempt * 2.0))
    raise CollectorError(f"download failed: {url}: {last_error}")


@dataclass(slots=True)
class CandidateBundleBuilder:
    output_dir: Path
    collector_name: str
    collector_version: str
    source_family: str
    query_config: dict[str, Any]
    candidates: list[dict[str, Any]] = field(default_factory=list)
    source_candidates: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    _external_ids: set[str] = field(default_factory=set)

    def __init__(
        self,
        output_dir: str | Path,
        collector_name: str,
        collector_version: str,
        source_family: str,
        query_config: dict[str, Any] | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.collector_name = collector_name
        self.collector_version = collector_version
        self.source_family = source_family
        self.query_config = query_config or {}
        self.candidates = []
        self.source_candidates = []
        self.errors = []
        self._external_ids = set()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "raw").mkdir(parents=True, exist_ok=True)

    def store_raw(
        self,
        external_id: str,
        content: bytes,
        *,
        suffix: str = "",
        media_type: str | None = None,
    ) -> dict[str, Any]:
        digest = sha256_bytes(content)
        guessed_suffix = suffix or mimetypes.guess_extension(media_type or "") or ".bin"
        if not guessed_suffix.startswith("."):
            guessed_suffix = "." + guessed_suffix
        filename = f"{safe_name(external_id)}-{digest[:16]}{guessed_suffix}"
        path = self.output_dir / "raw" / filename
        if not path.exists():
            path.write_bytes(content)
        return {
            "relative_path": path.relative_to(self.output_dir).as_posix(),
            "sha256": digest,
            "size_bytes": len(content),
            "media_type": media_type or "application/octet-stream",
        }

    def copy_raw(self, external_id: str, source_path: str | Path, media_type: str | None = None) -> dict[str, Any]:
        source = Path(source_path)
        if not source.is_file():
            raise CollectorError(f"source file does not exist: {source}")
        content = source.read_bytes()
        return self.store_raw(
            external_id,
            content,
            suffix=source.suffix,
            media_type=media_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream",
        )

    def add_candidate(self, candidate: dict[str, Any]) -> bool:
        external_id = str(candidate.get("external_id") or "").strip()
        if not external_id:
            raise CollectorError("candidate external_id is required")
        if candidate.get("record_type") not in ALLOWED_RECORD_TYPES:
            raise CollectorError(f"unsupported record_type for {external_id}: {candidate.get('record_type')}")
        if external_id in self._external_ids:
            return False
        candidate.setdefault("candidate_id", stable_id("CAND", candidate["record_type"], external_id))
        candidate["status"] = "candidate"
        candidate["root_cause_l1"] = None
        candidate["root_cause_l2"] = None
        candidate["generated_by_model"] = False
        candidate.setdefault("collected_at", now_iso())
        self.candidates.append(candidate)
        self._external_ids.add(external_id)
        return True

    def add_source_candidate(self, value: dict[str, Any]) -> None:
        value = dict(value)
        value.setdefault("requires_human_confirmation", True)
        value.setdefault("discovered_at", now_iso())
        self.source_candidates.append(value)

    def add_error(self, stage: str, message: str, **context: Any) -> None:
        self.errors.append({"stage": stage, "message": message, "context": context, "at": now_iso()})

    def finalize(self) -> dict[str, Any]:
        candidates_path = self.output_dir / "candidates.jsonl"
        sources_path = self.output_dir / "source_candidates.jsonl"
        errors_path = self.output_dir / "errors.jsonl"
        write_jsonl(candidates_path, self.candidates)
        write_jsonl(sources_path, self.source_candidates)
        write_jsonl(errors_path, self.errors)
        files = []
        for path in sorted(p for p in self.output_dir.rglob("*") if p.is_file() and p.name != "manifest.json"):
            files.append(
                {
                    "path": path.relative_to(self.output_dir).as_posix(),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        manifest = {
            "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
            "ingestion_run_id": stable_id("INGEST", self.collector_name, now_iso(), str(self.output_dir.resolve())),
            "collector_name": self.collector_name,
            "collector_version": self.collector_version,
            "source_family": self.source_family,
            "created_at": now_iso(),
            "candidate_count": len(self.candidates),
            "source_candidate_count": len(self.source_candidates),
            "error_count": len(self.errors),
            "query_config": self.query_config,
            "query_config_hash": sha256_bytes(canonical_json(self.query_config).encode("utf-8")),
            "files": files,
        }
        (self.output_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return manifest


def read_source_bytes(source: dict[str, Any]) -> tuple[bytes, str, str]:
    path = source.get("path")
    url = source.get("url")
    if bool(path) == bool(url):
        raise CollectorError("each source must define exactly one of path or url")
    if path:
        file_path = Path(str(path))
        content = file_path.read_bytes()
        media_type = source.get("media_type") or mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        return content, media_type, str(file_path)
    content, media_type = fetch_bytes(str(url))
    return content, source.get("media_type") or media_type, str(url)
