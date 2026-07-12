from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import (
    Assertion,
    EvidenceFragment,
    EvidenceLevel,
    KnowledgeRecord,
    RecordStatus,
    RecordType,
    Source,
    VerificationStatus,
)
from .repository import TrustedKnowledgeRepository

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_KEYWORDS = (
    "docker",
    "runc",
    "containerd",
    "kubernetes",
    "kubelet",
    "cri-o",
    "kata containers",
    "firecracker",
    "gvisor",
    "container escape",
    "container breakout",
    "ebpf",
    "cgroup",
    "seccomp",
)


@dataclass(slots=True)
class IngestStats:
    downloaded_pages: int = 0
    discovered: int = 0
    imported_candidates: int = 0
    skipped_irrelevant: int = 0
    skipped_rejected: int = 0
    failed_requests: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "downloaded_pages": self.downloaded_pages,
            "discovered": self.discovered,
            "imported_candidates": self.imported_candidates,
            "skipped_irrelevant": self.skipped_irrelevant,
            "skipped_rejected": self.skipped_rejected,
            "failed_requests": self.failed_requests,
        }


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _stable_id(prefix: str, *parts: str, length: int = 24) -> str:
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}"


def _date_chunks(start_year: int, end_year: int) -> Iterable[tuple[dt.date, dt.date]]:
    current = dt.date(start_year, 1, 1)
    end = dt.date(end_year, 12, 31)
    while current <= end:
        chunk_end = min(current + dt.timedelta(days=119), end)
        yield current, chunk_end
        current = chunk_end + dt.timedelta(days=1)


def _english_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    for item in descriptions:
        if item.get("lang") == "en":
            return str(item.get("value") or "").strip()
    return ""


def _reference_urls(cve: dict[str, Any]) -> list[str]:
    # NVD API 2.0 represents references as a list of objects.
    references = cve.get("references") or []
    return sorted(
        {
            str(item.get("url")).strip()
            for item in references
            if isinstance(item, dict) and item.get("url")
        }
    )


def _weaknesses(cve: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").strip()
            if value:
                values.add(value)
    return sorted(values)


def _cvss(cve: dict[str, Any]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    metrics = cve.get("metrics") or {}
    for metric_name in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(metric_name) or []:
            data = metric.get("cvssData") or {}
            output.append(
                {
                    "metric": metric_name,
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                    "base_score": data.get("baseScore"),
                    "base_severity": metric.get("baseSeverity") or data.get("baseSeverity"),
                    "vector": data.get("vectorString"),
                }
            )
    return output


def _relevance(cve_id: str, description: str, references: list[str], keyword: str) -> tuple[list[str], int]:
    text = " ".join((cve_id, description, " ".join(references), keyword)).lower()
    tokens = {
        "docker",
        "runc",
        "containerd",
        "kubernetes",
        "kubelet",
        "cri-o",
        "kata",
        "firecracker",
        "gvisor",
        "container",
        "ebpf",
        "cgroup",
        "seccomp",
    }
    hits = sorted(token for token in tokens if token in text)
    return hits, len(hits)


class NVDClient:
    def __init__(
        self,
        api_key: str = "",
        timeout: int = 60,
        min_interval: float = 6.0,
        max_retries: int = 4,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.min_interval = min_interval
        self.max_retries = max_retries
        self._last_request_at = 0.0

    def _wait(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

    def get(self, params: dict[str, Any]) -> dict[str, Any]:
        query = urllib.parse.urlencode(params, doseq=True)
        headers = {
            "Accept": "application/json",
            "User-Agent": "cver-trusted-kb-nvd-ingest/0.1",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key

        last_error: Exception | None = None
        for attempt in range(self.max_retries):
            self._wait()
            request = urllib.request.Request(f"{NVD_CVE_API}?{query}", headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read()
                self._last_request_at = time.monotonic()
                return json.loads(raw.decode("utf-8"))
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc
                self._last_request_at = time.monotonic()
                if attempt + 1 >= self.max_retries:
                    break
                time.sleep(min(60.0, 2.0 ** attempt * 3.0))
        raise RuntimeError(f"NVD request failed after {self.max_retries} attempts: {last_error}")

    def iter_query(self, params: dict[str, Any]) -> Iterable[dict[str, Any]]:
        start_index = 0
        while True:
            page_params = dict(params)
            page_params["startIndex"] = start_index
            page_params.setdefault("resultsPerPage", 2000)
            page = self.get(page_params)
            yield page
            count = int(page.get("resultsPerPage") or 0)
            total = int(page.get("totalResults") or 0)
            if count <= 0 or start_index + count >= total:
                break
            start_index += count


class NVDCandidateIngestor:
    def __init__(
        self,
        db_path: str | Path,
        raw_dir: str | Path,
        annotator: str,
    ) -> None:
        if not annotator.strip():
            raise ValueError("annotator must not be empty")
        self.repository = TrustedKnowledgeRepository(db_path)
        self.raw_dir = Path(raw_dir)
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.annotator = annotator.strip()

    def _write_snapshot(self, cve_id: str, cve: dict[str, Any]) -> tuple[str, str, str]:
        raw = (_canonical_json(cve) + "\n").encode("utf-8")
        content_hash = _sha256_bytes(raw)
        target_dir = self.raw_dir / cve_id[:8]
        target_dir.mkdir(parents=True, exist_ok=True)
        path = target_dir / f"{cve_id}-{content_hash[:16]}.json"
        if not path.exists():
            path.write_bytes(raw)
        snapshot_id = _stable_id("SNAP", "NVD", cve_id, content_hash)
        return snapshot_id, content_hash, str(path)

    def ingest_cve(self, cve: dict[str, Any], keyword: str) -> bool:
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id.startswith("CVE-"):
            return False
        if str(cve.get("vulnStatus") or "").lower() == "rejected":
            return False

        description = _english_description(cve)
        references = _reference_urls(cve)
        relevance_hits, relevance_score = _relevance(cve_id, description, references, keyword)
        if relevance_score <= 0:
            return False

        snapshot_id, snapshot_hash, storage_path = self._write_snapshot(cve_id, cve)
        source_id = f"SRC-NVD-{cve_id}"
        evidence_id = _stable_id("EV", source_id, snapshot_hash, "description")
        record_id = _stable_id("REC", RecordType.VULNERABILITY.value, cve_id, length=20)

        self.repository.add_source(
            Source(
                source_id=source_id,
                name=f"NVD record for {cve_id}",
                source_type="nvd_record",
                authority_level=EvidenceLevel.E1_AUTHORITY,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                publisher="NIST National Vulnerability Database",
                license_name="NVD data terms apply",
                retrieved_at=_now_iso(),
                metadata={
                    "api": NVD_CVE_API,
                    "vuln_status": cve.get("vulnStatus"),
                    "source_identifier": cve.get("sourceIdentifier"),
                },
            )
        )
        self.repository.add_source_snapshot(
            snapshot_id=snapshot_id,
            source_id=source_id,
            content_hash=snapshot_hash,
            storage_path=storage_path,
            media_type="application/json",
            metadata={"cve_id": cve_id, "provider": "NVD API 2.0"},
        )
        self.repository.add_evidence(
            EvidenceFragment(
                evidence_id=evidence_id,
                source_id=source_id,
                snapshot_id=snapshot_id,
                locator="$.descriptions[?(@.lang=='en')].value",
                excerpt=description or f"NVD record {cve_id} contains no English description.",
                evidence_level=EvidenceLevel.E1_AUTHORITY,
                content_hash=_sha256_bytes((description or cve_id).encode("utf-8")),
                language="en",
                metadata={"query_keyword": keyword},
            )
        )

        record = KnowledgeRecord(
            record_id=record_id,
            record_type=RecordType.VULNERABILITY,
            external_id=cve_id,
            title_en=cve_id,
            status=RecordStatus.CANDIDATE,
            summary_en=description,
            attributes={
                "candidate_source": "NVD API 2.0",
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "vuln_status": cve.get("vulnStatus"),
                "source_identifier": cve.get("sourceIdentifier"),
                "cvss": _cvss(cve),
                "weaknesses": _weaknesses(cve),
                "references": references,
                "configurations": cve.get("configurations") or [],
                "relevance_hits": relevance_hits,
                "relevance_score": relevance_score,
                "query_keyword": keyword,
                "ingestion_notice": (
                    "NVD data is enrichment evidence only. Root cause, affected/fixed versions, "
                    "and Gold status require manual verification against primary sources and patches."
                ),
            },
        )
        self.repository.upsert_record(
            record,
            changed_by=self.annotator,
            change_reason="NVD candidate ingestion; no trusted root-cause label assigned",
        )

        assertions = {
            "description": description,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "nvd_status": cve.get("vulnStatus"),
            "nvd_cvss": _cvss(cve),
            "nvd_cwe_candidates": _weaknesses(cve),
            "reference_urls": references,
        }
        for predicate, object_value in assertions.items():
            if object_value in (None, "", []):
                continue
            assertion_id = _stable_id("AST", record_id, predicate)
            self.repository.add_assertion(
                Assertion(
                    assertion_id=assertion_id,
                    record_id=record_id,
                    predicate=predicate,
                    object_value=object_value,
                    evidence_ids=[evidence_id],
                    verification_status=VerificationStatus.MODERATE,
                    asserted_by=self.annotator,
                    notes="Automatically imported from an NVD snapshot; requires human review before Gold use.",
                )
            )
        return True


def fetch_and_ingest_nvd_candidates(
    *,
    db_path: str | Path,
    raw_dir: str | Path,
    annotator: str,
    start_year: int,
    end_year: int,
    max_records: int,
    keywords: Iterable[str] = DEFAULT_KEYWORDS,
    api_key: str | None = None,
    sleep_seconds: float | None = None,
) -> dict[str, Any]:
    if start_year > end_year:
        raise ValueError("start_year must be <= end_year")
    if max_records <= 0:
        raise ValueError("max_records must be positive")

    actual_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
    interval = sleep_seconds if sleep_seconds is not None else (0.7 if actual_key else 6.0)
    client = NVDClient(api_key=actual_key, min_interval=interval)
    ingestor = NVDCandidateIngestor(db_path=db_path, raw_dir=raw_dir, annotator=annotator)
    stats = IngestStats()
    seen: set[str] = set()

    for keyword in keywords:
        for start, end in _date_chunks(start_year, end_year):
            params = {
                "keywordSearch": keyword,
                "pubStartDate": f"{start.isoformat()}T00:00:00.000Z",
                "pubEndDate": f"{end.isoformat()}T23:59:59.999Z",
                "noRejected": "",
            }
            try:
                pages = client.iter_query(params)
                for page in pages:
                    stats.downloaded_pages += 1
                    for wrapper in page.get("vulnerabilities") or []:
                        cve = wrapper.get("cve") or {}
                        cve_id = str(cve.get("id") or "").upper()
                        if not cve_id or cve_id in seen:
                            continue
                        seen.add(cve_id)
                        stats.discovered += 1
                        if str(cve.get("vulnStatus") or "").lower() == "rejected":
                            stats.skipped_rejected += 1
                            continue
                        if ingestor.ingest_cve(cve, keyword):
                            stats.imported_candidates += 1
                        else:
                            stats.skipped_irrelevant += 1
                        if stats.imported_candidates >= max_records:
                            return {
                                "ok": True,
                                "database": str(db_path),
                                "raw_dir": str(raw_dir),
                                "stats": stats.to_dict(),
                            }
            except RuntimeError:
                stats.failed_requests += 1
                raise

    return {
        "ok": True,
        "database": str(db_path),
        "raw_dir": str(raw_dir),
        "stats": stats.to_dict(),
    }
