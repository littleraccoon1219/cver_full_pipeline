from __future__ import annotations

import datetime as dt
import json
import os
import urllib.parse
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..source_discovery import classify_reference_url
from .common import CandidateBundleBuilder, CollectorError, fetch_bytes, load_yaml, now_iso

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
COLLECTOR_VERSION = "1.0.0"


def date_chunks(start_year: int, end_year: int) -> Iterable[tuple[dt.date, dt.date]]:
    if start_year > end_year:
        raise ValueError("start_year must be <= end_year")
    current = dt.date(start_year, 1, 1)
    today = dt.datetime.now(dt.timezone.utc).date()
    end = min(dt.date(end_year, 12, 31), today)
    while current <= end:
        chunk_end = min(current + dt.timedelta(days=119), end)
        yield current, chunk_end
        current = chunk_end + dt.timedelta(days=1)


def stratified_date_chunks(start_year: int, end_year: int) -> Iterable[tuple[dt.date, dt.date]]:
    """Interleave yearly windows so early years cannot consume an entire bucket quota."""
    by_year = {year: list(date_chunks(year, year)) for year in range(start_year, end_year + 1)}
    max_chunks = max((len(chunks) for chunks in by_year.values()), default=0)
    for chunk_index in range(max_chunks):
        for year in range(start_year, end_year + 1):
            chunks = by_year[year]
            if chunk_index < len(chunks):
                yield chunks[chunk_index]


def english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en":
            return str(item.get("value") or "").strip()
    return ""


def reference_urls(cve: dict[str, Any]) -> list[str]:
    return sorted(
        {
            str(item.get("url")).strip()
            for item in cve.get("references") or []
            if isinstance(item, dict) and item.get("url")
        }
    )


def weaknesses(cve: dict[str, Any]) -> list[str]:
    output: set[str] = set()
    for item in cve.get("weaknesses") or []:
        for description in item.get("description") or []:
            value = str(description.get("value") or "").strip()
            if value:
                output.add(value)
    return sorted(output)


def cvss_metrics(cve: dict[str, Any]) -> list[dict[str, Any]]:
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


class NVDClient:
    def __init__(self, api_key: str = "", timeout: int = 60, min_interval: float | None = None) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.min_interval = min_interval if min_interval is not None else (0.7 if api_key else 6.0)
        self.state: dict[str, float] = {}

    def get(self, params: dict[str, Any]) -> dict[str, Any]:
        query = urllib.parse.urlencode(params, doseq=True)
        headers = {"Accept": "application/json", "User-Agent": "cver-trusted-kb-nvd/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        content, _ = fetch_bytes(
            f"{NVD_CVE_API}?{query}",
            timeout=self.timeout,
            headers=headers,
            min_interval=self.min_interval,
            state=self.state,
        )
        try:
            payload = json.loads(content.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise CollectorError(f"NVD returned invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise CollectorError("NVD response root is not an object")
        return payload

    def iter_pages(self, params: dict[str, Any]) -> Iterable[dict[str, Any]]:
        start_index = 0
        while True:
            page_params = dict(params)
            page_params["startIndex"] = start_index
            page_params.setdefault("resultsPerPage", 2000)
            page = self.get(page_params)
            yield page
            page_size = int(page.get("resultsPerPage") or len(page.get("vulnerabilities") or []))
            total = int(page.get("totalResults") or 0)
            if page_size <= 0 or start_index + page_size >= total:
                break
            start_index += page_size


def load_quota_config(path: str | Path) -> dict[str, Any]:
    payload = load_yaml(path)
    buckets = payload.get("buckets")
    if not isinstance(buckets, list) or not buckets:
        raise CollectorError("quota config must contain a non-empty buckets list")
    for bucket in buckets:
        if not isinstance(bucket, dict) or not bucket.get("name") or not bucket.get("keywords"):
            raise CollectorError("each bucket requires name and keywords")
        bucket.setdefault("target", 10)
    return payload


def _candidate_from_cve(cve: dict[str, Any], bucket: str, keyword: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    cve_id = str(cve.get("id") or "").strip().upper()
    description = english_description(cve)
    refs = reference_urls(cve)
    return {
        "record_type": "vulnerability",
        "external_id": cve_id,
        "title_en": cve_id,
        "summary_en": description,
        "technology_bucket_candidate": bucket,
        "candidate_source": "NVD API 2.0",
        "attributes": {
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "vuln_status": cve.get("vulnStatus"),
            "source_identifier": cve.get("sourceIdentifier"),
            "cvss": cvss_metrics(cve),
            "cwe_candidates": weaknesses(cve),
            "references": refs,
            "configurations": cve.get("configurations") or [],
            "query_keyword": keyword,
            "technology_bucket_candidate": bucket,
            "review_notice": "NVD is an authority aggregator, not sufficient evidence for Gold admission.",
        },
        "source": {
            "source_key": f"NVD:{cve_id}",
            "name": f"NVD record for {cve_id}",
            "source_type": "nvd_record",
            "authority_level": "E1",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "publisher": "NIST National Vulnerability Database",
            "license_name": "NVD data terms apply",
            "retrieved_at": now_iso(),
        },
        "snapshot": snapshot,
        "evidence": {
            "locator": "$.descriptions[?(@.lang=='en')].value",
            "excerpt": description or f"NVD record {cve_id} has no English description.",
            "language": "en",
            "evidence_level": "E1",
            "fragment_type": "json",
        },
        "assertions": [
            {"predicate": "description", "object": description, "verification_status": "moderate"},
            {"predicate": "published", "object": cve.get("published"), "verification_status": "moderate"},
            {"predicate": "last_modified", "object": cve.get("lastModified"), "verification_status": "moderate"},
            {"predicate": "nvd_status", "object": cve.get("vulnStatus"), "verification_status": "moderate"},
            {"predicate": "nvd_cvss", "object": cvss_metrics(cve), "verification_status": "moderate"},
            {"predicate": "nvd_cwe_candidates", "object": weaknesses(cve), "verification_status": "moderate"},
            {"predicate": "reference_urls", "object": refs, "verification_status": "moderate"},
        ],
    }


def collect_nvd_candidates(
    *,
    output_dir: str | Path,
    quota_config: str | Path,
    start_year: int = 2020,
    end_year: int = 2026,
    target_count: int = 158,
    api_key: str | None = None,
    sleep_seconds: float | None = None,
) -> dict[str, Any]:
    config = load_quota_config(quota_config)
    builder = CandidateBundleBuilder(
        output_dir,
        "nvd",
        COLLECTOR_VERSION,
        "NVD CVE API 2.0",
        {
            "start_year": start_year,
            "end_year": end_year,
            "target_count": target_count,
            "quota_config": str(quota_config),
            "buckets": config["buckets"],
        },
    )
    key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
    client = NVDClient(api_key=key, min_interval=sleep_seconds)
    assigned: set[str] = set()
    bucket_counts: dict[str, int] = {}

    for bucket in config["buckets"]:
        bucket_name = str(bucket["name"])
        bucket_target = int(bucket.get("target") or 0)
        bucket_counts[bucket_name] = 0
        for keyword in bucket["keywords"]:
            if bucket_counts[bucket_name] >= bucket_target or len(builder.candidates) >= target_count:
                break
            for start, end in stratified_date_chunks(start_year, end_year):
                if bucket_counts[bucket_name] >= bucket_target or len(builder.candidates) >= target_count:
                    break
                params = {
                    "keywordSearch": str(keyword),
                    "pubStartDate": f"{start.isoformat()}T00:00:00.000Z",
                    "pubEndDate": f"{end.isoformat()}T23:59:59.999Z",
                }
                try:
                    pages = client.iter_pages(params)
                    for page in pages:
                        for wrapper in page.get("vulnerabilities") or []:
                            cve = wrapper.get("cve") or {}
                            cve_id = str(cve.get("id") or "").strip().upper()
                            if not cve_id.startswith("CVE-") or cve_id in assigned:
                                continue
                            if str(cve.get("vulnStatus") or "").lower() == "rejected":
                                continue
                            raw = (json.dumps(cve, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
                            snapshot = builder.store_raw(cve_id, raw, suffix=".json", media_type="application/json")
                            candidate = _candidate_from_cve(cve, bucket_name, str(keyword), snapshot)
                            if builder.add_candidate(candidate):
                                assigned.add(cve_id)
                                bucket_counts[bucket_name] += 1
                                for url in reference_urls(cve):
                                    source = classify_reference_url(url, component_hint=bucket_name)
                                    source["external_id"] = cve_id
                                    builder.add_source_candidate(source)
                            if bucket_counts[bucket_name] >= bucket_target or len(builder.candidates) >= target_count:
                                break
                        if bucket_counts[bucket_name] >= bucket_target or len(builder.candidates) >= target_count:
                            break
                except Exception as exc:  # collection continues and records the failed slice
                    builder.add_error(
                        "nvd_query",
                        str(exc),
                        bucket=bucket_name,
                        keyword=keyword,
                        start=start.isoformat(),
                        end=end.isoformat(),
                    )
    manifest = builder.finalize()
    manifest["bucket_counts"] = bucket_counts
    manifest_path = Path(output_dir) / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest
