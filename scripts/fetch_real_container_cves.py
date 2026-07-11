#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fetch real container-related CVE metadata from NVD CVE API 2.0.
Only public vulnerability metadata is collected. No PoC, exploit code, or offensive payloads are fetched.
"""
from __future__ import annotations
import argparse, datetime as dt, json, os, sqlite3, time, urllib.parse, urllib.request
from pathlib import Path
from typing import Any

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORDS = ["docker","runc","containerd","kubernetes","kubelet","cri-o","kata containers","gvisor","cgroup","namespace","seccomp","apparmor","ebpf","container escape","container breakout"]
TERMS = [x.lower() for x in KEYWORDS] + ["hostpath","docker.sock","privileged container"]

def http_json(params: dict[str,Any], api_key: str, timeout: int=60) -> dict[str,Any]:
    qs = urllib.parse.urlencode(params, doseq=True)
    headers = {"User-Agent":"cver-cve-fetcher/0.1"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(NVD + "?" + qs, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

def chunks(y1: int, y2: int):
    cur = dt.date(y1,1,1); end = dt.date(y2,12,31)
    while cur <= end:
        e = min(cur + dt.timedelta(days=119), end)
        yield cur, e
        cur = e + dt.timedelta(days=1)

def desc(cve: dict[str,Any]) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""

def refs(cve: dict[str,Any]) -> list[str]:
    return sorted({r.get("url") for r in cve.get("references", {}).get("referenceData", []) if r.get("url")})

def cvss(cve: dict[str,Any]) -> dict[str,Any]:
    m = cve.get("metrics", {})
    for key in ["cvssMetricV40","cvssMetricV31","cvssMetricV30","cvssMetricV2"]:
        if m.get(key):
            item=m[key][0]; data=item.get("cvssData", {})
            return {"score":data.get("baseScore"),"severity":item.get("baseSeverity") or data.get("baseSeverity"),"vector":data.get("vectorString")}
    return {"score":None,"severity":"UNKNOWN","vector":None}

def component(text: str) -> str:
    low=text.lower()
    for c in ["runc","containerd","docker","kubernetes","kubelet","cri-o","kata","gvisor","linux kernel","ebpf","cgroup"]:
        if c in low:
            return c.replace(" ","_")
    return "unknown"

def normalize(vuln: dict[str,Any], keyword: str) -> dict[str,Any]:
    cve=vuln["cve"]; cve_id=cve.get("id"); d=desc(cve); rs=refs(cve); text=" ".join([cve_id or "", d, " ".join(rs), keyword])
    hits=sorted({t for t in TERMS if t in text.lower()})
    comp=component(text)
    root="kernel_attack_surface" if comp in ["linux_kernel","ebpf","cgroup"] else ("orchestration_config" if comp in ["kubernetes","kubelet"] else "runtime_isolation")
    fine="container_runtime_escape" if comp in ["runc","containerd","docker"] else ("k8s_orchestration_vuln" if comp in ["kubernetes","kubelet"] else "kernel_or_ebpf_vuln")
    return {
      "schema_version":"cver-cve-knowledge-v1",
      "record_id":"cver-" + str(cve_id),
      "facts":{"cve_id":cve_id,"source":"NVD","title":cve_id,"component":comp,"description":d,"published":cve.get("published"),"last_modified":cve.get("lastModified"),"severity":cvss(cve).get("severity"),"cvss":cvss(cve),"references":rs,"affected_version_ranges":[],"fixed_versions":["unknown"]},
      "semantic_annotations":{"root_cause":root,"fine_type":fine,"required_conditions":[{"name":"affected_component_present","expr":f"component == {comp}","source_type":"rule_inferred","confidence":0.5,"human_confirmed":False}],"blocking_conditions":[{"name":"patched_component","expr":"component_version >= fixed_version when known","source_type":"rule_inferred","confidence":0.5,"human_confirmed":False}],"escape_primitives":["runtime_boundary_break"] if fine=="container_runtime_escape" else ["unknown"],"confidence":0.55,"human_confirmed":False},
      "evidence_sources":[{"source":"NVD","url":"https://nvd.nist.gov/vuln/detail/" + str(cve_id)}],
      "redteam_mapping":[{"scenario_id":"runtime_version_exposure","trigger_reason":"container-related CVE metadata","execution_level":"dry-run","poc_policy":"no_real_poc"}],
      "crawler_metadata":{"query_keyword":keyword,"relevance_hits":hits,"relevance_score":len(hits)}
    }

def write_sqlite(path: str, records: list[dict[str,Any]]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as c:
        c.execute("CREATE TABLE IF NOT EXISTS cve_knowledge(cve_id TEXT PRIMARY KEY, component TEXT, root_cause TEXT, fine_type TEXT, severity TEXT, cvss_score REAL, published TEXT, last_modified TEXT, json TEXT, retrieved_at TEXT)")
        for r in records:
            f=r["facts"]; s=r["semantic_annotations"]; cv=f.get("cvss") or {}
            c.execute("INSERT OR REPLACE INTO cve_knowledge VALUES(?,?,?,?,?,?,?,?,?,?)",(f["cve_id"],f.get("component"),s.get("root_cause"),s.get("fine_type"),f.get("severity"),cv.get("score"),f.get("published"),f.get("last_modified"),json.dumps(r,ensure_ascii=False),dt.datetime.utcnow().isoformat()+"Z"))

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--years", nargs=2, type=int, default=[2021, dt.date.today().year])
    ap.add_argument("--max-records", type=int, default=40)
    ap.add_argument("--sleep", type=float, default=6.0)
    ap.add_argument("--out-json", default="data/cve_knowledge/container_cves.json")
    ap.add_argument("--out-jsonl", default="data/cve_knowledge/container_cves.jsonl")
    ap.add_argument("--sqlite", default="data/cver_full_pipeline.db")
    ap.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY",""))
    args=ap.parse_args()
    byid={}
    for kw in KEYWORDS:
        for a,b in chunks(args.years[0], args.years[1]):
            data=http_json({"keywordSearch":kw,"pubStartDate":f"{a}T00:00:00.000Z","pubEndDate":f"{b}T23:59:59.999Z","resultsPerPage":2000,"startIndex":0,"noRejected":""}, args.nvd_api_key)
            for v in data.get("vulnerabilities", []):
                item=normalize(v, kw)
                if item["crawler_metadata"]["relevance_score"] > 0:
                    byid[item["facts"]["cve_id"]] = item
                    print("[hit]", item["facts"]["cve_id"], item["facts"]["component"])
                    if len(byid) >= args.max_records:
                        break
            if len(byid) >= args.max_records:
                break
            time.sleep(args.sleep)
        if len(byid) >= args.max_records:
            break
    records=list(byid.values())[:args.max_records]
    Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_json).write_text(json.dumps({"records":records}, ensure_ascii=False, indent=2), encoding="utf-8")
    Path(args.out_jsonl).write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + ("\n" if records else ""), encoding="utf-8")
    write_sqlite(args.sqlite, records)
    print(json.dumps({"ok":True,"records":len(records),"out_json":args.out_json,"sqlite":args.sqlite}, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
