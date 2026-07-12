# Trusted KB candidate ingestion

## Inspect old and trusted databases

```bash
python3 scripts/kb_db_status.py \
  data/cver_full_pipeline.db \
  data/trusted_knowledge.db
```

## Download NVD candidates

```bash
export NVD_API_KEY='optional-key'
python3 scripts/kb_fetch_nvd_candidates.py \
  --db data/trusted_knowledge.db \
  --raw-dir data/raw/nvd \
  --annotator yupeng \
  --years 2016 2026 \
  --max-records 100
```

The command creates immutable per-CVE JSON snapshots and inserts only Candidate
records. It deliberately does not assign trusted root causes, affected versions,
fixed versions, or Gold status.

## Do not drop the old tables yet

`cver/pipeline.py` still imports and queries `cver.vulndb.VulnDB`. Therefore,
`cve_knowledge` and its FTS objects must remain until the pipeline lookup is
migrated to `TrustedKnowledgeRepository`.

After that migration, inspect the dry run:

```bash
python3 scripts/kb_drop_legacy_knowledge_tables.py \
  --db data/cver_full_pipeline.db
```

Only after confirming the pipeline no longer imports `VulnDB`:

```bash
python3 scripts/kb_drop_legacy_knowledge_tables.py \
  --db data/cver_full_pipeline.db \
  --execute \
  --pipeline-migrated
```
