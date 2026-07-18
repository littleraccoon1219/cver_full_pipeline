# CVER Safety Policy

## Non-negotiable controls

- The LLM may choose an enumerated experiment kind; it never provides a command line.
- `subprocess` is invoked with `shell=False` by trusted adapters only.
- Unknown experiment kinds are skipped.
- Low-risk work maps to Docker, medium-risk work maps to Kata, and high/critical work
  maps to Firecracker.
- A weaker explicitly requested backend is denied rather than silently accepted.
- Unavailable backends produce `skipped_with_reason`; the system does not downgrade
  risky work to a weaker sandbox.
- Cloud-LLM data handling is: public raw, internal sanitized, confidential abstract
  only, restricted prohibited.
- Model-generated data never enters the trusted knowledge database.

## Historical vulnerability boundary

The package includes metadata-only replay for CVE-2024-21626 and CVE-2019-5736.
It performs version, prerequisite and patch-presence checks. It ships no container
escape payload and no host-impact executor.

Even a future executor must require all of the following:

1. `CVER_DISPOSABLE_LAB_READY=true`;
2. `CVER_ALLOW_HISTORICAL_POC=true`;
3. scoped human approval;
4. a separately reviewed disposable-lab adapter;
5. network and credential isolation.

On the current workstation the state is `BLOCKED_NO_DISPOSABLE_LAB`.

## Emergency stop

The interlock is active when either `CVER_EMERGENCY_STOP=true` or the configured
`CVER_EMERGENCY_STOP_FILE` exists. New jobs and backend smoke tests are rejected,
workers stop claiming jobs, workflow stage boundaries re-check the marker, and the
trusted command runner terminates an active tool process group. A cloud request that
is already in flight remains bounded by `CVER_LLM_TIMEOUT_SECONDS` and is checked
again before the next workflow stage.

```bash
python -m cver discovery-stop --actor OPERATOR --reason "incident response"
python -m cver discovery-resume --actor OPERATOR --reason "review completed"
```

## Binary inspection

General binary targets are never executed for inventory or version discovery. The
pipeline uses file metadata, SHA-256, Go build metadata and embedded version strings.
Historical runc binary replay is static-only. Source tests and fuzzing remain disabled
until a reviewed sandbox adapter is enabled.
