# Autonomous Discovery v1 Release Notes

Baseline: `7d9be97a20672c7cca73c07d0919562a188d85ba`.

## Added

- Durable SQLite job queue, leases, heartbeats, events, approvals and audit records.
- OpenAI Responses API provider with strict structured-output schemas and no runtime mock fallback.
- Data-class handling: public raw, internal sanitized, confidential abstract, restricted rejected.
- Read-only bridge to `trusted_knowledge.db`.
- Deterministic evidence promotion gates and a safe synthetic benchmark.
- Docker, Kata and Firecracker backend availability/smoke controllers with no weak fallback.
- Static, non-destructive replay metadata for CVE-2024-21626 and CVE-2019-5736.
- Authenticated FastAPI endpoints and `discovery-*` CLI commands.
- Emergency-stop marker, process-group cancellation and durable worker lease heartbeat.
- Versioned Firecracker/Kata installers and Firecracker guest-asset provisioning.

## Corrected

- Legacy `PolicyGuard` now evaluates the action keys actually emitted by the legacy executor.
- Binary inventory and historical replay do not execute the target binary.

## Deliberately blocked

- Real container-escape payloads and host-impact verification.
- Promotion to `exploitable_zero_day`.
- Active target-specific Go tests/fuzzing and Tracee collection until reviewed sandbox adapters exist.
- Image/live-cluster target submission in the new durable v1 API.
