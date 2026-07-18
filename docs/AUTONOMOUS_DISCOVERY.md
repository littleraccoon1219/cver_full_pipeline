# CVER Autonomous Discovery v1

## Purpose

This subsystem adds an evidence-gated, durable discovery loop without replacing the
existing CVER pipeline. Existing commands continue to use `cver.legacy.pipeline`;
new commands are prefixed with `discovery-`.

The v1 loop is:

1. inventory a reviewed local target;
2. read reviewed context from `trusted_knowledge.db` in read-only mode;
3. ask the planner for bounded hypotheses, never shell commands or exploit payloads;
4. map experiment kinds to trusted adapters;
5. enforce the non-bypassable risk/sandbox policy;
6. persist hypotheses, experiments, approvals, model calls and events in
   `discovery_runtime.db`;
7. use a critic and deterministic evidence adjudicator;
8. produce an auditable JSON report.

## Evidence promotion

The only valid progression is:

`candidate_defect -> reproducible_bug -> security_vulnerability -> exploitable_zero_day`

The model cannot assign the final stage. v1 never promotes to `exploitable_zero_day`.
That stage requires a separate novelty assessment, disposable nested-virtualization
lab, reviewed impact evidence, and human disclosure approval.

## Databases

- `data/trusted_knowledge.db`: reviewed knowledge and provenance. Discovery opens it
  read-only and stores only stable record links.
- `data/discovery_runtime.db`: queue, events, model-call audit records, hypotheses,
  experiments and approvals.

Do not merge these databases. Runtime/model output is not trusted knowledge.

## Commands

```bash
python -m cver discovery-init
python -m cver discovery-doctor --project-root .
python -m cver discovery-submit \
  --target ~/cver-lab/sources/runc-current \
  --target-kind source \
  --data-class internal
python -m cver discovery-benchmark --project-root .
python -m cver discovery-worker --once --project-root .
python -m cver discovery-list
python -m cver discovery-status JOB_ID
python -m cver discovery-api --host 127.0.0.1 --port 8080
```

The worker requires `OPENAI_API_KEY` and `OPENAI_PLANNER_MODEL`. Tests use an
explicitly injected `FakeProvider`; production code has no automatic fake fallback.

## Current adapter boundary

The durable v1 submission API accepts reviewed local source checkouts and local binary
artifacts. Image, live-cluster and environment targets are reserved for later adapters;
the existing legacy pipeline remains available for its current image-oriented flow.

v1 directly executes only low-risk, fixed adapters such as static version metadata,
Semgrep, patch metadata and the reviewed synthetic fixture. General binary targets are
not executed. Active target-specific tests/fuzzing, Tracee collection and historical
PoC execution remain disabled until reviewed sandbox adapters and backend acceptance
evidence exist.

The emergency-stop marker is checked before job submission, before each workflow
stage and by the trusted command runner during tool execution. Use `discovery-stop`
and `discovery-resume` for operator control.
