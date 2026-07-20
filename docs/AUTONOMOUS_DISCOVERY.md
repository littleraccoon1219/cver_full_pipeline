# CVER full-stack autonomous discovery

## System objective

CVER is designed as a cloud-native full-stack multi-agent system for known-vulnerability analysis and unknown/0day discovery, evidence-gated exploitability determination, controlled attack-chain validation, adaptive remediation, retest, and continuous observation. Rust-Shyper is an M3 test and defense platform, not a prerequisite for building the generic system.

## Staged implementation

### M1 — governed platform and data foundation

M1 provides the durable queue, fixed survey-derived taxonomy, SP1-SP13 properties, full-stack registries, candidate/human-label workflow, local hybrid retrieval, immutable approvals, capability matrix, encrypted zero-day case storage, API/CLI, and audit controls.

### M2 — active discovery and exploitability

M2 adds real component-specific static/differential/fuzz/runtime adapters, Docker/Kata/Firecracker execution, Aya/Tracee observation, structured evidence promotion, E0-E5 exploitability, and L1-L5 attack-chain validation.

### M3 — repair and Rust-Shyper

M3 adds isolated adaptive patch/policy application, functional and security retest, responsible disclosure workflow, and Rust-Shyper runtime/shim, guest-agent, hypervisor monitoring and defense adapters.

## Evidence progression

The only valid progression is:

`candidate defect -> reproducible bug -> security vulnerability -> environment exploitable -> attack chain validated -> suspected/confirmed zero-day`

A model may propose hypotheses and explain evidence. It may not bypass deterministic gates or self-admit a record as trusted ground truth. A security vulnerability must be supported by either a dynamic security-impact path or a source/patch causal path and must violate at least one SP1-SP13 property. Novelty/0day status additionally requires isolated storage, reproducibility, human grading, and responsible disclosure controls.

## Taxonomy contract

The immutable first-level taxonomy is:

- RC-1 Implementation Correctness Failure;
- RC-2 Isolation and Resource Boundary Failure;
- RC-3 Privilege and Security Policy Failure;
- RC-4 Trust and Integrity Failure;
- RC-5 Cross-Layer Interaction and Semantic Failure.

Each second-level label defines positive and negative examples, machine signals, evidence combinations, and a counterfactual causal test. One primary second-level cause is selected as the first failed invariant in the minimal causal chain. Secondary causes are unbounded in count but each requires independent evidence and a causal counterfactual.

## Data trust boundary

- Collected records enter the candidate store and are not searchable as trusted few-shot examples.
- Only human annotations can create trusted labels.
- Test split groups and related families are excluded from RAG retrieval.
- Public data may be sent raw to cloud models; internal data is sanitized; confidential/0day content is abstracted to minimum evidence; restricted material is never sent.
- Suspected zero-day material is encrypted per case and excluded from ordinary RAG/few-shot stores.

## Risk and sandbox policy

Composed risk is the maximum of experiment, task, and target risk. Low maps to Docker, medium to Kata, and high/critical to Firecracker. High-risk approvals bind to the canonical hash of source revision, generated code, build artifacts, images, kernel/configuration, network/mount/device policy, resources, and expected validation action.

The platform does not weaken the backend silently. Missing capabilities return `skipped_with_reason`.

## Current M1 boundary

M1 does not claim real equal-depth full-stack fuzzing, an Aya production agent, attack-chain exploitation, automatic remediation, or Rust-Shyper integration. Those remain explicit M2/M3 acceptance requirements.
