# M1 Platform Foundation

M1 establishes the data, taxonomy, governance, queue, API, and capability foundations for the cloud-native full-stack autonomous vulnerability research platform. It does **not** claim that real full-stack 0day discovery is complete; those active execution capabilities are M2 acceptance items.

## Implemented in M1

- Fixed survey-derived macro taxonomy: RC-1 through RC-5, plus `UNKNOWN/NEEDS_REVIEW`.
- Twenty-nine fixed second-level labels with machine definitions, positive/negative examples, static/dynamic signals, evidence gates, and counterfactual causal tests.
- SP1-SP13 container security properties with evidence gates.
- Human-only trusted annotation admission. Collected records remain candidates until a human annotation is accepted.
- Full-stack component and data-source registries for application/dependency, image/supply chain, Moby, runc, containerd, CRI-O/conmon, Kubernetes, BuildKit, Linux/eBPF, gVisor, Kata, Firecracker, and the M3 Rust-Shyper adapter.
- Capability matrix with explicit `skipped_with_reason` rather than simulated success.
- Local layered retrieval baseline: metadata/BM25-like filtering, local hashing-vector recall, MMR diversity, and split-group leakage exclusion.
- Schema v2 durable runtime database: candidates, artifacts, annotations, evidence, capability snapshots, immutable approvals, audit records, and isolated zero-day cases.
- Immutable experiment digest and composed risk policy. Low risk maps to Docker, medium to Kata, and high/critical to Firecracker.
- Per-case AES-GCM zero-day vault with wrapped data keys, audit records, Linux keyring development provider, disposable ephemeral provider, and future KMS/Vault/TPM interface.
- Configurable `quick`, `balanced`, and `deep` experiment budgets.
- `/v2` API and CLI for capabilities, taxonomy, budgets, candidate staging, human annotation, and zero-day sealing while retaining v1 compatibility.
- Layered manual verification scripts; no GitHub CI workflow.

## Explicitly deferred to M2

- Real per-component source acquisition/version matrices and active adapters at equal depth.
- LLM-generated test/Fuzz harness validation through language ASTs and sandbox compilation.
- Unified `execute(ExperimentSpec)` for Docker, dedicated Kata containerd, and Firecracker guests.
- Rust+Aya adaptive full syscall/file/process/network observation with Tracee fallback.
- Deterministic defect-to-vulnerability promotion from structured evidence rather than output markers.
- E0-E5 environment-aware exploitability and L1-L5 attack-chain validation.
- Blind historical, reverse-patch, non-security bug, and current-stable-version discovery benchmark execution.

## Explicitly deferred to M3

- Isolated automatic patch/policy application, functional regression, and exploit-chain retest.
- Responsible disclosure workflow automation.
- Rust-Shyper runtime/shim, guest-agent, and hypervisor adapters and dedicated defenses.
