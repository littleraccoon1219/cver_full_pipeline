# Acceptance Checklist

Development is staged as M1, M2, and M3. M3 must satisfy the complete system acceptance gate; an M1 pass must not be represented as full 0day-discovery completion.

## M1 — platform foundation

```bash
scripts/verify_basic.sh
```

Required outcomes:

- schema migration reports version 2;
- the taxonomy contains exactly RC-1 through RC-5, 29 fixed second-level labels, and SP1 through SP13;
- every non-UNKNOWN primary annotation requires two independent evidence IDs, a causal-role statement, and a passing counterfactual test;
- candidate collection is content-addressed and does not create trusted labels;
- immutable experiment digests change when any experiment input changes;
- the zero-day vault stores no plaintext case material;
- all tests pass.

Privileged, non-destructive backend checks are separate:

```bash
CVER_ACK_PRIVILEGED_SMOKE=yes scripts/verify_sandbox.sh
```

An unavailable backend must return `skipped_with_reason` with a concrete missing capability. It must not silently fall back to a weaker backend.

## M2 — full-stack discovery and verified exploitability

M2 acceptance requires real, reviewed adapters for the component registry and cannot be satisfied by interface stubs. It must demonstrate:

- hidden-identity historical vulnerable/fixed pairs;
- reverse-patch injected samples and ordinary non-security bugs;
- autonomous current-stable exploration;
- validated generated test/Fuzz harnesses;
- unified Docker/Kata/Firecracker execution;
- adaptive Aya/Tracee evidence capture;
- deterministic security-property gates;
- E0-E5 exploitability and L1-L5 attack-chain evidence.

## M3 — remediation, disclosure, and Rust-Shyper

M3 acceptance requires isolated patch/policy application, functional regression, exploit-chain retest, responsible disclosure state transitions, and Rust-Shyper runtime/shim, guest, and hypervisor adapters.

## Emergency stop

```bash
python -m cver discovery-stop --actor tester --reason "acceptance test"
python -m cver discovery-worker --once --project-root .; test $? -eq 3
python -m cver discovery-resume --actor tester --reason "acceptance complete"
```

## Escape-lab guard validation

```bash
CVER_DISPOSABLE_LAB_READY=true \
CVER_ESCAPE_APPROVAL_DIGEST=<approved-64-hex-digest> \
CVER_AUTHORIZED_TARGETS=<owned-lab-targets> \
scripts/verify_escape_lab.sh
```

M1 ships no L3-L5 escape executor. Passing this guard script proves only that required operator inputs exist.
