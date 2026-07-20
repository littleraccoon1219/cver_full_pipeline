# Manual verification policy

The project deliberately does not install a GitHub Actions workflow. Verification is separated by privilege and risk:

1. `scripts/verify_basic.sh` — compilation, migrations, taxonomy validation, tests, optional Ruff.
2. `CVER_ACK_PRIVILEGED_SMOKE=yes scripts/verify_sandbox.sh` — non-destructive Docker/Kata/Firecracker smoke checks.
3. `scripts/verify_fullstack_experiments.sh` — capability matrix and optional safe historical runc replay.
4. `scripts/verify_escape_lab.sh` — validates disposable-lab and immutable-approval guards only; M1 ships no escape executor.

A skipped backend is acceptable only when the output contains a concrete reason and remediation. A missing dependency must never be converted into a simulated successful result.
