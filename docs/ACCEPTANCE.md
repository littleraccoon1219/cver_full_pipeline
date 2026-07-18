# Acceptance Checklist

## Automated local checks

```bash
python -m compileall -q cver scripts tests
pytest -q
python scripts/migrate_discovery_runtime.py
python -m cver discovery-doctor --project-root .
```

## Synthetic evidence gate

Direct fixture check:

```bash
python scripts/lab/run_synthetic_fixture.py benchmarks/synthetic_pathguard
```

Durable end-to-end benchmark job:

```bash
python -m cver discovery-benchmark --project-root .
python -m cver discovery-worker --once --project-root .
python -m cver discovery-list --limit 5
```

Expected markers:

- `CVER_SYNTHETIC_REPRODUCED`
- `SECURITY_INVARIANT_VIOLATION_CONFIRMED`

## Backend checks on the ARM64 Ubuntu VM

```bash
scripts/lab/smoke_backends.sh docker
scripts/lab/prepare_kata_image.sh
scripts/lab/smoke_backends.sh kata
source "$HOME/cver-lab/firecracker-assets/env.sh"
scripts/lab/smoke_backends.sh firecracker
```

Each unavailable backend must report `skipped_with_reason`; it must not silently use
another backend. Full historical escape validation is not an acceptance criterion
until an independent disposable KVM server exists.

## Historical non-destructive replay

```bash
# CVE-2024-21626 is the default case.
python -m cver historical-replay \
  --target "$HOME/cver-lab/sources/runc-current" --project-root .
python -m cver historical-replay CVE-2019-5736 \
  --target "$HOME/cver-lab/sources/runc-current" --project-root .
```

## Emergency-stop acceptance

```bash
python -m cver discovery-stop --actor tester --reason "acceptance test"
python -m cver discovery-worker --once --project-root .; test $? -eq 3
python -m cver discovery-resume --actor tester --reason "acceptance complete"
```
