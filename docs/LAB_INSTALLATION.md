# ARM64 Laboratory Installation

## Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp .env.example .env
```

Set `OPENAI_API_KEY`, `OPENAI_PLANNER_MODEL`, and `CVER_API_TOKEN` in `.env`.
`OPENAI_BASE_URL` is optional. Critic and summary models inherit the planner model.

## Existing installation scripts

The repository's existing ARM64 bootstrap and installer scripts remain available.
The new coordinator runs idempotent component installers and then the discovery
migration/doctor:

```bash
scripts/lab/bootstrap.sh
```

## Kata

Kata availability requires `ctr`, `kata-runtime`, and `containerd-shim-kata-v2`.
Import the configured image into containerd, then run the smoke test:

```bash
scripts/lab/prepare_kata_image.sh
python -m cver sandbox-smoke --backend kata --project-root .
```

## Firecracker assets

Resolution order is:

1. existing `CVER_FIRECRACKER_KERNEL` and `CVER_FIRECRACKER_ROOTFS`;
2. a reviewed manifest entry with SHA-256 values;
3. local source build.

```bash
CVER_FIRECRACKER_ASSET_MODE=build scripts/install/install_firecracker_assets.sh
source "$HOME/cver-lab/firecracker-assets/env.sh"
python -m cver sandbox-smoke --backend firecracker --project-root .
```

The source-build path needs internet access and the Linux/BusyBox build toolchain.
The smoke rootfs contains only a fixed init program that prints
`CVER_FIRECRACKER_SMOKE_OK` and powers off.

## Versioned component installers

The coordinator uses the existing Syft and Tracee installers plus versioned Firecracker and Kata installers:

```bash
scripts/install/install_firecracker.sh
scripts/install/install_kata.sh
scripts/install/install_firecracker_assets.sh
```

Release archives are accepted only when the GitHub release API exposes a publisher SHA-256 digest or when the operator supplies `CVER_FIRECRACKER_SHA256` / `CVER_KATA_SHA256`. Kata is installed under a versioned `/opt/kata-<version>` path and is not registered as the default containerd runtime.

Firecracker guest assets resolve in this order: existing `CVER_FIRECRACKER_KERNEL` and `CVER_FIRECRACKER_ROOTFS`, a reviewed checksum manifest, then a local source build. Source the generated `env.sh` before the smoke test.
