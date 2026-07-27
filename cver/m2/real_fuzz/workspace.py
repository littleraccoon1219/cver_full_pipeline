from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .models import AdapterState, SourceInspection, asdict
from .sequences import DeterministicSequencePlanner


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "unknown"


ROOT_CARGO = """[workspace]
members = ["bridge", "mocks", "fuzz"]
resolver = "2"

[workspace.package]
edition = "2021"
license = "Apache-2.0"
"""

MOCK_CARGO = """[package]
name = "cver-kata-agent-mocks"
version = "0.1.0"
edition.workspace = true

[dependencies]
serde = { version = "1", features = ["derive"] }
"""

MOCK_LIB = """use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeterministicState {
    pub process_exists: bool,
    pub process_exited: bool,
    pub bytes_written: usize,
}

impl DeterministicState {
    pub fn bounded_input(data: &[u8]) -> &[u8] {
        &data[..data.len().min(65_536)]
    }
}
"""

BRIDGE_CARGO = """[package]
name = "cver-kata-agent-bridge"
version = "0.1.0"
edition.workspace = true

[features]
default = []
approved-real-adapter = []

[dependencies]
anyhow = "1"
cver-kata-agent-mocks = { path = "../mocks" }
"""

BRIDGE_LIB = """#[cfg(not(feature = "approved-real-adapter"))]
compile_error!("real handler fuzzing requires an approved source-pinned adapter");

#[cfg(feature = "approved-real-adapter")]
mod approved;
#[cfg(feature = "approved-real-adapter")]
pub use approved::{invoke_handler, invoke_sequence};
"""

BRIDGE_PLACEHOLDER = """//! Replace only through the reviewed adapter approval workflow.
use anyhow::{bail, Result};

pub fn invoke_handler(_handler: &str, _data: &[u8]) -> Result<()> {
    bail!("approved kata-agent bridge implementation has not been installed")
}

pub fn invoke_sequence(_plan: &[u8]) -> Result<()> {
    bail!("approved kata-agent sequence bridge implementation has not been installed")
}
"""

FUZZ_HEADER = """[package]
name = "cver-kata-agent-real-fuzz"
version = "0.1.0"
publish = false
edition.workspace = true

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
cver-kata-agent-bridge = { path = "../bridge", features = ["approved-real-adapter"] }

"""


class RealFuzzWorkspace:
    """Creates an independent cargo-fuzz workspace outside the Kata checkout.

    The generated bridge crate is intentionally non-buildable until an approved,
    source-pinned adapter implementation is supplied. This prevents a mock parser
    from being mistaken for evidence from the real kata-agent handler.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def prepare(
        self,
        inspection: SourceInspection,
        adapter_check: dict[str, Any],
        *,
        track: str,
        seed: int = 1337,
    ) -> dict[str, Any]:
        commit = inspection.commit or inspection.rpc_sha256[:12] or "unknown"
        workspace = self.root / "kata-agent" / _safe(track) / _safe(inspection.version) / _safe(commit[:16])
        for path in (
            workspace / "fuzz" / "fuzz_targets",
            workspace / "fuzz" / "corpus",
            workspace / "bridge" / "src",
            workspace / "mocks" / "src",
            workspace / "patches",
            workspace / "plans",
            workspace / "artifacts",
        ):
            path.mkdir(parents=True, exist_ok=True)
        self._write_root_manifest(workspace)
        self._write_mock_backend(workspace)
        self._write_bridge(workspace, adapter_check)
        self._write_fuzz_manifest(workspace, inspection)
        for handler in inspection.handlers:
            self._write_target(workspace, handler.handler_id, handler.rust_method)
            self._write_seed(workspace, handler.handler_id, handler.request_type)
        planner = DeterministicSequencePlanner()
        (workspace / "plans" / "stateful-sequence.json").write_text(
            json.dumps(planner.plan(seed=seed), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        (workspace / "plans" / "controlled-concurrency.json").write_text(
            json.dumps(planner.concurrency(seed=seed), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        lock = {
            "schema_version": 1,
            "source": asdict(inspection),
            "adapter": adapter_check.get("adapter"),
            "adapter_state": adapter_check.get("state"),
            "track": track,
            "workspace_policy": {
                "independent_from_kata_checkout": True,
                "real_handler_evidence_requires_approved_bridge": True,
                "mock_results_are_interface_tests_only": True,
                "automatic_patch_execution": False,
                "automatic_escape_payload_generation": False,
            },
        }
        lock_bytes = json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        (workspace / "workspace-lock.json").write_bytes(lock_bytes)
        self._write_patch_policy(workspace, inspection, adapter_check)
        return {
            "status": "prepared",
            "workspace": str(workspace),
            "workspace_lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "adapter_state": adapter_check.get("state"),
            "handler_targets": [handler.handler_id for handler in inspection.handlers],
            "real_build_ready": adapter_check.get("state") == AdapterState.APPROVED.value,
            "next_gate": (
                None
                if adapter_check.get("state") == AdapterState.APPROVED.value
                else "approve an exact adapter and replace bridge/src/approved.rs"
            ),
        }

    @staticmethod
    def _write_root_manifest(workspace: Path) -> None:
        (workspace / "Cargo.toml").write_text(ROOT_CARGO, encoding="utf-8")

    @staticmethod
    def _write_mock_backend(workspace: Path) -> None:
        (workspace / "mocks" / "Cargo.toml").write_text(MOCK_CARGO, encoding="utf-8")
        (workspace / "mocks" / "src" / "lib.rs").write_text(MOCK_LIB, encoding="utf-8")

    @staticmethod
    def _write_bridge(workspace: Path, adapter_check: dict[str, Any]) -> None:
        approved = adapter_check.get("state") == AdapterState.APPROVED.value
        (workspace / "bridge" / "Cargo.toml").write_text(BRIDGE_CARGO, encoding="utf-8")
        (workspace / "bridge" / "src" / "lib.rs").write_text(BRIDGE_LIB, encoding="utf-8")
        approved_path = workspace / "bridge" / "src" / "approved.rs"
        if not approved_path.exists():
            approved_path.write_text(BRIDGE_PLACEHOLDER, encoding="utf-8")
        (workspace / "bridge" / "adapter-state.json").write_text(
            json.dumps(
                {
                    "state": adapter_check.get("state"),
                    "approved": approved,
                    "adapter_id": (adapter_check.get("adapter") or {}).get("adapter_id"),
                    "automatic_execution": False,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _write_fuzz_manifest(workspace: Path, inspection: SourceInspection) -> None:
        bins = []
        for handler in inspection.handlers:
            target = f"fuzz_{handler.rust_method}"
            bins.append(
                f"[[bin]]\nname = \"{target}\"\npath = \"fuzz_targets/{target}.rs\"\n"
                "test = false\ndoc = false\nbench = false\n"
            )
        (workspace / "fuzz" / "Cargo.toml").write_text(
            FUZZ_HEADER + "\n".join(bins), encoding="utf-8"
        )

    @staticmethod
    def _write_target(workspace: Path, handler_id: str, method: str) -> None:
        target = workspace / "fuzz" / "fuzz_targets" / f"fuzz_{method}.rs"
        target.write_text(
            "#![no_main]\nuse libfuzzer_sys::fuzz_target;\n\n"
            f"fuzz_target!(|data: &[u8]| {{ let _ = cver_kata_agent_bridge::invoke_handler(\"{handler_id}\", data); }});\n",
            encoding="utf-8",
        )

    @staticmethod
    def _write_seed(workspace: Path, handler_id: str, request_type: str) -> None:
        root = workspace / "fuzz" / "corpus" / f"fuzz_{re.sub(r'(?<!^)(?=[A-Z])', '_', handler_id).lower()}"
        root.mkdir(parents=True, exist_ok=True)
        seed = json.dumps(
            {
                "request_type": request_type,
                "handler": handler_id,
                "container_id": "cver-test",
                "exec_id": "cver-exec",
                "bounded": True,
            },
            sort_keys=True,
        ).encode("utf-8")
        (root / f"seed-{hashlib.sha256(seed).hexdigest()[:12]}").write_bytes(seed)

    @staticmethod
    def _write_patch_policy(
        workspace: Path, inspection: SourceInspection, adapter_check: dict[str, Any]
    ) -> None:
        content = {
            "schema_version": 1,
            "status": "candidate_only_not_applied",
            "source_root": inspection.source_root,
            "source_commit": inspection.commit,
            "rpc_sha256": inspection.rpc_sha256,
            "adapter_state": adapter_check.get("state"),
            "allowed_patch_scope": [
                "feature-gated visibility wrappers",
                "deterministic mock backend injection",
                "construction helpers under cfg(cver-fuzz)",
            ],
            "forbidden_patch_scope": [
                "validation changes",
                "authorization changes",
                "production feature defaults",
                "panic suppression",
                "security check removal",
            ],
            "required_checks": [
                "git diff scope review",
                "stable cargo check of unmodified production features",
                "adapter interface test",
                "semantic differential test against the unpatched handler",
            ],
        }
        (workspace / "patches" / "adapter-patch-policy.json").write_text(
            json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8"
        )
