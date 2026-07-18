from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

from .errors import ConfigurationError


def _as_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigurationError(f"expected integer, got {value!r}") from exc


@dataclass(frozen=True, slots=True)
class DiscoverySettings:
    runtime_db: Path = Path("data/discovery_runtime.db")
    trusted_kb_db: Path = Path("data/trusted_knowledge.db")
    artifacts_dir: Path = Path("data/discovery_artifacts")
    workspace_root: Path = Path("data/discovery_workspaces")
    emergency_stop_file: Path = Path("data/CVER_EMERGENCY_STOP")

    openai_api_key: str | None = None
    openai_base_url: str | None = None
    planner_model: str | None = None
    critic_model: str | None = None
    summary_model: str | None = None
    llm_timeout_seconds: int = 120
    llm_store: bool = False

    api_token: str | None = None
    api_auth_required: bool = True
    test_mode: bool = False

    worker_lease_seconds: int = 300
    worker_poll_seconds: int = 2
    max_tool_seconds: int = 600
    disposable_lab_ready: bool = False
    allow_historical_poc: bool = False

    docker_image: str = "alpine:3.20"
    kata_image: str = "docker.io/library/alpine:3.20"
    kata_runtime: str = "io.containerd.kata.v2"
    firecracker_kernel: Path | None = None
    firecracker_rootfs: Path | None = None

    @classmethod
    def from_env(cls, *, env_file: str | Path | None = ".env", test_mode: bool | None = None) -> "DiscoverySettings":
        if env_file:
            load_dotenv(env_file, override=False)
        resolved_test_mode = _as_bool(os.getenv("CVER_TEST_MODE"), False) if test_mode is None else test_mode
        planner = os.getenv("OPENAI_PLANNER_MODEL")
        critic = os.getenv("OPENAI_CRITIC_MODEL") or planner
        summary = os.getenv("OPENAI_SUMMARY_MODEL") or planner
        return cls(
            runtime_db=Path(os.getenv("CVER_DISCOVERY_DB", "data/discovery_runtime.db")),
            trusted_kb_db=Path(os.getenv("CVER_TRUSTED_KB_DB", "data/trusted_knowledge.db")),
            artifacts_dir=Path(os.getenv("CVER_DISCOVERY_ARTIFACTS", "data/discovery_artifacts")),
            workspace_root=Path(os.getenv("CVER_DISCOVERY_WORKSPACES", "data/discovery_workspaces")),
            emergency_stop_file=Path(os.getenv("CVER_EMERGENCY_STOP_FILE", "data/CVER_EMERGENCY_STOP")),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            openai_base_url=os.getenv("OPENAI_BASE_URL") or None,
            planner_model=planner,
            critic_model=critic,
            summary_model=summary,
            llm_timeout_seconds=_as_int(os.getenv("CVER_LLM_TIMEOUT_SECONDS"), 120),
            llm_store=_as_bool(os.getenv("CVER_LLM_STORE"), False),
            api_token=os.getenv("CVER_API_TOKEN"),
            api_auth_required=_as_bool(os.getenv("CVER_API_AUTH_REQUIRED"), True),
            test_mode=resolved_test_mode,
            worker_lease_seconds=_as_int(os.getenv("CVER_WORKER_LEASE_SECONDS"), 300),
            worker_poll_seconds=_as_int(os.getenv("CVER_WORKER_POLL_SECONDS"), 2),
            max_tool_seconds=_as_int(os.getenv("CVER_MAX_TOOL_SECONDS"), 600),
            disposable_lab_ready=_as_bool(os.getenv("CVER_DISPOSABLE_LAB_READY"), False),
            allow_historical_poc=_as_bool(os.getenv("CVER_ALLOW_HISTORICAL_POC"), False),
            docker_image=os.getenv("CVER_DOCKER_IMAGE", "alpine:3.20"),
            kata_image=os.getenv("CVER_KATA_IMAGE", "docker.io/library/alpine:3.20"),
            kata_runtime=os.getenv("CVER_KATA_RUNTIME", "io.containerd.kata.v2"),
            firecracker_kernel=Path(os.environ["CVER_FIRECRACKER_KERNEL"]) if os.getenv("CVER_FIRECRACKER_KERNEL") else None,
            firecracker_rootfs=Path(os.environ["CVER_FIRECRACKER_ROOTFS"]) if os.getenv("CVER_FIRECRACKER_ROOTFS") else None,
        )

    def emergency_stop_active(self) -> bool:
        return _as_bool(os.getenv("CVER_EMERGENCY_STOP"), False) or self.emergency_stop_file.is_file()

    def validate_runtime(self, *, require_llm: bool = True, require_api_token: bool = False) -> None:
        if require_llm and not self.test_mode:
            missing = []
            if not self.openai_api_key:
                missing.append("OPENAI_API_KEY")
            if not self.planner_model:
                missing.append("OPENAI_PLANNER_MODEL")
            if missing:
                raise ConfigurationError("missing required LLM configuration: " + ", ".join(missing))
        if require_api_token and self.api_auth_required and not self.api_token and not self.test_mode:
            raise ConfigurationError("CVER_API_TOKEN is required while API authentication is enabled")
        if self.allow_historical_poc and not self.disposable_lab_ready:
            raise ConfigurationError(
                "CVER_ALLOW_HISTORICAL_POC requires CVER_DISPOSABLE_LAB_READY=true"
            )

    def ensure_directories(self) -> None:
        self.runtime_db.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
