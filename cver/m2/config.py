from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class Budget:
    name: str
    parallel_harnesses: int
    fuzz_seconds: int
    max_tasks_per_component: int
    rss_limit_mb: int
    source_depth: int
    qemu_native_build: bool


BUDGETS: dict[str, Budget] = {
    "quick": Budget("quick", 1, 60, 2, 1024, 1, False),
    "balanced": Budget("balanced", 2, 1800, 6, 2048, 1, False),
    "deep": Budget("deep", 4, 7200, 12, 4096, 50, True),
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(slots=True)
class M2Settings:
    project_root: Path
    state_root: Path
    runtime_db: Path
    artifacts_dir: Path
    reports_dir: Path
    candidates_dir: Path
    source_root: Path
    trusted_kb_db: Path
    namespace: str = "cver-m2"
    budget_profile: str = "balanced"
    llm_api_key: str = ""
    llm_base_url: str = "https://api.deepseek.com"
    llm_model: str = "deepseek-v4-pro"
    llm_timeout_seconds: float = 180.0
    llm_max_tokens: int = 4096
    llm_enabled: bool = True
    allow_source_fetch: bool = False
    allow_external_candidates: bool = False
    disposable_lab_ready: bool = False
    smoke_image: str = "docker.io/cver/kata-smoke:arm64"
    kata_config: Path = Path("/opt/kata/share/defaults/kata-containers/configuration-qemu.toml")
    sudo_helper: Path = Path("/usr/local/libexec/cver-m2-helper")
    api_token: str = ""
    zero_day_key_mode: str = "linux-keyring"
    component_filter: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_env(cls, project_root: str | Path = ".") -> "M2Settings":
        root = Path(project_root).expanduser().resolve()
        state_root = Path(os.getenv("CVER_M2_STATE_DIR", str(root / "data" / "m2"))).expanduser().resolve()
        source_root = Path(os.getenv("CVER_M2_SOURCE_ROOT", str(Path.home() / "security-src"))).expanduser().resolve()
        selected = tuple(
            item.strip()
            for item in os.getenv("CVER_M2_COMPONENTS", "").split(",")
            if item.strip()
        )
        return cls(
            project_root=root,
            state_root=state_root,
            runtime_db=Path(os.getenv("CVER_M2_RUNTIME_DB", str(state_root / "runtime.db"))).expanduser().resolve(),
            artifacts_dir=Path(
                os.getenv("CVER_M2_ARTIFACTS_DIR", str(state_root / "artifacts"))
            ).expanduser().resolve(),
            reports_dir=Path(os.getenv("CVER_M2_REPORTS_DIR", str(state_root / "reports"))).expanduser().resolve(),
            candidates_dir=Path(
                os.getenv("CVER_M2_CANDIDATES_DIR", str(state_root / "candidates"))
            ).expanduser().resolve(),
            source_root=source_root,
            trusted_kb_db=Path(
                os.getenv("CVER_M2_TRUSTED_KB_DB", str(root / "data" / "trusted_knowledge.db"))
            ).expanduser().resolve(),
            namespace=os.getenv("CVER_M2_CONTAINERD_NAMESPACE", "cver-m2"),
            budget_profile=os.getenv("CVER_M2_BUDGET", "balanced"),
            llm_api_key=(
                os.getenv("DEEPSEEK_API_KEY")
                or os.getenv("CVER_LLM_API_KEY")
                or os.getenv("OPENAI_API_KEY")
                or ""
            ),
            llm_base_url=os.getenv("CVER_LLM_BASE_URL", "https://api.deepseek.com"),
            llm_model=os.getenv("CVER_LLM_MODEL", "deepseek-v4-pro"),
            llm_timeout_seconds=float(os.getenv("CVER_LLM_TIMEOUT_SECONDS", "180")),
            llm_max_tokens=int(os.getenv("CVER_LLM_MAX_TOKENS", "4096")),
            llm_enabled=_env_bool("CVER_M2_LLM_ENABLED", True),
            allow_source_fetch=_env_bool("CVER_M2_ALLOW_SOURCE_FETCH", False),
            allow_external_candidates=_env_bool("CVER_M2_ALLOW_EXTERNAL_CANDIDATES", False),
            disposable_lab_ready=_env_bool("CVER_M2_DISPOSABLE_LAB_READY", False),
            smoke_image=os.getenv("CVER_M2_KATA_SMOKE_IMAGE", "docker.io/cver/kata-smoke:arm64"),
            kata_config=Path(
                os.getenv(
                    "CVER_M2_KATA_CONFIG",
                    "/opt/kata/share/defaults/kata-containers/configuration-qemu.toml",
                )
            ),
            sudo_helper=Path(os.getenv("CVER_M2_SUDO_HELPER", "/usr/local/libexec/cver-m2-helper")),
            api_token=os.getenv("CVER_M2_API_TOKEN") or os.getenv("CVER_API_TOKEN") or "",
            zero_day_key_mode=os.getenv("CVER_ZERO_DAY_KEY_MODE", "linux-keyring"),
            component_filter=selected,
        )

    @property
    def budget(self) -> Budget:
        try:
            return BUDGETS[self.budget_profile]
        except KeyError as exc:
            raise ValueError(f"unknown M2 budget profile: {self.budget_profile}") from exc

    def ensure_directories(self) -> None:
        for path in (
            self.state_root,
            self.artifacts_dir,
            self.reports_dir,
            self.candidates_dir,
            self.source_root,
        ):
            path.mkdir(parents=True, exist_ok=True)

    def redacted(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["llm_api_key"] = "configured" if self.llm_api_key else "missing"
        for key, value in tuple(payload.items()):
            if isinstance(value, Path):
                payload[key] = str(value)
        payload["budget"] = asdict(self.budget)
        return payload
