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
    max_versions: int
    max_disk_gb: int
    coverage_plateau_minutes: int
    replay_attempts: int


BUDGETS: dict[str, Budget] = {
    "quick": Budget("quick", 1, 60, 2, 1024, 1, False, 1, 5, 5, 1),
    "balanced": Budget("balanced", 2, 1800, 6, 2048, 1, False, 3, 20, 30, 3),
    "deep": Budget("deep", 2, 7200, 12, 4096, 50, True, 5, 45, 120, 5),
}

# These ceilings are intentionally independent of a profile. A caller cannot bypass
# them by supplying a larger CLI value. Raising a ceiling requires a code review.
HARD_LIMITS: dict[str, int] = {
    "fuzz_seconds": 14_400,
    "parallel_harnesses": 2,
    "max_versions": 5,
    "max_disk_gb": 50,
    "coverage_plateau_minutes": 180,
    "replay_attempts": 5,
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


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
    real_fuzz_root: Path | None = None
    runtime_assets_root: Path | None = None
    adapter_manifest_dir: Path | None = None
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
    allow_adapter_patch: bool = False
    allow_runtime_build: bool = False
    allow_guest_replay: bool = False
    disposable_lab_ready: bool = False
    smoke_image: str = "docker.io/cver/kata-smoke:arm64"
    kata_config: Path = Path("/opt/kata/share/defaults/kata-containers/configuration-qemu.toml")
    sudo_helper: Path = Path("/usr/local/libexec/cver-m2-helper")
    api_token: str = ""
    zero_day_key_mode: str = "linux-keyring"
    component_filter: tuple[str, ...] = field(default_factory=tuple)
    rust_nightly: str = "nightly-2026-06-01"
    current_kata_version: str = "3.32.0"
    max_versions_override: int | None = None
    max_disk_gb_override: int | None = None
    coverage_plateau_override: int | None = None

    def __post_init__(self) -> None:
        self.real_fuzz_root = (self.real_fuzz_root or self.state_root / "real-fuzz").expanduser().resolve()
        self.runtime_assets_root = (
            self.runtime_assets_root or self.state_root / "runtime-assets"
        ).expanduser().resolve()
        self.adapter_manifest_dir = (
            self.adapter_manifest_dir or self.project_root / "configs" / "m2_adapters"
        ).expanduser().resolve()

    @classmethod
    def from_env(cls, project_root: str | Path = ".") -> "M2Settings":
        root = Path(project_root).expanduser().resolve()
        state_root = Path(os.getenv("CVER_M2_STATE_DIR", str(root / "data" / "m2"))).expanduser().resolve()
        source_root = Path(os.getenv("CVER_M2_SOURCE_ROOT", str(Path.home() / "security-src"))).expanduser().resolve()
        selected = tuple(item.strip() for item in os.getenv("CVER_M2_COMPONENTS", "").split(",") if item.strip())
        return cls(
            project_root=root,
            state_root=state_root,
            runtime_db=Path(os.getenv("CVER_M2_RUNTIME_DB", str(state_root / "runtime.db"))).expanduser().resolve(),
            artifacts_dir=Path(os.getenv("CVER_M2_ARTIFACTS_DIR", str(state_root / "artifacts"))).expanduser().resolve(),
            reports_dir=Path(os.getenv("CVER_M2_REPORTS_DIR", str(state_root / "reports"))).expanduser().resolve(),
            candidates_dir=Path(os.getenv("CVER_M2_CANDIDATES_DIR", str(state_root / "candidates"))).expanduser().resolve(),
            source_root=source_root,
            trusted_kb_db=Path(
                os.getenv("CVER_M2_TRUSTED_KB_DB", str(root / "data" / "trusted_knowledge.db"))
            ).expanduser().resolve(),
            real_fuzz_root=Path(os.getenv("CVER_M2_REAL_FUZZ_ROOT", str(state_root / "real-fuzz"))),
            runtime_assets_root=Path(os.getenv("CVER_M2_RUNTIME_ASSETS_ROOT", str(state_root / "runtime-assets"))),
            adapter_manifest_dir=Path(
                os.getenv("CVER_M2_ADAPTER_MANIFEST_DIR", str(root / "configs" / "m2_adapters"))
            ),
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
            allow_adapter_patch=_env_bool("CVER_M2_ALLOW_ADAPTER_PATCH", False),
            allow_runtime_build=_env_bool("CVER_M2_ALLOW_RUNTIME_BUILD", False),
            allow_guest_replay=_env_bool("CVER_M2_ALLOW_GUEST_REPLAY", False),
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
            rust_nightly=os.getenv("CVER_M2_RUST_NIGHTLY", "nightly-2026-06-01"),
            current_kata_version=os.getenv("CVER_M2_CURRENT_KATA_VERSION", "3.32.0"),
            max_versions_override=(
                _env_int("CVER_M2_MAX_VERSIONS", 0) or None
            ),
            max_disk_gb_override=(
                _env_int("CVER_M2_MAX_DISK_GB", 0) or None
            ),
            coverage_plateau_override=(
                _env_int("CVER_M2_COVERAGE_PLATEAU_MINUTES", 0) or None
            ),
        )

    @property
    def budget(self) -> Budget:
        try:
            base = BUDGETS[self.budget_profile]
        except KeyError as exc:
            raise ValueError(f"unknown M2 budget profile: {self.budget_profile}") from exc
        max_versions = self.max_versions_override or base.max_versions
        max_disk_gb = self.max_disk_gb_override or base.max_disk_gb
        plateau = self.coverage_plateau_override or base.coverage_plateau_minutes
        if max_versions > HARD_LIMITS["max_versions"]:
            raise ValueError(f"max_versions exceeds hard ceiling {HARD_LIMITS['max_versions']}")
        if max_disk_gb > HARD_LIMITS["max_disk_gb"]:
            raise ValueError(f"max_disk_gb exceeds hard ceiling {HARD_LIMITS['max_disk_gb']}")
        if plateau > HARD_LIMITS["coverage_plateau_minutes"]:
            raise ValueError(
                f"coverage plateau exceeds hard ceiling {HARD_LIMITS['coverage_plateau_minutes']} minutes"
            )
        return Budget(
            base.name,
            min(base.parallel_harnesses, HARD_LIMITS["parallel_harnesses"]),
            min(base.fuzz_seconds, HARD_LIMITS["fuzz_seconds"]),
            base.max_tasks_per_component,
            base.rss_limit_mb,
            base.source_depth,
            base.qemu_native_build,
            max_versions,
            max_disk_gb,
            plateau,
            min(base.replay_attempts, HARD_LIMITS["replay_attempts"]),
        )

    def resolve_fuzz_seconds(self, value: int | None) -> int:
        seconds = self.budget.fuzz_seconds if value is None else int(value)
        if seconds < 1:
            raise ValueError("fuzz seconds must be positive")
        if seconds > HARD_LIMITS["fuzz_seconds"]:
            raise ValueError(f"fuzz seconds exceeds hard ceiling {HARD_LIMITS['fuzz_seconds']}")
        return seconds

    def ensure_directories(self) -> None:
        for path in (
            self.state_root,
            self.artifacts_dir,
            self.reports_dir,
            self.candidates_dir,
            self.source_root,
            self.real_fuzz_root,
            self.runtime_assets_root,
            self.adapter_manifest_dir,
        ):
            assert path is not None
            path.mkdir(parents=True, exist_ok=True)

    def redacted(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["llm_api_key"] = "configured" if self.llm_api_key else "missing"
        for key, value in tuple(payload.items()):
            if isinstance(value, Path):
                payload[key] = str(value)
        payload["budget"] = asdict(self.budget)
        payload["hard_limits"] = dict(HARD_LIMITS)
        return payload
