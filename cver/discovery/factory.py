from __future__ import annotations

from pathlib import Path

from .config import DiscoverySettings
from .db import DiscoveryRepository
from .llm import LLMGateway, LLMProvider, OpenAIProvider
from .workflow import DiscoveryWorkflow


def build_gateway(
    settings: DiscoverySettings, repository: DiscoveryRepository, provider: LLMProvider | None = None
) -> LLMGateway:
    settings.validate_runtime(require_llm=provider is None)
    if provider is None:
        provider = OpenAIProvider(
            api_key=settings.openai_api_key or "",
            base_url=settings.openai_base_url,
            timeout_seconds=settings.llm_timeout_seconds,
            store=settings.llm_store,
        )
    return LLMGateway(settings, repository, provider)


def build_workflow(
    settings: DiscoverySettings,
    *,
    provider: LLMProvider | None = None,
    project_root: str | Path = ".",
) -> DiscoveryWorkflow:
    settings.ensure_directories()
    repository = DiscoveryRepository(settings.runtime_db)
    repository.migrate()
    gateway = build_gateway(settings, repository, provider)
    return DiscoveryWorkflow(settings, repository, gateway, project_root=project_root)
