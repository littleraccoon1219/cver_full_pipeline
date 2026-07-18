from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class LLMRequest:
    role: str
    model: str
    instructions: str
    input_text: str
    json_schema_name: str
    json_schema: dict[str, Any]
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LLMResponse:
    data: dict[str, Any]
    provider: str
    model: str
    response_id: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)


class LLMProvider(Protocol):
    name: str

    def complete_json(self, request: LLMRequest) -> LLMResponse:
        """Return one response that conforms to ``request.json_schema``."""
        ...
