from __future__ import annotations

import json
from typing import Any

from ..errors import ConfigurationError
from .base import LLMRequest, LLMResponse


class OpenAIProvider:
    name = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str | None = None,
        timeout_seconds: int = 120,
        store: bool = False,
    ) -> None:
        if not api_key:
            raise ConfigurationError("OPENAI_API_KEY is required")
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise ConfigurationError("openai package is not installed") from exc
        kwargs: dict[str, Any] = {"api_key": api_key, "timeout": timeout_seconds}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = OpenAI(**kwargs)
        self._store = store

    def complete_json(self, request: LLMRequest) -> LLMResponse:
        response = self._client.responses.create(
            model=request.model,
            instructions=request.instructions,
            input=request.input_text,
            store=self._store,
            metadata=request.metadata or None,
            text={
                "format": {
                    "type": "json_schema",
                    "name": request.json_schema_name,
                    "schema": request.json_schema,
                    "strict": True,
                }
            },
        )
        output_text = getattr(response, "output_text", None)
        if not output_text:
            raise RuntimeError("OpenAI response did not contain output_text")
        data = json.loads(output_text)
        usage_obj = getattr(response, "usage", None)
        if usage_obj is None:
            usage: dict[str, Any] = {}
        elif hasattr(usage_obj, "model_dump"):
            usage = usage_obj.model_dump()
        elif isinstance(usage_obj, dict):
            usage = usage_obj
        else:
            usage = {"raw": str(usage_obj)}
        return LLMResponse(
            data=data,
            provider=self.name,
            model=getattr(response, "model", request.model),
            response_id=getattr(response, "id", None),
            usage=usage,
        )
