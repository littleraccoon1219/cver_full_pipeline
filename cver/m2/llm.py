from __future__ import annotations

import json
from typing import Any

from .config import M2Settings


class DeepSeekReviewer:
    def __init__(self, settings: M2Settings) -> None:
        self.settings = settings
        self._client: Any | None = None
        self._error: str | None = None
        if not settings.llm_enabled:
            self._error = "CVER_M2_LLM_ENABLED is false"
            return
        if not settings.llm_api_key:
            self._error = "DEEPSEEK_API_KEY is not configured"
            return
        try:
            from openai import OpenAI

            self._client = OpenAI(
                api_key=settings.llm_api_key,
                base_url=settings.llm_base_url,
                timeout=settings.llm_timeout_seconds,
                max_retries=2,
            )
        except Exception as exc:
            self._error = f"{type(exc).__name__}: {exc}"

    @property
    def available(self) -> bool:
        return self._client is not None

    @property
    def unavailable_reason(self) -> str | None:
        return self._error

    def review_findings(self, findings: list[dict[str, Any]], environment: dict[str, Any]) -> dict[str, Any]:
        if not self.available:
            return {
                "status": "skipped_with_reason",
                "reason": self.unavailable_reason,
                "candidate_status": "unreviewed",
                "reviews": [],
            }
        compact = []
        for item in findings[:80]:
            compact.append(
                {
                    "finding_id": item.get("finding_id"),
                    "component": item.get("component"),
                    "category": item.get("category"),
                    "file": item.get("file"),
                    "line": item.get("line"),
                    "description": item.get("description"),
                    "tags": item.get("tags", []),
                    "context": item.get("metadata", {}).get("context", "")[:2400],
                }
            )
        system = (
            "You are the defensive Critic for an authorized Kata Containers research lab. "
            "Return JSON only. Never generate an exploit, guest-to-host escape payload, persistence, "
            "credential theft, or arbitrary command sequence. Distinguish candidate patterns from "
            "evidence-supported vulnerabilities. Require executable sanitizer, reachability, or "
            "boundary evidence before promotion."
        )
        user = json.dumps(
            {
                "task": "Review vulnerability candidates and propose safe validation steps.",
                "required_json_shape": {
                    "reviews": [
                        {
                            "finding_id": "string",
                            "decision": "SUPPORTED|REJECTED|NEEDS_DYNAMIC_EVIDENCE",
                            "confidence": 0.0,
                            "reason": "string",
                            "required_evidence": ["string"],
                            "safe_validation_plan": ["non-weaponized step"],
                            "remediation": ["string"],
                        }
                    ]
                },
                "environment": {
                    "architecture": environment.get("host", {}).get("architecture"),
                    "kata": environment.get("kata", {}),
                    "qemu": environment.get("qemu", {}),
                    "configuration": environment.get("configuration", {}),
                },
                "candidates": compact,
            },
            ensure_ascii=False,
        )
        try:
            response = self._client.chat.completions.create(
                model=self.settings.llm_model,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                response_format={"type": "json_object"},
                max_tokens=self.settings.llm_max_tokens,
                reasoning_effort="high",
                extra_body={"thinking": {"type": "enabled"}},
                stream=False,
            )
            content = response.choices[0].message.content or ""
            if not content.strip():
                raise RuntimeError("DeepSeek returned empty content")
            payload = json.loads(content)
            reviews = payload.get("reviews", [])
            return {
                "status": "ok",
                "provider": "deepseek-openai-compatible",
                "model": self.settings.llm_model,
                "reviews": reviews,
                "usage": self._usage(response),
            }
        except Exception as exc:
            return {
                "status": "skipped_with_reason",
                "reason": f"{type(exc).__name__}: {exc}",
                "candidate_status": "unreviewed",
                "reviews": [],
            }

    @staticmethod
    def _usage(response: Any) -> dict[str, Any]:
        usage = getattr(response, "usage", None)
        if usage is None:
            return {}
        if hasattr(usage, "model_dump"):
            return usage.model_dump()
        return {
            "prompt_tokens": getattr(usage, "prompt_tokens", None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "total_tokens": getattr(usage, "total_tokens", None),
        }
