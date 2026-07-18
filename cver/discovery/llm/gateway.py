from __future__ import annotations

import hashlib
from typing import Any

from jsonschema import Draft202012Validator

from ..config import DiscoverySettings
from ..db import DiscoveryRepository
from ..errors import ConfigurationError
from .base import LLMProvider, LLMRequest
from .redaction import DataClass, compact_json, sanitize_text
from .schemas import CRITIC_SCHEMA, HYPOTHESIS_SCHEMA, SUMMARY_SCHEMA


class LLMGateway:
    def __init__(self, settings: DiscoverySettings, repository: DiscoveryRepository, provider: LLMProvider) -> None:
        self.settings = settings
        self.repository = repository
        self.provider = provider

    def _invoke(
        self,
        *,
        job_id: str,
        role: str,
        model: str | None,
        instructions: str,
        payload: dict[str, Any],
        schema_name: str,
        schema: dict[str, Any],
        classification: DataClass,
    ) -> dict[str, Any]:
        if not model:
            raise ConfigurationError(f"model is not configured for role {role}")
        raw = compact_json(payload)
        sanitized = sanitize_text(raw, classification)
        request_hash = hashlib.sha256(sanitized.text.encode("utf-8")).hexdigest()
        call_id = self.repository.create_llm_call(
            job_id=job_id,
            role=role,
            provider=self.provider.name,
            model=model,
            request_hash=request_hash,
            classification=sanitized.classification.value,
        )
        request = LLMRequest(
            role=role,
            model=model,
            instructions=instructions,
            input_text=sanitized.text,
            json_schema_name=schema_name,
            json_schema=schema,
            metadata={"cver_job_id": job_id, "cver_role": role},
        )
        try:
            response = self.provider.complete_json(request)
            Draft202012Validator(schema).validate(response.data)
        except Exception as exc:
            self.repository.finish_llm_call(call_id, response=None, usage=None, error=str(exc))
            raise
        self.repository.finish_llm_call(
            call_id,
            response={"response_id": response.response_id, "data": response.data, "redactions": sanitized.redactions},
            usage=response.usage,
        )
        return response.data

    def plan(self, job_id: str, payload: dict[str, Any], *, classification: DataClass = DataClass.INTERNAL) -> dict[str, Any]:
        return self._invoke(
            job_id=job_id,
            role="planner",
            model=self.settings.planner_model,
            instructions=(
                "You are the hypothesis planner for an evidence-gated container vulnerability research system. "
                "Generate bounded hypotheses, never exploit payloads or arbitrary shell commands. Select only "
                "the enumerated experiment kinds. Distinguish known-CVE resemblance from novel evidence."
            ),
            payload=payload,
            schema_name="cver_hypothesis_plan",
            schema=HYPOTHESIS_SCHEMA,
            classification=classification,
        )

    def critique(self, job_id: str, payload: dict[str, Any], *, classification: DataClass = DataClass.INTERNAL) -> dict[str, Any]:
        return self._invoke(
            job_id=job_id,
            role="critic",
            model=self.settings.critic_model,
            instructions=(
                "Act as a strict security evidence critic. Do not infer successful exploitation from scanner output. "
                "A security vulnerability requires a violated security invariant and boundary impact evidence. "
                "Never recommend exploitable_zero_day; that promotion is reserved for policy and human review."
            ),
            payload=payload,
            schema_name="cver_evidence_critique",
            schema=CRITIC_SCHEMA,
            classification=classification,
        )

    def summarize(self, job_id: str, payload: dict[str, Any], *, classification: DataClass = DataClass.INTERNAL) -> dict[str, Any]:
        return self._invoke(
            job_id=job_id,
            role="summary",
            model=self.settings.summary_model,
            instructions=(
                "Produce a concise evidence-grounded research report. State limitations and skipped experiments. "
                "Do not upgrade the finding stage beyond the supplied adjudicated stage."
            ),
            payload=payload,
            schema_name="cver_discovery_summary",
            schema=SUMMARY_SCHEMA,
            classification=classification,
        )
