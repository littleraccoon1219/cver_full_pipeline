from __future__ import annotations

from cver.discovery.db import DiscoveryRepository
from cver.discovery.llm.gateway import LLMGateway

from .conftest import FakeProvider


def test_fake_provider_is_injected_explicitly(settings):
    repository = DiscoveryRepository(settings.runtime_db)
    repository.migrate()
    job = repository.submit_job(target=".")
    gateway = LLMGateway(settings, repository, FakeProvider())
    plan = gateway.plan(job.job_id, {"target": "."})
    assert plan["hypotheses"][0]["experiment_kinds"] == ["synthetic_fixture"]
