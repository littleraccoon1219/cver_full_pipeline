from __future__ import annotations

from fastapi.testclient import TestClient

from cver.discovery.api import create_app


def test_api_requires_token(settings):
    client = TestClient(create_app(settings))
    unauthorized = client.get("/v1/jobs")
    assert unauthorized.status_code == 401
    authorized = client.get("/v1/jobs", headers={"Authorization": "Bearer test-token"})
    assert authorized.status_code == 200


def test_job_submission(settings, tmp_path):
    client = TestClient(create_app(settings))
    response = client.post(
        "/v1/jobs",
        headers={"X-API-Key": "test-token"},
        json={"target": str(tmp_path), "target_kind": "source", "risk": "low", "backend": "auto"},
    )
    assert response.status_code == 202
    assert response.json()["status"] == "queued"


def test_api_rejects_restricted_cloud_job(settings, tmp_path):
    client = TestClient(create_app(settings))
    response = client.post(
        "/v1/jobs",
        headers={"X-API-Key": "test-token"},
        json={
            "target": str(tmp_path),
            "target_kind": "source",
            "risk": "low",
            "backend": "auto",
            "data_class": "restricted",
        },
    )
    assert response.status_code == 400


def test_emergency_stop_blocks_new_jobs_and_can_resume(settings, tmp_path):
    client = TestClient(create_app(settings))
    headers = {"X-API-Key": "test-token"}
    stopped = client.post(
        "/v1/control/emergency-stop",
        headers=headers,
        json={"actor": "operator", "reason": "test interlock"},
    )
    assert stopped.status_code == 200
    assert settings.emergency_stop_file.is_file()
    blocked = client.post(
        "/v1/jobs",
        headers=headers,
        json={"target": str(tmp_path), "target_kind": "source"},
    )
    assert blocked.status_code == 423
    resumed = client.request(
        "DELETE",
        "/v1/control/emergency-stop",
        headers=headers,
        json={"actor": "operator", "reason": "test complete"},
    )
    assert resumed.status_code == 200
    assert not settings.emergency_stop_file.exists()


def test_v2_taxonomy_and_budget_endpoints(settings):
    client = TestClient(create_app(settings))
    headers = {"X-API-Key": "test-token"}
    taxonomy = client.get("/v2/taxonomy", headers=headers)
    assert taxonomy.status_code == 200
    assert {item["code"] for item in taxonomy.json()["macro_categories"]} == {"RC-1", "RC-2", "RC-3", "RC-4", "RC-5"}
    budgets = client.get("/v2/budgets", headers=headers)
    assert budgets.status_code == 200
    assert budgets.json()["balanced"]["max_llm_calls"] == 50


def test_v2_candidate_and_human_annotation(settings, tmp_path):
    client = TestClient(create_app(settings))
    headers = {"X-API-Key": "test-token"}
    artifact = tmp_path / "evidence.txt"
    artifact.write_text("source and runtime boundary evidence", encoding="utf-8")
    created = client.post(
        "/v2/candidates",
        headers=headers,
        json={
            "source_type": "vendor_advisory",
            "component_id": "runc",
            "title": "candidate",
            "data_class": "public",
            "artifacts": [{"path": str(artifact), "kind": "advisory"}],
        },
    )
    assert created.status_code == 201
    candidate_id = created.json()["candidate_id"]
    annotation = {
        "taxonomy_version": "1.0.0",
        "security_status": "SECURITY_VULNERABILITY",
        "primary_root_cause": "RC-2",
        "primary_secondary_root_cause": "RC-2.2",
        "primary_causal_role": "The first failed invariant exposed a host mount.",
        "primary_counterfactual_changes_outcome": True,
        "secondary_root_causes": [],
        "primary_security_property": "SP6",
        "secondary_security_properties": [],
        "evidence_ids": ["ev-source", "ev-runtime"],
        "rationale": "Human-reviewed source and runtime evidence establish the boundary violation.",
        "classification_status": "ACCEPTED",
        "status": "gold",
    }
    annotated = client.post(
        f"/v2/candidates/{candidate_id}/annotations",
        headers=headers,
        json={"annotator": "human-researcher", "annotation": annotation},
    )
    assert annotated.status_code == 201
    assert annotated.json()["annotation_id"].startswith("ann-")
