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
