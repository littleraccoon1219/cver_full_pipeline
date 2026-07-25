from __future__ import annotations

from fastapi.testclient import TestClient

from cver.m2.api import create_app
from cver.m2.reporting import redact


def test_redaction_hides_restricted_paths():
    payload = redact(
        {
            "crash_artifacts": [
                {"artifact_path": "/secret/crash", "sha256": "abc", "size_bytes": 3, "restricted": True}
            ],
            "context": "sensitive call path",
        }
    )
    assert payload["context"] == "[redacted]"
    assert payload["crash_artifacts"][0] == {"sha256": "abc", "size_bytes": 3, "restricted": True}


def test_api_health_and_job_submission(m2_settings, monkeypatch):
    app = create_app(m2_settings)
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    # Prevent a background execution in this unit test; submission persistence is the target.
    monkeypatch.setattr("cver.m2.api._EXECUTOR.submit", lambda *args, **kwargs: None)
    response = client.post("/api/m2/jobs", json={"run_fuzz": False, "kata_smoke": False})
    assert response.status_code == 202
    job_id = response.json()["job_id"]
    detail = client.get(f"/api/m2/jobs/{job_id}")
    assert detail.status_code == 200
    assert detail.json()["status"] == "queued"
