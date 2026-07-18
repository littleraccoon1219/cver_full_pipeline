from __future__ import annotations

from cver import db
from cver.models import Target
from cver.policy.guard import PolicyGuard


def test_executor_field_name_cannot_bypass_guard(tmp_path):
    db_path = tmp_path / "runtime.db"
    db.init_db(db_path)
    guard = PolicyGuard({"policy": {"require_lab_label": True}}, str(db_path))
    target = Target("local-image", "image", labels={"cver-lab": "true"})
    result = guard.decide(
        target=target,
        action={"execution_level": "dry-run", "forbidden_actions": ["real_escape_poc"]},
    )
    assert result["allowed"] is False
    assert "real_escape_poc" in result["reason"]
