from __future__ import annotations

from cver.m2.workflow import M2Workflow


def test_degraded_workflow_finishes_without_llm_or_kata(m2_settings):
    workflow = M2Workflow(m2_settings)
    result = workflow.run_new(
        {
            "profile": "quick",
            "components": ["kata-containers"],
            "run_fuzz": False,
            "kata_smoke": False,
            "actor": "tester",
        }
    )
    assert result["status"] in {"partial", "completed"}
    assert result["result"]["phases"]["llm_review"]["status"] == "skipped_with_reason"
    assert result["result"]["phases"]["report"]["status"] == "completed"
