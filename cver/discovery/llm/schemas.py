from __future__ import annotations

from typing import Any

HYPOTHESIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["hypotheses", "coverage_gaps"],
    "properties": {
        "hypotheses": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "title",
                    "root_cause_l1",
                    "root_cause_l2",
                    "security_boundary",
                    "invariant",
                    "rationale",
                    "confidence",
                    "experiment_kinds",
                    "known_cve_candidates",
                ],
                "properties": {
                    "title": {"type": "string", "minLength": 1, "maxLength": 240},
                    "root_cause_l1": {"type": "string", "enum": ["RC-1", "RC-2", "RC-3", "RC-4", "RC-5", "UNKNOWN"]},
                    "root_cause_l2": {
                        "type": "string",
                        "enum": [
                            "RC-1.1",
                            "RC-1.2",
                            "RC-1.3",
                            "RC-1.4",
                            "RC-1.5",
                            "RC-1.6",
                            "RC-2.1",
                            "RC-2.2",
                            "RC-2.3",
                            "RC-2.4",
                            "RC-2.5",
                            "RC-2.6",
                            "RC-3.1",
                            "RC-3.2",
                            "RC-3.3",
                            "RC-3.4",
                            "RC-3.5",
                            "RC-3.6",
                            "RC-4.1",
                            "RC-4.2",
                            "RC-4.3",
                            "RC-4.4",
                            "RC-4.5",
                            "RC-5.1",
                            "RC-5.2",
                            "RC-5.3",
                            "RC-5.4",
                            "RC-5.5",
                            "RC-5.6",
                            "UNKNOWN",
                        ],
                    },
                    "security_boundary": {"type": "string", "minLength": 1, "maxLength": 240},
                    "invariant": {"type": "string", "minLength": 1, "maxLength": 500},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 1600},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "experiment_kinds": {
                        "type": "array",
                        "maxItems": 5,
                        "items": {
                            "type": "string",
                            "enum": [
                                "version_check",
                                "semgrep_scan",
                                "go_test",
                                "go_fuzz",
                                "patch_diff",
                                "synthetic_fixture",
                                "tracee_observe",
                            ],
                        },
                    },
                    "known_cve_candidates": {
                        "type": "array",
                        "maxItems": 10,
                        "items": {"type": "string", "pattern": "^CVE-[0-9]{4}-[0-9]{4,}$"},
                    },
                },
            },
        },
        "coverage_gaps": {"type": "array", "maxItems": 20, "items": {"type": "string"}},
    },
}

CRITIC_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["verdict", "supported_claims", "unsupported_claims", "next_experiments", "recommended_stage"],
    "properties": {
        "verdict": {"type": "string", "enum": ["supported", "partially_supported", "unsupported"]},
        "supported_claims": {"type": "array", "items": {"type": "string"}, "maxItems": 30},
        "unsupported_claims": {"type": "array", "items": {"type": "string"}, "maxItems": 30},
        "next_experiments": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": [
                    "version_check",
                    "semgrep_scan",
                    "go_test",
                    "go_fuzz",
                    "patch_diff",
                    "synthetic_fixture",
                    "tracee_observe",
                ],
            },
            "maxItems": 10,
        },
        "recommended_stage": {
            "type": "string",
            "enum": ["candidate_defect", "reproducible_bug", "security_vulnerability"],
        },
    },
}

SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["executive_summary", "findings", "limitations", "next_actions"],
    "properties": {
        "executive_summary": {"type": "string", "maxLength": 2400},
        "findings": {"type": "array", "items": {"type": "string"}, "maxItems": 30},
        "limitations": {"type": "array", "items": {"type": "string"}, "maxItems": 30},
        "next_actions": {"type": "array", "items": {"type": "string"}, "maxItems": 30},
    },
}
