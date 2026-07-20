from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class TaxonomyError(ValueError):
    pass


def load_taxonomy(path: str | Path = "taxonomy/root_causes.yaml") -> dict[str, Any]:
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    validate_taxonomy(payload)
    return payload


def validate_taxonomy(payload: dict[str, Any]) -> None:
    if payload.get("taxonomy_id") != "cver-root-cause":
        raise TaxonomyError("taxonomy_id must be cver-root-cause")
    if payload.get("immutable_macro_categories") is not True:
        raise TaxonomyError("immutable_macro_categories must be true")
    categories = payload.get("categories", [])
    if len(categories) != 5:
        raise TaxonomyError("the first-level taxonomy must contain exactly five macro root causes")

    expected = {f"RC-{index}" for index in range(1, 6)}
    actual = {category.get("code") for category in categories}
    if actual != expected:
        raise TaxonomyError(f"macro categories are immutable and must be {sorted(expected)}")

    seen: set[str] = set()
    for category in categories:
        code = category.get("code")
        if not code or code in seen:
            raise TaxonomyError(f"duplicate or missing category code: {code}")
        for required in ["name_en", "name_zh", "definition"]:
            if not category.get(required):
                raise TaxonomyError(f"{code} missing {required}")
        seen.add(code)
        children = category.get("children", [])
        if not 3 <= len(children) <= 6:
            raise TaxonomyError(f"{code} must contain 3-6 second-level categories")
        for child in children:
            child_code = child.get("code")
            if not child_code or child_code in seen or not child_code.startswith(f"{code}."):
                raise TaxonomyError(f"invalid child code: {child_code}")
            seen.add(child_code)
            for required in [
                "name_en",
                "name_zh",
                "definition",
                "include",
                "exclude",
                "positive_examples",
                "negative_examples",
                "machine_signals",
                "evidence_gate",
                "causal_test",
            ]:
                if not child.get(required):
                    raise TaxonomyError(f"{child_code} missing {required}")
            gate = child["evidence_gate"]
            if int(gate.get("minimum_independent_evidence", 0)) < 2:
                raise TaxonomyError(f"{child_code} evidence gate must require at least two independent evidence items")
            if gate.get("allows_text_only_classification") is not False:
                raise TaxonomyError(f"{child_code} must reject text-only classification")

    unknown = payload.get("unknown_label", {})
    if unknown.get("code") != "UNKNOWN" or unknown.get("classification_status") != "NEEDS_REVIEW":
        raise TaxonomyError("UNKNOWN label must be fixed and map to NEEDS_REVIEW")
