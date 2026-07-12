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
    categories = payload.get("categories", [])
    if len(categories) != 5:
        raise TaxonomyError("the first-level taxonomy must contain exactly five macro root causes")

    seen: set[str] = set()
    for category in categories:
        code = category.get("code")
        if not code or code in seen:
            raise TaxonomyError(f"duplicate or missing category code: {code}")
        seen.add(code)
        children = category.get("children", [])
        if not 3 <= len(children) <= 6:
            raise TaxonomyError(f"{code} must contain 3-6 second-level categories")
        for child in children:
            child_code = child.get("code")
            if not child_code or child_code in seen or not child_code.startswith(f"{code}."):
                raise TaxonomyError(f"invalid child code: {child_code}")
            seen.add(child_code)
            for required in ["name_en", "name_zh", "definition", "include", "exclude"]:
                if not child.get(required):
                    raise TaxonomyError(f"{child_code} missing {required}")
