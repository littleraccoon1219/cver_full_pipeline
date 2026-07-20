from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from cver.knowledge.taxonomy import TaxonomyError, load_taxonomy


@dataclass(frozen=True, slots=True)
class RootCauseLabel:
    code: str
    parent: str
    name_en: str
    name_zh: str
    definition: str
    positive_examples: tuple[str, ...]
    negative_examples: tuple[str, ...]
    machine_signals: dict[str, tuple[str, ...]]
    evidence_gate: dict[str, Any]
    causal_test: str


@dataclass(frozen=True, slots=True)
class SecurityProperty:
    code: str
    name_en: str
    name_zh: str
    definition: str
    positive_examples: tuple[str, ...]
    negative_examples: tuple[str, ...]
    evidence_gate: dict[str, Any]


class TaxonomyCatalog:
    def __init__(
        self,
        root_cause_path: str | Path = "taxonomy/root_causes.yaml",
        security_property_path: str | Path = "taxonomy/security_properties.yaml",
    ) -> None:
        self.root_payload = load_taxonomy(root_cause_path)
        self.security_payload = yaml.safe_load(Path(security_property_path).read_text(encoding="utf-8"))
        self._validate_security_properties(self.security_payload)
        self.root_labels: dict[str, RootCauseLabel] = {}
        self.parents: dict[str, dict[str, Any]] = {}
        for category in self.root_payload["categories"]:
            self.parents[category["code"]] = category
            for child in category["children"]:
                self.root_labels[child["code"]] = RootCauseLabel(
                    code=child["code"],
                    parent=category["code"],
                    name_en=child["name_en"],
                    name_zh=child["name_zh"],
                    definition=child["definition"],
                    positive_examples=tuple(child["positive_examples"]),
                    negative_examples=tuple(child["negative_examples"]),
                    machine_signals={key: tuple(value) for key, value in child["machine_signals"].items()},
                    evidence_gate=dict(child["evidence_gate"]),
                    causal_test=child["causal_test"],
                )
        self.security_properties = {
            item["code"]: SecurityProperty(
                code=item["code"],
                name_en=item["name_en"],
                name_zh=item["name_zh"],
                definition=item["definition"],
                positive_examples=tuple(item["positive_examples"]),
                negative_examples=tuple(item["negative_examples"]),
                evidence_gate=dict(item["evidence_gate"]),
            )
            for item in self.security_payload["properties"]
        }

    @staticmethod
    def _validate_security_properties(payload: dict[str, Any]) -> None:
        if payload.get("taxonomy_id") != "cver-security-properties":
            raise TaxonomyError("security property taxonomy_id must be cver-security-properties")
        properties = payload.get("properties", [])
        expected = {f"SP{index}" for index in range(1, 14)}
        actual = {item.get("code") for item in properties}
        if actual != expected:
            raise TaxonomyError(f"security properties must be exactly {sorted(expected)}")
        for item in properties:
            for required in [
                "name_en",
                "name_zh",
                "definition",
                "positive_examples",
                "negative_examples",
                "evidence_gate",
            ]:
                if not item.get(required):
                    raise TaxonomyError(f"{item.get('code')} missing {required}")

    @property
    def version(self) -> str:
        return str(self.root_payload["version"])

    def prompt_context(self) -> dict[str, Any]:
        return {
            "taxonomy_version": self.version,
            "macro_categories": [
                {
                    "code": code,
                    "name_en": item["name_en"],
                    "name_zh": item["name_zh"],
                    "definition": item["definition"],
                }
                for code, item in sorted(self.parents.items())
            ],
            "second_level_labels": [
                {
                    "code": item.code,
                    "parent": item.parent,
                    "name_en": item.name_en,
                    "name_zh": item.name_zh,
                    "definition": item.definition,
                    "positive_examples": list(item.positive_examples),
                    "negative_examples": list(item.negative_examples),
                    "machine_signals": {key: list(value) for key, value in item.machine_signals.items()},
                    "evidence_gate": item.evidence_gate,
                    "causal_test": item.causal_test,
                }
                for item in self.root_labels.values()
            ],
            "security_properties": [
                {
                    "code": item.code,
                    "name_en": item.name_en,
                    "name_zh": item.name_zh,
                    "definition": item.definition,
                    "evidence_gate": item.evidence_gate,
                }
                for item in self.security_properties.values()
            ],
            "unknown_policy": self.root_payload["unknown_label"],
        }

    def validate_decision(self, decision: dict[str, Any], evidence_ids: Iterable[str]) -> list[str]:
        errors: list[str] = []
        evidence = {value for value in evidence_ids if value}
        primary_l1 = decision.get("primary_root_cause")
        primary_l2 = decision.get("primary_secondary_root_cause")
        status = decision.get("classification_status")

        if primary_l1 == "UNKNOWN" or primary_l2 == "UNKNOWN":
            if status != "NEEDS_REVIEW":
                errors.append("UNKNOWN requires classification_status=NEEDS_REVIEW")
        else:
            if primary_l1 not in self.parents:
                errors.append(f"invalid primary_root_cause: {primary_l1}")
            label = self.root_labels.get(str(primary_l2))
            if label is None:
                errors.append(f"invalid primary_secondary_root_cause: {primary_l2}")
            elif label.parent != primary_l1:
                errors.append(f"{primary_l2} does not belong to {primary_l1}")

        if primary_l1 != "UNKNOWN" and primary_l2 != "UNKNOWN":
            if len(evidence) < 2:
                errors.append("primary root cause requires at least two independent evidence IDs")
            if not decision.get("primary_causal_role"):
                errors.append("primary root cause must explain the first failure point in the causal chain")
            if decision.get("primary_counterfactual_changes_outcome") is not True:
                errors.append("primary root cause must pass the counterfactual causality test")

        used: set[str] = set()
        for item in decision.get("secondary_root_causes", []):
            code = item.get("code") if isinstance(item, dict) else None
            ids = set(item.get("evidence_ids", [])) if isinstance(item, dict) else set()
            if code not in self.root_labels:
                errors.append(f"invalid secondary root cause: {code}")
                continue
            if code in used or code == primary_l2:
                errors.append(f"duplicate root cause label: {code}")
            used.add(code)
            if not ids:
                errors.append(f"{code} must cite independent evidence IDs")
            if not ids.issubset(evidence):
                errors.append(f"{code} references unknown evidence IDs")
            if not item.get("causal_role"):
                errors.append(f"{code} must explain its causal role")
            if item.get("counterfactual_changes_outcome") is not True:
                errors.append(f"{code} must pass the counterfactual causality test")

        primary_property = decision.get("primary_security_property")
        if primary_property and primary_property not in self.security_properties:
            errors.append(f"invalid primary security property: {primary_property}")
        for code in decision.get("secondary_security_properties", []):
            if code not in self.security_properties:
                errors.append(f"invalid secondary security property: {code}")
        if decision.get("security_status") == "SECURITY_VULNERABILITY" and not primary_property:
            errors.append("confirmed security vulnerability requires a primary security property")
        return errors
