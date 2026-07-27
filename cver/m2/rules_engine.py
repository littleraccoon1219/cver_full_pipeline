from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


class TriState(str, enum.Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class RuleResult:
    rule_id: str
    outcome: TriState
    trace: list[dict[str, Any]] = field(default_factory=list)
    missing_facts: list[str] = field(default_factory=list)
    input_hash: str = ""


class ThreeValuedRuleEngine:
    def evaluate(self, rule_id: str, expression: dict[str, Any], facts: dict[str, Any]) -> dict[str, Any]:
        trace: list[dict[str, Any]] = []
        missing: set[str] = set()
        outcome = self._expression(expression, facts, trace, missing)
        input_hash = hashlib.sha256(
            json.dumps({"expression": expression, "facts": facts}, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        result = RuleResult(rule_id, outcome, trace, sorted(missing), input_hash)
        return {
            "rule_id": result.rule_id,
            "outcome": result.outcome.value,
            "trace": result.trace,
            "missing_facts": result.missing_facts,
            "input_hash": result.input_hash,
        }

    def _expression(
        self,
        expression: dict[str, Any],
        facts: dict[str, Any],
        trace: list[dict[str, Any]],
        missing: set[str],
    ) -> TriState:
        logic = str(expression.get("logic", "condition")).lower()
        if logic == "condition" or "fact" in expression:
            return self._condition(expression, facts, trace, missing)
        conditions = list(expression.get("conditions", []))
        if logic == "not":
            if len(conditions) != 1:
                raise ValueError("not expression requires exactly one condition")
            value = self._expression(conditions[0], facts, trace, missing)
            return {TriState.TRUE: TriState.FALSE, TriState.FALSE: TriState.TRUE}.get(value, TriState.UNKNOWN)
        values = [self._expression(item, facts, trace, missing) for item in conditions]
        if logic == "and":
            if TriState.FALSE in values:
                return TriState.FALSE
            if TriState.UNKNOWN in values:
                return TriState.UNKNOWN
            return TriState.TRUE
        if logic == "or":
            if TriState.TRUE in values:
                return TriState.TRUE
            if TriState.UNKNOWN in values:
                return TriState.UNKNOWN
            return TriState.FALSE
        raise ValueError(f"unsupported rule logic: {logic}")

    def _condition(
        self,
        condition: dict[str, Any],
        facts: dict[str, Any],
        trace: list[dict[str, Any]],
        missing: set[str],
    ) -> TriState:
        path = str(condition.get("fact", ""))
        operator = str(condition.get("operator", "equals"))
        expected = condition.get("value")
        exists, actual = _lookup(facts, path)
        if not exists:
            missing.add(path)
            outcome = TriState.UNKNOWN
        else:
            outcome = self._compare(operator, actual, expected)
        trace.append(
            {
                "fact": path,
                "operator": operator,
                "expected": expected,
                "actual": actual if exists else None,
                "outcome": outcome.value,
            }
        )
        return outcome

    @staticmethod
    def _compare(operator: str, actual: Any, expected: Any) -> TriState:
        try:
            if operator == "equals":
                return TriState.TRUE if actual == expected else TriState.FALSE
            if operator == "not_equals":
                return TriState.TRUE if actual != expected else TriState.FALSE
            if operator == "exists":
                return TriState.TRUE
            if operator in {"contains", "has_capability"}:
                return TriState.TRUE if expected in actual else TriState.FALSE
            if operator == "path_mounted":
                values = actual if isinstance(actual, list) else [actual]
                return TriState.TRUE if any(str(expected) == str(item) for item in values) else TriState.FALSE
            if operator == "socket_exposed":
                values = actual if isinstance(actual, list) else [actual]
                return TriState.TRUE if any(str(expected) in str(item) for item in values) else TriState.FALSE
            if operator == "version_in_range":
                return TriState.TRUE if Version(str(actual)) in SpecifierSet(str(expected)) else TriState.FALSE
            if operator == "lt":
                return TriState.TRUE if actual < expected else TriState.FALSE
            if operator == "lte":
                return TriState.TRUE if actual <= expected else TriState.FALSE
            if operator == "gt":
                return TriState.TRUE if actual > expected else TriState.FALSE
            if operator == "gte":
                return TriState.TRUE if actual >= expected else TriState.FALSE
        except (TypeError, ValueError, InvalidVersion, InvalidSpecifier):
            return TriState.UNKNOWN
        raise ValueError(f"unsupported rule operator: {operator}")


class ExploitabilityLadder:
    """Computes E0-E5 from hard evidence; advisory agents cannot change the level."""

    def assess(
        self,
        *,
        affected_version: TriState,
        prerequisites: TriState,
        reachable: TriState,
        controlled_trigger: TriState,
        boundary_impact: TriState,
    ) -> dict[str, Any]:
        ordered = [
            ("E1", affected_version),
            ("E2", prerequisites),
            ("E3", reachable),
            ("E4", controlled_trigger),
            ("E5", boundary_impact),
        ]
        level = "E0"
        missing = []
        blocking = []
        for candidate_level, state in ordered:
            if state is TriState.TRUE:
                level = candidate_level
                continue
            if state is TriState.UNKNOWN:
                missing.append(candidate_level)
            else:
                blocking.append(candidate_level)
            break
        return {
            "level": level,
            "states": {name: state.value for name, state in ordered},
            "missing_evidence_levels": missing,
            "blocking_levels": blocking,
            "confidence_policy": "unknown prerequisites remain UNKNOWN and are never coerced to false or true",
            "agent_override_allowed": False,
        }


def _lookup(facts: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = facts
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        else:
            return False, None
    return True, current
