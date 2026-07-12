from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .models import RuleEvaluation, TriState

EVALUATOR_VERSION = "0.1.0"


@dataclass(slots=True)
class EvaluationContext:
    facts: dict[str, Any]

    def get(self, path: str) -> tuple[bool, Any]:
        current: Any = self.facts
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return False, None
        return True, current


def _loose_version(value: str) -> tuple[tuple[int, Any], ...]:
    tokens = re.findall(r"\d+|[A-Za-z]+", str(value))
    out: list[tuple[int, Any]] = []
    for token in tokens:
        if token.isdigit():
            out.append((0, int(token)))
        else:
            out.append((1, token.lower()))
    return tuple(out)


def _compare_versions(left: str, right: str) -> int:
    a = list(_loose_version(left))
    b = list(_loose_version(right))
    size = max(len(a), len(b))
    a.extend([(0, 0)] * (size - len(a)))
    b.extend([(0, 0)] * (size - len(b)))
    return (a > b) - (a < b)


def version_in_range(version: str, spec: str) -> bool:
    for clause in [item.strip() for item in spec.split(",") if item.strip()]:
        match = re.fullmatch(r"(<=|>=|==|!=|<|>)\s*(.+)", clause)
        if not match:
            raise ValueError(f"invalid version clause: {clause}")
        operator, expected = match.groups()
        comparison = _compare_versions(version, expected)
        ok = {
            "<": comparison < 0,
            "<=": comparison <= 0,
            ">": comparison > 0,
            ">=": comparison >= 0,
            "==": comparison == 0,
            "!=": comparison != 0,
        }[operator]
        if not ok:
            return False
    return True


def _negate(value: TriState) -> TriState:
    if value is TriState.TRUE:
        return TriState.FALSE
    if value is TriState.FALSE:
        return TriState.TRUE
    return TriState.UNKNOWN


def _all(values: list[TriState]) -> TriState:
    if any(value is TriState.FALSE for value in values):
        return TriState.FALSE
    if any(value is TriState.UNKNOWN for value in values):
        return TriState.UNKNOWN
    return TriState.TRUE


def _any(values: list[TriState]) -> TriState:
    if any(value is TriState.TRUE for value in values):
        return TriState.TRUE
    if any(value is TriState.UNKNOWN for value in values):
        return TriState.UNKNOWN
    return TriState.FALSE


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(actual, dict):
        return expected in actual
    if isinstance(actual, (list, tuple, set, str)):
        return expected in actual
    return False


def _evaluate_leaf(node: dict[str, Any], context: EvaluationContext) -> tuple[TriState, dict[str, Any]]:
    path = str(node.get("fact", ""))
    operator = str(node.get("operator", ""))
    expected = node.get("value")
    exists, actual = context.get(path)

    trace = {
        "node": "condition",
        "fact": path,
        "operator": operator,
        "expected": expected,
        "actual": actual if exists else None,
    }

    if operator == "exists":
        result = TriState.TRUE if exists else TriState.FALSE
    elif not exists or actual is None:
        result = TriState.UNKNOWN
    elif operator == "equals":
        result = TriState.TRUE if actual == expected else TriState.FALSE
    elif operator == "not_equals":
        result = TriState.TRUE if actual != expected else TriState.FALSE
    elif operator == "contains":
        result = TriState.TRUE if _contains(actual, expected) else TriState.FALSE
    elif operator == "version_in_range":
        result = TriState.TRUE if version_in_range(str(actual), str(expected)) else TriState.FALSE
    elif operator == "has_capability":
        result = TriState.TRUE if _contains(actual, expected) else TriState.FALSE
    elif operator == "kernel_config_enabled":
        result = TriState.TRUE if actual in (True, "y", "Y", "yes", "enabled", 1) else TriState.FALSE
    elif operator == "runtime_equals":
        result = TriState.TRUE if str(actual).lower() == str(expected).lower() else TriState.FALSE
    elif operator in {"path_mounted", "socket_exposed"}:
        result = TriState.TRUE if _contains(actual, expected) else TriState.FALSE
    else:
        raise ValueError(f"unsupported operator: {operator}")

    trace["result"] = result.value
    return result, trace


def evaluate_expression(expression: dict[str, Any], facts: dict[str, Any]) -> tuple[TriState, list[dict[str, Any]]]:
    context = EvaluationContext(facts)

    def walk(node: dict[str, Any]) -> tuple[TriState, dict[str, Any]]:
        logic = node.get("logic")
        if logic in {"and", "or"}:
            children = node.get("conditions", [])
            child_results = [walk(child) for child in children]
            values = [result for result, _ in child_results]
            result = _all(values) if logic == "and" else _any(values)
            return result, {
                "node": logic,
                "result": result.value,
                "children": [trace for _, trace in child_results],
            }
        if logic == "not":
            child = node.get("condition")
            if not isinstance(child, dict):
                raise ValueError("not expression requires condition")
            child_result, child_trace = walk(child)
            result = _negate(child_result)
            return result, {"node": "not", "result": result.value, "children": [child_trace]}
        return _evaluate_leaf(node, context)

    result, root_trace = walk(expression)
    return result, [root_trace]


def evaluate_rule(rule_id: str, environment_id: str, expression: dict[str, Any], facts: dict[str, Any]) -> RuleEvaluation:
    result, trace = evaluate_expression(expression, facts)
    canonical = json.dumps({"expression": expression, "facts": facts}, sort_keys=True, ensure_ascii=False, default=str)
    return RuleEvaluation(
        rule_id=rule_id,
        environment_id=environment_id,
        result=result,
        trace=trace,
        evaluator_version=EVALUATOR_VERSION,
        input_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )
