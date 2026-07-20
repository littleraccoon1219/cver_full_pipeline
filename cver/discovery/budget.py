from __future__ import annotations

from dataclasses import replace
from typing import Any

from .models import BudgetLimits

DEFAULT_BUDGETS = {
    "quick": BudgetLimits(
        profile="quick",
        max_duration_seconds=3600,
        max_llm_calls=20,
        max_experiments=10,
        fuzz_budget_seconds=1200,
        max_deep_experiments=2,
    ),
    "balanced": BudgetLimits(
        profile="balanced",
        max_duration_seconds=3 * 3600,
        max_llm_calls=50,
        max_experiments=30,
        fuzz_budget_seconds=90 * 60,
        max_deep_experiments=5,
    ),
    "deep": BudgetLimits(
        profile="deep",
        max_duration_seconds=8 * 3600,
        max_llm_calls=120,
        max_experiments=80,
        fuzz_budget_seconds=4 * 3600,
        max_deep_experiments=15,
    ),
}


def resolve_budget(profile: str, overrides: dict[str, Any] | None = None) -> BudgetLimits:
    try:
        budget = DEFAULT_BUDGETS[profile]
    except KeyError as exc:
        raise ValueError(f"unknown budget profile: {profile}") from exc
    overrides = overrides or {}
    allowed = {
        "max_duration_seconds",
        "max_llm_calls",
        "max_experiments",
        "fuzz_budget_seconds",
        "max_deep_experiments",
        "max_api_cost_usd",
    }
    unknown = set(overrides) - allowed
    if unknown:
        raise ValueError(f"unknown budget override fields: {sorted(unknown)}")
    values = {key: value for key, value in overrides.items() if value is not None}
    for key, value in values.items():
        if key != "max_api_cost_usd" and int(value) <= 0:
            raise ValueError(f"{key} must be positive")
        if key == "max_api_cost_usd" and float(value) <= 0:
            raise ValueError("max_api_cost_usd must be positive")
    return replace(budget, **values)
