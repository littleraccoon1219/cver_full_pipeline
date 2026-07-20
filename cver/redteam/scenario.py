from __future__ import annotations

from ..storage import read_json


def load_scenarios(path: str = "data/scenarios/attack_scenarios.json") -> list[dict]:
    return read_json(path).get("scenarios", [])
