from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class RpcStep:
    handler: str
    input_profile: str
    expected_states: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)


BASE_SEQUENCES: dict[str, tuple[RpcStep, ...]] = {
    "exec-write-signal-wait": (
        RpcStep("ExecProcess", "valid_minimal", ("process_created",)),
        RpcStep("WriteStream", "bounded_stdio", ("process_created", "process_running")),
        RpcStep("SignalProcess", "non_fatal_signal", ("process_running",)),
        RpcStep("WaitProcess", "bounded_wait", ("process_running", "process_exited")),
    ),
    "update-wait": (
        RpcStep("ExecProcess", "valid_minimal", ("process_created",)),
        RpcStep("UpdateContainer", "bounded_resources", ("process_created", "process_running")),
        RpcStep("WaitProcess", "bounded_wait", ("process_running", "process_exited")),
    ),
}

CONCURRENCY_SCENARIOS: dict[str, tuple[str, str]] = {
    "wait-signal": ("WaitProcess", "SignalProcess"),
    "write-exit": ("WriteStream", "WaitProcess"),
    "update-wait": ("UpdateContainer", "WaitProcess"),
}


class DeterministicSequencePlanner:
    def plan(self, *, seed: int, sequence: str = "exec-write-signal-wait") -> dict[str, Any]:
        if sequence not in BASE_SEQUENCES:
            raise ValueError(f"unknown sequence: {sequence}")
        rng = random.Random(seed)
        steps = []
        for index, step in enumerate(BASE_SEQUENCES[sequence]):
            steps.append(
                {
                    "index": index,
                    "handler": step.handler,
                    "input_profile": step.input_profile,
                    "expected_states": list(step.expected_states),
                    "mutation_seed": rng.getrandbits(64),
                    "metadata": dict(step.metadata),
                }
            )
        payload = {
            "schema_version": 1,
            "mode": "stateful_sequence",
            "sequence": sequence,
            "seed": seed,
            "initial_state": "sandbox_ready",
            "steps": steps,
            "invariants": [
                "no duplicate terminal transition",
                "no process operation after terminal cleanup",
                "bounded wait completes or returns a typed timeout",
                "mock backend and real adapter return equivalent state classes",
            ],
        }
        payload["schedule_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return payload

    def concurrency(self, *, seed: int, scenario: str = "wait-signal") -> dict[str, Any]:
        if scenario not in CONCURRENCY_SCENARIOS:
            raise ValueError(f"unknown concurrency scenario: {scenario}")
        left, right = CONCURRENCY_SCENARIOS[scenario]
        rng = random.Random(seed)
        interleaving = [
            {"tick": index, "branch": rng.choice(("A", "B")), "yield_point": rng.randrange(0, 8)}
            for index in range(12)
        ]
        payload = {
            "schema_version": 1,
            "mode": "controlled_concurrency",
            "scenario": scenario,
            "seed": seed,
            "max_branches": 2,
            "branches": {"A": left, "B": right},
            "interleaving": interleaving,
            "classifiers": ["race", "deadlock", "timeout", "resource_exhaustion", "illegal_state"],
            "required_reproductions": 3,
        }
        payload["schedule_sha256"] = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return payload
