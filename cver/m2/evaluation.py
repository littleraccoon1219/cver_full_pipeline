from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Iterable


def classification_metrics(truth: list[str], predicted: list[str]) -> dict[str, Any]:
    if len(truth) != len(predicted):
        raise ValueError("truth and predicted lengths differ")
    labels = sorted(set(truth) | set(predicted))
    per_class = {}
    weighted_sum = 0.0
    macro_sum = 0.0
    correct = 0
    for label in labels:
        tp = sum(t == label and p == label for t, p in zip(truth, predicted))
        fp = sum(t != label and p == label for t, p in zip(truth, predicted))
        fn = sum(t == label and p != label for t, p in zip(truth, predicted))
        support = sum(t == label for t in truth)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_class[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }
        macro_sum += f1
        weighted_sum += f1 * support
    correct = sum(t == p for t, p in zip(truth, predicted))
    total = len(truth)
    return {
        "accuracy": correct / total if total else 0.0,
        "macro_f1": macro_sum / len(labels) if labels else 0.0,
        "weighted_f1": weighted_sum / total if total else 0.0,
        "per_class": per_class,
        "support": total,
    }


def binary_calibration(truth: list[int], probability: list[float]) -> dict[str, Any]:
    if len(truth) != len(probability):
        raise ValueError("truth and probability lengths differ")
    clipped = [min(1.0, max(0.0, float(value))) for value in probability]
    brier = sum((p - y) ** 2 for p, y in zip(clipped, truth)) / len(truth) if truth else 0.0
    return {"brier_score": brier, "auroc": _auroc(truth, clipped)}


def ranking_metrics(relevance: list[int], *, k: int = 10) -> dict[str, float]:
    top = relevance[:k]
    first = next((index + 1 for index, value in enumerate(relevance) if value > 0), None)
    recall = sum(value > 0 for value in top) / max(1, sum(value > 0 for value in relevance))
    dcg = sum((2**value - 1) / math.log2(index + 2) for index, value in enumerate(top))
    ideal = sorted(relevance, reverse=True)[:k]
    idcg = sum((2**value - 1) / math.log2(index + 2) for index, value in enumerate(ideal))
    return {
        "mrr": 1 / first if first else 0.0,
        f"recall@{k}": recall,
        f"ndcg@{k}": dcg / idcg if idcg else 0.0,
    }


def fuzz_metrics(runs: Iterable[dict[str, Any]]) -> dict[str, Any]:
    values = list(runs)
    unique_hashes = {
        item.get("sha256")
        for run in values
        for item in run.get("evidence", [])
        if item.get("sha256")
    }
    crashes = sum(bool(run.get("evidence")) for run in values)
    durations = [float(run.get("duration_seconds", 0.0)) for run in values]
    reproduced = sum(
        int((run.get("reproducibility") or {}).get("successful_reproductions", 0) >= 3)
        for run in values
    )
    coverage = defaultdict(list)
    for run in values:
        for key, value in (run.get("coverage") or {}).items():
            if isinstance(value, (int, float)):
                coverage[key].append(value)
    return {
        "runs": len(values),
        "crash_runs": crashes,
        "unique_crash_artifacts": len(unique_hashes),
        "time_to_first_crash_seconds": next((sum(durations[: index + 1]) for index, run in enumerate(values) if run.get("evidence")), None),
        "reproduction_rate": reproduced / crashes if crashes else 0.0,
        "coverage_max": {key: max(items) for key, items in coverage.items()},
        "total_runtime_seconds": sum(durations),
    }


def evaluate_predictions(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    values = list(records)
    macro = classification_metrics(
        [str(item["truth_macro"]) for item in values],
        [str(item["predicted_macro"]) for item in values],
    )
    fine = classification_metrics(
        [str(item["truth_fine"]) for item in values],
        [str(item["predicted_fine"]) for item in values],
    )
    exploitability = classification_metrics(
        [str(item["truth_exploitability"]) for item in values],
        [str(item["predicted_exploitability"]) for item in values],
    )
    binary = binary_calibration(
        [int(item.get("truth_exploitable_binary", 0)) for item in values],
        [float(item.get("predicted_probability", 0.0)) for item in values],
    )
    layers = defaultdict(list)
    for item in values:
        layers[str(item.get("dataset_layer", "unknown"))].append(item)
    return {
        "macro_classification": macro,
        "fine_classification": fine,
        "exploitability": {**exploitability, **binary},
        "by_dataset_layer": {
            layer: classification_metrics(
                [str(item["truth_exploitability"]) for item in items],
                [str(item["predicted_exploitability"]) for item in items],
            )
            for layer, items in layers.items()
        },
        "reporting_note": "controlled synthetic and real vulnerability results are separated",
    }


def _auroc(truth: list[int], probability: list[float]) -> float:
    positives = [score for label, score in zip(truth, probability) if label == 1]
    negatives = [score for label, score in zip(truth, probability) if label == 0]
    if not positives or not negatives:
        return 0.0
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            wins += 1.0 if positive > negative else 0.5 if positive == negative else 0.0
    return wins / (len(positives) * len(negatives))
