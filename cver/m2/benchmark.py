from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .static_analysis import AttackSurfaceScanner


def _prf1(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


class M2Benchmark:
    def __init__(self, project_root: str | Path) -> None:
        self.project_root = Path(project_root).resolve()

    def run(self) -> dict[str, Any]:
        root = self.project_root / "benchmarks" / "m2_kata_synthetic"
        labels_path = root / "labels.json"
        if not labels_path.is_file():
            return {"status": "skipped_with_reason", "reason": f"missing benchmark labels: {labels_path}"}
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        result = AttackSurfaceScanner(max_findings=200).scan("synthetic-kata", root / "fixtures")
        predicted = {item["metadata"]["pattern_code"] for item in result.get("findings", [])}
        expected = set(labels.get("expected_pattern_codes", []))
        negative = set(labels.get("negative_pattern_codes", []))
        tp = len(predicted & expected)
        fp = len((predicted - expected) | (predicted & negative))
        fn = len(expected - predicted)
        return {
            "status": "completed",
            "dataset": "m2_kata_synthetic",
            "metrics": _prf1(tp, fp, fn),
            "predicted": sorted(predicted),
            "expected": sorted(expected),
            "negative": sorted(negative),
            "finding_count": len(result.get("findings", [])),
            "limitations": "Synthetic pattern-gate benchmark; it does not estimate real zero-day discovery rate.",
        }
