from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DEFAULT = {
    "profile": "demo",
    "storage": {"db_path": "data/cver_full_pipeline.db", "output_dir": "outputs/runs"},
    "scanner": {"backend_priority": ["mock", "real-cli", "dry-run"], "use_demo_data": True},
    "llm": {"provider": "mock", "mode": "hybrid"},
    "rag": {"mode": "keyword-rag"},
    "redteam": {"execution_level": "dry-run", "require_human_confirm": False},
    "repair": {"safe_apply": False, "require_human_confirm": True},
    "policy": {"require_lab_label": True, "allow_public_targets": False},
}


def deep_update(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_update(out[k], v)
        else:
            out[k] = v
    return out


def load_profile(profile: str | None = None) -> dict[str, Any]:
    profile = profile or os.environ.get("CVER_PROFILE") or "demo"
    data = {}
    for ext in ["json", "yaml"]:
        p = Path("config/profiles") / f"{profile}.{ext}"
        if p.exists():
            text = p.read_text(encoding="utf-8")
            try:
                data = json.loads(text)
            except Exception:
                try:
                    import yaml  # type: ignore

                    data = yaml.safe_load(text) or {}
                except Exception:
                    data = {}
            break
    cfg = deep_update(DEFAULT, data)
    if os.environ.get("CVER_DB_PATH"):
        cfg["storage"]["db_path"] = os.environ["CVER_DB_PATH"]
    if os.environ.get("CVER_LLM_PROVIDER"):
        cfg["llm"]["provider"] = os.environ["CVER_LLM_PROVIDER"]
    return cfg
