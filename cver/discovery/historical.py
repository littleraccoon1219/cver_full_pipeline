from __future__ import annotations

import hashlib
import mmap
import re
from pathlib import Path
from typing import Any

import yaml
from packaging.version import InvalidVersion, Version

from .tools.runner import CommandRunner


def _version(value: str) -> Version:
    cleaned = value.strip().lstrip("v").replace("-rc.", "rc").replace("-rc", "rc")
    return Version(cleaned)


def _extract_runc_version(text: str) -> str | None:
    match = re.search(
        r"(?:runc version|version)\s+v?([0-9]+(?:\.[0-9]+){1,2}(?:[-.]?rc\.?[0-9]+)?)",
        text,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def _embedded_runc_version(path: Path) -> str | None:
    """Extract common runc version strings without executing the target binary."""
    patterns = [
        re.compile(rb"runc version\s+v?([0-9]+(?:\.[0-9]+){1,2}(?:[-.]?rc\.?[0-9]+)?)", re.IGNORECASE),
        re.compile(
            rb"github\.com/opencontainers/runc(?:/v2)?\s+v?([0-9]+(?:\.[0-9]+){1,2}(?:[-.]?rc\.?[0-9]+)?)",
            re.IGNORECASE,
        ),
    ]
    with path.open("rb") as stream:
        if path.stat().st_size == 0:
            return None
        with mmap.mmap(stream.fileno(), length=0, access=mmap.ACCESS_READ) as data:
            for pattern in patterns:
                match = pattern.search(data)
                if match:
                    return match.group(1).decode("ascii", errors="ignore")
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _affected(version: str, rule: dict[str, str]) -> bool | None:
    try:
        current = _version(version)
        if rule.get("min_inclusive") and current < _version(rule["min_inclusive"]):
            return False
        if rule.get("max_inclusive") and current > _version(rule["max_inclusive"]):
            return False
        if rule.get("max_exclusive") and current >= _version(rule["max_exclusive"]):
            return False
        return True
    except InvalidVersion:
        return None


class HistoricalReplay:
    """Non-destructive historical-CVE prerequisite and patch verifier."""

    def __init__(self, manifest: str | Path, runner: CommandRunner) -> None:
        self.manifest = Path(manifest)
        self.runner = runner

    def cases(self) -> list[dict[str, Any]]:
        payload = yaml.safe_load(self.manifest.read_text(encoding="utf-8")) or {}
        return list(payload.get("cases", []))

    def replay(self, case_id: str, target: str) -> dict[str, Any]:
        case = next((item for item in self.cases() if item.get("id") == case_id), None)
        if not case:
            raise KeyError(case_id)

        path = Path(target).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(path)

        observations: dict[str, Any] = {}
        version: str | None = None
        if path.is_file():
            version = _embedded_runc_version(path)
            build_info = self.runner.run(["go", "version", "-m", str(path)], tool="go-binary-metadata")
            observations["binary_metadata"] = {
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
                "go_build_info": build_info.to_dict(),
                "inspection_policy": "static_only_binary_not_executed",
            }
            if not version:
                version = _extract_runc_version(build_info.stdout + "\n" + build_info.stderr)
        elif (path / ".git").is_dir():
            describe = self.runner.run(
                ["git", "describe", "--tags", "--always"],
                cwd=path,
                tool="git-describe",
            )
            observations["git_describe"] = describe.to_dict()
            version = _extract_runc_version("version " + describe.stdout.strip())
            fix_presence: dict[str, bool] = {}
            for commit in case.get("fix_commits", []):
                check = self.runner.run(
                    ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
                    cwd=path,
                    tool="git-ancestor",
                )
                fix_presence[commit] = check.exit_code == 0
            observations["fix_commit_presence"] = fix_presence
        else:
            raise ValueError("target must be a runc executable or Git checkout")

        affected = _affected(version, case.get("affected", {})) if version else None
        fix_presence = observations.get("fix_commit_presence", {})
        if fix_presence and any(fix_presence.values()):
            patch_state = "fixed_commit_present"
        elif affected is False:
            patch_state = "version_not_affected"
        elif affected is True:
            patch_state = "affected_version_without_confirmed_fix_commit"
        else:
            patch_state = "fixed_commit_not_confirmed"
        return {
            "case_id": case_id,
            "title": case.get("title"),
            "mode": "non_destructive_prerequisite_and_patch_validation",
            "poc_executed": False,
            "detected_version": version,
            "version_appears_affected": affected,
            "patch_state": patch_state,
            "security_invariant": case.get("security_invariant"),
            "prerequisites": case.get("prerequisites", []),
            "fixed_versions": case.get("fixed_versions", []),
            "references": case.get("references", []),
            "observations": observations,
            "status": "completed",
            "limitations": [
                "No container escape payload was executed.",
                "Version matching alone is not proof of exploitability.",
                "Full host-impact validation remains BLOCKED_NO_DISPOSABLE_LAB.",
            ],
        }
