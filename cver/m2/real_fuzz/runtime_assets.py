from __future__ import annotations

import hashlib
import json
import os
import shutil
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..config import M2Settings
from ..runner import SafeCommandRunner


REQUIRED_ASSETS = ("runtime", "agent", "kernel", "image", "config", "qemu")
ALLOWED_RELEASE_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class RuntimeAssetManager:
    def __init__(self, settings: M2Settings, runner: SafeCommandRunner | None = None) -> None:
        self.settings = settings
        assert settings.runtime_assets_root is not None
        self.root = settings.runtime_assets_root
        self.root.mkdir(parents=True, exist_ok=True)
        self.runner = runner or SafeCommandRunner(helper=settings.sudo_helper)

    def version_root(self, version: str) -> Path:
        safe = "".join(character for character in version if character.isalnum() or character in "._-")
        if not safe or safe != version:
            raise ValueError("invalid Kata version")
        path = (self.root / safe).resolve()
        if self.root not in path.parents:
            raise PermissionError("runtime asset path escaped its root")
        return path

    def register(
        self,
        version: str,
        assets: dict[str, str | Path],
        *,
        source: str,
        copy_assets: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        unknown = set(assets) - set(REQUIRED_ASSETS)
        if unknown:
            raise ValueError(f"unknown runtime assets: {', '.join(sorted(unknown))}")
        target_root = self.version_root(version)
        target_root.mkdir(parents=True, exist_ok=True)
        records: dict[str, Any] = {}
        for key in REQUIRED_ASSETS:
            raw = assets.get(key)
            if raw is None:
                records[key] = {"status": "missing"}
                continue
            source_path = Path(raw).expanduser().resolve()
            if not source_path.is_file():
                records[key] = {"status": "missing", "requested_path": str(source_path)}
                continue
            selected = source_path
            if copy_assets:
                if not confirm:
                    raise PermissionError("copying runtime assets requires --confirm")
                destination = target_root / key / source_path.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                if str(destination).startswith("/opt/kata"):
                    raise PermissionError("M2 never overwrites /opt/kata")
                shutil.copy2(source_path, destination)
                selected = destination
            records[key] = {
                "status": "present",
                "path": str(selected),
                "sha256": sha256(selected),
                "size_bytes": selected.stat().st_size,
            }
        complete = all(records[key]["status"] == "present" for key in REQUIRED_ASSETS)
        manifest = {
            "schema_version": 1,
            "version": version,
            "source": source,
            "registered_at": utc_now(),
            "asset_root": str(target_root),
            "assets": records,
            "complete": complete,
            "runtime_name": f"io.containerd.kata-cver-{version.replace('.', '-')}.v2",
            "namespace": self.settings.namespace,
            "system_kata_overwrite": False,
        }
        path = target_root / "manifest.json"
        path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"status": "READY" if complete else "INCOMPLETE", "manifest_path": str(path), **manifest}

    def readiness(self, version: str) -> dict[str, Any]:
        path = self.version_root(version) / "manifest.json"
        if not path.is_file():
            return {
                "status": "RUNTIME_NOT_REPRODUCED",
                "version": version,
                "reason": "versioned runtime asset manifest is missing",
                "missing": list(REQUIRED_ASSETS),
            }
        payload = json.loads(path.read_text(encoding="utf-8"))
        missing = []
        changed = []
        for key in REQUIRED_ASSETS:
            item = (payload.get("assets") or {}).get(key) or {}
            asset_path = Path(str(item.get("path", ""))).expanduser()
            if not asset_path.is_file():
                missing.append(key)
                continue
            if item.get("sha256") != sha256(asset_path):
                changed.append(key)
        if missing or changed:
            return {
                "status": "RUNTIME_NOT_REPRODUCED",
                "version": version,
                "manifest_path": str(path),
                "missing": missing,
                "hash_mismatch": changed,
            }
        return {"status": "READY", "version": version, "manifest_path": str(path), "manifest": payload}

    def list(self) -> list[dict[str, Any]]:
        values = []
        for manifest in sorted(self.root.glob("*/manifest.json")):
            try:
                payload = json.loads(manifest.read_text(encoding="utf-8"))
                values.append(
                    {
                        "version": payload.get("version"),
                        "complete": payload.get("complete"),
                        "manifest_path": str(manifest),
                        "source": payload.get("source"),
                    }
                )
            except (OSError, json.JSONDecodeError):
                continue
        return values

    def fetch_official(
        self,
        version: str,
        *,
        url: str,
        expected_sha256: str,
        asset_name: str,
        confirm: bool,
    ) -> dict[str, Any]:
        if not confirm:
            raise PermissionError("official asset download requires --confirm")
        if asset_name not in REQUIRED_ASSETS:
            raise ValueError(f"unknown asset name: {asset_name}")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_RELEASE_HOSTS:
            raise PermissionError("release URL host is not allowlisted")
        destination = self.version_root(version) / "downloads" / Path(parsed.path).name
        destination.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(url, headers={"User-Agent": "cver-m2-runtime-assets/1"})
        with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
            final_host = urllib.parse.urlparse(response.geturl()).hostname
            if final_host not in ALLOWED_RELEASE_HOSTS:
                raise PermissionError("release redirect host is not allowlisted")
            shutil.copyfileobj(response, output, length=1024 * 1024)
        actual = sha256(destination)
        if actual.lower() != expected_sha256.lower():
            destination.unlink(missing_ok=True)
            raise RuntimeError("downloaded release asset hash mismatch")
        return {
            "status": "DOWNLOADED",
            "version": version,
            "asset_name": asset_name,
            "path": str(destination),
            "sha256": actual,
            "source_url": url,
        }

    def build_from_recipe(
        self,
        version: str,
        *,
        source_root: str | Path,
        recipe_path: str | Path,
        confirm: bool,
    ) -> dict[str, Any]:
        if not (confirm and self.settings.allow_runtime_build):
            raise PermissionError(
                "runtime build requires CVER_M2_ALLOW_RUNTIME_BUILD=true and --confirm"
            )
        source = Path(source_root).expanduser().resolve()
        recipe_file = Path(recipe_path).expanduser().resolve()
        if not source.is_dir() or not recipe_file.is_file():
            raise FileNotFoundError("source checkout or approved build recipe is missing")
        recipe = json.loads(recipe_file.read_text(encoding="utf-8"))
        if recipe.get("approved") is not True:
            raise PermissionError("runtime build recipe is not approved")
        workspace = self.version_root(version) / "build"
        workspace.mkdir(parents=True, exist_ok=True)
        free_gb = shutil.disk_usage(workspace).free // (1024**3)
        if free_gb < self.settings.budget.max_disk_gb:
            return {
                "status": "SKIPPED_WITH_REASON",
                "reason": f"free disk {free_gb} GiB is below configured build allowance {self.settings.budget.max_disk_gb} GiB",
            }
        substitutions = {
            "${SOURCE_ROOT}": str(source),
            "${BUILD_ROOT}": str(workspace),
            "${VERSION}": version,
        }
        runs = []
        for index, raw_command in enumerate(recipe.get("commands", []), start=1):
            if not isinstance(raw_command, list) or not raw_command:
                raise ValueError("recipe commands must be non-empty argument arrays")
            command = []
            for argument in raw_command:
                value = str(argument)
                for old, new in substitutions.items():
                    value = value.replace(old, new)
                command.append(value)
            result = self.runner.run(command, cwd=workspace, timeout=float(recipe.get("timeout_seconds", 3600)))
            runs.append(
                {
                    "step": index,
                    "command": result.argv,
                    "exit_code": result.returncode,
                    "duration_seconds": result.duration_seconds,
                    "stdout_tail": result.stdout[-8000:],
                    "stderr_tail": result.stderr[-8000:],
                }
            )
            if not result.ok:
                return {
                    "status": "RUNTIME_ASSET_BUILD_FAILED",
                    "version": version,
                    "recipe_sha256": sha256(recipe_file),
                    "runs": runs,
                }
        return {
            "status": "BUILD_COMPLETED_ASSETS_REQUIRE_REGISTRATION",
            "version": version,
            "build_root": str(workspace),
            "recipe_sha256": sha256(recipe_file),
            "runs": runs,
        }
