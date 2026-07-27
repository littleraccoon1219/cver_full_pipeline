from __future__ import annotations

import os
import hashlib
import json
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import M2Settings
from .environment import EnvironmentCollector
from .runner import SafeCommandRunner


@dataclass(frozen=True, slots=True)
class ComponentSource:
    component: str
    repository_url: str
    provider: str
    default_ref: str = "HEAD"


SOURCES: dict[str, ComponentSource] = {
    "kata-containers": ComponentSource(
        "kata-containers", "https://github.com/kata-containers/kata-containers.git", "github"
    ),
    "qemu": ComponentSource("qemu", "https://github.com/qemu/qemu.git", "github"),
    "virtiofsd": ComponentSource(
        "virtiofsd", "https://gitlab.com/virtio-fs/virtiofsd.git", "gitlab"
    ),
    "cloud-hypervisor": ComponentSource(
        "cloud-hypervisor", "https://github.com/cloud-hypervisor/cloud-hypervisor.git", "github"
    ),
    "firecracker": ComponentSource(
        "firecracker", "https://github.com/firecracker-microvm/firecracker.git", "github"
    ),
    "linux": ComponentSource("linux", "https://github.com/torvalds/linux.git", "github"),
}


class SourceManager:
    def __init__(self, settings: M2Settings, runner: SafeCommandRunner | None = None) -> None:
        self.settings = settings
        self.runner = runner or SafeCommandRunner(helper=settings.sudo_helper)

    def _selected(self, components: Iterable[str] | None) -> list[str]:
        selected = list(components or self.settings.component_filter or SOURCES.keys())
        unknown = sorted(set(selected) - set(SOURCES))
        if unknown:
            raise ValueError(f"unknown source components: {', '.join(unknown)}")
        return selected

    def _installed_refs(self) -> dict[str, str | None]:
        env = EnvironmentCollector(self.settings, self.runner).collect()
        qemu_version = env.get("qemu", {}).get("version")
        virtiofsd_version = env.get("virtiofsd", {}).get("version")
        return {
            "kata-containers": (os.getenv("CVER_M2_KATA_SOURCE_REF")or env.get("kata", {}).get("commit")),
            "qemu": (os.getenv("CVER_M2_QEMU_SOURCE_REF")or (f"v{qemu_version}" if qemu_version else None)),
            "virtiofsd": (os.getenv("CVER_M2_VIRTIOFSD_SOURCE_REF")or (f"v{virtiofsd_version}" if virtiofsd_version else None)),
            "cloud-hypervisor": (os.getenv("CVER_M2_CLOUD_HYPERVISOR_SOURCE_REF") or None),
            "firecracker": (os.getenv("CVER_M2_FIRECRACKER_SOURCE_REF") or None),
            "linux": (os.getenv("CVER_M2_LINUX_SOURCE_REF")or self._kernel_tag(env.get("host", {}).get("kernel"))),
        }


    @staticmethod
    def _kernel_tag(kernel: str | None) -> str | None:
        if not kernel:
            return None
        # Ubuntu内核如6.8.0-136-generic映射到上游主线标签v6.8
        match = re.match(r"(\d+)\.(\d+)", kernel)
        if not match:
            return None
        return f"v{match.group(1)}.{match.group(2)}"

    def plan(self, components: Iterable[str] | None = None) -> dict[str, Any]:
        installed = self._installed_refs()
        plans = []
        for component in self._selected(components):
            spec = SOURCES[component]
            for track, requested_ref in (
                ("installed-baseline", installed.get(component)),
                ("research-head", spec.default_ref),
            ):
                path = self.settings.source_root / component / track
                status = "present" if (path / ".git").is_dir() else "missing"
                if track == "installed-baseline" and not requested_ref:
                    status = "source_version_unresolved"
                plans.append(
                    {
                        "component": component,
                        "track": track,
                        "repository_url": spec.repository_url,
                        "requested_ref": requested_ref,
                        "path": str(path),
                        "status": status,
                    }
                )
        return {
            "source_root": str(self.settings.source_root),
            "automatic_fetch": False,
            "plans": plans,
        }

    def sync(
        self,
        components: Iterable[str] | None = None,
        *,
        fetch: bool = False,
        confirm: bool = False,
    ) -> dict[str, Any]:
        if fetch and not confirm:
            raise ValueError("source fetching requires explicit confirmation")
        if fetch and not self.settings.allow_source_fetch:
            raise PermissionError("CVER_M2_ALLOW_SOURCE_FETCH is not enabled")
        plan = self.plan(components)
        results = []
        for item in plan["plans"]:
            if item["status"] == "source_version_unresolved":
                item["reason"] = "installed binary could not be mapped to a reviewed source ref"
                results.append(item)
                continue
            path = Path(item["path"])
            if (path / ".git").is_dir():
                results.append(self._inspect_existing(item))
                continue
            if not fetch:
                item["status"] = "skipped_with_reason"
                item["reason"] = "source missing and explicit fetch was not requested"
                results.append(item)
                continue
            results.append(self._clone(item))
        manifest = {
            "schema_version": 1,
            "created_at": time.time(),
            "source_root": str(self.settings.source_root),
            "results": results,
        }
        manifest_path = self.settings.artifacts_dir / "source-manifests" / f"sources-{int(time.time())}.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest["manifest_path"] = str(manifest_path)
        manifest["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        return manifest

    def _inspect_existing(self, item: dict[str, Any]) -> dict[str, Any]:
        path = Path(item["path"])
        origin = self.runner.run(["git", "-C", str(path), "remote", "get-url", "origin"], timeout=20)
        commit = self.runner.run(["git", "-C", str(path), "rev-parse", "HEAD"], timeout=20)
        dirty = self.runner.run(["git", "-C", str(path), "status", "--porcelain"], timeout=20)
        expected = item["repository_url"].removesuffix(".git")
        actual = origin.stdout.strip().removesuffix(".git")
        item.update(
            {
                "status": "present" if commit.ok and actual == expected else "invalid",
                "origin": origin.stdout.strip(),
                "resolved_commit": commit.stdout.strip() if commit.ok else None,
                "dirty": bool(dirty.stdout.strip()),
                "source_digest": self._tree_digest(path) if commit.ok else None,
            }
        )
        if actual != expected:
            item["reason"] = "origin URL does not match the allowlisted upstream"
        return item

    def _clone(self, item: dict[str, Any]) -> dict[str, Any]:
        path = Path(item["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if any(path.iterdir()):
                item["status"] = "blocked"
                item["reason"] = "destination exists and is not an empty Git repository"
                return item
            path.rmdir()
        clone = self.runner.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout", item["repository_url"], str(path)],
            timeout=900,
        )
        if not clone.ok:
            item.update(status="failed", reason=(clone.stderr or clone.stdout)[-4000:])
            return item
        requested = item["requested_ref"] or "HEAD"
        fetch = self.runner.run(
            ["git", "-C", str(path), "fetch", "--depth=1", "origin", requested],
            timeout=900,
        )
        if not fetch.ok:
            shutil.rmtree(path, ignore_errors=True)
            item.update(status="failed", reason=(fetch.stderr or fetch.stdout)[-4000:])
            return item
        checkout = self.runner.run(["git", "-C", str(path), "checkout", "--detach", "FETCH_HEAD"], timeout=300)
        if not checkout.ok:
            shutil.rmtree(path, ignore_errors=True)
            item.update(status="failed", reason=(checkout.stderr or checkout.stdout)[-4000:])
            return item
        commit = self.runner.run(["git", "-C", str(path), "rev-parse", "HEAD"], timeout=20)
        item.update(
            {
                "status": "fetched",
                "resolved_commit": commit.stdout.strip(),
                "source_digest": self._tree_digest(path),
                "dirty": False,
            }
        )
        return item

    def _tree_digest(self, path: Path) -> str | None:
        # Hash the Git index representation, not decoded archive bytes. This is stable for
        # a pinned commit and avoids treating binary tar output as UTF-8 text.
        files = self.runner.run(["git", "-C", str(path), "ls-files", "-s"], timeout=120)
        if not files.ok:
            return None
        return hashlib.sha256(files.stdout.encode("utf-8")).hexdigest()
