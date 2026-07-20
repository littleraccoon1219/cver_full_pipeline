from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from ..models import Target
from ..storage import read_json


@dataclass
class ScanArtifact:
    source: str
    backend: str
    status: str
    data: dict[str, Any]
    errors: list[str]


class Scanner:
    name = "base"

    def available(self) -> bool:
        return False

    def scan(self, target: Target, profile: dict[str, Any]) -> ScanArtifact:
        raise NotImplementedError


class MockCompositeScanner(Scanner):
    name = "mock-composite"

    def available(self) -> bool:
        return True

    def scan(self, target: Target, profile: dict[str, Any]) -> ScanArtifact:
        data = read_json("data/demo/findings_demo.json")
        data["target"] = {
            "target_id": target.target_id,
            "name": target.name,
            "kind": target.kind,
            "labels": target.labels,
        }
        return ScanArtifact(self.name, "mock", "ok", data, [])


class TrivyScanner(Scanner):
    name = "trivy"

    def available(self) -> bool:
        return shutil.which("trivy") is not None

    def scan(self, target: Target, profile: dict[str, Any]) -> ScanArtifact:
        if profile.get("scanner", {}).get("use_demo_data") or not self.available():
            return ScanArtifact(
                self.name,
                "mock" if profile.get("scanner", {}).get("use_demo_data") else "dry-run",
                "ok",
                read_json("data/demo/trivy_image_demo.json"),
                [],
            )
        args = ["trivy", "image", "--format", "json", "--scanners", "vuln,misconfig,secret,license"]
        if profile.get("scanner", {}).get("trivy_skip_db_update"):
            args.append("--skip-db-update")
        args.append(target.name)
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=180, check=False)
            if p.returncode not in (0, 1):
                return ScanArtifact(self.name, "real-cli", "error", {}, [p.stderr[-1000:]])
            return ScanArtifact(
                self.name, "real-cli", "ok", json.loads(p.stdout or "{}"), [p.stderr] if p.stderr else []
            )
        except Exception as e:
            return ScanArtifact(self.name, "dry-run", "error", {}, [str(e)])


class SyftScanner(Scanner):
    name = "syft"

    def available(self) -> bool:
        return shutil.which("syft") is not None

    def scan(self, target: Target, profile: dict[str, Any]) -> ScanArtifact:
        if profile.get("scanner", {}).get("use_demo_data") or not self.available():
            return ScanArtifact(
                self.name,
                "mock" if profile.get("scanner", {}).get("use_demo_data") else "dry-run",
                "ok",
                read_json("data/demo/syft_sbom_demo.json"),
                [],
            )
        try:
            p = subprocess.run(
                ["syft", target.name, "-o", "json"], capture_output=True, text=True, timeout=120, check=False
            )
            if p.returncode != 0:
                return ScanArtifact(self.name, "real-cli", "error", {}, [p.stderr[-1000:]])
            return ScanArtifact(self.name, "real-cli", "ok", json.loads(p.stdout or "{}"), [])
        except Exception as e:
            return ScanArtifact(self.name, "dry-run", "error", {}, [str(e)])


class DockerInspectScanner(Scanner):
    name = "docker-inspect"

    def available(self) -> bool:
        return shutil.which("docker") is not None

    def scan(self, target: Target, profile: dict[str, Any]) -> ScanArtifact:
        if profile.get("scanner", {}).get("use_demo_data") or not self.available():
            return ScanArtifact(
                self.name,
                "mock" if profile.get("scanner", {}).get("use_demo_data") else "dry-run",
                "ok",
                read_json("data/demo/docker_inspect_demo.json"),
                [],
            )
        if target.kind not in ("image", "container"):
            return ScanArtifact(self.name, "dry-run", "skipped", {}, [])
        try:
            p = subprocess.run(
                ["docker", "inspect", target.name], capture_output=True, text=True, timeout=30, check=False
            )
            if p.returncode != 0:
                return ScanArtifact(self.name, "real-cli", "error", {}, [p.stderr[-1000:]])
            d = json.loads(p.stdout or "[]")
            return ScanArtifact(self.name, "real-cli", "ok", d[0] if isinstance(d, list) and d else d, [])
        except Exception as e:
            return ScanArtifact(self.name, "dry-run", "error", {}, [str(e)])


class K8sInspectScanner(Scanner):
    name = "k8s-inspect"

    def available(self) -> bool:
        return shutil.which("kubectl") is not None

    def scan(self, target: Target, profile: dict[str, Any]) -> ScanArtifact:
        if (
            profile.get("scanner", {}).get("use_demo_data")
            or not self.available()
            or target.kind not in ("pod", "deployment", "namespace")
        ):
            return ScanArtifact(
                self.name,
                "mock" if profile.get("scanner", {}).get("use_demo_data") else "dry-run",
                "ok",
                read_json("data/demo/k8s_inspect_demo.json"),
                [],
            )
        kind = {"pod": "pod", "deployment": "deployment", "namespace": "namespace"}.get(target.kind, target.kind)
        args = ["kubectl", "get", kind, target.name, "-o", "json"]
        if target.namespace:
            args[3:3] = ["-n", target.namespace]
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
            if p.returncode != 0:
                return ScanArtifact(self.name, "real-cli", "error", {}, [p.stderr[-1000:]])
            return ScanArtifact(self.name, "real-cli", "ok", json.loads(p.stdout or "{}"), [])
        except Exception as e:
            return ScanArtifact(self.name, "dry-run", "error", {}, [str(e)])


class KataInspectScanner(Scanner):
    name = "kata-inspect"

    def available(self) -> bool:
        return shutil.which("kubectl") is not None

    def scan(self, target: Target, profile: dict[str, Any]) -> ScanArtifact:
        if profile.get("scanner", {}).get("use_demo_data") or not self.available():
            return ScanArtifact(
                self.name,
                "mock" if profile.get("scanner", {}).get("use_demo_data") else "dry-run",
                "ok",
                read_json("data/demo/kata_runtimeclass_demo.json"),
                [],
            )
        try:
            p = subprocess.run(
                ["kubectl", "get", "runtimeclass", "kata", "-o", "json"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if p.returncode != 0:
                return ScanArtifact(self.name, "dry-run", "skipped", {}, [p.stderr[-1000:]])
            return ScanArtifact(self.name, "real-cli", "ok", json.loads(p.stdout or "{}"), [])
        except Exception as e:
            return ScanArtifact(self.name, "dry-run", "error", {}, [str(e)])


class ScannerManager:
    def __init__(self) -> None:
        self.mock = MockCompositeScanner()
        self.scanners = [
            TrivyScanner(),
            SyftScanner(),
            DockerInspectScanner(),
            K8sInspectScanner(),
            KataInspectScanner(),
        ]

    def scan(self, target: Target, profile: dict[str, Any]) -> list[ScanArtifact]:
        if profile.get("scanner", {}).get("use_demo_data"):
            return [self.mock.scan(target, profile)]
        arts = [s.scan(target, profile) for s in self.scanners]
        arts = [a for a in arts if a.status != "skipped"]
        return arts or [self.mock.scan(target, profile)]
