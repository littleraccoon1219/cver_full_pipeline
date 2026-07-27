from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

from .models import HandlerTarget, SourceInspection, asdict


DEFAULT_HANDLERS: dict[str, dict[str, Any]] = {
    "ReadStdout": {
        "method": "read_stdout",
        "group": "filesystem-stream",
        "stateful": True,
    },
    "ReadStderr": {
        "method": "read_stderr",
        "group": "filesystem-stream",
        "stateful": True,
    },
    "WriteStdin": {
        "method": "write_stdin",
        "group": "filesystem-stream",
        "stateful": True,
    },
    "ExecProcess": {
        "method": "exec_process",
        "group": "process-lifecycle",
        "stateful": True,
    },
    "SignalProcess": {
        "method": "signal_process",
        "group": "process-lifecycle",
        "stateful": True,
    },
    "WaitProcess": {
        "method": "wait_process",
        "group": "process-lifecycle",
        "stateful": True,
    },
    "UpdateContainer": {
        "method": "update_container",
        "group": "process-lifecycle",
        "stateful": True,
    },
}

CONCURRENCY_PAIRS: dict[str, tuple[str, ...]] = {
    "ReadStdout": ("WaitProcess",),
    "ReadStderr": ("WaitProcess",),
    "WriteStdin": ("WaitProcess",),
    "ExecProcess": ("SignalProcess", "WaitProcess"),
    "SignalProcess": ("WaitProcess",),
    "WaitProcess": (
        "SignalProcess",
        "UpdateContainer",
        "ReadStdout",
        "ReadStderr",
        "WriteStdin",
    ),
    "UpdateContainer": ("WaitProcess",),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_value(root: Path, *args: str) -> str | None:
    try:
        value = subprocess.run(
            ["git", "-C", str(root), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return value.stdout.strip() if value.returncode == 0 and value.stdout.strip() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


class KataAgentInspector:
    """Extracts the real kata-agent RPC interface without compiling or patching it."""

    def __init__(self, required_handlers: dict[str, dict[str, Any]] | None = None) -> None:
        self.required_handlers = required_handlers or DEFAULT_HANDLERS

    def inspect(self, source_root: str | Path, *, version: str = "unknown") -> SourceInspection:
        root = Path(source_root).expanduser().resolve()
        rpc = root / "src" / "agent" / "src" / "rpc.rs"
        if not rpc.is_file():
            return SourceInspection(
                source_root=str(root),
                version=version,
                commit=_git_value(root, "rev-parse", "HEAD"),
                rpc_path=str(rpc),
                rpc_sha256="",
                interface_fingerprint="",
                handlers=[],
                missing_handlers=sorted(self.required_handlers),
                status="ADAPTER_REQUIRED",
                metadata={"reason": "src/agent/src/rpc.rs was not found"},
            )
        raw = rpc.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        handlers: list[HandlerTarget] = []
        missing: list[str] = []
        for handler_id, spec in self.required_handlers.items():
            method = str(spec["method"])
            match = self._find_method(text, method)
            if match is None:
                missing.append(handler_id)
                continue
            signature, request_type, response_type, start = match
            handlers.append(
                HandlerTarget(
                    handler_id=handler_id,
                    rust_method=method,
                    request_type=request_type,
                    response_type=response_type,
                    group=str(spec["group"]),
                    source_path=str(rpc.relative_to(root)),
                    source_line=text.count("\n", 0, start) + 1,
                    signature=" ".join(signature.split()),
                    signature_sha256=_sha256(" ".join(signature.split()).encode("utf-8")),
                    stateful=bool(spec.get("stateful", False)),
                    concurrency_pairs=CONCURRENCY_PAIRS.get(handler_id, ()),
                )
            )
        interface = {
            "rpc_sha256": _sha256(raw),
            "handlers": [
                {
                    "handler_id": item.handler_id,
                    "method": item.rust_method,
                    "request_type": item.request_type,
                    "response_type": item.response_type,
                    "signature_sha256": item.signature_sha256,
                }
                for item in sorted(handlers, key=lambda value: value.handler_id)
            ],
        }
        fingerprint = _sha256(json.dumps(interface, sort_keys=True).encode("utf-8"))
        return SourceInspection(
            source_root=str(root),
            version=version,
            commit=_git_value(root, "rev-parse", "HEAD"),
            rpc_path=str(rpc),
            rpc_sha256=_sha256(raw),
            interface_fingerprint=fingerprint,
            handlers=handlers,
            missing_handlers=missing,
            status="COMPATIBLE" if not missing else "ADAPTER_REQUIRED",
            metadata={
                "git_describe": _git_value(root, "describe", "--tags", "--always", "--dirty"),
                "handler_count": len(handlers),
                "required_handler_count": len(self.required_handlers),
            },
        )

    @staticmethod
    def _find_method(text: str, method: str) -> tuple[str, str, str | None, int] | None:
        # Keep the parser deliberately narrow: it only accepts an async RPC method with
        # a typed request. Source layouts outside this shape require a reviewed adapter.
        pattern = re.compile(
            rf"async\s+fn\s+{re.escape(method)}\s*\((?P<args>.{{0,1800}}?)\)\s*"
            rf"(?:->\s*(?P<response>[^\{{;]+))?\s*\{{",
            re.DOTALL,
        )
        match = pattern.search(text)
        if not match:
            return None
        args = match.group("args")
        request = re.search(
            r"(?:^|,)\s*(?:req|request)\s*:\s*(?:protocols::agent::)?(?P<type>[A-Za-z0-9_:<>]+)",
            args,
            re.DOTALL,
        )
        if not request:
            return None
        signature = text[match.start() : match.end() - 1]
        response = " ".join((match.group("response") or "").split()) or None
        return signature, request.group("type").split("::")[-1], response, match.start()

    @staticmethod
    def to_payload(inspection: SourceInspection) -> dict[str, Any]:
        return asdict(inspection)
