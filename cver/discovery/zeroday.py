from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .db import DiscoveryRepository, utc_now


class MasterKeyProvider(Protocol):
    @property
    def key_ref(self) -> str: ...

    def get_key(self) -> bytes: ...


@dataclass(slots=True)
class EphemeralMasterKeyProvider:
    """Test/disposable-lab provider. The key disappears with the process."""

    key: bytes
    name: str = "ephemeral"

    @classmethod
    def generate(cls) -> EphemeralMasterKeyProvider:
        return cls(AESGCM.generate_key(bit_length=256))

    @property
    def key_ref(self) -> str:
        return self.name

    def get_key(self) -> bytes:
        return self.key


class EnvironmentMasterKeyProvider:
    """Explicit opt-in provider for automated tests; never selected by default."""

    def __init__(self, variable: str = "CVER_ZERO_DAY_MASTER_KEY") -> None:
        self.variable = variable

    @property
    def key_ref(self) -> str:
        return f"env:{self.variable}"

    def get_key(self) -> bytes:
        raw = os.getenv(self.variable)
        if not raw:
            raise RuntimeError(f"{self.variable} is not configured")
        try:
            key = base64.urlsafe_b64decode(raw.encode("ascii"))
        except Exception as exc:
            raise RuntimeError(f"{self.variable} must be URL-safe base64") from exc
        if len(key) != 32:
            raise RuntimeError(f"{self.variable} must decode to 32 bytes")
        return key


class LinuxKeyringMasterKeyProvider:
    """Stores the development master key in the current Linux user keyring."""

    def __init__(self, name: str = "cver-zero-day-master-v1", *, create: bool = True) -> None:
        self.name = name
        self.create = create

    @property
    def key_ref(self) -> str:
        return f"linux-keyring:user:{self.name}"

    @staticmethod
    def _keyctl() -> str:
        executable = shutil.which("keyctl")
        if not executable:
            raise RuntimeError("keyctl is required for local zero-day vault key management")
        return executable

    def _search(self) -> str | None:
        result = subprocess.run(
            [self._keyctl(), "search", "@u", "user", self.name],
            capture_output=True,
            check=False,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else None

    def get_key(self) -> bytes:
        serial = self._search()
        if serial is None:
            if not self.create:
                raise RuntimeError(f"Linux keyring entry {self.name!r} does not exist")
            key = AESGCM.generate_key(bit_length=256)
            result = subprocess.run(
                [self._keyctl(), "padd", "user", self.name, "@u"],
                input=key,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(f"failed to create Linux keyring entry: {result.stderr.decode(errors='replace')}")
            serial = result.stdout.decode("ascii", errors="replace").strip()
        result = subprocess.run(
            [self._keyctl(), "pipe", serial],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"failed to read Linux keyring entry: {result.stderr.decode(errors='replace')}")
        if len(result.stdout) != 32:
            raise RuntimeError("Linux keyring master key must be exactly 32 bytes")
        return result.stdout


def master_key_provider(mode: str) -> MasterKeyProvider:
    if mode == "linux-keyring":
        return LinuxKeyringMasterKeyProvider()
    if mode == "environment":
        return EnvironmentMasterKeyProvider()
    if mode == "ephemeral":
        return EphemeralMasterKeyProvider.generate()
    raise ValueError(f"unsupported zero-day key mode: {mode}")


class ZeroDayVault:
    def __init__(
        self,
        repository: DiscoveryRepository,
        *,
        root: str | Path,
        master_key: MasterKeyProvider,
    ) -> None:
        self.repository = repository
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.master_key = master_key

    @staticmethod
    def _encrypt(key: bytes, plaintext: bytes, aad: bytes) -> dict[str, str]:
        nonce = secrets.token_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return {
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
        }

    @staticmethod
    def _decrypt(key: bytes, envelope: dict[str, str], aad: bytes) -> bytes:
        nonce = base64.urlsafe_b64decode(envelope["nonce"])
        ciphertext = base64.urlsafe_b64decode(envelope["ciphertext"])
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def seal_case(
        self,
        *,
        files: list[str | Path],
        metadata: dict[str, Any],
        actor: str,
        job_id: str | None = None,
        hypothesis_id: str | None = None,
        case_id: str | None = None,
    ) -> dict[str, Any]:
        resolved_case_id = case_id or f"zday-{uuid.uuid4().hex}"
        case_dir = self.root / resolved_case_id
        if case_dir.exists():
            raise FileExistsError(case_dir)
        case_dir.mkdir(mode=0o700)
        data_key = AESGCM.generate_key(bit_length=256)
        entries: list[dict[str, Any]] = []
        digest = hashlib.sha256()
        for index, raw_path in enumerate(files, start=1):
            source = Path(raw_path).expanduser().resolve()
            if not source.is_file():
                raise FileNotFoundError(source)
            plaintext = source.read_bytes()
            file_hash = hashlib.sha256(plaintext).hexdigest()
            digest.update(file_hash.encode("ascii"))
            logical_name = f"{index:03d}-{source.name}"
            aad = f"{resolved_case_id}:{logical_name}".encode()
            envelope = self._encrypt(data_key, plaintext, aad)
            output = case_dir / f"{logical_name}.cverenc"
            output.write_text(json.dumps(envelope, sort_keys=True), encoding="utf-8")
            os.chmod(output, 0o600)
            entries.append(
                {
                    "logical_name": logical_name,
                    "encrypted_path": output.name,
                    "sha256": file_hash,
                    "size_bytes": len(plaintext),
                }
            )
        manifest = {
            "case_id": resolved_case_id,
            "status": "suspected_zero_day",
            "data_class": "restricted",
            "created_at": utc_now(),
            "job_id": job_id,
            "hypothesis_id": hypothesis_id,
            "metadata": metadata,
            "files": entries,
        }
        manifest_bytes = json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8")
        digest.update(manifest_bytes)
        case_digest = digest.hexdigest()
        manifest_envelope = self._encrypt(data_key, manifest_bytes, f"{resolved_case_id}:manifest".encode())
        manifest_path = case_dir / "manifest.cverenc"
        manifest_path.write_text(json.dumps(manifest_envelope, sort_keys=True), encoding="utf-8")
        os.chmod(manifest_path, 0o600)

        master = self.master_key.get_key()
        wrapped = self._encrypt(master, data_key, f"{resolved_case_id}:data-key".encode())
        key_envelope_path = case_dir / "key-envelope.json"
        key_envelope_path.write_text(
            json.dumps({"key_ref": self.master_key.key_ref, "wrapped_data_key": wrapped}, sort_keys=True),
            encoding="utf-8",
        )
        os.chmod(key_envelope_path, 0o600)
        self.repository.register_zero_day_case(
            case_id=resolved_case_id,
            job_id=job_id,
            hypothesis_id=hypothesis_id,
            status="suspected_zero_day",
            data_class="restricted",
            case_digest=case_digest,
            encrypted_manifest_path=str(manifest_path),
            key_ref=self.master_key.key_ref,
        )
        self.repository.add_audit(
            actor,
            "zero_day.sealed",
            "zero_day_case",
            resolved_case_id,
            {"case_digest": case_digest, "files": len(entries)},
        )
        return {
            "case_id": resolved_case_id,
            "case_digest": case_digest,
            "encrypted_manifest_path": str(manifest_path),
            "key_ref": self.master_key.key_ref,
            "files": len(entries),
        }

    def read_manifest(self, case_id: str, *, actor: str) -> dict[str, Any]:
        case_dir = self.root / case_id
        key_payload = json.loads((case_dir / "key-envelope.json").read_text(encoding="utf-8"))
        if key_payload["key_ref"] != self.master_key.key_ref:
            raise RuntimeError("the configured master key provider does not match this case")
        master = self.master_key.get_key()
        data_key = self._decrypt(master, key_payload["wrapped_data_key"], f"{case_id}:data-key".encode())
        envelope = json.loads((case_dir / "manifest.cverenc").read_text(encoding="utf-8"))
        manifest = json.loads(self._decrypt(data_key, envelope, f"{case_id}:manifest".encode()))
        self.repository.add_audit(actor, "zero_day.manifest_read", "zero_day_case", case_id, {})
        return manifest
