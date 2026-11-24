"""Versioned, integrity-checked storage for trusted UBADS model artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

ARTIFACT_PRODUCER = "ubads-backend"
MANIFEST_VERSION = 1
_PROFILE_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
_MODEL_VERSION_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_CONTAINER_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")


class ModelStorageError(RuntimeError):
    """Base class for safe, user-facing model-storage failures."""


class ModelArtifactIntegrityError(ModelStorageError):
    """A model artifact or its manifest is missing or corrupted."""


class ModelArtifactConflictError(ModelStorageError):
    """A versioned artifact already exists and will not be overwritten."""


class ModelStorageUnavailableError(ModelStorageError):
    """The configured model-storage provider could not complete an operation."""


@dataclass(frozen=True)
class StoredModelArtifact:
    payload: bytes
    metadata: dict[str, Any]


class ModelArtifactStore(Protocol):
    def save(
        self,
        profile_id: str,
        model_version: str,
        payload: bytes,
        metadata: dict[str, Any],
    ) -> None: ...

    def load(self, profile_id: str, model_version: str | None = None) -> StoredModelArtifact | None: ...

    def list_versions(self, profile_id: str) -> list[str]: ...

    def get_metadata(self, profile_id: str, model_version: str | None = None) -> dict[str, Any] | None: ...

    def exists(self, profile_id: str, model_version: str | None = None) -> bool: ...

    def validate(self, profile_id: str, model_version: str | None = None) -> bool: ...


def _validate_identifiers(profile_id: str, model_version: str | None = None) -> None:
    if not isinstance(profile_id, str) or not _PROFILE_ID_PATTERN.fullmatch(profile_id):
        raise ValueError("Invalid behavioral profile identifier.")
    if model_version is not None and (
        not isinstance(model_version, str) or not _MODEL_VERSION_PATTERN.fullmatch(model_version)
    ):
        raise ValueError("Invalid model version.")


def _make_manifest(
    profile_id: str,
    model_version: str,
    payload: bytes,
    metadata: dict[str, Any],
) -> bytes:
    _validate_identifiers(profile_id, model_version)
    if (
        metadata.get("artifact_producer") != ARTIFACT_PRODUCER
        or metadata.get("profile_id") != profile_id
        or metadata.get("model_version") != model_version
    ):
        raise ValueError("Model metadata does not match the requested artifact identity.")
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "metadata": metadata,
    }
    try:
        return json.dumps(manifest, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Model metadata is not JSON serializable.") from exc


def _parse_manifest(raw: bytes, profile_id: str, model_version: str) -> dict[str, Any]:
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ModelArtifactIntegrityError("Model artifact manifest is corrupted.") from None
    if not isinstance(manifest, dict):
        raise ModelArtifactIntegrityError("Model artifact manifest is invalid.")
    metadata = manifest.get("metadata")
    checksum = manifest.get("sha256")
    if (
        manifest.get("manifest_version") != MANIFEST_VERSION
        or not isinstance(metadata, dict)
        or not isinstance(checksum, str)
        or not _SHA256_PATTERN.fullmatch(checksum)
        or metadata.get("artifact_producer") != ARTIFACT_PRODUCER
        or metadata.get("profile_id") != profile_id
        or metadata.get("model_version") != model_version
    ):
        raise ModelArtifactIntegrityError("Model artifact manifest is invalid or incompatible.")
    return manifest


class _BaseModelArtifactStore(ABC):
    @abstractmethod
    def _read_manifest(self, profile_id: str, model_version: str) -> bytes | None:
        ...

    @abstractmethod
    def _read_payload(self, profile_id: str, model_version: str) -> bytes | None:
        ...

    @abstractmethod
    def _write_artifact(self, profile_id: str, model_version: str, payload: bytes, manifest: bytes) -> None:
        ...

    @abstractmethod
    def _list_model_versions(self, profile_id: str) -> list[str]:
        ...

    @abstractmethod
    def _artifact_exists(self, profile_id: str, model_version: str) -> bool:
        ...

    @abstractmethod
    def _manifest_exists(self, profile_id: str, model_version: str) -> bool:
        ...

    def save(
        self,
        profile_id: str,
        model_version: str,
        payload: bytes,
        metadata: dict[str, Any],
    ) -> None:
        _validate_identifiers(profile_id, model_version)
        if not isinstance(payload, bytes):
            raise TypeError("Model artifact payload must be bytes.")
        manifest = _make_manifest(profile_id, model_version, payload, metadata)
        self._write_artifact(profile_id, model_version, payload, manifest)

    def list_versions(self, profile_id: str) -> list[str]:
        _validate_identifiers(profile_id)
        versions = self._list_model_versions(profile_id)
        version_metadata = []
        for version in versions:
            _validate_identifiers(profile_id, version)
            metadata = self.get_metadata(profile_id, version)
            if metadata is not None:
                version_metadata.append((version, str(metadata.get("trained_at", ""))))
        return [version for version, _ in sorted(version_metadata, key=lambda item: item[1], reverse=True)]

    def get_metadata(
        self,
        profile_id: str,
        model_version: str | None = None,
    ) -> dict[str, Any] | None:
        _validate_identifiers(profile_id, model_version)
        version = model_version or self._latest_version(profile_id)
        if version is None:
            return None
        raw = self._read_manifest(profile_id, version)
        if raw is None:
            return None
        return _parse_manifest(raw, profile_id, version)["metadata"]

    def exists(self, profile_id: str, model_version: str | None = None) -> bool:
        _validate_identifiers(profile_id, model_version)
        version = model_version or self._latest_version(profile_id)
        return bool(
            version
            and self._manifest_exists(profile_id, version)
            and self._artifact_exists(profile_id, version)
        )

    def validate(self, profile_id: str, model_version: str | None = None) -> bool:
        return self._load(profile_id, model_version) is not None

    def load(self, profile_id: str, model_version: str | None = None) -> StoredModelArtifact | None:
        return self._load(profile_id, model_version)

    def _load(self, profile_id: str, model_version: str | None) -> StoredModelArtifact | None:
        _validate_identifiers(profile_id, model_version)
        version = model_version or self._latest_version(profile_id)
        if version is None:
            return None
        raw_manifest = self._read_manifest(profile_id, version)
        if raw_manifest is None:
            return None
        manifest = _parse_manifest(raw_manifest, profile_id, version)
        payload = self._read_payload(profile_id, version)
        if payload is None or hashlib.sha256(payload).hexdigest() != manifest["sha256"]:
            raise ModelArtifactIntegrityError("Model artifact integrity validation failed.")
        return StoredModelArtifact(payload=payload, metadata=manifest["metadata"])

    def _latest_version(self, profile_id: str) -> str | None:
        versions = self.list_versions(profile_id)
        return versions[0] if versions else None


class LocalModelArtifactStore(_BaseModelArtifactStore):
    """Store versioned artifacts under an operator-protected local directory."""

    def __init__(self, root: Path | str):
        self.root = Path(root).expanduser().resolve()

    def _profile_dir(self, profile_id: str) -> Path:
        _validate_identifiers(profile_id)
        return self.root / profile_id

    def _artifact_path(self, profile_id: str, model_version: str) -> Path:
        _validate_identifiers(profile_id, model_version)
        return self._profile_dir(profile_id) / f"{model_version}.joblib"

    def _manifest_path(self, profile_id: str, model_version: str) -> Path:
        _validate_identifiers(profile_id, model_version)
        return self._profile_dir(profile_id) / f"{model_version}.json"

    def _read_manifest(self, profile_id: str, model_version: str) -> bytes | None:
        try:
            return self._manifest_path(profile_id, model_version).read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _read_payload(self, profile_id: str, model_version: str) -> bytes | None:
        try:
            return self._artifact_path(profile_id, model_version).read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _write_artifact(self, profile_id: str, model_version: str, payload: bytes, manifest: bytes) -> None:
        profile_dir = self._profile_dir(profile_id)
        artifact_path = self._artifact_path(profile_id, model_version)
        manifest_path = self._manifest_path(profile_id, model_version)
        created_paths: list[Path] = []
        try:
            profile_dir.mkdir(parents=True, exist_ok=True)
            with artifact_path.open("xb") as artifact_file:
                created_paths.append(artifact_path)
                artifact_file.write(payload)
            with manifest_path.open("xb") as manifest_file:
                created_paths.append(manifest_path)
                manifest_file.write(manifest)
        except FileExistsError:
            self._cleanup(created_paths)
            raise ModelArtifactConflictError("Model version already exists.") from None
        except OSError:
            self._cleanup(created_paths)
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _cleanup(self, paths: list[Path]) -> None:
        for path in paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

    def _list_model_versions(self, profile_id: str) -> list[str]:
        profile_dir = self._profile_dir(profile_id)
        try:
            if not profile_dir.is_dir():
                return []
            return [
                path.stem
                for path in profile_dir.glob("*.json")
                if _MODEL_VERSION_PATTERN.fullmatch(path.stem)
            ]
        except OSError:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _artifact_exists(self, profile_id: str, model_version: str) -> bool:
        try:
            return self._artifact_path(profile_id, model_version).is_file()
        except OSError:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _manifest_exists(self, profile_id: str, model_version: str) -> bool:
        try:
            return self._manifest_path(profile_id, model_version).is_file()
        except OSError:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None


class AzureBlobModelArtifactStore(_BaseModelArtifactStore):
    """Store artifacts in a pre-existing private container using backend identity."""

    def __init__(self, account_url: str, container_name: str, *, service_client: Any | None = None):
        parsed_url = urlparse(account_url or "")
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or parsed_url.username
            or parsed_url.password
            or parsed_url.query
            or parsed_url.fragment
            or parsed_url.path not in ("", "/")
            or not (3 <= len(container_name or "") <= 63)
            or not _CONTAINER_PATTERN.fullmatch(container_name or "")
        ):
            raise ValueError("Azure Blob model storage requires a valid HTTPS account URL and container name.")
        self.account_url = account_url
        self.container_name = container_name
        self._service_client = service_client
        self._container_client: Any | None = None

    def _container(self) -> Any:
        if self._container_client is not None:
            return self._container_client
        try:
            if self._service_client is None:
                from azure.identity import DefaultAzureCredential
                from azure.storage.blob import BlobServiceClient

                self._service_client = BlobServiceClient(
                    account_url=self.account_url,
                    credential=DefaultAzureCredential(),
                )
            self._container_client = self._service_client.get_container_client(self.container_name)
            return self._container_client
        except Exception:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _blob_name(self, profile_id: str, model_version: str, suffix: str) -> str:
        _validate_identifiers(profile_id, model_version)
        return f"models/{profile_id}/{model_version}.{suffix}"

    def _read_blob(self, name: str) -> bytes | None:
        try:
            blob = self._container().get_blob_client(name)
            if not blob.exists():
                return None
            return blob.download_blob().readall()
        except Exception:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _read_manifest(self, profile_id: str, model_version: str) -> bytes | None:
        return self._read_blob(self._blob_name(profile_id, model_version, "json"))

    def _read_payload(self, profile_id: str, model_version: str) -> bytes | None:
        return self._read_blob(self._blob_name(profile_id, model_version, "joblib"))

    def _write_artifact(self, profile_id: str, model_version: str, payload: bytes, manifest: bytes) -> None:
        artifact_name = self._blob_name(profile_id, model_version, "joblib")
        manifest_name = self._blob_name(profile_id, model_version, "json")
        artifact_blob = None
        artifact_uploaded = False
        try:
            container = self._container()
            artifact_blob = container.get_blob_client(artifact_name)
            manifest_blob = container.get_blob_client(manifest_name)
            if artifact_blob.exists() or manifest_blob.exists():
                raise ModelArtifactConflictError("Model version already exists.")
            artifact_blob.upload_blob(payload, overwrite=False)
            artifact_uploaded = True
            manifest_blob.upload_blob(manifest, overwrite=False)
        except ModelArtifactConflictError:
            raise
        except Exception:
            if artifact_uploaded and artifact_blob is not None:
                try:
                    artifact_blob.delete_blob()
                except Exception:
                    pass
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _list_model_versions(self, profile_id: str) -> list[str]:
        _validate_identifiers(profile_id)
        prefix = f"models/{profile_id}/"
        try:
            versions = []
            for blob in self._container().list_blobs(name_starts_with=prefix):
                name = blob.name
                if name.startswith(prefix) and name.endswith(".json"):
                    version = name[len(prefix) : -len(".json")]
                    if _MODEL_VERSION_PATTERN.fullmatch(version):
                        versions.append(version)
            return versions
        except Exception:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _artifact_exists(self, profile_id: str, model_version: str) -> bool:
        try:
            return self._container().get_blob_client(self._blob_name(profile_id, model_version, "joblib")).exists()
        except Exception:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None

    def _manifest_exists(self, profile_id: str, model_version: str) -> bool:
        try:
            return self._container().get_blob_client(self._blob_name(profile_id, model_version, "json")).exists()
        except Exception:
            raise ModelStorageUnavailableError("Model artifact storage is unavailable.") from None


@lru_cache(maxsize=8)
def configured_model_artifact_store(
    provider: str,
    local_directory: str,
    azure_account_url: str | None,
    azure_container: str,
) -> ModelArtifactStore:
    if provider == "local":
        return LocalModelArtifactStore(local_directory)
    if provider == "azure_blob" and azure_account_url:
        return AzureBlobModelArtifactStore(azure_account_url, azure_container)
    raise ValueError("The configured model artifact storage provider is invalid.")
