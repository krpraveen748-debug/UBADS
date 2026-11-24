from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import joblib
import pytest

import anomaly_detection
from model_storage import (
    ARTIFACT_PRODUCER,
    AzureBlobModelArtifactStore,
    LocalModelArtifactStore,
    ModelArtifactConflictError,
    ModelArtifactIntegrityError,
    ModelStorageUnavailableError,
)

PROFILE_ID = "a" * 32


def _metadata(version="isolation-forest-v1-000000000001", *, trained_at=None):
    return {
        "artifact_producer": ARTIFACT_PRODUCER,
        "format_version": anomaly_detection.MODEL_FORMAT_VERSION,
        "profile_id": PROFILE_ID,
        "model_version": version,
        "trained_at": (trained_at or datetime.now(timezone.utc)).isoformat(),
        "library_version": anomaly_detection.sklearn.__version__,
        "joblib_version": joblib.__version__,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
    }


def test_local_store_saves_versions_and_preserves_metadata(tmp_path):
    store = LocalModelArtifactStore(tmp_path)
    first = _metadata()
    second = _metadata(
        "isolation-forest-v1-000000000002",
        trained_at=datetime.now(timezone.utc) + timedelta(seconds=1),
    )
    store.save(PROFILE_ID, first["model_version"], b"model-one", first)
    store.save(PROFILE_ID, second["model_version"], b"model-two", second)

    assert store.list_versions(PROFILE_ID) == [second["model_version"], first["model_version"]]
    assert store.exists(PROFILE_ID)
    assert store.validate(PROFILE_ID, first["model_version"])
    assert store.get_metadata(PROFILE_ID) == second
    loaded = store.load(PROFILE_ID)
    assert loaded is not None
    assert loaded.payload == b"model-two"
    assert loaded.metadata == second

    with pytest.raises(ModelArtifactConflictError):
        store.save(PROFILE_ID, first["model_version"], b"replacement", first)


def test_local_store_handles_missing_and_stale_artifacts(tmp_path):
    store = LocalModelArtifactStore(tmp_path)
    assert store.load(PROFILE_ID) is None
    assert store.get_metadata(PROFILE_ID) is None
    assert store.list_versions(PROFILE_ID) == []
    assert not store.exists(PROFILE_ID)
    assert not store.validate(PROFILE_ID)

    now = datetime.now(timezone.utc)
    stale = _metadata(trained_at=now - timedelta(days=31))
    store.save(PROFILE_ID, stale["model_version"], b"old-model", stale)
    metadata = store.get_metadata(PROFILE_ID)
    assert metadata is not None
    assert anomaly_detection.model_is_stale(metadata, now=now)


def test_corrupt_artifact_is_rejected_before_joblib_deserialization(tmp_path, monkeypatch):
    store = LocalModelArtifactStore(tmp_path)
    metadata = _metadata()
    store.save(PROFILE_ID, metadata["model_version"], b"trusted-model-bytes", metadata)
    artifact_path = tmp_path / PROFILE_ID / f"{metadata['model_version']}.joblib"
    artifact_path.write_bytes(b"corrupted")

    monkeypatch.setattr(
        anomaly_detection.joblib,
        "load",
        lambda *_args, **_kwargs: pytest.fail("Corrupt artifact must not be deserialized."),
    )
    with pytest.raises(ModelArtifactIntegrityError, match="integrity"):
        anomaly_detection.load_profile_model(tmp_path, PROFILE_ID)


def test_store_rejects_profile_path_traversal(tmp_path):
    store = LocalModelArtifactStore(tmp_path)
    with pytest.raises(ValueError, match="profile identifier"):
        store.load("../outside")


@pytest.mark.parametrize(
    "version_key,incompatible_version",
    [
        ("joblib_version", "0.0"),
        ("python_version", "0.0"),
    ],
)
def test_incompatible_runtime_version_is_rejected_before_deserialization(
    tmp_path,
    monkeypatch,
    version_key,
    incompatible_version,
):
    store = LocalModelArtifactStore(tmp_path)
    metadata = _metadata()
    metadata[version_key] = incompatible_version
    store.save(PROFILE_ID, metadata["model_version"], b"untrusted-payload", metadata)
    monkeypatch.setattr(
        anomaly_detection.joblib,
        "load",
        lambda *_args, **_kwargs: pytest.fail("Incompatible artifact must not be deserialized."),
    )

    with pytest.raises(ModelArtifactIntegrityError, match="incompatible"):
        anomaly_detection.load_profile_model(tmp_path, PROFILE_ID)


class _FakeBlob:
    def __init__(self, blobs, name):
        self.blobs = blobs
        self.name = name

    def exists(self):
        return self.name in self.blobs

    def upload_blob(self, payload, *, overwrite):
        if self.exists() and not overwrite:
            raise RuntimeError("exists")
        self.blobs[self.name] = payload if isinstance(payload, bytes) else payload.encode("utf-8")

    def download_blob(self):
        payload = self.blobs[self.name]
        return SimpleNamespace(readall=lambda: payload)

    def delete_blob(self):
        self.blobs.pop(self.name, None)


class _FakeContainer:
    def __init__(self):
        self.blobs = {}

    def get_blob_client(self, name):
        return _FakeBlob(self.blobs, name)

    def list_blobs(self, *, name_starts_with):
        return [SimpleNamespace(name=name) for name in self.blobs if name.startswith(name_starts_with)]


class _FakeBlobService:
    def __init__(self):
        self.container = _FakeContainer()

    def get_container_client(self, _container_name):
        return self.container


def test_mocked_azure_blob_store_saves_lists_and_validates():
    service = _FakeBlobService()
    store = AzureBlobModelArtifactStore(
        "https://storage.example.invalid",
        "ubads-models",
        service_client=service,
    )
    metadata = _metadata()
    store.save(PROFILE_ID, metadata["model_version"], b"azure-model", metadata)

    assert store.exists(PROFILE_ID, metadata["model_version"])
    assert store.validate(PROFILE_ID, metadata["model_version"])
    assert store.list_versions(PROFILE_ID) == [metadata["model_version"]]
    loaded = store.load(PROFILE_ID, metadata["model_version"])
    assert loaded is not None and loaded.payload == b"azure-model"
    assert loaded.metadata == metadata
    assert f"models/{PROFILE_ID}/" in next(iter(service.container.blobs))


def test_azure_storage_errors_are_sanitized():
    class UnavailableService:
        def get_container_client(self, _container_name):
            raise RuntimeError("credential-value-must-not-be-exposed")

    store = AzureBlobModelArtifactStore(
        "https://storage.example.invalid",
        "ubads-models",
        service_client=UnavailableService(),
    )
    with pytest.raises(ModelStorageUnavailableError) as error:
        store.list_versions(PROFILE_ID)
    assert "credential-value" not in str(error.value)


def test_azure_account_url_rejects_embedded_sas_tokens():
    with pytest.raises(ValueError, match="HTTPS account URL"):
        AzureBlobModelArtifactStore(
            "https://storage.example.invalid?sig=secret",
            "ubads-models",
        )
