from __future__ import annotations

import json
import tempfile
from pathlib import Path

from modelchain.integrity.diff import IntegrityDiff
from modelchain.integrity.fingerprint import ModelFingerprint
from modelchain.integrity.manifest import IntegrityManifest, ManifestEntry
from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    ModelMetadata,
)


class TestManifestEntry:
    def test_minimal(self):
        entry = ManifestEntry(path="/tmp/f.bin", hash="abc123")
        assert entry.algorithm == "sha256"
        assert entry.size is None


class TestIntegrityManifest:
    def test_generate_minimal(self):
        manifest = IntegrityManifest()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        result = manifest.generate(meta)
        assert "entries" in result
        assert result["generator"] == "modelchain-sbom/0.1.0"

    def test_generate_with_components(self):
        manifest = IntegrityManifest()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            base_model="base-llm",
            base_model_hash="abc123",
            datasets=[DatasetComponent(name="ds1", version="1", source="s", hash="def456")],
            adapters=[AdapterComponent(name="lora1", type="LoRA", source="s", hash="ghi789")],
        )
        result = manifest.generate(meta)
        assert len(result["entries"]) == 3

    def test_generate_verified_flag(self):
        manifest = IntegrityManifest()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        result = manifest.generate(meta)
        assert result["verified"] is True

    def test_generate_from_paths(self):
        manifest = IntegrityManifest()
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = Path(tmpdir) / "model.bin"
            f1.write_text("test data")
            f2 = Path(tmpdir) / "weights.bin"
            f2.write_text("weights data")
            paths = {"model": str(f1), "weights": str(f2)}
            result = manifest.generate_from_paths(paths)
            assert len(result["entries"]) == 2
            assert result["entries"][0]["hash"]

    def test_generate_from_paths_with_metadata(self):
        manifest = IntegrityManifest()
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.bin"
            f.write_text("data")
            result = manifest.generate_from_paths(
                {"test": str(f)},
                metadata={"version": "1.0"},
            )
            assert result["metadata"]["version"] == "1.0"

    def test_to_yaml(self):
        manifest = IntegrityManifest()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        m = manifest.generate(meta)
        yaml_str = manifest.to_yaml(m)
        assert "manifest_version" in yaml_str
        assert "modelchain-sbom" in yaml_str

    def test_to_json(self):
        manifest = IntegrityManifest()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        m = manifest.generate(meta)
        json_str = manifest.to_json(m)
        parsed = json.loads(json_str)
        assert parsed["manifest_version"] == "1.0"


class TestModelFingerprint:
    def test_generate_minimal(self):
        fp = ModelFingerprint()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        result = fp.generate(meta)
        assert "fingerprint" in result
        assert len(result["fingerprint"]) == 64

    def test_generate_deterministic(self):
        fp = ModelFingerprint()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        r1 = fp.generate(meta)
        r2 = fp.generate(meta)
        assert r1["fingerprint"] == r2["fingerprint"]

    def test_different_models_different_fingerprints(self):
        fp = ModelFingerprint()
        m1 = ModelMetadata(model_name="model-a", model_version="1", model_type="llm")
        m2 = ModelMetadata(model_name="model-b", model_version="1", model_type="llm")
        assert fp.generate(m1)["fingerprint"] != fp.generate(m2)["fingerprint"]

    def test_fingerprint_with_datasets(self):
        fp = ModelFingerprint()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
        )
        result = fp.generate(meta)
        assert result["components"] >= 3

    def test_verify_correct(self):
        fp = ModelFingerprint()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        fingerprint = fp.generate(meta)["fingerprint"]
        assert fp.verify(meta, fingerprint) is True

    def test_verify_wrong(self):
        fp = ModelFingerprint()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        assert fp.verify(meta, "wrongfingerprint") is False


class TestIntegrityDiff:
    def test_compare_identical(self):
        diff = IntegrityDiff()
        meta_a = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        meta_b = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        result = diff.compare(meta_a, meta_b)
        assert result.fingerprint_match is True
        assert len(result.added_components) == 0
        assert len(result.removed_components) == 0

    def test_compare_different_versions(self):
        diff = IntegrityDiff()
        meta_a = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        meta_b = ModelMetadata(model_name="test", model_version="2", model_type="llm")
        result = diff.compare(meta_a, meta_b)
        assert result.fingerprint_match is False

    def test_compare_added_component(self):
        diff = IntegrityDiff()
        meta_a = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        meta_b = ModelMetadata(
            model_name="test",
            model_version="2",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
        )
        result = diff.compare(meta_a, meta_b)
        assert len(result.added_components) >= 1

    def test_compare_removed_component(self):
        diff = IntegrityDiff()
        meta_a = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
        )
        meta_b = ModelMetadata(model_name="test", model_version="2", model_type="llm")
        result = diff.compare(meta_a, meta_b)
        assert len(result.removed_components) >= 1

    def test_compare_modified_component(self):
        diff = IntegrityDiff()
        meta_a = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="hash_a")],
        )
        meta_b = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="hash_b")],
        )
        result = diff.compare(meta_a, meta_b)
        assert len(result.modified_components) >= 1

    def test_compare_manifests(self):
        diff = IntegrityDiff()
        manifest_a = {
            "entries": [
                {"path": "model.bin", "component_name": "model", "hash": "abc"},
                {"path": "ds.bin", "component_name": "ds", "hash": "def"},
            ],
        }
        manifest_b = {
            "entries": [
                {"path": "model.bin", "component_name": "model", "hash": "abc"},
                {"path": "ds.bin", "component_name": "ds", "hash": "xyz"},
                {"path": "new.bin", "component_name": "new", "hash": "ghi"},
            ],
        }
        result = diff.compare_manifests(manifest_a, manifest_b)
        assert len(result["added"]) == 1
        assert len(result["modified"]) == 1
        assert len(result["unchanged"]) == 1
        assert result["summary"]["added"] == 1
        assert result["summary"]["modified"] == 1
