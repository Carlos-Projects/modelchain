from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from modelchain.provenance.verifier import ProvenanceVerifier
from modelchain.utils.crypto import hash_file


@pytest.fixture
def temp_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        f1 = Path(tmpdir) / "model.bin"
        f1.write_text("test model data")
        f2 = Path(tmpdir) / "dataset.bin"
        f2.write_text("test dataset data")
        yield tmpdir


class TestProvenanceVerifier:
    def test_verify_missing_file(self):
        verifier = ProvenanceVerifier()
        result = verifier.verify_component(
            "c1",
            "test",
            Path("/nonexistent/file.bin"),
            "abc123",
        )
        assert not result.verified
        assert len(result.errors) > 0
        assert "File not found" in result.errors[0]

    def test_verify_correct_hash(self, temp_files):
        verifier = ProvenanceVerifier()
        path = Path(temp_files) / "model.bin"
        expected = hash_file(path)
        result = verifier.verify_component("c1", "model", path, expected)
        assert result.verified
        assert result.computed_hash == expected

    def test_verify_wrong_hash(self, temp_files):
        verifier = ProvenanceVerifier()
        path = Path(temp_files) / "model.bin"
        result = verifier.verify_component("c1", "model", path, "wronghash123")
        assert not result.verified
        assert result.computed_hash != result.expected_hash

    def test_verify_manifest_all_correct(self, temp_files):
        verifier = ProvenanceVerifier()
        path = Path(temp_files) / "model.bin"
        manifest = {"model.bin": hash_file(path)}
        results = verifier.verify_manifest(manifest, base_path=temp_files)
        assert all(r.verified for r in results)
        assert len(results) == 1

    def test_verify_manifest_with_failures(self, temp_files):
        verifier = ProvenanceVerifier()
        manifest = {
            "model.bin": hash_file(Path(temp_files) / "model.bin"),
            "nonexistent.bin": "badhash",
        }
        results = verifier.verify_manifest(manifest, base_path=temp_files)
        assert not all(r.verified for r in results)
        assert len(results) == 2

    def test_verify_manifest_empty(self):
        verifier = ProvenanceVerifier()
        results = verifier.verify_manifest({})
        assert results == []

    def test_verify_model_graph_empty(self):
        verifier = ProvenanceVerifier()
        result = verifier.verify_model_graph({"nodes": [], "edges": []})
        assert result["total"] == 0
        assert result["verified"] == 0

    def test_different_algorithms(self, temp_files):
        verifier = ProvenanceVerifier(algorithm="sha512")
        path = Path(temp_files) / "model.bin"
        expected = hash_file(path, "sha512")
        result = verifier.verify_component("c1", "model", path, expected)
        assert result.verified
        assert result.algorithm == "sha512"

    def test_verify_with_nonexistent_base_path(self):
        verifier = ProvenanceVerifier()
        manifest = {"test.bin": "abc123"}
        results = verifier.verify_manifest(manifest, base_path="/nonexistent")
        assert not any(r.verified for r in results)
