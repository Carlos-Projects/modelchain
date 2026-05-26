from __future__ import annotations

import tempfile
from pathlib import Path

from modelchain.utils.crypto import generate_checksum_manifest, hash_bytes, hash_file, verify_hash


class TestCryptoUtils:
    def test_hash_bytes(self):
        h = hash_bytes(b"hello world")
        assert len(h) == 64
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert h == expected

    def test_hash_file(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name
        try:
            h = hash_file(path)
            assert len(h) == 64
            assert h == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        finally:
            Path(path).unlink(missing_ok=True)

    def test_hash_file_sha512(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("test data")
            path = f.name
        try:
            h = hash_file(path, "sha512")
            assert len(h) == 128
        finally:
            Path(path).unlink(missing_ok=True)

    def test_verify_hash_correct(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name
        try:
            expected = hash_file(path)
            assert verify_hash(path, expected) is True
        finally:
            Path(path).unlink(missing_ok=True)

    def test_verify_hash_wrong(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name
        try:
            assert verify_hash(path, "wronghash") is False
        finally:
            Path(path).unlink(missing_ok=True)

    def test_verify_hash_case_insensitive(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            f.write("hello world")
            path = f.name
        try:
            expected = hash_file(path).upper()
            assert verify_hash(path, expected) is True
        finally:
            Path(path).unlink(missing_ok=True)

    def test_generate_checksum_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = Path(tmpdir) / "a.bin"
            f1.write_text("content a")
            f2 = Path(tmpdir) / "b.bin"
            f2.write_text("content b")
            manifest = generate_checksum_manifest([f1, f2])
            assert len(manifest) == 2
            assert "a.bin" in manifest
            assert "b.bin" in manifest
            assert len(manifest["a.bin"]) == 64

    def test_generate_checksum_manifest_empty(self):
        manifest = generate_checksum_manifest([])
        assert manifest == {}

    def test_different_bytes_same_algo(self):
        h1 = hash_bytes(b"content1")
        h2 = hash_bytes(b"content2")
        assert h1 != h2
