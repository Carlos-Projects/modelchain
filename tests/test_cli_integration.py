from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from modelchain.cli import app

runner = CliRunner()


@pytest.fixture
def sbom_json():
    return {
        "generator": "modelchain-sbom/0.1.0",
        "format": "modelchain",
        "metadata": {
            "model_name": "test-cli",
            "model_version": "1.0.0",
            "model_type": "llm",
        },
        "sbom": {
            "datasets": [
                {"name": "ds1", "version": "1", "source": "src", "hash": "abc"},
            ],
            "adapters": [
                {"name": "lora1", "type": "LoRA", "source": "s", "hash": "def"},
            ],
            "dependencies": [
                {"name": "torch", "version": "2.1.0", "type": "framework"},
            ],
        },
        "integrity_manifest": {
            "entries": [],
        },
        "provenance_graph": {"nodes": [], "edges": []},
        "audit_summary": {
            "total_components": 0,
            "datasets": 0,
            "adapters": 0,
            "dependencies": 0,
            "integrity_verified": True,
            "vulnerabilities_found": 0,
        },
        "compliance_reports": [],
        "generated_at": "2026-01-01T00:00:00Z",
    }


class TestCLIGenerate:
    def test_help_succeeds(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "generate" in result.stdout
        assert "verify" in result.stdout
        assert "audit" in result.stdout
        assert "report" in result.stdout
        assert "sbom" in result.stdout

    def test_generate_with_minimal_args(self):
        result = runner.invoke(
            app,
            [
                "generate",
                "test-model",
                "1.0.0",
            ],
        )
        assert result.exit_code == 0
        assert "ModelChain SBOM" in result.stdout
        assert "test-model" in result.stdout

    def test_generate_with_full_args(self):
        result = runner.invoke(
            app,
            [
                "generate",
                "security-model",
                "2.0.0",
                "--type",
                "llm",
                "--base",
                "meta-llama/Meta-Llama-3-8B",
                "--framework",
                "transformers",
                "--framework-version",
                "4.36.0",
                "--author",
                "Test Author",
                "--description",
                "Test model for CLI",
            ],
        )
        assert result.exit_code == 0
        assert "security-model" in result.stdout

    def test_generate_with_datasets(self):
        result = runner.invoke(
            app,
            [
                "generate",
                "test",
                "1.0",
                "--dataset",
                "ds1:1:src:abc123",
                "--dataset",
                "ds2:2:src:def456",
            ],
        )
        assert result.exit_code == 0
        assert "ds1" in result.stdout
        assert "ds2" in result.stdout

    def test_generate_with_adapters(self):
        result = runner.invoke(
            app,
            [
                "generate",
                "test",
                "1.0",
                "--adapter",
                "lora1:LoRA:local:h1",
            ],
        )
        assert result.exit_code == 0
        assert "lora1" in result.stdout

    def test_generate_with_dependencies(self):
        result = runner.invoke(
            app,
            [
                "generate",
                "test",
                "1.0",
                "--dependency",
                "torch:2.0.0:framework",
            ],
        )
        assert result.exit_code == 0
        assert "torch" in result.stdout

    def test_generate_output_to_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "output"
            result = runner.invoke(
                app,
                [
                    "generate",
                    "test",
                    "1.0",
                    "--output",
                    str(out_path),
                ],
            )
            assert result.exit_code == 0
            assert out_path.with_suffix(".json").exists()
            assert out_path.with_suffix(".html").exists()


class TestCLIVerify:
    def test_verify_missing_manifest(self):
        result = runner.invoke(app, ["verify", "/nonexistent/manifest.json"])
        assert result.exit_code != 0
        assert "File not found" in result.stdout

    def test_verify_with_manifest(self, sbom_json):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            manifest_path.write_text(json.dumps(sbom_json["integrity_manifest"]))
            result = runner.invoke(app, ["verify", str(manifest_path)])
            assert result.exit_code == 0


class TestCLIAudit:
    def test_audit_missing_sbom(self):
        result = runner.invoke(app, ["audit", "/nonexistent/sbom.json"])
        assert result.exit_code != 0
        assert "File not found" in result.stdout

    def test_audit_with_sbom(self, sbom_json):
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "sbom.json"
            sbom_path.write_text(json.dumps(sbom_json))
            result = runner.invoke(app, ["audit", str(sbom_path)])
            assert result.exit_code == 0


class TestCLIReport:
    def test_report_missing_sbom(self):
        result = runner.invoke(app, ["report", "/nonexistent/sbom.json"])
        assert result.exit_code != 0
        assert "File not found" in result.stdout

    def test_report_console(self, sbom_json):
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "sbom.json"
            sbom_path.write_text(json.dumps(sbom_json))
            result = runner.invoke(app, ["report", str(sbom_path)])
            assert result.exit_code == 0

    def test_report_json_output(self, sbom_json):
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "sbom.json"
            sbom_path.write_text(json.dumps(sbom_json))
            out_path = Path(tmpdir) / "report.json"
            result = runner.invoke(
                app,
                [
                    "report",
                    str(sbom_path),
                    "--format",
                    "json",
                    "--output",
                    str(out_path),
                ],
            )
            assert result.exit_code == 0
            assert out_path.exists()

    def test_report_html_output(self, sbom_json):
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "sbom.json"
            sbom_path.write_text(json.dumps(sbom_json))
            out_path = Path(tmpdir) / "report.html"
            result = runner.invoke(
                app,
                [
                    "report",
                    str(sbom_path),
                    "--format",
                    "html",
                    "--output",
                    str(out_path),
                ],
            )
            assert result.exit_code == 0
            assert out_path.exists()


class TestCLISbom:
    def test_sbom_missing_file(self):
        result = runner.invoke(app, ["sbom", "/nonexistent/sbom.json"])
        assert result.exit_code != 0
        assert "File not found" in result.stdout

    def test_sbom_display(self, sbom_json):
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_path = Path(tmpdir) / "sbom.json"
            sbom_path.write_text(json.dumps(sbom_json))
            result = runner.invoke(app, ["sbom", str(sbom_path)])
            assert result.exit_code == 0
            assert "test-cli" in result.stdout
