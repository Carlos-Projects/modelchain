from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from modelchain.generator import generate_sbom
from modelchain.models import DatasetComponent, ModelMetadata
from modelchain.reporters.console import ConsoleReporter
from modelchain.reporters.html import HTMLReporter
from modelchain.reporters.json import JSONReporter


@pytest.fixture
def sample_result():
    meta = ModelMetadata(
        model_name="test",
        model_version="1.0",
        model_type="llm",
        base_model="base",
        base_model_hash="abc",
        description="Test",
        author="A",
        framework="transformers",
    )
    return generate_sbom(meta)


class TestConsoleReporter:
    def test_report_sbom_does_not_raise(self, sample_result):
        reporter = ConsoleReporter()
        reporter.report_sbom(sample_result)

    def test_report_audit(self):
        reporter = ConsoleReporter()
        audit = {
            "passed": True,
            "model_name": "test",
            "model_version": "1.0",
            "findings": [],
            "summary": {"total_findings": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        reporter.report_audit(audit)

    def test_report_audit_with_findings(self):
        reporter = ConsoleReporter()
        audit = {
            "passed": False,
            "model_name": "test",
            "model_version": "1.0",
            "findings": [
                {
                    "type": "vulnerability",
                    "severity": "HIGH",
                    "message": "Test vuln",
                    "component": "test-pkg",
                },
                {
                    "type": "dependency",
                    "severity": "MEDIUM",
                    "message": "Outdated dep",
                    "component": "other",
                },
            ],
            "summary": {"total_findings": 2, "critical": 0, "high": 1, "medium": 1, "low": 0},
        }
        reporter.report_audit(audit)

    def test_report_compliance(self):
        reporter = ConsoleReporter()
        report = {
            "frameworks": {
                "eu_ai_act": {
                    "passed": True,
                    "summary": {"passed": 8, "total_requirements": 8},
                },
                "nist_ai_rmf": {
                    "passed": False,
                    "summary": {"passed": 2, "total_categories": 4},
                },
            },
        }
        reporter.report_compliance(report)

    def test_report_verify(self):
        reporter = ConsoleReporter()
        result = {
            "total": 2,
            "verified": 1,
            "failed": 1,
            "results": [
                {"component": "model.bin", "verified": True, "errors": []},
                {"component": "bad.bin", "verified": False, "errors": ["File not found"]},
            ],
        }
        reporter.report_verify(result)


class TestJSONReporter:
    def test_report_sbom(self, sample_result):
        reporter = JSONReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.report_sbom(sample_result, Path(tmpdir) / "sbom.json")
            assert path.exists()
            data = json.loads(path.read_text())
            assert "generator" in data
            assert "sbom" in data
            assert "integrity_manifest" in data

    def test_report_audit(self):
        reporter = JSONReporter()
        audit = {"passed": True, "findings": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.report_audit(audit, Path(tmpdir) / "audit.json")
            data = json.loads(path.read_text())
            assert data["passed"] is True

    def test_report_compliance(self):
        reporter = JSONReporter()
        cr = {"frameworks": {"eu_ai_act": {"passed": True}}}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.report_compliance(cr, Path(tmpdir) / "compliance.json")
            data = json.loads(path.read_text())
            assert "frameworks" in data

    def test_report_sbom_structured(self, sample_result):
        reporter = JSONReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.report_sbom(sample_result, Path(tmpdir) / "out.json")
            data = json.loads(path.read_text())
            assert data["format"] == sample_result.format
            assert data["metadata"]["model_name"] == "test"


class TestHTMLReporter:
    def test_report_sbom(self, sample_result):
        reporter = HTMLReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.report_sbom(sample_result, Path(tmpdir) / "report.html")
            assert path.exists()
            html = path.read_text()
            assert "<!DOCTYPE html>" in html
            assert sample_result.metadata.model_name in html

    def test_report_sbom_with_datasets(self):
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds1", version="1", source="src", hash="h")],
        )
        result = generate_sbom(meta)
        reporter = HTMLReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = reporter.report_sbom(result, Path(tmpdir) / "report.html")
            html = path.read_text()
            assert "Datasets" in html
            assert "ds1" in html
