from __future__ import annotations

from modelchain.compliance.reporter import ComplianceReporter
from modelchain.models import (
    DatasetComponent,
    FrameworkDependency,
    HyperParameters,
    ModelMetadata,
)


class TestComplianceReporter:
    def test_generate_all(self):
        reporter = ComplianceReporter()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        reports = reporter.generate_all(meta)
        assert len(reports) == 2
        frameworks = {r["framework"] for r in reports}
        assert "EU AI Act" in frameworks
        assert "NIST AI RMF 1.0" in frameworks

    def test_generate_report(self):
        reporter = ComplianceReporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            author="A",
            license="MIT",
            description="Test",
            base_model="base",
            base_model_hash="abc",
            framework="transformers",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
            dependencies=[FrameworkDependency(name="torch", version="2.0", type="framework")],
            hyperparameters=HyperParameters(learning_rate=1e-4, epochs=3),
        )
        report = reporter.generate_report(meta)
        assert report.model_name == "test"
        assert report.model_version == "1.0"
        assert "eu_ai_act" in report.frameworks
        assert "nist_ai_rmf" in report.frameworks
        assert report.summary["total_frameworks"] == 2

    def test_generate_report_summary(self):
        reporter = ComplianceReporter()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        report = reporter.generate_report(meta)
        assert report.summary["total_frameworks"] == 2
        assert "all_passed" in report.summary
        assert not report.summary["all_passed"]
