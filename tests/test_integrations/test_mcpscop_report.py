from __future__ import annotations

from modelchain.integrations.mcpscop_report import MCPscopReportExporter
from modelchain.models import FrameworkDependency, ModelMetadata


class TestMCPscopReportExporter:
    def test_export_basic(self):
        exporter = MCPscopReportExporter()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        report = exporter.export(meta)
        assert report["tool"] == "modelchain-sbom"
        assert report["scan_target"] == "test"
        assert report["summary"]["total_findings"] == 0

    def test_export_with_vulnerable_deps(self):
        exporter = MCPscopReportExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="transformers", version="4.30.0", type="framework"),
            ],
        )
        report = exporter.export(meta)
        assert report["summary"]["total_findings"] >= 1
        assert len(report["findings"]) >= 1
        finding = report["findings"][0]
        assert "vulnerability" in finding["type"]
        assert "supply_chain" in finding["taxonomy"]["attack_category"]

    def test_findings_structure(self):
        exporter = MCPscopReportExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="torch", version="2.0.0", type="framework"),
            ],
        )
        report = exporter.export(meta)
        finding = report["findings"][0]
        assert "type" in finding
        assert "severity" in finding
        assert "title" in finding
        assert "component" in finding
        assert "taxonomy" in finding
        assert "attack_category" in finding["taxonomy"]

    def test_summary_breakdown(self):
        exporter = MCPscopReportExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="torch", version="2.0.0", type="framework"),
                FrameworkDependency(name="tensorflow", version="2.12.0", type="framework"),
            ],
        )
        report = exporter.export(meta)
        assert report["summary"]["severity_breakdown"]["critical"] >= 1
        assert report["summary"]["severity_breakdown"]["high"] >= 1
