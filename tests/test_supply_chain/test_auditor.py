from __future__ import annotations

from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    ModelMetadata,
)
from modelchain.supply_chain.auditor import SupplyChainAuditor


class TestSupplyChainAuditor:
    def test_audit_clean_model(self):
        auditor = SupplyChainAuditor()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
        )
        result = auditor.audit(meta)
        assert result.passed
        assert len(result.findings) == 0
        assert result.summary["total_findings"] == 0

    def test_audit_with_vulnerable_dependency(self):
        auditor = SupplyChainAuditor()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="transformers", version="4.30.0", type="framework"),
            ],
        )
        result = auditor.audit(meta)
        assert not result.passed
        vulnerability_findings = [f for f in result.findings if f["type"] == "vulnerability"]
        assert len(vulnerability_findings) >= 1

    def test_audit_with_safe_dependency(self):
        auditor = SupplyChainAuditor()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="transformers", version="4.36.0", type="framework"),
            ],
        )
        result = auditor.audit(meta)
        vulnerability_findings = [f for f in result.findings if f["type"] == "vulnerability"]
        assert len(vulnerability_findings) == 0

    def test_audit_with_datasets_and_adapters(self):
        auditor = SupplyChainAuditor()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
            adapters=[AdapterComponent(name="lora", type="LoRA", source="s", hash="h")],
            dependencies=[FrameworkDependency(name="torch", version="2.1.0", type="framework")],
        )
        result = auditor.audit(meta)
        assert result.model_name == "test"
        assert result.model_version == "1.0"

    def test_audit_summary_counts(self):
        auditor = SupplyChainAuditor()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="transformers", version="4.30.0", type="framework"),
                FrameworkDependency(name="torch", version="2.0.0", type="framework"),
            ],
        )
        result = auditor.audit(meta)
        assert result.summary["total_findings"] >= 1
        assert "critical" in result.summary
        assert "high" in result.summary

    def test_integrity_check_in_audit(self):
        auditor = SupplyChainAuditor()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            base_model_hash="abc123",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
        )
        result = auditor.audit(meta)
        assert "entries" in result.integrity_check
        assert len(result.integrity_check["entries"]) >= 2
