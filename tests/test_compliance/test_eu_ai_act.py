from __future__ import annotations

from modelchain.compliance.eu_ai_act import HIGH_RISK_CATEGORIES, EUAIActChecker
from modelchain.models import (
    DatasetComponent,
    FrameworkDependency,
    HyperParameters,
    ModelMetadata,
)


class TestEUAIActChecker:
    def test_default_risk_category(self):
        checker = EUAIActChecker()
        assert checker.risk_category == "general_purpose"

    def test_custom_risk_category(self):
        checker = EUAIActChecker(risk_category="biometric")
        assert checker.risk_category == "biometric"

    def test_check_minimal_model(self):
        checker = EUAIActChecker()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        report = checker.check(meta)
        assert not report.passed
        assert "transparency" in report.requirements
        assert "documentation" in report.requirements

    def test_check_full_model(self):
        checker = EUAIActChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            base_model="base-llm",
            base_model_hash="abc",
            description="Test model",
            author="Author",
            license="MIT",
            datasets=[
                DatasetComponent(name="ds", version="1", source="src", hash="h", license="MIT")
            ],
            dependencies=[FrameworkDependency(name="torch", version="2.0", type="framework")],
            hyperparameters=HyperParameters(learning_rate=1e-4, epochs=5),
        )
        report = checker.check(meta)
        assert report.passed
        assert report.summary["passed"] == report.summary["total_requirements"]

    def test_high_risk_categories(self):
        assert "biometric" in HIGH_RISK_CATEGORIES
        assert "critical_infrastructure" in HIGH_RISK_CATEGORIES

    def test_transparency_check(self):
        checker = EUAIActChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            description="Test",
            author="A",
        )
        report = checker.check(meta)
        assert report.requirements["transparency"]["passed"]

    def test_data_governance_check(self):
        checker = EUAIActChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[
                DatasetComponent(name="ds", version="1", source="src", hash="h", license="MIT"),
            ],
        )
        report = checker.check(meta)
        assert report.requirements["data_governance"]["passed"]

    def test_risk_management_check(self):
        checker = EUAIActChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
        )
        report = checker.check(meta)
        assert report.requirements["risk_management"]["passed"]
