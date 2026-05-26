from __future__ import annotations

from modelchain.compliance.nist_rmf import NISTRMFChecker
from modelchain.models import (
    DatasetComponent,
    FrameworkDependency,
    HyperParameters,
    ModelMetadata,
)


class TestNISTRMFChecker:
    def test_check_minimal_model(self):
        checker = NISTRMFChecker()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        report = checker.check(meta)
        assert "govern" in report.categories
        assert "map" in report.categories

    def test_check_full_model(self):
        checker = NISTRMFChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            base_model="base-llm",
            base_model_hash="abc",
            description="Test",
            author="A",
            license="MIT",
            framework="transformers",
            datasets=[
                DatasetComponent(name="ds", version="1", source="s", hash="h"),
            ],
            dependencies=[
                FrameworkDependency(name="torch", version="2.0", type="framework"),
            ],
            hyperparameters=HyperParameters(learning_rate=1e-4, epochs=5),
        )
        report = checker.check(meta)
        assert report.passed
        assert report.summary["passed"] == report.summary["total_categories"]

    def test_govern_check(self):
        checker = NISTRMFChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            author="A",
            license="MIT",
        )
        report = checker.check(meta)
        assert report.categories["govern"]["passed"]

    def test_map_check_fails_without_components(self):
        checker = NISTRMFChecker()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        report = checker.check(meta)
        assert not report.categories["map"]["passed"]

    def test_map_check_passes_with_datasets(self):
        checker = NISTRMFChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            base_model="base",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
            dependencies=[FrameworkDependency(name="torch", version="2.0", type="framework")],
        )
        report = checker.check(meta)
        assert report.categories["map"]["passed"]

    def test_measure_check(self):
        checker = NISTRMFChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            framework="transformers",
            hyperparameters=HyperParameters(learning_rate=1e-4),
        )
        report = checker.check(meta)
        assert report.categories["measure"]["passed"]

    def test_manage_check(self):
        checker = NISTRMFChecker()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="s", hash="h")],
            dependencies=[FrameworkDependency(name="torch", version="2.0", type="framework")],
        )
        report = checker.check(meta)
        assert report.categories["manage"]["passed"]
