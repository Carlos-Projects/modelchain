from __future__ import annotations

import pytest

from modelchain.generator import (
    generate_sbom,
)
from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    HyperParameters,
    ModelMetadata,
)


@pytest.fixture
def sample_metadata() -> ModelMetadata:
    return ModelMetadata(
        model_name="test-model",
        model_version="1.0.0",
        model_type="llm",
        base_model="base-llm",
        base_model_hash="abc123",
        description="Test model",
        author="Test Author",
        framework="transformers",
        framework_version="4.36.0",
        license="MIT",
        datasets=[
            DatasetComponent(
                name="test-dataset",
                version="1.0",
                source="huggingface",
                hash="def456",
            ),
        ],
        adapters=[
            AdapterComponent(
                name="test-lora",
                type="LoRA",
                source="local",
                hash="ghi789",
            ),
        ],
        dependencies=[
            FrameworkDependency(
                name="transformers",
                version="4.36.0",
                type="framework",
            ),
        ],
        hyperparameters=HyperParameters(
            learning_rate=2e-5,
            batch_size=8,
            epochs=3,
        ),
    )


class TestModelMetadata:
    def test_default_values(self):
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        assert meta.model_name == "test"
        assert meta.model_version == "1.0"
        assert meta.model_type == "llm"
        assert meta.datasets == []
        assert meta.adapters == []
        assert meta.dependencies == []

    def test_full_metadata(self, sample_metadata):
        assert sample_metadata.model_name == "test-model"
        assert len(sample_metadata.datasets) == 1
        assert len(sample_metadata.adapters) == 1
        assert len(sample_metadata.dependencies) == 1
        assert sample_metadata.hyperparameters.learning_rate == 2e-5

    def test_created_at_timestamp(self):
        meta = ModelMetadata(model_name="t", model_version="1", model_type="llm")
        assert meta.created_at.endswith("Z") or "+" in meta.created_at


class TestSBOMResult:
    def test_default_generator(self, sample_metadata):
        result = generate_sbom(sample_metadata)
        assert result.generator == "modelchain-sbom/0.1.0"

    def test_contains_all_sections(self, sample_metadata):
        result = generate_sbom(sample_metadata)
        assert result.sbom is not None
        assert result.manifest is not None
        assert result.provenance_graph is not None
        assert result.audit_summary is not None

    def test_audit_summary_counts(self, sample_metadata):
        result = generate_sbom(sample_metadata)
        assert result.audit_summary["total_components"] >= 3
        assert result.audit_summary["datasets"] == 1
        assert result.audit_summary["adapters"] == 1
        assert result.audit_summary["dependencies"] == 1

    def test_different_formats(self, sample_metadata):
        result_mc = generate_sbom(sample_metadata, "modelchain")
        assert result_mc.format == "modelchain"

    def test_cyclonedx_format(self, sample_metadata):
        result = generate_sbom(sample_metadata, "cyclonedx")
        assert result.format == "cyclonedx"
        assert "bomFormat" in result.sbom
        assert result.sbom["bomFormat"] == "CycloneDX"

    def test_spdx_format(self, sample_metadata):
        result = generate_sbom(sample_metadata, "spdx")
        assert result.format == "spdx"
        assert "spdxVersion" in result.sbom

    def test_compliance_reports(self, sample_metadata):
        result = generate_sbom(sample_metadata)
        assert len(result.compliance_reports) == 2
        frameworks = {r["framework"] for r in result.compliance_reports}
        assert "EU AI Act" in frameworks
        assert "NIST AI RMF 1.0" in frameworks


class TestGenerateSBOM:
    def test_empty_model(self):
        meta = ModelMetadata(model_name="empty", model_version="0.1", model_type="llm")
        result = generate_sbom(meta)
        assert result.metadata.model_name == "empty"
        assert result.audit_summary["total_components"] == 1
        assert result.audit_summary["datasets"] == 0

    def test_invalid_format(self, sample_metadata):
        with pytest.raises(ValueError, match="Unknown SBOM format"):
            generate_sbom(sample_metadata, "invalid")

    def test_multiple_datasets(self):
        meta = ModelMetadata(
            model_name="multi",
            model_version="1.0",
            model_type="llm",
            datasets=[
                DatasetComponent(name="ds1", version="1", source="src1", hash="h1"),
                DatasetComponent(name="ds2", version="2", source="src2", hash="h2"),
                DatasetComponent(name="ds3", version="3", source="src3", hash="h3"),
            ],
        )
        result = generate_sbom(meta)
        assert result.audit_summary["datasets"] == 3
        assert result.audit_summary["total_components"] == 4

    def test_multiple_adapters(self):
        meta = ModelMetadata(
            model_name="multi-adp",
            model_version="1.0",
            model_type="llm",
            adapters=[
                AdapterComponent(name="lora1", type="LoRA", source="s1", hash="h1"),
                AdapterComponent(name="lora2", type="LoRA", source="s2", hash="h2"),
            ],
        )
        result = generate_sbom(meta)
        assert result.audit_summary["adapters"] == 2

    def test_integrity_manifest_in_result(self, sample_metadata):
        result = generate_sbom(sample_metadata)
        manifest = result.manifest
        assert "entries" in manifest
        assert len(manifest["entries"]) >= 2
        assert manifest["generator"] == "modelchain-sbom/0.1.0"


class TestDatasetComponent:
    def test_minimal(self):
        ds = DatasetComponent(name="ds", version="1", source="src", hash="h")
        assert ds.size is None
        assert ds.description == ""
        assert ds.license == ""

    def test_full(self):
        ds = DatasetComponent(
            name="ds",
            version="1",
            source="src",
            hash="h",
            size=1000,
            description="desc",
            license="MIT",
            url="https://example.com",
        )
        assert ds.size == 1000
        assert ds.description == "desc"


class TestAdapterComponent:
    def test_minimal(self):
        adp = AdapterComponent(name="lora", type="LoRA", source="s", hash="h")
        assert adp.base_model == ""
        assert adp.parameters == {}

    def test_with_params(self):
        adp = AdapterComponent(
            name="lora",
            type="LoRA",
            source="s",
            hash="h",
            base_model="base",
            parameters={"r": 16},
        )
        assert adp.base_model == "base"
        assert adp.parameters["r"] == 16


class TestHyperParameters:
    def test_defaults(self):
        hp = HyperParameters()
        assert hp.learning_rate is None
        assert hp.batch_size is None
        assert hp.additional == {}

    def test_custom(self):
        hp = HyperParameters(
            learning_rate=1e-4,
            batch_size=32,
            epochs=5,
            additional={"custom_param": "value"},
        )
        assert hp.learning_rate == 1e-4
        assert hp.additional["custom_param"] == "value"
