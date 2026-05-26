from __future__ import annotations

import pytest

from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    ModelMetadata,
)
from modelchain.sbom.builder import SBOMBuilder


@pytest.fixture
def builder():
    return SBOMBuilder()


@pytest.fixture
def sample_metadata():
    return ModelMetadata(
        model_name="test-model",
        model_version="1.0.0",
        model_type="llm",
        base_model="base-llm",
        base_model_hash="abc123",
        description="Test",
        author="Author",
        framework="transformers",
        framework_version="4.36.0",
        license="MIT",
    )


class TestSBOMBuilder:
    def test_supported_formats(self, builder):
        fmts = builder.supported_formats()
        assert "modelchain" in fmts
        assert "cyclonedx" in fmts
        assert "spdx" in fmts

    def test_build_modelchain(self, builder, sample_metadata):
        result = builder.build(sample_metadata, "modelchain")
        assert "modelchain" in result
        assert result["modelchain"]["format"] == "modelchain"

    def test_build_cyclonedx(self, builder, sample_metadata):
        result = builder.build(sample_metadata, "cyclonedx")
        assert result["bomFormat"] == "CycloneDX"
        assert "components" in result

    def test_build_spdx(self, builder, sample_metadata):
        result = builder.build(sample_metadata, "spdx")
        assert result["spdxVersion"] == "SPDX-2.3"
        assert "packages" in result

    def test_build_invalid_format(self, builder, sample_metadata):
        with pytest.raises(ValueError, match="Unknown SBOM format"):
            builder.build(sample_metadata, "invalid")

    def test_build_all(self, builder, sample_metadata):
        results = builder.build_all(sample_metadata)
        assert "modelchain" in results
        assert "cyclonedx" in results
        assert "spdx" in results

    def test_build_with_datasets(self, builder):
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="src", hash="h")],
        )
        result = builder.build(meta, "modelchain")
        assert len(result["datasets"]) == 1

    def test_build_with_adapters(self, builder):
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            adapters=[AdapterComponent(name="lora", type="LoRA", source="s", hash="h")],
        )
        result = builder.build(meta, "modelchain")
        assert len(result["adapters"]) == 1

    def test_build_with_dependencies(self, builder):
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[FrameworkDependency(name="torch", version="2.0", type="framework")],
        )
        result = builder.build(meta, "modelchain")
        assert len(result["dependencies"]) == 1

    def test_build_all_includes_base_model(self, builder):
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            base_model="base-llm",
        )
        results = builder.build_all(meta)
        assert results["modelchain"]["base_model"]["name"] == "base-llm"
