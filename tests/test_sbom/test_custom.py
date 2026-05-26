from __future__ import annotations

from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    HyperParameters,
    ModelMetadata,
)
from modelchain.sbom.custom import CustomExporter


class TestCustomExporter:
    def test_export_basic(self):
        exporter = CustomExporter()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        result = exporter.export(meta)
        assert result["modelchain"]["format"] == "modelchain"
        assert result["model"]["name"] == "test"

    def test_export_with_base_model(self):
        exporter = CustomExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            base_model="base-llm",
            base_model_hash="abc",
        )
        result = exporter.export(meta)
        assert result["base_model"]["name"] == "base-llm"

    def test_export_without_base_model(self):
        exporter = CustomExporter()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        result = exporter.export(meta)
        assert "base_model" not in result

    def test_export_with_dataset(self):
        exporter = CustomExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds", version="1", source="src", hash="h")],
        )
        result = exporter.export(meta)
        assert len(result["datasets"]) == 1

    def test_export_with_adapter(self):
        exporter = CustomExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            adapters=[AdapterComponent(name="lora", type="LoRA", source="s", hash="h")],
        )
        result = exporter.export(meta)
        assert len(result["adapters"]) == 1

    def test_export_with_dependencies(self):
        exporter = CustomExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[FrameworkDependency(name="torch", version="2.0", type="framework")],
        )
        result = exporter.export(meta)
        assert len(result["dependencies"]) == 1

    def test_export_with_tags(self):
        exporter = CustomExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            tags=["security", "llm"],
        )
        result = exporter.export(meta)
        assert len(result["model"]["tags"]) == 2

    def test_export_with_hyperparameters(self):
        exporter = CustomExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            hyperparameters=HyperParameters(learning_rate=1e-4, epochs=5),
        )
        result = exporter.export(meta)
        assert result["hyperparameters"]["learning_rate"] == 1e-4
        assert result["hyperparameters"]["epochs"] == 5
