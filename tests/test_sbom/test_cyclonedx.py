from __future__ import annotations

from modelchain.models import AdapterComponent, DatasetComponent, ModelMetadata
from modelchain.sbom.cyclonedx import CycloneDXExporter


class TestCycloneDXExporter:
    def test_export_basic(self):
        exporter = CycloneDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
        )
        result = exporter.export(meta)
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.6"
        assert len(result["components"]) == 1

    def test_export_with_base_model(self):
        exporter = CycloneDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            base_model="base-llm",
            base_model_hash="abc",
        )
        result = exporter.export(meta)
        components = result["components"]
        assert len(components) == 2
        base_comps = [c for c in components if "base" in c.get("name", "").lower()]
        assert len(base_comps) == 1

    def test_export_with_datasets(self):
        exporter = CycloneDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[DatasetComponent(name="ds1", version="1", source="s", hash="h")],
        )
        result = exporter.export(meta)
        data_comps = [c for c in result["components"] if c["type"] == "data"]
        assert len(data_comps) == 1

    def test_export_with_adapters(self):
        exporter = CycloneDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            adapters=[AdapterComponent(name="lora1", type="LoRA", source="s", hash="h")],
        )
        result = exporter.export(meta)
        app_comps = [
            c for c in result["components"] if c.get("properties", [{}])[0].get("value") == "LoRA"
        ]
        assert len(app_comps) == 1

    def test_has_serial_number(self):
        exporter = CycloneDXExporter()
        meta = ModelMetadata(model_name="t", model_version="1", model_type="llm")
        result = exporter.export(meta)
        assert result["serialNumber"].startswith("urn:uuid:")

    def test_has_metadata_timestamp(self):
        exporter = CycloneDXExporter()
        meta = ModelMetadata(model_name="t", model_version="1", model_type="llm")
        result = exporter.export(meta)
        assert "timestamp" in result["metadata"]
