from __future__ import annotations

from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    ModelMetadata,
)
from modelchain.sbom.spdx import SPDXExporter


class TestSPDXExporter:
    def test_export_basic(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        result = exporter.export(meta)
        assert result["spdxVersion"] == "SPDX-2.3"
        assert result["dataLicense"] == "CC0-1.0"
        assert len(result["packages"]) == 1

    def test_export_with_base_model(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            base_model="base-llm",
        )
        result = exporter.export(meta)
        assert len(result["packages"]) == 2
        assert len(result["relationships"]) == 1
        assert result["relationships"][0]["relationshipType"] == "DERIVED_FROM"

    def test_export_with_dataset(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            datasets=[
                DatasetComponent(name="ds1", version="1", source="s", hash="h1"),
            ],
        )
        result = exporter.export(meta)
        data_pkgs = [p for p in result["packages"] if p["primaryPackagePurpose"] == "DATA"]
        assert len(data_pkgs) == 1

    def test_export_with_adapter(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            adapters=[
                AdapterComponent(name="lora1", type="LoRA", source="s", hash="h1"),
            ],
        )
        result = exporter.export(meta)
        assert len(result["packages"]) == 2
        adapter_rels = [
            r for r in result["relationships"] if r["relationshipType"] == "CONTAINED_BY"
        ]
        assert len(adapter_rels) == 1

    def test_export_with_dependencies(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="torch", version="2.0", type="framework"),
            ],
        )
        result = exporter.export(meta)
        dep_rels = [r for r in result["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
        assert len(dep_rels) == 1

    def test_has_creation_info(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(model_name="t", model_version="1", model_type="llm")
        result = exporter.export(meta)
        assert "creationInfo" in result
        assert "creators" in result["creationInfo"]

    def test_has_document_namespace(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(model_name="t", model_version="1", model_type="llm")
        result = exporter.export(meta)
        assert result["documentNamespace"].startswith(
            "https://github.com/Carlos-Projects/modelchain/spdx/"
        )

    def test_checksum_in_dataset(self):
        exporter = SPDXExporter()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            datasets=[
                DatasetComponent(name="ds", version="1", source="s", hash="abcdef1234567890")
            ],
        )
        result = exporter.export(meta)
        data_pkg = [p for p in result["packages"] if p.get("checksums")]
        assert len(data_pkg) >= 1
