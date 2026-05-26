from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from modelchain.models import ModelMetadata


class CycloneDXExporter:
    """Exports SBOM in CycloneDX AI format.

    Follows the CycloneDX AI SBOM standard:
    https://cyclonedx.org/capabilities/ai/
    """

    NAMESPACE = "https://cyclonedx.org/schema/bom-1.6"

    def export(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Export model metadata to CycloneDX JSON format.

        Args:
            metadata: Model metadata.

        Returns:
            CycloneDX BOM document as a dict.
        """
        components: list[dict[str, Any]] = []

        model_component = {
            "type": "application",
            "name": metadata.model_name,
            "version": metadata.model_version,
            "description": metadata.description,
            "author": metadata.author,
            "licenses": [{"license": {"name": metadata.license}}] if metadata.license else [],
            "properties": [
                {"name": "aqua:security:model:type", "value": metadata.model_type},
                {"name": "aqua:security:model:framework", "value": metadata.framework},
            ],
        }
        if metadata.base_model_hash:
            model_component["hashes"] = [{"alg": "SHA-256", "content": metadata.base_model_hash}]
        components.append(model_component)

        if metadata.base_model:
            components.append(
                {
                    "type": "application",
                    "name": f"Base: {metadata.base_model}",
                    "version": "",
                    "description": f"Base model for {metadata.model_name}",
                    "properties": [{"name": "aqua:security:model:base", "value": "true"}],
                }
            )

        for ds in metadata.datasets:
            ds_entry: dict[str, Any] = {
                "type": "data",
                "name": ds.name,
                "version": ds.version,
                "description": ds.description,
                "licenses": [{"license": {"name": ds.license}}] if ds.license else [],
                "properties": [
                    {"name": "aqua:security:dataset:source", "value": ds.source},
                    {"name": "aqua:security:dataset:url", "value": ds.url},
                ],
            }
            if ds.hash:
                ds_entry["hashes"] = [{"alg": "SHA-256", "content": ds.hash}]
            if ds.size is not None:
                ds_entry["size"] = ds.size
            components.append(ds_entry)

        for adp in metadata.adapters:
            adapter_entry: dict[str, Any] = {
                "type": "application",
                "name": adp.name,
                "version": "",
                "description": f"Adapter ({adp.type}) for {metadata.model_name}",
                "properties": [
                    {"name": "aqua:security:adapter:type", "value": adp.type},
                    {"name": "aqua:security:adapter:base_model", "value": adp.base_model},
                ],
            }
            if adp.hash:
                adapter_entry["hashes"] = [{"alg": "SHA-256", "content": adp.hash}]
            components.append(adapter_entry)

        for dep in metadata.dependencies:
            comp = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "description": f"Dependency ({dep.type})",
                "licenses": [{"license": {"name": dep.license}}] if dep.license else [],
                "properties": [{"name": "aqua:security:dependency:type", "value": dep.type}],
            }
            if dep.url:
                comp["purl"] = (
                    f"pkg:pypi/{dep.name}@{dep.version}" if dep.type != "framework" else dep.url
                )
            components.append(comp)

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "ModelChain", "name": "modelchain-sbom", "version": "0.1.0"}],
                "properties": [
                    {"name": "aqua:security:model:framework", "value": metadata.framework},
                    {
                        "name": "aqua:security:model:framework_version",
                        "value": metadata.framework_version,
                    },
                ],
            },
            "components": components,
        }
