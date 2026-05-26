from __future__ import annotations

from typing import Any

from modelchain.models import ModelMetadata
from modelchain.sbom.custom import CustomExporter
from modelchain.sbom.cyclonedx import CycloneDXExporter
from modelchain.sbom.spdx import SPDXExporter


class SBOMBuilder:
    """Builds SBOM documents from model metadata in multiple formats."""

    def __init__(self):
        self._exporters = {
            "cyclonedx": CycloneDXExporter(),
            "spdx": SPDXExporter(),
            "modelchain": CustomExporter(),
        }

    def build(self, metadata: ModelMetadata, fmt: str = "modelchain") -> dict[str, Any]:
        """Build an SBOM document in the specified format.

        Args:
            metadata: Model metadata.
            fmt: Output format ("modelchain", "cyclonedx", "spdx").

        Returns:
            SBOM document as a dict.
        """
        exporter = self._exporters.get(fmt)
        if exporter is None:
            msg = f"Unknown SBOM format: {fmt}. Supported: {list(self._exporters)}"
            raise ValueError(msg)
        return exporter.export(metadata)

    def build_all(self, metadata: ModelMetadata) -> dict[str, dict[str, Any]]:
        """Build SBOM documents in all supported formats.

        Args:
            metadata: Model metadata.

        Returns:
            Dict mapping format names to SBOM documents.
        """
        return {name: exporter.export(metadata) for name, exporter in self._exporters.items()}

    def supported_formats(self) -> list[str]:
        """Return list of supported output formats."""
        return list(self._exporters)
