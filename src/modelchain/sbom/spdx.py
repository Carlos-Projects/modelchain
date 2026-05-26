from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from modelchain.models import ModelMetadata


class SPDXExporter:
    """Exports SBOM in SPDX 2.3 format.

    Follows the SPDX specification:
    https://spdx.dev/specifications/
    """

    SPDX_VERSION = "SPDX-2.3"
    DATA_LICENSE = "CC0-1.0"

    def export(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Export model metadata to SPDX JSON format.

        Args:
            metadata: Model metadata.

        Returns:
            SPDX document as a dict.
        """
        doc_namespace = f"https://github.com/Carlos-Projects/modelchain/spdx/{uuid4()}"
        packages: list[dict[str, Any]] = []
        relationships: list[dict[str, Any]] = []

        model_pkg_id = f"SPDXRef-Model-{metadata.model_name.replace(' ', '-')}"
        packages.append(
            {
                "SPDXID": model_pkg_id,
                "name": metadata.model_name,
                "versionInfo": metadata.model_version,
                "supplier": f"Person: {metadata.author}" if metadata.author else "NOASSERTION",
                "downloadLocation": metadata.url or "NOASSERTION",
                "licenseDeclared": metadata.license or "NOASSERTION",
                "description": metadata.description,
                "primaryPackagePurpose": "APPLICATION",
                "externalRefs": [
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": "aqua:security:model:type",
                        "referenceLocator": metadata.model_type,
                    },
                ],
            }
        )

        if metadata.base_model:
            base_pkg_id = f"SPDXRef-Base-{metadata.base_model.replace(' ', '-')}"
            packages.append(
                {
                    "SPDXID": base_pkg_id,
                    "name": f"Base: {metadata.base_model}",
                    "versionInfo": "",
                    "supplier": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "primaryPackagePurpose": "APPLICATION",
                }
            )
            relationships.append(
                {
                    "spdxElementId": model_pkg_id,
                    "relatedSpdxElement": base_pkg_id,
                    "relationshipType": "DERIVED_FROM",
                }
            )

        for ds in metadata.datasets:
            ds_id = f"SPDXRef-Dataset-{ds.name.replace(' ', '-')}"
            packages.append(
                {
                    "SPDXID": ds_id,
                    "name": ds.name,
                    "versionInfo": ds.version,
                    "supplier": "NOASSERTION",
                    "downloadLocation": ds.url or "NOASSERTION",
                    "licenseDeclared": ds.license or "NOASSERTION",
                    "description": ds.description,
                    "primaryPackagePurpose": "DATA",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": ds.hash}]
                    if ds.hash
                    else [],
                }
            )
            relationships.append(
                {
                    "spdxElementId": model_pkg_id,
                    "relatedSpdxElement": ds_id,
                    "relationshipType": "DATA_FILE_OF",
                }
            )

        for adp in metadata.adapters:
            adp_id = f"SPDXRef-Adapter-{adp.name.replace(' ', '-')}"
            packages.append(
                {
                    "SPDXID": adp_id,
                    "name": adp.name,
                    "versionInfo": "",
                    "supplier": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "description": f"Adapter ({adp.type})",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": adp.hash}]
                    if adp.hash
                    else [],
                }
            )
            relationships.append(
                {
                    "spdxElementId": model_pkg_id,
                    "relatedSpdxElement": adp_id,
                    "relationshipType": "CONTAINED_BY",
                }
            )

        for dep in metadata.dependencies:
            dep_id = f"SPDXRef-Dep-{dep.name.replace(' ', '-')}"
            packages.append(
                {
                    "SPDXID": dep_id,
                    "name": dep.name,
                    "versionInfo": dep.version,
                    "supplier": "NOASSERTION",
                    "downloadLocation": dep.url or "NOASSERTION",
                    "licenseDeclared": dep.license or "NOASSERTION",
                    "primaryPackagePurpose": "LIBRARY",
                }
            )
            relationships.append(
                {
                    "spdxElementId": model_pkg_id,
                    "relatedSpdxElement": dep_id,
                    "relationshipType": "DEPENDS_ON",
                }
            )

        return {
            "spdxVersion": self.SPDX_VERSION,
            "dataLicense": self.DATA_LICENSE,
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{metadata.model_name}-{metadata.model_version}-sbom",
            "documentNamespace": doc_namespace,
            "creationInfo": {
                "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "creators": [
                    "Tool: modelchain-sbom-0.1.0",
                    "Organization: Carlos-Projects",
                ],
            },
            "packages": packages,
            "relationships": relationships,
        }
