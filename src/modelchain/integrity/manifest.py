from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from modelchain.models import ModelMetadata
from modelchain.utils.crypto import hash_bytes, hash_file


@dataclass
class ManifestEntry:
    """A single entry in an integrity manifest."""

    path: str
    hash: str
    algorithm: str = "sha256"
    size: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class IntegrityManifest:
    """Generates cryptographic integrity manifests for model components.

    Shares patterns with reverse-abliterate's integrity verification.
    """

    def __init__(self, algorithm: str = "sha256"):
        self.algorithm = algorithm

    def generate(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Generate an integrity manifest from model metadata.

        Args:
            metadata: Model metadata.

        Returns:
            Integrity manifest as a dict.
        """
        entries: list[dict[str, Any]] = []

        if metadata.base_model_hash:
            entries.append(
                {
                    "path": f"models/{metadata.base_model}",
                    "hash": metadata.base_model_hash,
                    "algorithm": "sha256",
                    "component_type": "base_model",
                    "component_name": metadata.base_model,
                }
            )

        for ds in metadata.datasets:
            entries.append(
                {
                    "path": f"datasets/{ds.name}",
                    "hash": ds.hash,
                    "algorithm": "sha256",
                    "component_type": "dataset",
                    "component_name": ds.name,
                    "version": ds.version,
                    "source": ds.source,
                }
            )

        for adp in metadata.adapters:
            entries.append(
                {
                    "path": f"adapters/{adp.name}",
                    "hash": adp.hash,
                    "algorithm": "sha256",
                    "component_type": "adapter",
                    "component_name": adp.name,
                    "adapter_type": adp.type,
                }
            )

        serialized = f"{metadata.model_name}@{metadata.model_version}".encode()
        model_digest = hash_bytes(serialized, self.algorithm)

        manifest: dict[str, Any] = {
            "manifest_version": "1.0",
            "generator": "modelchain-sbom/0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "algorithm": self.algorithm,
            "model": {
                "name": metadata.model_name,
                "version": metadata.model_version,
                "fingerprint": model_digest,
            },
            "entries": entries,
            "verified": True,
        }

        return manifest

    def generate_from_paths(
        self,
        paths: dict[str, str | Path],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate an integrity manifest from file paths.

        Args:
            paths: Dict mapping component names to file paths.
            metadata: Optional metadata to include in the manifest.

        Returns:
            Integrity manifest as a dict.
        """
        entries: list[dict[str, Any]] = []
        for name, path in paths.items():
            p = Path(path).resolve()
            if p.exists():
                file_hash = hash_file(p, self.algorithm)
                entries.append(
                    {
                        "path": str(p),
                        "name": name,
                        "hash": file_hash,
                        "algorithm": self.algorithm,
                        "size": p.stat().st_size,
                    }
                )

        manifest: dict[str, Any] = {
            "manifest_version": "1.0",
            "generator": "modelchain-sbom/0.1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "algorithm": self.algorithm,
            "entries": entries,
        }
        if metadata:
            manifest["metadata"] = metadata

        return manifest

    def to_yaml(self, manifest: dict[str, Any]) -> str:
        """Serialize manifest to YAML format.

        Args:
            manifest: Integrity manifest dict.

        Returns:
            YAML string.
        """
        return yaml.dump(manifest, default_flow_style=False, sort_keys=False)

    def to_json(self, manifest: dict[str, Any]) -> str:
        """Serialize manifest to JSON format.

        Args:
            manifest: Integrity manifest dict.

        Returns:
            JSON string.
        """
        return json.dumps(manifest, indent=2)
