from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modelchain.integrity.fingerprint import ModelFingerprint
from modelchain.models import ModelMetadata


@dataclass
class DiffResult:
    """Result of comparing two model versions."""

    model_name: str
    version_a: str
    version_b: str
    fingerprint_match: bool
    added_components: list[dict[str, Any]]
    removed_components: list[dict[str, Any]]
    modified_components: list[dict[str, Any]]
    unchanged_components: list[dict[str, Any]]
    summary: dict[str, int]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class IntegrityDiff:
    """Compares integrity manifests between model versions."""

    def __init__(self):
        self._fingerprinter = ModelFingerprint()

    def compare(
        self,
        metadata_a: ModelMetadata,
        metadata_b: ModelMetadata,
    ) -> DiffResult:
        """Compare two model versions and produce a diff.

        Args:
            metadata_a: First model version.
            metadata_b: Second model version.

        Returns:
            DiffResult with added, removed, and modified components.
        """
        fingerprint_a = self._fingerprinter.generate(metadata_a)
        fingerprint_b = self._fingerprinter.generate(metadata_b)
        fingerprint_match = fingerprint_a["fingerprint"] == fingerprint_b["fingerprint"]

        components_a = self._index_components(metadata_a)
        components_b = self._index_components(metadata_b)

        keys_a = set(components_a)
        keys_b = set(components_b)

        added_keys = keys_b - keys_a
        removed_keys = keys_a - keys_b
        common_keys = keys_a & keys_b

        added = [components_b[k] for k in sorted(added_keys)]
        removed = [components_a[k] for k in sorted(removed_keys)]

        modified: list[dict[str, Any]] = []
        unchanged: list[dict[str, Any]] = []
        for key in sorted(common_keys):
            ca = components_a[key]
            cb = components_b[key]
            if ca["hash"] == cb["hash"]:
                unchanged.append(cb)
            else:
                modified.append(
                    {
                        "name": key,
                        "hash_a": ca["hash"],
                        "hash_b": cb["hash"],
                        "type": ca["type"],
                    }
                )

        return DiffResult(
            model_name=metadata_a.model_name,
            version_a=metadata_a.model_version,
            version_b=metadata_b.model_version,
            fingerprint_match=fingerprint_match,
            added_components=added,
            removed_components=removed,
            modified_components=modified,
            unchanged_components=unchanged,
            summary={
                "total_a": len(components_a),
                "total_b": len(components_b),
                "added": len(added),
                "removed": len(removed),
                "modified": len(modified),
                "unchanged": len(unchanged),
                "fingerprint_match": fingerprint_match,
            },
        )

    def _index_components(self, metadata: ModelMetadata) -> dict[str, dict[str, Any]]:
        """Index all components by a unique key."""
        index: dict[str, dict[str, Any]] = {}

        if metadata.base_model:
            index[f"base:{metadata.base_model}"] = {
                "name": metadata.base_model,
                "hash": metadata.base_model_hash,
                "type": "base_model",
                "version": "",
            }

        for ds in metadata.datasets:
            index[f"dataset:{ds.name}"] = {
                "name": ds.name,
                "hash": ds.hash,
                "type": "dataset",
                "version": ds.version,
            }

        for adp in metadata.adapters:
            index[f"adapter:{adp.name}"] = {
                "name": adp.name,
                "hash": adp.hash,
                "type": "adapter",
                "version": adp.type,
            }

        for dep in metadata.dependencies:
            index[f"dep:{dep.name}"] = {
                "name": dep.name,
                "hash": "",
                "type": "dependency",
                "version": dep.version,
            }

        return index

    def compare_manifests(
        self,
        manifest_a: dict[str, Any],
        manifest_b: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare two integrity manifests.

        Args:
            manifest_a: First integrity manifest.
            manifest_b: Second integrity manifest.

        Returns:
            Diff result dict.
        """
        entries_a = {(e["path"], e["component_name"]): e for e in manifest_a.get("entries", [])}
        entries_b = {(e["path"], e["component_name"]): e for e in manifest_b.get("entries", [])}

        keys_a = set(entries_a)
        keys_b = set(entries_b)

        modified = []
        unchanged = []
        for key in keys_a & keys_b:
            if entries_a[key]["hash"] == entries_b[key]["hash"]:
                unchanged.append(entries_b[key])
            else:
                modified.append(
                    {
                        "key": key,
                        "hash_a": entries_a[key]["hash"],
                        "hash_b": entries_b[key]["hash"],
                    }
                )

        return {
            "added": [entries_b[k] for k in sorted(keys_b - keys_a)],
            "removed": [entries_a[k] for k in sorted(keys_a - keys_b)],
            "modified": modified,
            "unchanged": unchanged,
            "summary": {
                "total_a": len(entries_a),
                "total_b": len(entries_b),
                "added": len(keys_b - keys_a),
                "removed": len(keys_a - keys_b),
                "modified": len(modified),
                "unchanged": len(unchanged),
            },
        }
