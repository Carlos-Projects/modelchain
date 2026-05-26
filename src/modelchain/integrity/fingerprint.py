from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from modelchain.models import ModelMetadata
from modelchain.utils.crypto import hash_bytes


@dataclass
class ModelFingerprint:
    """Generates and manages cryptographic fingerprints for AI models.

    A fingerprint is a unique hash that identifies a specific combination
    of model + datasets + adapters + hyperparameters.
    """

    algorithm: str = "sha256"

    def generate(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Generate a fingerprint for a model configuration.

        The fingerprint is computed from all components that define
        the model's identity, making it unique to this specific build.

        Args:
            metadata: Model metadata.

        Returns:
            Fingerprint dict with the cryptographic digest.
        """
        components: list[bytes] = []

        components.append(f"model:{metadata.model_name}:{metadata.model_version}".encode())
        components.append(f"type:{metadata.model_type}".encode())

        if metadata.base_model:
            components.append(f"base:{metadata.base_model}".encode())
        if metadata.base_model_hash:
            components.append(f"base_hash:{metadata.base_model_hash}".encode())

        for ds in sorted(metadata.datasets, key=lambda x: x.name):
            components.append(f"dataset:{ds.name}:{ds.version}:{ds.hash}".encode())

        for adp in sorted(metadata.adapters, key=lambda x: x.name):
            components.append(f"adapter:{adp.name}:{adp.type}:{adp.hash}".encode())

        hp = metadata.hyperparameters
        hp_fields = [
            f"lr:{hp.learning_rate}",
            f"batch:{hp.batch_size}",
            f"epochs:{hp.epochs}",
            f"optimizer:{hp.optimizer}",
            f"precision:{hp.precision}",
        ]
        for field_val in hp_fields:
            components.append(field_val.encode())

        canonical = b"|".join(components)
        digest = hash_bytes(canonical, self.algorithm)

        return {
            "fingerprint": digest,
            "algorithm": self.algorithm,
            "canonical_input": canonical.decode("utf-8", errors="replace"),
            "components": len(components),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def verify(self, metadata: ModelMetadata, expected_fingerprint: str) -> bool:
        """Verify a model's fingerprint matches an expected value.

        Args:
            metadata: Model metadata to verify.
            expected_fingerprint: Expected fingerprint hash.

        Returns:
            True if fingerprints match.
        """
        current = self.generate(metadata)
        return current["fingerprint"] == expected_fingerprint.lower()
