from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from modelchain.models import ModelMetadata


class CustomExporter:
    """Exports SBOM in ModelChain's native (custom) JSON format."""

    def export(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Export model metadata to ModelChain native format.

        This format includes all provenance, integrity, and supply chain
        information in a structured JSON format optimized for ModelChain's
        tooling.

        Args:
            metadata: Model metadata.

        Returns:
            ModelChain native SBOM document.
        """
        return {
            "modelchain": {
                "format": "modelchain",
                "version": "1.0",
                "generator": "modelchain-sbom/0.1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            "model": {
                "name": metadata.model_name,
                "version": metadata.model_version,
                "type": metadata.model_type,
                "description": metadata.description,
                "author": metadata.author,
                "license": metadata.license,
                "url": metadata.url,
                "framework": metadata.framework,
                "framework_version": metadata.framework_version,
                "created_at": metadata.created_at,
                "tags": metadata.tags,
            },
            "base_model": {
                "name": metadata.base_model,
                "hash": metadata.base_model_hash,
            }
            if metadata.base_model
            else None,
            "hyperparameters": {
                "learning_rate": metadata.hyperparameters.learning_rate,
                "batch_size": metadata.hyperparameters.batch_size,
                "epochs": metadata.hyperparameters.epochs,
                "optimizer": metadata.hyperparameters.optimizer,
                "scheduler": metadata.hyperparameters.scheduler,
                "warmup_steps": metadata.hyperparameters.warmup_steps,
                "weight_decay": metadata.hyperparameters.weight_decay,
                "precision": metadata.hyperparameters.precision,
                "additional": metadata.hyperparameters.additional,
            },
            "datasets": [
                {
                    "name": ds.name,
                    "version": ds.version,
                    "source": ds.source,
                    "hash": ds.hash,
                    "size": ds.size,
                    "description": ds.description,
                    "license": ds.license,
                    "url": ds.url,
                }
                for ds in metadata.datasets
            ],
            "adapters": [
                {
                    "name": adp.name,
                    "type": adp.type,
                    "source": adp.source,
                    "hash": adp.hash,
                    "base_model": adp.base_model,
                    "parameters": adp.parameters,
                }
                for adp in metadata.adapters
            ],
            "dependencies": [
                {
                    "name": dep.name,
                    "version": dep.version,
                    "type": dep.type,
                    "url": dep.url,
                    "license": dep.license,
                }
                for dep in metadata.dependencies
            ],
        }
