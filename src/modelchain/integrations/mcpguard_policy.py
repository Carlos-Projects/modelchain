from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import yaml

from modelchain.models import ModelMetadata


class MCPGuardPolicyGenerator:
    """Generates MCPGuard-compatible YAML policies from SBOM data.

    Policies can be used by MCPGuard to enforce rules on model components
    (datasets, adapters, dependencies) at runtime.

    Reference: https://github.com/Carlos-Projects/mcpguard
    """

    def __init__(self):
        self._allowed_models: dict[str, str] = {}
        self._allowed_datasets: dict[str, str] = {}
        self._allowed_adapters: dict[str, str] = {}
        self._allowed_dependencies: dict[str, str] = {}

    def generate_policy(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Generate an MCPGuard-compatible policy from model metadata.

        Args:
            metadata: Model metadata.

        Returns:
            Policy dict that can be serialized to YAML.
        """
        rules: list[dict[str, Any]] = []
        for ds in metadata.datasets:
            rules.append(
                {
                    "id": f"allow-dataset-{ds.name}",
                    "type": "allow",
                    "resource": f"dataset:{ds.name}",
                    "conditions": [
                        {"field": "hash", "operator": "eq", "value": ds.hash} if ds.hash else {},
                        {"field": "source", "operator": "eq", "value": ds.source}
                        if ds.source
                        else {},
                    ],
                    "action": "allow",
                }
            )

        for adp in metadata.adapters:
            rules.append(
                {
                    "id": f"allow-adapter-{adp.name}",
                    "type": "allow",
                    "resource": f"adapter:{adp.name}",
                    "conditions": [
                        {"field": "hash", "operator": "eq", "value": adp.hash} if adp.hash else {},
                    ],
                    "action": "allow",
                }
            )

        for dep in metadata.dependencies:
            rules.append(
                {
                    "id": f"allow-dep-{dep.name}",
                    "type": "allow",
                    "resource": f"dependency:{dep.name}:{dep.version}",
                    "action": "allow",
                }
            )

        policy = {
            "policy": {
                "name": f"modelchain-sbom-{metadata.model_name}-{metadata.model_version}",
                "description": f"Auto-generated policy for {metadata.model_name} v{metadata.model_version}",
                "version": "1.0",
                "source": "modelchain-sbom/0.1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "model": {
                    "name": metadata.model_name,
                    "version": metadata.model_version,
                    "type": metadata.model_type,
                },
                "rules": rules,
                "default_action": "deny",
            },
        }

        return policy

    def generate_policy_yaml(self, metadata: ModelMetadata) -> str:
        """Generate a MCPGuard policy as YAML string.

        Args:
            metadata: Model metadata.

        Returns:
            YAML-formatted policy string.
        """
        policy = self.generate_policy(metadata)
        return yaml.dump(policy, default_flow_style=False, sort_keys=False)

    def generate_policy_json(self, metadata: ModelMetadata) -> str:
        """Generate a MCPGuard policy as JSON string.

        Args:
            metadata: Model metadata.

        Returns:
            JSON-formatted policy string.
        """
        policy = self.generate_policy(metadata)
        return json.dumps(policy, indent=2)
