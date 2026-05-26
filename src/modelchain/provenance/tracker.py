from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modelchain.models import ModelMetadata


@dataclass
class ProvenanceNode:
    """A node in the provenance graph representing a component."""

    id: str
    name: str
    type: str  # "model", "dataset", "adapter", "framework"
    version: str
    hash: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    """An edge in the provenance graph representing a relationship."""

    source_id: str
    target_id: str
    relationship: str  # "trained_on", "fine_tuned_from", "uses", "derived_from"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceTracker:
    """Tracks the provenance of model components through the supply chain."""

    nodes: dict[str, ProvenanceNode] = field(default_factory=dict)
    edges: list[ProvenanceEdge] = field(default_factory=list)

    def add_node(self, node: ProvenanceNode) -> None:
        """Add a provenance node to the graph.

        Args:
            node: The provenance node to add.
        """
        self.nodes[node.id] = node

    def add_edge(self, edge: ProvenanceEdge) -> None:
        """Add a provenance edge to the graph.

        Args:
            edge: The provenance edge to add.
        """
        self.edges.append(edge)

    def build_graph(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Build a provenance graph from model metadata.

        Args:
            metadata: Model metadata with all components.

        Returns:
            Serialized provenance graph as a dict.
        """
        self.nodes.clear()
        self.edges.clear()

        model_id = f"model:{metadata.model_name}@{metadata.model_version}"
        self.add_node(
            ProvenanceNode(
                id=model_id,
                name=metadata.model_name,
                type="model",
                version=metadata.model_version,
                hash=metadata.base_model_hash,
                metadata={
                    "model_type": metadata.model_type,
                    "framework": metadata.framework,
                    "description": metadata.description,
                },
            )
        )

        if metadata.base_model:
            base_id = f"base:{metadata.base_model}"
            self.add_node(
                ProvenanceNode(
                    id=base_id,
                    name=metadata.base_model,
                    type="model",
                    version="",
                    hash="",
                    metadata={"is_base": True},
                )
            )
            self.add_edge(
                ProvenanceEdge(
                    source_id=model_id,
                    target_id=base_id,
                    relationship="fine_tuned_from",
                )
            )

        for ds in metadata.datasets:
            ds_id = f"dataset:{ds.name}@{ds.version}"
            self.add_node(
                ProvenanceNode(
                    id=ds_id,
                    name=ds.name,
                    type="dataset",
                    version=ds.version,
                    hash=ds.hash,
                    metadata={"source": ds.source, "size": ds.size},
                )
            )
            self.add_edge(
                ProvenanceEdge(
                    source_id=model_id,
                    target_id=ds_id,
                    relationship="trained_on",
                )
            )

        for adp in metadata.adapters:
            adp_id = f"adapter:{adp.name}"
            self.add_node(
                ProvenanceNode(
                    id=adp_id,
                    name=adp.name,
                    type="adapter",
                    version="",
                    hash=adp.hash,
                    metadata={"adapter_type": adp.type, "base_model": adp.base_model},
                )
            )
            self.add_edge(
                ProvenanceEdge(
                    source_id=model_id,
                    target_id=adp_id,
                    relationship="uses",
                )
            )

        for dep in metadata.dependencies:
            dep_id = f"dep:{dep.name}@{dep.version}"
            self.add_node(
                ProvenanceNode(
                    id=dep_id,
                    name=dep.name,
                    type="framework",
                    version=dep.version,
                    hash="",
                    metadata={"dep_type": dep.type},
                )
            )
            self.add_edge(
                ProvenanceEdge(
                    source_id=model_id,
                    target_id=dep_id,
                    relationship="uses",
                )
            )

        return self.serialize()

    def serialize(self) -> dict[str, Any]:
        """Serialize the provenance graph to a dict."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "type": n.type,
                    "version": n.version,
                    "hash": n.hash,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "relationship": e.relationship,
                    "metadata": e.metadata,
                }
                for e in self.edges
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
