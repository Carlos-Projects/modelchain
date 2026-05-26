from __future__ import annotations

from typing import Any


class ProvenanceGraph:
    """Manipulates and queries provenance graphs for AI model supply chains."""

    def __init__(self, graph_data: dict[str, Any] | None = None):
        self.graph_data = graph_data or {"nodes": [], "edges": []}

    def load(self, graph_data: dict[str, Any]) -> None:
        """Load provenance graph data."""
        self.graph_data = graph_data

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        """Get a node by its ID."""
        for node in self.graph_data.get("nodes", []):
            if node.get("id") == node_id:
                return node
        return None

    def get_children(self, node_id: str) -> list[dict[str, Any]]:
        """Get all children of a node (nodes that this node points to)."""
        child_ids = [
            e["target"] for e in self.graph_data.get("edges", []) if e["source"] == node_id
        ]
        return [n for n in self.graph_data.get("nodes", []) if n["id"] in child_ids]

    def get_parents(self, node_id: str) -> list[dict[str, Any]]:
        """Get all parents of a node (nodes that point to this node)."""
        parent_ids = [
            e["source"] for e in self.graph_data.get("edges", []) if e["target"] == node_id
        ]
        return [n for n in self.graph_data.get("nodes", []) if n["id"] in parent_ids]

    def find_path(self, from_id: str, to_id: str) -> list[dict[str, Any]]:
        """Find the shortest path between two nodes (BFS).

        Args:
            from_id: Source node ID.
            to_id: Target node ID.

        Returns:
            List of edge dicts forming the path, or empty list if no path exists.
        """
        visited: set[str] = set()
        queue: list[tuple[str, list[dict[str, Any]]]] = [(from_id, [])]

        while queue:
            current, path = queue.pop(0)
            if current == to_id:
                return path
            if current in visited:
                continue
            visited.add(current)

            for edge in self.graph_data.get("edges", []):
                if edge["source"] == current:
                    next_id = edge["target"]
                    if next_id not in visited:
                        queue.append((next_id, [*path, edge]))

        return []

    def get_upstream_chain(self, node_id: str) -> list[dict[str, Any]]:
        """Get the full upstream supply chain for a node.

        Args:
            node_id: The node to trace upstream from.

        Returns:
            List of ancestor nodes in dependency order.
        """
        ancestors: list[dict[str, Any]] = []
        visited: set[str] = set()
        queue: list[str] = [node_id]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            for edge in self.graph_data.get("edges", []):
                if edge["target"] == current:
                    parent = self.get_node(edge["source"])
                    if parent and parent["id"] not in visited:
                        ancestors.append(parent)
                        queue.append(parent["id"])

        return ancestors

    def to_dot(self) -> str:
        """Export the graph as Graphviz DOT format."""
        lines = ["digraph ProvenanceGraph {", "  rankdir=LR;", "  node [shape=box];"]
        for node in self.graph_data.get("nodes", []):
            label = f"{node['name']}\\n({node['type']})"
            lines.append(f'  "{node["id"]}" [label="{label}"];')
        for edge in self.graph_data.get("edges", []):
            lines.append(
                f'  "{edge["source"]}" -> "{edge["target"]}" [label="{edge["relationship"]}"];'
            )
        lines.append("}")
        return "\n".join(lines)
