from __future__ import annotations

import pytest

from modelchain.provenance.graph import ProvenanceGraph


@pytest.fixture
def sample_graph():
    return ProvenanceGraph(
        {
            "nodes": [
                {
                    "id": "model:test@1",
                    "name": "test",
                    "type": "model",
                    "version": "1",
                    "hash": "h1",
                },
                {
                    "id": "base:base-llm",
                    "name": "base-llm",
                    "type": "model",
                    "version": "",
                    "hash": "",
                },
                {
                    "id": "dataset:ds1",
                    "name": "ds1",
                    "type": "dataset",
                    "version": "1",
                    "hash": "h2",
                },
                {
                    "id": "adapter:lora1",
                    "name": "lora1",
                    "type": "adapter",
                    "version": "",
                    "hash": "h3",
                },
                {
                    "id": "dep:torch",
                    "name": "torch",
                    "type": "framework",
                    "version": "2.0",
                    "hash": "",
                },
            ],
            "edges": [
                {
                    "source": "model:test@1",
                    "target": "base:base-llm",
                    "relationship": "fine_tuned_from",
                },
                {"source": "model:test@1", "target": "dataset:ds1", "relationship": "trained_on"},
                {"source": "model:test@1", "target": "adapter:lora1", "relationship": "uses"},
                {"source": "model:test@1", "target": "dep:torch", "relationship": "uses"},
            ],
        }
    )


class TestProvenanceGraph:
    def test_init_empty(self):
        graph = ProvenanceGraph()
        assert graph.graph_data == {"nodes": [], "edges": []}

    def test_init_with_data(self, sample_graph):
        assert len(sample_graph.graph_data["nodes"]) == 5
        assert len(sample_graph.graph_data["edges"]) == 4

    def test_load(self):
        graph = ProvenanceGraph()
        graph.load({"nodes": [{"id": "n1"}], "edges": []})
        assert len(graph.graph_data["nodes"]) == 1

    def test_get_node_found(self, sample_graph):
        node = sample_graph.get_node("model:test@1")
        assert node is not None
        assert node["name"] == "test"

    def test_get_node_not_found(self, sample_graph):
        node = sample_graph.get_node("nonexistent")
        assert node is None

    def test_get_children(self, sample_graph):
        children = sample_graph.get_children("model:test@1")
        assert len(children) == 4
        names = {c["name"] for c in children}
        assert "base-llm" in names
        assert "ds1" in names
        assert "lora1" in names
        assert "torch" in names

    def test_get_children_no_children(self, sample_graph):
        children = sample_graph.get_children("dataset:ds1")
        assert children == []

    def test_get_parents(self, sample_graph):
        parents = sample_graph.get_parents("dataset:ds1")
        assert len(parents) == 1
        assert parents[0]["name"] == "test"

    def test_get_parents_no_parents(self, sample_graph):
        parents = sample_graph.get_parents("model:test@1")
        assert parents == []

    def test_find_path_direct(self, sample_graph):
        path = sample_graph.find_path("model:test@1", "dataset:ds1")
        assert len(path) == 1
        assert path[0]["relationship"] == "trained_on"

    def test_find_path_no_path(self, sample_graph):
        path = sample_graph.find_path("dataset:ds1", "model:test@1")
        assert path == []

    def test_get_upstream_chain(self, sample_graph):
        chain = sample_graph.get_upstream_chain("model:test@1")
        assert len(chain) == 0

    def test_to_dot(self, sample_graph):
        dot = sample_graph.to_dot()
        assert dot.startswith("digraph")
        assert "model:test@1" in dot
        assert "dataset:ds1" in dot
        assert "->" in dot
        assert dot.endswith("}")
