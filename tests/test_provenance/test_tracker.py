from __future__ import annotations

from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    ModelMetadata,
)
from modelchain.provenance.tracker import (
    ProvenanceEdge,
    ProvenanceNode,
    ProvenanceTracker,
)


class TestProvenanceNode:
    def test_minimal(self):
        node = ProvenanceNode(id="n1", name="test", type="model", version="1.0", hash="abc")
        assert node.id == "n1"
        assert node.metadata == {}

    def test_with_metadata(self):
        node = ProvenanceNode(
            id="n1",
            name="test",
            type="dataset",
            version="1.0",
            hash="abc",
            metadata={"source": "hf"},
        )
        assert node.metadata["source"] == "hf"


class TestProvenanceEdge:
    def test_minimal(self):
        edge = ProvenanceEdge(source_id="s1", target_id="t1", relationship="trained_on")
        assert edge.source_id == "s1"
        assert edge.metadata == {}


class TestProvenanceTracker:
    def test_add_node(self):
        tracker = ProvenanceTracker()
        node = ProvenanceNode(id="n1", name="test", type="model", version="1.0", hash="abc")
        tracker.add_node(node)
        assert len(tracker.nodes) == 1

    def test_add_edge(self):
        tracker = ProvenanceTracker()
        edge = ProvenanceEdge(source_id="s1", target_id="t1", relationship="trained_on")
        tracker.add_edge(edge)
        assert len(tracker.edges) == 1

    def test_build_graph_basic(self):
        meta = ModelMetadata(
            model_name="test-model",
            model_version="1.0",
            model_type="llm",
        )
        tracker = ProvenanceTracker()
        graph = tracker.build_graph(meta)
        assert len(graph["nodes"]) == 1
        assert graph["nodes"][0]["name"] == "test-model"
        assert len(graph["edges"]) == 0

    def test_build_graph_with_base_model(self):
        meta = ModelMetadata(
            model_name="test-model",
            model_version="1.0",
            model_type="llm",
            base_model="base-llm",
        )
        tracker = ProvenanceTracker()
        graph = tracker.build_graph(meta)
        assert len(graph["nodes"]) == 2
        assert len(graph["edges"]) == 1
        assert graph["edges"][0]["relationship"] == "fine_tuned_from"

    def test_build_graph_with_datasets(self):
        meta = ModelMetadata(
            model_name="test-model",
            model_version="1.0",
            model_type="llm",
            datasets=[
                DatasetComponent(name="ds1", version="1", source="src", hash="h1"),
                DatasetComponent(name="ds2", version="2", source="src", hash="h2"),
            ],
        )
        tracker = ProvenanceTracker()
        graph = tracker.build_graph(meta)
        dataset_nodes = [n for n in graph["nodes"] if n["type"] == "dataset"]
        assert len(dataset_nodes) == 2
        dataset_edges = [e for e in graph["edges"] if e["relationship"] == "trained_on"]
        assert len(dataset_edges) == 2

    def test_build_graph_with_adapters(self):
        meta = ModelMetadata(
            model_name="test-model",
            model_version="1.0",
            model_type="llm",
            adapters=[
                AdapterComponent(name="lora1", type="LoRA", source="s", hash="h1"),
            ],
        )
        tracker = ProvenanceTracker()
        graph = tracker.build_graph(meta)
        adapter_nodes = [n for n in graph["nodes"] if n["type"] == "adapter"]
        assert len(adapter_nodes) == 1

    def test_build_graph_with_dependencies(self):
        meta = ModelMetadata(
            model_name="test-model",
            model_version="1.0",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="torch", version="2.0", type="framework"),
            ],
        )
        tracker = ProvenanceTracker()
        graph = tracker.build_graph(meta)
        dep_nodes = [n for n in graph["nodes"] if n["type"] == "framework"]
        assert len(dep_nodes) == 1

    def test_serialize(self):
        tracker = ProvenanceTracker()
        node = ProvenanceNode(id="n1", name="test", type="model", version="1.0", hash="abc")
        tracker.add_node(node)
        data = tracker.serialize()
        assert "nodes" in data
        assert "edges" in data
        assert "generated_at" in data

    def test_build_graph_clears_previous(self):
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        tracker = ProvenanceTracker()
        tracker.add_node(ProvenanceNode(id="old", name="old", type="model", version="1", hash="h"))
        graph = tracker.build_graph(meta)
        assert len(graph["nodes"]) == 1
        assert graph["nodes"][0]["name"] == "test"
