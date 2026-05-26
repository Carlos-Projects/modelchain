from __future__ import annotations

from modelchain.integrations.taxonomy_adapter import ModelChainTaxonomyAdapter


class TestModelChainTaxonomyAdapter:
    def test_available_without_mcp_taxonomy(self):
        adapter = ModelChainTaxonomyAdapter()
        assert not adapter.available

    def test_fallback_classification(self):
        adapter = ModelChainTaxonomyAdapter()
        result = adapter.classify_vulnerability(
            {
                "package": "transformers",
                "severity": "HIGH",
                "vulnerability_id": "ML-2024-001",
            }
        )
        assert result["attack_category"] == "supply_chain:transformers"
        assert result["severity"] == "HIGH"

    def test_fallback_component_type(self):
        adapter = ModelChainTaxonomyAdapter()
        result = adapter.classify_component_type("dataset")
        assert result == "dataset"

    def test_classify_unknown_vulnerability(self):
        adapter = ModelChainTaxonomyAdapter()
        result = adapter.classify_vulnerability(
            {
                "package": "unknown-pkg",
                "severity": "LOW",
            }
        )
        assert "attack_category" in result
