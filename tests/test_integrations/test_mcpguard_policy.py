from __future__ import annotations

from modelchain.integrations.mcpguard_policy import MCPGuardPolicyGenerator
from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    ModelMetadata,
)


class TestMCPGuardPolicyGenerator:
    def test_generate_empty_policy(self):
        gen = MCPGuardPolicyGenerator()
        meta = ModelMetadata(model_name="test", model_version="1.0", model_type="llm")
        policy = gen.generate_policy(meta)
        assert policy["policy"]["name"] == "modelchain-sbom-test-1.0"
        assert policy["policy"]["default_action"] == "deny"
        assert len(policy["policy"]["rules"]) == 0

    def test_generate_with_datasets(self):
        gen = MCPGuardPolicyGenerator()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            datasets=[DatasetComponent(name="ds1", version="1", source="hf", hash="abc")],
        )
        policy = gen.generate_policy(meta)
        rules = policy["policy"]["rules"]
        assert len(rules) == 1
        assert rules[0]["resource"] == "dataset:ds1"

    def test_generate_with_adapters(self):
        gen = MCPGuardPolicyGenerator()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            adapters=[AdapterComponent(name="lora1", type="LoRA", source="s", hash="h1")],
        )
        policy = gen.generate_policy(meta)
        rules = policy["policy"]["rules"]
        assert len(rules) == 1
        assert "adapter:lora1" in rules[0]["resource"]

    def test_generate_with_dependencies(self):
        gen = MCPGuardPolicyGenerator()
        meta = ModelMetadata(
            model_name="test",
            model_version="1.0",
            model_type="llm",
            dependencies=[FrameworkDependency(name="torch", version="2.0", type="framework")],
        )
        policy = gen.generate_policy(meta)
        rules = policy["policy"]["rules"]
        assert len(rules) == 1
        assert "torch" in rules[0]["resource"]

    def test_yaml_output(self):
        gen = MCPGuardPolicyGenerator()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        yaml_str = gen.generate_policy_yaml(meta)
        assert "modelchain-sbom-test-1" in yaml_str
        assert "default_action: deny" in yaml_str

    def test_json_output(self):
        gen = MCPGuardPolicyGenerator()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        json_str = gen.generate_policy_json(meta)
        assert "modelchain-sbom-test-1" in json_str
        assert "deny" in json_str
