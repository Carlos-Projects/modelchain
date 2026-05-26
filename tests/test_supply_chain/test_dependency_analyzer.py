from __future__ import annotations

from modelchain.models import FrameworkDependency, ModelMetadata
from modelchain.supply_chain.dependency_analyzer import DependencyAnalyzer


class TestDependencyAnalyzer:
    def test_analyze_empty(self):
        analyzer = DependencyAnalyzer()
        meta = ModelMetadata(model_name="test", model_version="1", model_type="llm")
        report = analyzer.analyze(meta)
        assert report.total == 0
        assert report.frameworks == []
        assert report.libraries == []
        assert report.outdated == []

    def test_analyze_with_deps(self):
        analyzer = DependencyAnalyzer()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="torch", version="2.1.0", type="framework"),
                FrameworkDependency(name="safetensors", version="0.4.0", type="library"),
            ],
        )
        report = analyzer.analyze(meta)
        assert report.total == 2
        assert len(report.frameworks) == 1
        assert len(report.libraries) == 1

    def test_outdated_dependency(self):
        analyzer = DependencyAnalyzer()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="transformers", version="4.30.0", type="framework"),
            ],
        )
        report = analyzer.analyze(meta)
        assert len(report.outdated) >= 1
        assert report.outdated[0]["name"] == "transformers"

    def test_current_dependency_not_outdated(self):
        analyzer = DependencyAnalyzer()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="transformers", version="4.36.0", type="framework"),
            ],
        )
        report = analyzer.analyze(meta)
        outdated = [d for d in report.outdated if d["name"] == "transformers"]
        assert len(outdated) == 0

    def test_recommendations_with_outdated(self):
        analyzer = DependencyAnalyzer()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="transformers", version="4.30.0", type="framework"),
            ],
        )
        report = analyzer.analyze(meta)
        assert len(report.recommendations) >= 2
        assert report.recommendations[0] == "Update 1 outdated package(s):"

    def test_analyze_from_list(self):
        analyzer = DependencyAnalyzer()
        deps = [
            FrameworkDependency(name="torch", version="2.1.0", type="framework"),
        ]
        report = analyzer.analyze_from_list(deps)
        assert report.total == 1
        assert len(report.frameworks) == 1

    def test_categorization(self):
        analyzer = DependencyAnalyzer()
        meta = ModelMetadata(
            model_name="test",
            model_version="1",
            model_type="llm",
            dependencies=[
                FrameworkDependency(name="torch", version="2.0", type="framework"),
                FrameworkDependency(name="requests", version="2.31", type="library"),
                FrameworkDependency(name="black", version="24.0", type="tool"),
            ],
        )
        report = analyzer.analyze(meta)
        assert len(report.frameworks) == 1
        assert len(report.libraries) == 1
        assert len(report.tools) == 1
