from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from packaging.version import InvalidVersion, Version

from modelchain.models import FrameworkDependency, ModelMetadata


@dataclass
class DependencyReport:
    """Analysis report for model dependencies."""

    total: int
    frameworks: list[dict[str, Any]]
    libraries: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    outdated: list[dict[str, Any]]
    transitive_count: int
    recommendations: list[str]


class DependencyAnalyzer:
    """Analyzes model dependencies for security and compatibility."""

    def __init__(self):
        self._known_outdated: dict[str, str] = {
            "transformers": "4.36.0",
            "torch": "2.1.0",
            "tensorflow": "2.13.0",
            "onnx": "1.15.0",
            "safetensors": "0.4.0",
            "vllm": "0.4.0",
            "llama-cpp-python": "0.2.70",
            "bitsandbytes": "0.43.0",
            "peft": "0.10.0",
            "trl": "0.9.0",
            "accelerate": "0.28.0",
            "datasets": "2.19.0",
            "tokenizers": "0.19.0",
        }

    def analyze(self, metadata: ModelMetadata) -> DependencyReport:
        """Analyze dependencies in model metadata.

        Args:
            metadata: Model metadata.

        Returns:
            DependencyReport with categorized dependencies.
        """
        frameworks: list[dict[str, Any]] = []
        libraries: list[dict[str, Any]] = []
        tools: list[dict[str, Any]] = []
        outdated: list[dict[str, Any]] = []

        for dep in metadata.dependencies:
            entry = {
                "name": dep.name,
                "version": dep.version,
                "url": dep.url,
                "license": dep.license,
            }
            if dep.type == "framework":
                frameworks.append(entry)
            elif dep.type == "library":
                libraries.append(entry)
            else:
                tools.append(entry)

            self._check_outdated(dep, outdated)

        return DependencyReport(
            total=len(metadata.dependencies),
            frameworks=frameworks,
            libraries=libraries,
            tools=tools,
            outdated=outdated,
            transitive_count=0,
            recommendations=self._generate_recommendations(outdated),
        )

    def analyze_from_list(self, deps: list[FrameworkDependency]) -> DependencyReport:
        """Analyze a list of framework dependencies.

        Args:
            deps: List of framework dependencies.

        Returns:
            DependencyReport with analysis.
        """
        fake_metadata = ModelMetadata(
            model_name="_analysis_only",
            model_version="0.0.0",
            model_type="llm",
            dependencies=deps,
        )
        return self.analyze(fake_metadata)

    def _check_outdated(self, dep: FrameworkDependency, outdated: list[dict[str, Any]]) -> None:
        """Check if a dependency is outdated."""
        if dep.name.lower() in self._known_outdated:
            try:
                current = Version(dep.version)
                latest = Version(self._known_outdated[dep.name.lower()])
                if current < latest:
                    outdated.append(
                        {
                            "name": dep.name,
                            "current": dep.version,
                            "latest": self._known_outdated[dep.name.lower()],
                            "type": dep.type,
                        }
                    )
            except InvalidVersion:
                pass

    def _generate_recommendations(self, outdated: list[dict[str, Any]]) -> list[str]:
        """Generate recommendations based on analysis."""
        recs: list[str] = []
        if outdated:
            recs.append(f"Update {len(outdated)} outdated package(s):")
            for pkg in outdated:
                recs.append(f"  - {pkg['name']}: {pkg['current']} -> {pkg['latest']}")
        recs.append("Run dependency audit regularly to detect new vulnerabilities.")
        return recs
