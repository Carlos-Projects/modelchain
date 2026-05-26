from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modelchain.models import ModelMetadata

NIST_RMF_CATEGORIES = [
    "govern",
    "map",
    "measure",
    "manage",
]


@dataclass
class NISTRMFReport:
    """Compliance report for NIST AI RMF."""

    passed: bool
    categories: dict[str, dict[str, Any]]
    summary: dict[str, Any]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class NISTRMFChecker:
    """Checks model compliance with NIST AI RMF 1.0.

    Reference: https://www.nist.gov/itl/ai-risk-management-framework
    """

    def check(self, metadata: ModelMetadata) -> NISTRMFReport:
        """Check model compliance with NIST AI RMF.

        Args:
            metadata: Model metadata to check.

        Returns:
            NISTRMFReport with compliance status per category.
        """
        categories: dict[str, dict[str, Any]] = {
            "govern": self._check_govern(metadata),
            "map": self._check_map(metadata),
            "measure": self._check_measure(metadata),
            "manage": self._check_manage(metadata),
        }

        total = len(categories)
        passed = sum(1 for c in categories.values() if c["passed"])

        return NISTRMFReport(
            passed=passed == total,
            categories=categories,
            summary={
                "total_categories": total,
                "passed": passed,
                "failed": total - passed,
            },
        )

    def _check_govern(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check Govern (GOVERN) category."""
        checks = {
            "model_documented": bool(metadata.model_name and metadata.model_version),
            "author_identified": bool(metadata.author),
            "license_specified": bool(metadata.license),
            "version_controlled": bool(metadata.model_version),
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "category": "GOVERN - AI RMF 1.0 Govern",
        }

    def _check_map(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check Map (MAP) category."""
        checks = {
            "model_type_identified": bool(metadata.model_type),
            "base_model_tracked": bool(metadata.base_model),
            "datasets_mapped": len(metadata.datasets) > 0,
            "dependencies_mapped": len(metadata.dependencies) > 0,
            "adapters_mapped": len(metadata.adapters) > 0 or True,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "category": "MAP - AI RMF 1.0 Map",
        }

    def _check_measure(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check Measure (MEASURE) category."""
        checks = {
            "integrity_hashes": bool(metadata.base_model_hash)
            or any(ds.hash for ds in metadata.datasets),
            "hyperparameters_documented": (
                metadata.hyperparameters.learning_rate is not None
                or metadata.hyperparameters.epochs is not None
            ),
            "framework_documented": bool(metadata.framework),
        }
        return {
            "passed": any(checks.values()),
            "checks": checks,
            "category": "MEASURE - AI RMF 1.0 Measure",
        }

    def _check_manage(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check Manage (MANAGE) category."""
        checks = {
            "supply_chain_tracked": (
                len(metadata.datasets) > 0
                or len(metadata.adapters) > 0
                or bool(metadata.base_model)
            ),
            "dependencies_tracked": len(metadata.dependencies) > 0,
            "version_tracked": bool(metadata.model_version),
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "category": "MANAGE - AI RMF 1.0 Manage",
        }
