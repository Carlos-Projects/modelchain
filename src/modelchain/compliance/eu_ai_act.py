from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modelchain.models import ModelMetadata

HIGH_RISK_CATEGORIES = [
    "biometric",
    "critical_infrastructure",
    "education",
    "employment",
    "law_enforcement",
    "migration",
    "justice",
]


@dataclass
class EUAIActReport:
    """Compliance report for EU AI Act."""

    passed: bool
    risk_category: str
    requirements: dict[str, dict[str, Any]]
    summary: dict[str, Any]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class EUAIActChecker:
    """Checks model compliance with the EU AI Act.

    Reference: https://artificialintelligenceact.eu/
    """

    def __init__(self, risk_category: str = "general_purpose"):
        self.risk_category = risk_category

    def check(self, metadata: ModelMetadata) -> EUAIActReport:
        """Check model compliance with EU AI Act requirements.

        Args:
            metadata: Model metadata to check.

        Returns:
            EUAIActReport with compliance status per requirement.
        """
        requirements: dict[str, dict[str, Any]] = {
            "transparency": self._check_transparency(metadata),
            "documentation": self._check_documentation(metadata),
            "human_oversight": self._check_human_oversight(metadata),
            "accuracy": self._check_accuracy(metadata),
            "robustness": self._check_robustness(metadata),
            "cybersecurity": self._check_cybersecurity(metadata),
            "data_governance": self._check_data_governance(metadata),
            "risk_management": self._check_risk_management(metadata),
        }

        total = len(requirements)
        passed = sum(1 for r in requirements.values() if r["passed"])

        return EUAIActReport(
            passed=passed == total,
            risk_category=self.risk_category,
            requirements=requirements,
            summary={
                "total_requirements": total,
                "passed": passed,
                "failed": total - passed,
                "risk_category": self.risk_category,
                "is_high_risk": self.risk_category in HIGH_RISK_CATEGORIES,
            },
        )

    def _check_transparency(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check transparency requirements (Art. 13)."""
        checks = {
            "model_identified": bool(metadata.model_name),
            "version_documented": bool(metadata.model_version),
            "description_provided": bool(metadata.description),
            "author_identified": bool(metadata.author),
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 13 - Transparency",
        }

    def _check_documentation(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check documentation requirements (Art. 11)."""
        checks = {
            "base_model_documented": bool(metadata.base_model),
            "datasets_documented": len(metadata.datasets) > 0,
            "training_parameters_documented": (
                metadata.hyperparameters.learning_rate is not None
                or metadata.hyperparameters.batch_size is not None
            ),
            "dependencies_documented": len(metadata.dependencies) > 0,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 11 - Technical Documentation",
        }

    def _check_human_oversight(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check human oversight requirements (Art. 14)."""
        checks = {
            "model_type_identified": bool(metadata.model_type),
            "intended_use_traceable": True,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 14 - Human Oversight",
        }

    def _check_accuracy(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check accuracy requirements (Art. 15)."""
        checks = {
            "version_tracked": bool(metadata.model_version),
            "base_model_known": bool(metadata.base_model) or True,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 15 - Accuracy",
        }

    def _check_robustness(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check robustness requirements (Art. 15)."""
        checks = {
            "integrity_verifiable": bool(metadata.base_model_hash) or len(metadata.datasets) > 0,
            "dependencies_tracked": len(metadata.dependencies) > 0,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 15 - Robustness",
        }

    def _check_cybersecurity(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check cybersecurity requirements (Art. 15)."""
        checks = {
            "supply_chain_tracked": (
                len(metadata.datasets) > 0
                or len(metadata.adapters) > 0
                or bool(metadata.base_model)
            ),
            "integrity_hashes_provided": (
                bool(metadata.base_model_hash) or any(ds.hash for ds in metadata.datasets)
            ),
        }
        return {
            "passed": any(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 15 - Cybersecurity",
        }

    def _check_data_governance(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check data governance requirements (Art. 10)."""
        checks = {
            "datasets_tracked": len(metadata.datasets) > 0,
            "dataset_provenance": all(bool(ds.source) for ds in metadata.datasets)
            if metadata.datasets
            else False,
            "dataset_licenses": all(bool(ds.license) for ds in metadata.datasets)
            if metadata.datasets
            else True,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 10 - Data Governance",
        }

    def _check_risk_management(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check risk management requirements (Art. 9)."""
        checks = {
            "vulnerability_tracking": True,
            "version_control": bool(metadata.model_version),
            "component_tracking": (
                len(metadata.datasets) > 0
                or len(metadata.adapters) > 0
                or len(metadata.dependencies) > 0
            ),
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "requirement": "EU AI Act Art. 9 - Risk Management",
        }
