from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modelchain.compliance.eu_ai_act import EUAIActChecker
from modelchain.compliance.nist_rmf import NISTRMFChecker
from modelchain.models import ModelMetadata


@dataclass
class ComplianceReport:
    """Combined compliance report across multiple frameworks."""

    model_name: str
    model_version: str
    frameworks: dict[str, dict[str, Any]]
    summary: dict[str, Any]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ComplianceReporter:
    """Generates compliance reports across multiple regulatory frameworks."""

    def __init__(self):
        self._eu_checker = EUAIActChecker()
        self._nist_checker = NISTRMFChecker()

    def generate_all(self, metadata: ModelMetadata) -> list[dict[str, Any]]:
        """Generate compliance reports for all supported frameworks.

        Args:
            metadata: Model metadata.

        Returns:
            List of compliance report dicts.
        """
        return [
            self._generate_eu(metadata),
            self._generate_nist(metadata),
        ]

    def generate_report(self, metadata: ModelMetadata) -> ComplianceReport:
        """Generate a comprehensive compliance report.

        Args:
            metadata: Model metadata.

        Returns:
            ComplianceReport with all framework results.
        """
        eu_report = self._eu_checker.check(metadata)
        nist_report = self._nist_checker.check(metadata)

        frameworks = {
            "eu_ai_act": {
                "passed": eu_report.passed,
                "risk_category": eu_report.risk_category,
                "requirements": eu_report.requirements,
                "summary": eu_report.summary,
            },
            "nist_ai_rmf": {
                "passed": nist_report.passed,
                "categories": nist_report.categories,
                "summary": nist_report.summary,
            },
        }

        total_frameworks = len(frameworks)
        passed_frameworks = sum(1 for f in frameworks.values() if f["passed"])

        return ComplianceReport(
            model_name=metadata.model_name,
            model_version=metadata.model_version,
            frameworks=frameworks,
            summary={
                "total_frameworks": total_frameworks,
                "passed_frameworks": passed_frameworks,
                "failed_frameworks": total_frameworks - passed_frameworks,
                "all_passed": passed_frameworks == total_frameworks,
            },
        )

    def _generate_eu(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Generate EU AI Act compliance report as dict."""
        report = self._eu_checker.check(metadata)
        return {
            "framework": "EU AI Act",
            "reference": "https://artificialintelligenceact.eu/",
            "passed": report.passed,
            "risk_category": report.risk_category,
            "requirements": report.requirements,
            "summary": report.summary,
        }

    def _generate_nist(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Generate NIST AI RMF compliance report as dict."""
        report = self._nist_checker.check(metadata)
        return {
            "framework": "NIST AI RMF 1.0",
            "reference": "https://www.nist.gov/itl/ai-risk-management-framework",
            "passed": report.passed,
            "categories": report.categories,
            "summary": report.summary,
        }
