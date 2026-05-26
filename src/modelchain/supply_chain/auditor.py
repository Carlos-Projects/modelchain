from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from packaging.version import InvalidVersion, Version

from modelchain.integrity.manifest import IntegrityManifest
from modelchain.models import ModelMetadata
from modelchain.provenance.verifier import ProvenanceVerifier
from modelchain.supply_chain.vulnerability_db import VulnerabilityDB


@dataclass
class AuditResult:
    """Result of a supply chain audit."""

    passed: bool
    model_name: str
    model_version: str
    integrity_check: dict[str, Any]
    vulnerability_check: list[dict[str, Any]]
    dependency_check: dict[str, Any]
    findings: list[dict[str, Any]]
    summary: dict[str, Any]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SupplyChainAuditor:
    """Audits the AI model supply chain for compromised components.

    Combines integrity verification, vulnerability correlation,
    and dependency analysis into a comprehensive audit.
    """

    def __init__(self):
        self._verifier = ProvenanceVerifier()
        self._vuln_db = VulnerabilityDB()
        self._manifest = IntegrityManifest()

    def audit(self, metadata: ModelMetadata) -> AuditResult:
        """Run a complete supply chain audit.

        Args:
            metadata: Model metadata to audit.

        Returns:
            AuditResult with all findings.
        """
        findings: list[dict[str, Any]] = []

        manifest = self._manifest.generate(metadata)
        integrity_check = manifest

        vulns = self._vuln_db.correlate(metadata)
        if vulns:
            for v in vulns:
                findings.append(
                    {
                        "type": "vulnerability",
                        "severity": v["severity"],
                        "message": (
                            f"{v['vulnerability_id']}: {v['package']} "
                            f"{v['installed_version']} - {v['description']}"
                        ),
                        "component": v["package"],
                    }
                )

        dependency_check = self._check_dependency_issues(metadata)
        for dep_issue in dependency_check.get("issues", []):
            findings.append(
                {
                    "type": "dependency",
                    "severity": dep_issue["severity"],
                    "message": dep_issue["message"],
                    "component": dep_issue["component"],
                }
            )

        passed = len(vulns) == 0 and len(dependency_check.get("issues", [])) == 0

        return AuditResult(
            passed=passed,
            model_name=metadata.model_name,
            model_version=metadata.model_version,
            integrity_check=integrity_check,
            vulnerability_check=vulns,
            dependency_check=dependency_check,
            findings=findings,
            summary={
                "passed": passed,
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "high": sum(1 for f in findings if f.get("severity") == "HIGH"),
                "medium": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
                "low": sum(1 for f in findings if f.get("severity") == "LOW"),
            },
        )

    def _check_dependency_issues(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Check for dependency-related issues."""
        issues: list[dict[str, Any]] = []

        known_minimums = {
            "transformers": "4.36.0",
            "torch": "2.1.0",
            "tensorflow": "2.13.0",
        }

        for dep in metadata.dependencies:
            if dep.name.lower() in known_minimums:
                try:
                    dep_ver = Version(dep.version)
                    min_ver = Version(known_minimums[dep.name.lower()])
                    if dep_ver < min_ver:
                        issues.append(
                            {
                                "component": dep.name,
                                "severity": "MEDIUM",
                                "message": (
                                    f"{dep.name} {dep.version} is outdated. "
                                    f"Minimum recommended: {min_ver}"
                                ),
                            }
                        )
                except InvalidVersion:
                    issues.append(
                        {
                            "component": dep.name,
                            "severity": "LOW",
                            "message": f"Could not parse version: {dep.version}",
                        }
                    )

        return {
            "issues": issues,
            "total_issues": len(issues),
        }
