from __future__ import annotations

from typing import Any

from modelchain.models import ModelMetadata
from modelchain.supply_chain.vulnerability_db import VulnerabilityDB


class MCPscopReportExporter:
    """Exports ModelChain SBOM results in MCPscop-consumable format.

    MCPscop is the unified security dashboard for MCP/A2A scanner results.
    This adapter produces reports that MCPscop can ingest via its /api/taxonomy
    normalization endpoints.

    Reference: https://github.com/Carlos-Projects/mcpscope
    """

    def export(self, metadata: ModelMetadata) -> dict[str, Any]:
        """Export model metadata to MCPscop-consumable JSON.

        Args:
            metadata: Model metadata.

        Returns:
            Dict in MCPscop findings format.
        """
        vuln_db = VulnerabilityDB()
        vulnerabilities = vuln_db.correlate(metadata)

        return {
            "tool": "modelchain-sbom",
            "tool_version": "0.1.0",
            "scan_target": metadata.model_name,
            "scan_target_version": metadata.model_version,
            "findings": self._build_findings(vulnerabilities),
            "summary": {
                "total_findings": len(vulnerabilities),
                "severity_breakdown": {
                    "critical": sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL"),
                    "high": sum(1 for v in vulnerabilities if v.get("severity") == "HIGH"),
                    "medium": sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM"),
                    "low": sum(1 for v in vulnerabilities if v.get("severity") == "LOW"),
                },
                "model_name": metadata.model_name,
                "model_version": metadata.model_version,
                "components_scanned": (
                    1 + len(metadata.datasets) + len(metadata.adapters) + len(metadata.dependencies)
                ),
            },
        }

    def _build_findings(
        self,
        vulnerabilities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build the findings list for MCPscop."""
        findings: list[dict[str, Any]] = []

        for vuln in vulnerabilities:
            findings.append(
                {
                    "type": "vulnerability",
                    "severity": vuln.get("severity", "UNKNOWN"),
                    "title": vuln.get("vulnerability_id", "Unknown"),
                    "description": vuln.get("description", ""),
                    "component": vuln.get("package", ""),
                    "component_version": vuln.get("installed_version", ""),
                    "recommendation": f"Update to {vuln.get('fix_version', 'latest')}",
                    "source": "modelchain-sbom",
                    "taxonomy": {
                        "attack_category": f"supply_chain:{vuln.get('package', '')}",
                        "severity": vuln.get("severity", "UNKNOWN"),
                        "confidence": "MEDIUM",
                        "detection_method": "static_analysis",
                    },
                }
            )

        return findings
