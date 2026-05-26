from __future__ import annotations

from typing import Any

try:
    from mcp_taxonomy import AttackCategory, Confidence, DetectionMethod, Severity

    _HAS_MCP_TAXONOMY = True
except ImportError:
    _HAS_MCP_TAXONOMY = False


class ModelChainTaxonomyAdapter:
    """Adapts ModelChain SBOM findings to mcp-taxonomy enums.

    Usage:
        adapter = ModelChainTaxonomyAdapter()
        taxonomies = adapter.classify_vulnerability(vuln_entry)
    """

    def __init__(self):
        self._available = _HAS_MCP_TAXONOMY

    @property
    def available(self) -> bool:
        """Whether mcp-taxonomy package is installed."""
        return self._available

    def classify_vulnerability(self, vuln: dict[str, Any]) -> dict[str, Any]:
        """Map a vulnerability finding to mcp-taxonomy categories.

        Args:
            vuln: Vulnerability dict from VulnerabilityDB.

        Returns:
            Dict with taxonomy classification, or best-effort strings.
        """
        if not self._available:
            return self._fallback_classification(vuln)

        package = vuln.get("package", "").lower()
        severity = vuln.get("severity", "").upper()

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }

        attack_map = {
            "transformers": AttackCategory.SUPPLY_CHAIN,
            "torch": AttackCategory.SUPPLY_CHAIN,
            "tensorflow": AttackCategory.SUPPLY_CHAIN,
        }

        return {
            "attack_category": str(attack_map.get(package, AttackCategory.UNKNOWN)),
            "severity": str(severity_map.get(severity, Severity.UNKNOWN)),
            "confidence": str(Confidence.MEDIUM),
            "detection_method": str(DetectionMethod.STATIC_ANALYSIS),
        }

    def classify_component_type(self, component_type: str) -> str:
        """Map a ModelChain component type to mcp-taxonomy.

        Args:
            component_type: e.g. "dataset", "model", "adapter", "dependency"

        Returns:
            String representation of the AttackCategory.
        """
        if not self._available:
            return component_type

        cmap = {
            "dataset": AttackCategory.DATA_POISONING,
            "model": AttackCategory.SUPPLY_CHAIN,
            "adapter": AttackCategory.MODEL_TAMPERING,
            "dependency": AttackCategory.SUPPLY_CHAIN,
        }
        return str(cmap.get(component_type, AttackCategory.UNKNOWN))

    def _fallback_classification(self, vuln: dict[str, Any]) -> dict[str, Any]:
        """Fallback when mcp-taxonomy is not installed."""
        return {
            "attack_category": f"supply_chain:{vuln.get('package', 'unknown')}",
            "severity": vuln.get("severity", "UNKNOWN"),
            "confidence": "MEDIUM",
            "detection_method": "static_analysis",
        }
