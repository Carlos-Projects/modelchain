from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from modelchain.compliance.reporter import ComplianceReporter
from modelchain.integrity.manifest import IntegrityManifest
from modelchain.models import ModelMetadata
from modelchain.provenance.tracker import ProvenanceTracker
from modelchain.sbom.builder import SBOMBuilder
from modelchain.supply_chain.dependency_analyzer import DependencyAnalyzer
from modelchain.supply_chain.vulnerability_db import VulnerabilityDB


@dataclass
class SBOMResult:
    """Result of an SBOM generation."""

    metadata: ModelMetadata
    sbom: dict[str, Any]
    manifest: dict[str, Any]
    provenance_graph: dict[str, Any]
    audit_summary: dict[str, Any]
    compliance_reports: list[dict[str, Any]]
    format: str = "modelchain"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    generator: str = "modelchain-sbom/0.1.0"


def generate_sbom(
    metadata: ModelMetadata,
    output_format: str = "modelchain",
) -> SBOMResult:
    """Generate a complete SBOM for an AI model.

    This is the main entry point for creating an SBOM. It builds the SBOM
    document, tracks provenance, generates integrity manifests, analyzes
    dependencies, correlates vulnerabilities, and checks compliance across
    all supported frameworks.

    Args:
        metadata: Model metadata containing all components.
        output_format: Output format ("modelchain", "cyclonedx", "spdx").

    Returns:
        Complete SBOMResult with SBOM, manifest, provenance, and compliance.
    """
    builder = SBOMBuilder()
    sbom = builder.build(metadata, output_format)

    provenance = ProvenanceTracker()
    provenance_graph = provenance.build_graph(metadata)

    manifest = IntegrityManifest()
    manifest_entries = manifest.generate(metadata)

    dep_analyzer = DependencyAnalyzer()
    dep_analyzer.analyze(metadata)

    vuln_db = VulnerabilityDB()
    vuln_correlation = vuln_db.correlate(metadata)

    compliance = ComplianceReporter()
    compliance_reports = compliance.generate_all(metadata)

    audit_summary = {
        "total_components": (
            len(metadata.datasets) + len(metadata.adapters) + len(metadata.dependencies) + 1
        ),
        "datasets": len(metadata.datasets),
        "adapters": len(metadata.adapters),
        "dependencies": len(metadata.dependencies),
        "integrity_verified": manifest_entries.get("verified", False),
        "vulnerabilities_found": len(vuln_correlation),
        "compliance_checks": len(compliance_reports),
    }

    return SBOMResult(
        metadata=metadata,
        sbom=sbom,
        manifest=manifest_entries,
        provenance_graph=provenance_graph,
        audit_summary=audit_summary,
        compliance_reports=compliance_reports,
        format=output_format,
    )
