from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from modelchain.generator import SBOMResult


class JSONReporter:
    """Reports SBOM results as JSON files."""

    def report_sbom(self, result: SBOMResult, path: str | Path) -> Path:
        """Write SBOM result as JSON.

        Args:
            result: SBOM generation result.
            path: Output file path.

        Returns:
            Path to the written file.
        """
        output = self._build_output(result)
        return self._write_json(output, path)

    def report_audit(self, audit_result: dict[str, Any], path: str | Path) -> Path:
        """Write audit result as JSON.

        Args:
            audit_result: Audit result dict.
            path: Output file path.

        Returns:
            Path to the written file.
        """
        return self._write_json(audit_result, path)

    def report_compliance(self, compliance_report: dict[str, Any], path: str | Path) -> Path:
        """Write compliance report as JSON.

        Args:
            compliance_report: Compliance report dict.
            path: Output file path.

        Returns:
            Path to the written file.
        """
        return self._write_json(compliance_report, path)

    def _build_output(self, result: SBOMResult) -> dict[str, Any]:
        """Build the full SBOM output dict."""
        return {
            "generator": result.generator,
            "generated_at": result.generated_at,
            "format": result.format,
            "metadata": {
                "model_name": result.metadata.model_name,
                "model_version": result.metadata.model_version,
                "model_type": result.metadata.model_type,
            },
            "sbom": result.sbom,
            "integrity_manifest": result.manifest,
            "provenance_graph": result.provenance_graph,
            "audit_summary": result.audit_summary,
            "compliance_reports": result.compliance_reports,
        }

    def _write_json(self, data: dict[str, Any], path: str | Path) -> Path:
        """Write dict as formatted JSON to file."""
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2))
        return p
