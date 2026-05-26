from __future__ import annotations

from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from modelchain.generator import SBOMResult


class ConsoleReporter:
    """Reports SBOM results to the console using Rich."""

    def __init__(self):
        self._console = Console()

    def report_sbom(self, result: SBOMResult) -> None:
        """Display SBOM result in console.

        Args:
            result: SBOM generation result.
        """
        self._display_header(result)
        self._display_model_info(result)
        self._display_components(result)
        self._display_integrity(result)
        self._display_compliance(result)
        self._display_provenance(result)
        self._display_summary(result)

    def _display_header(self, result: SBOMResult) -> None:
        self._console.print()
        self._console.print(
            Panel(
                f"[bold cyan]ModelChain SBOM[/]\n"
                f"Generator: {result.generator}\n"
                f"Format: {result.format}\n"
                f"Generated: {result.generated_at}",
                title="SBOM Report",
            )
        )

    def _display_model_info(self, result: SBOMResult) -> None:
        table = Table(title="Model Information", box=box.ROUNDED)
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")

        meta = result.metadata
        table.add_row("Name", meta.model_name)
        table.add_row("Version", meta.model_version)
        table.add_row("Type", meta.model_type)
        table.add_row("Framework", f"{meta.framework} {meta.framework_version}")
        table.add_row("Base Model", meta.base_model or "N/A")
        table.add_row("Author", meta.author or "N/A")
        table.add_row("License", meta.license or "N/A")

        hp = meta.hyperparameters
        if hp.learning_rate is not None:
            table.add_row("Learning Rate", str(hp.learning_rate))
        if hp.epochs is not None:
            table.add_row("Epochs", str(hp.epochs))
        if hp.precision:
            table.add_row("Precision", hp.precision)

        self._console.print(table)

    def _display_components(self, result: SBOMResult) -> None:
        meta = result.metadata

        if meta.datasets:
            table = Table(title="Datasets", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Version")
            table.add_column("Source")
            table.add_column("Hash")
            for ds in meta.datasets:
                table.add_row(ds.name, ds.version, ds.source, ds.hash[:16] + "...")
            self._console.print(table)

        if meta.adapters:
            table = Table(title="Adapters", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Type")
            table.add_column("Base Model")
            table.add_column("Hash")
            for adp in meta.adapters:
                table.add_row(adp.name, adp.type, adp.base_model, adp.hash[:16] + "...")
            self._console.print(table)

        if meta.dependencies:
            table = Table(title="Dependencies", box=box.ROUNDED)
            table.add_column("Name", style="cyan")
            table.add_column("Version")
            table.add_column("Type")
            table.add_column("License")
            for dep in meta.dependencies:
                table.add_row(dep.name, dep.version, dep.type, dep.license)
            self._console.print(table)

    def _display_integrity(self, result: SBOMResult) -> None:
        manifest = result.manifest
        entries: list[dict[str, Any]] = manifest.get("entries", [])

        table = Table(title="Integrity Manifest", box=box.ROUNDED)
        table.add_column("Component", style="cyan")
        table.add_column("Hash")
        table.add_column("Algorithm")

        for entry in entries:
            h = entry.get("hash", "")
            table.add_row(
                entry.get("component_name", ""),
                h[:32] + "...",
                entry.get("algorithm", "sha256"),
            )
        self._console.print(table)

    def _display_compliance(self, result: SBOMResult) -> None:
        for report in result.compliance_reports:
            framework = report.get("framework", "Unknown")
            passed = report.get("passed", False)
            status = "[green]PASSED[/]" if passed else "[red]FAILED[/]"
            summary = report.get("summary", {})
            self._console.print(
                Panel(
                    f"[bold]{framework}[/]\n"
                    f"Status: {status}\n"
                    f"Passed: {summary.get('passed', 0)}/{summary.get('total_requirements', 0) or summary.get('total_categories', 0)}",
                    title="Compliance Check",
                )
            )

    def _display_provenance(self, result: SBOMResult) -> None:
        graph = result.provenance_graph
        tree = Tree("[bold cyan]Provenance Graph[/]")
        model_nodes = [n for n in graph.get("nodes", []) if n["type"] == "model"]

        for model_node in model_nodes:
            model_branch = tree.add(f"[bold]{model_node['name']}[/] ({model_node['type']})")
            children = [
                e["target"] for e in graph.get("edges", []) if e["source"] == model_node["id"]
            ]
            child_nodes = [n for n in graph.get("nodes", []) if n["id"] in children]
            for child in child_nodes:
                model_branch.add(f"[cyan]{child['name']}[/] ({child['type']})")

        self._console.print(tree)

    def _display_summary(self, result: SBOMResult) -> None:
        summary = result.audit_summary
        table = Table(title="Audit Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        table.add_row("Total Components", str(summary.get("total_components", 0)))
        table.add_row("Datasets", str(summary.get("datasets", 0)))
        table.add_row("Adapters", str(summary.get("adapters", 0)))
        table.add_row("Dependencies", str(summary.get("dependencies", 0)))
        table.add_row("Integrity Verified", str(summary.get("integrity_verified", False)))
        table.add_row("Vulnerabilities Found", str(summary.get("vulnerabilities_found", 0)))
        self._console.print(table)

    def report_audit(self, audit_result: dict[str, Any]) -> None:
        """Display audit results in console."""
        passed = audit_result.get("passed", False)
        status = "[green]PASSED[/]" if passed else "[red]FAILED[/]"
        findings = audit_result.get("findings", [])
        summary = audit_result.get("summary", {})

        self._console.print()
        self._console.print(
            Panel(
                f"[bold cyan]Supply Chain Audit[/]\n"
                f"Model: {audit_result.get('model_name', 'N/A')} @ {audit_result.get('model_version', 'N/A')}\n"
                f"Status: {status}",
            )
        )

        if findings:
            table = Table(title=f"Findings ({len(findings)})", box=box.ROUNDED)
            table.add_column("Type", style="cyan")
            table.add_column("Severity")
            table.add_column("Message")
            table.add_column("Component")
            for f in findings:
                sev = f.get("severity", "")
                sev_style = {
                    "CRITICAL": "red",
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }.get(sev, "")
                table.add_row(
                    f.get("type", ""),
                    f"[{sev_style}]{sev}[/]",
                    f.get("message", ""),
                    f.get("component", ""),
                )
            self._console.print(table)

        self._console.print(
            Panel(
                f"Total: {summary.get('total_findings', 0)} | "
                f"Critical: {summary.get('critical', 0)} | "
                f"High: {summary.get('high', 0)} | "
                f"Medium: {summary.get('medium', 0)} | "
                f"Low: {summary.get('low', 0)}",
                title="Summary",
            )
        )

    def report_compliance(self, compliance_report: dict[str, Any]) -> None:
        """Display compliance report in console."""
        self._console.print()
        for framework, data in compliance_report.get("frameworks", {}).items():
            passed = data.get("passed", False)
            status = "[green]PASSED[/]" if passed else "[red]FAILED[/]"
            summary = data.get("summary", {})
            self._console.print(
                Panel(
                    f"[bold]{framework}[/]\n"
                    f"Status: {status}\n"
                    f"Passed: {summary.get('passed', 0)}/{summary.get('total_requirements', 0) or summary.get('total_categories', 0)}",
                )
            )

    def report_verify(self, verify_result: dict[str, Any]) -> None:
        """Display verification results in console."""
        total = verify_result.get("total", 0)
        verified = verify_result.get("verified", 0)
        failed = verify_result.get("failed", 0)

        self._console.print()
        self._console.print(
            Panel(
                f"[bold cyan]Integrity Verification[/]\n"
                f"Total: {total} | "
                f"[green]Verified: {verified}[/] | "
                + (f"[red]Failed: {failed}[/]" if failed else f"Failed: {failed}"),
            )
        )

        for result in verify_result.get("results", []):
            if not result["verified"]:
                self._console.print(
                    f"  [red]✗[/] {result['component']}: {result.get('errors', ['Unknown error'])[0]}"
                )
            else:
                self._console.print(f"  [green]✓[/] {result['component']}")
