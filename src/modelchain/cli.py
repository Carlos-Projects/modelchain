from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich import print as rprint

from modelchain.compliance.reporter import ComplianceReporter
from modelchain.generator import SBOMResult, generate_sbom
from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    HyperParameters,
    ModelMetadata,
)
from modelchain.provenance.verifier import ProvenanceVerifier
from modelchain.reporters.console import ConsoleReporter
from modelchain.reporters.html import HTMLReporter
from modelchain.reporters.json import JSONReporter
from modelchain.supply_chain.auditor import SupplyChainAuditor

app = typer.Typer(
    name="modelchain",
    help="ModelChain: Software Bill of Materials (SBOM) generator for AI models",
    add_completion=False,
)


@app.callback()
def callback() -> None:
    """ModelChain: SBOM generator for AI models with provenance tracking."""


@app.command()
def generate(
    name: str = typer.Argument(..., help="Model name"),
    version: str = typer.Argument(..., help="Model version"),
    model_type: str = typer.Option(
        "llm", "--type", "-t", help="Model type (llm, embedding, vision, multimodal)"
    ),
    base_model: str = typer.Option("", "--base", "-b", help="Base model name"),
    base_model_hash: str = typer.Option("", "--base-hash", help="Base model SHA-256 hash"),
    framework: str = typer.Option("", "--framework", "-f", help="Framework (e.g., transformers)"),
    framework_version: str = typer.Option("", "--framework-version", help="Framework version"),
    author: str = typer.Option("", "--author", "-a", help="Model author"),
    license: str = typer.Option("", "--license", "-l", help="Model license"),
    description: str = typer.Option("", "--description", "-d", help="Model description"),
    url: str = typer.Option("", "--url", "-u", help="Model URL"),
    dataset: list[str] = typer.Option(
        [], "--dataset", help="Dataset in format: name:version:source:hash"
    ),
    adapter: list[str] = typer.Option(
        [], "--adapter", help="Adapter in format: name:type:source:hash"
    ),
    dependency: list[str] = typer.Option(
        [], "--dependency", help="Dependency in format: name:version:type"
    ),
    output: str = typer.Option("", "--output", "-o", help="Output file path (without extension)"),
    fmt: str = typer.Option(
        "modelchain", "--format", help="Output format: modelchain, cyclonedx, spdx"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Generate an SBOM for an AI model."""
    hyperparameters = HyperParameters()

    datasets = _parse_datasets(dataset)
    adapters = _parse_adapters(adapter)
    dependencies = _parse_dependencies(dependency)

    metadata = ModelMetadata(
        model_name=name,
        model_version=version,
        model_type=model_type,
        base_model=base_model,
        base_model_hash=base_model_hash,
        description=description,
        author=author,
        framework=framework,
        framework_version=framework_version,
        license=license,
        url=url,
        datasets=datasets,
        adapters=adapters,
        dependencies=dependencies,
        hyperparameters=hyperparameters,
    )

    if verbose:
        rprint(f"[cyan]Generating SBOM for[/] {name} @ {version}")

    result = generate_sbom(metadata, output_format=fmt)

    console = ConsoleReporter()
    console.report_sbom(result)

    if output:
        output_path = Path(output)
        json_reporter = JSONReporter()
        json_reporter.report_sbom(result, output_path.with_suffix(".json"))

        html_reporter = HTMLReporter()
        html_reporter.report_sbom(result, output_path.with_suffix(".html"))

        rprint(
            f"\n[green]Reports written:[/] {output_path.with_suffix('.json')}, {output_path.with_suffix('.html')}"
        )


@app.command()
def verify(
    manifest: str = typer.Argument(..., help="Path to integrity manifest JSON file"),
    base_path: str = typer.Option(".", "--base-path", "-b", help="Base path for resolving files"),
) -> None:
    """Verify integrity of model components against a manifest."""
    manifest_path = Path(manifest)
    if not manifest_path.exists():
        rprint(f"[red]Error:[/] Manifest file not found: {manifest}")
        raise typer.Exit(1)

    data = json.loads(manifest_path.read_text())

    verifier = ProvenanceVerifier()
    result = verifier.verify_manifest(
        {e["path"]: e["hash"] for e in data.get("entries", [])},
        base_path=base_path,
    )

    console = ConsoleReporter()
    verify_data = {
        "total": len(result),
        "verified": sum(1 for r in result if r.verified),
        "failed": sum(1 for r in result if not r.verified),
        "results": [
            {
                "component": r.component_name,
                "verified": r.verified,
                "expected_hash": r.expected_hash,
                "computed_hash": r.computed_hash,
                "errors": r.errors,
            }
            for r in result
        ],
    }
    console.report_verify(verify_data)

    all_verified = all(r.verified for r in result)
    if not all_verified:
        raise typer.Exit(1)


@app.command()
def audit(
    manifest: str = typer.Argument(..., help="Path to model SBOM JSON file"),
) -> None:
    """Audit the model supply chain for vulnerabilities."""
    manifest_path = Path(manifest)
    if not manifest_path.exists():
        rprint(f"[red]Error:[/] SBOM file not found: {manifest}")
        raise typer.Exit(1)

    data = json.loads(manifest_path.read_text())

    meta = data.get("metadata", {})
    metadata = ModelMetadata(
        model_name=meta.get("model_name", "unknown"),
        model_version=meta.get("model_version", "0.0.0"),
        model_type=meta.get("model_type", "llm"),
    )

    sbom_data = data.get("sbom", {})
    for ds_entry in sbom_data.get("datasets", []):
        metadata.datasets.append(
            DatasetComponent(
                name=ds_entry.get("name", ""),
                version=ds_entry.get("version", ""),
                source=ds_entry.get("source", ""),
                hash=ds_entry.get("hash", ""),
            )
        )
    for adp_entry in sbom_data.get("adapters", []):
        metadata.adapters.append(
            AdapterComponent(
                name=adp_entry.get("name", ""),
                type=adp_entry.get("type", ""),
                source=adp_entry.get("source", ""),
                hash=adp_entry.get("hash", ""),
            )
        )
    for dep_entry in sbom_data.get("dependencies", []):
        metadata.dependencies.append(
            FrameworkDependency(
                name=dep_entry.get("name", ""),
                version=dep_entry.get("version", ""),
                type=dep_entry.get("type", ""),
            )
        )

    auditor = SupplyChainAuditor()
    result = auditor.audit(metadata)

    console = ConsoleReporter()
    console.report_audit(
        {
            "passed": result.passed,
            "model_name": result.model_name,
            "model_version": result.model_version,
            "findings": result.findings,
            "summary": result.summary,
        }
    )

    if not result.passed:
        raise typer.Exit(1)


@app.command()
def report(
    sbom: str = typer.Argument(..., help="Path to SBOM JSON file"),
    format: str = typer.Option(
        "console", "--format", "-f", help="Output format: console, json, html"
    ),
    output: str = typer.Option("", "--output", "-o", help="Output file path (for json/html)"),
) -> None:
    """Generate compliance reports from an SBOM."""
    sbom_path = Path(sbom)
    if not sbom_path.exists():
        rprint(f"[red]Error:[/] SBOM file not found: {sbom}")
        raise typer.Exit(1)

    data = json.loads(sbom_path.read_text())

    meta = data.get("metadata", {})
    metadata = ModelMetadata(
        model_name=meta.get("model_name", "unknown"),
        model_version=meta.get("model_version", "0.0.0"),
        model_type=meta.get("model_type", "llm"),
    )

    reporter = ComplianceReporter()
    report_data = reporter.generate_report(metadata)

    if format == "console" or not output:
        console = ConsoleReporter()
        console.report_compliance(
            {
                "frameworks": {
                    "eu_ai_act": report_data.frameworks["eu_ai_act"],
                    "nist_ai_rmf": report_data.frameworks["nist_ai_rmf"],
                },
            }
        )

    if format == "json" and output:
        out_path = Path(output)
        out_path.write_text(
            json.dumps(
                {
                    "model_name": report_data.model_name,
                    "model_version": report_data.model_version,
                    "frameworks": report_data.frameworks,
                    "summary": report_data.summary,
                },
                indent=2,
            )
        )
        rprint(f"[green]Report written:[/] {out_path}")

    if format == "html" and output:
        out_path = Path(output)
        html_reporter = HTMLReporter()
        fake_audit_summary: dict[str, Any] = {
            "total_components": 0,
            "datasets": 0,
            "adapters": 0,
            "dependencies": 0,
            "integrity_verified": False,
            "vulnerabilities_found": 0,
        }
        fake_compliance_reports: list[dict[str, Any]] = [
            {
                "framework": "EU AI Act",
                "passed": report_data.frameworks["eu_ai_act"]["passed"],
                "summary": report_data.frameworks["eu_ai_act"]["summary"],
            },
            {
                "framework": "NIST AI RMF 1.0",
                "passed": report_data.frameworks["nist_ai_rmf"]["passed"],
                "summary": report_data.frameworks["nist_ai_rmf"]["summary"],
            },
        ]
        html_reporter.report_sbom(
            SBOMResult(
                metadata=metadata,
                sbom={},
                manifest={},
                provenance_graph={},
                audit_summary=fake_audit_summary,
                compliance_reports=fake_compliance_reports,
            ),
            out_path,
        )
        rprint(f"[green]Report written:[/] {out_path}")


@app.command()
def sbom(
    path: str = typer.Argument(..., help="Path to SBOM JSON file"),
) -> None:
    """Display an SBOM in the console."""
    sbom_path = Path(path)
    if not sbom_path.exists():
        rprint(f"[red]Error:[/] SBOM file not found: {path}")
        raise typer.Exit(1)

    data = json.loads(sbom_path.read_text())

    meta = data.get("metadata", {})
    metadata = ModelMetadata(
        model_name=meta.get("model_name", "unknown"),
        model_version=meta.get("model_version", "0.0.0"),
        model_type=meta.get("model_type", "llm"),
    )

    sbom_data = data.get("sbom", {})
    if sbom_data:
        for ds_entry in sbom_data.get("datasets", []):
            metadata.datasets.append(
                DatasetComponent(
                    name=ds_entry.get("name", ""),
                    version=ds_entry.get("version", ""),
                    source=ds_entry.get("source", ""),
                    hash=ds_entry.get("hash", ""),
                )
            )
        for adp_entry in sbom_data.get("adapters", []):
            metadata.adapters.append(
                AdapterComponent(
                    name=adp_entry.get("name", ""),
                    type=adp_entry.get("type", ""),
                    source=adp_entry.get("source", ""),
                    hash=adp_entry.get("hash", ""),
                )
            )
        for dep_entry in sbom_data.get("dependencies", []):
            metadata.dependencies.append(
                FrameworkDependency(
                    name=dep_entry.get("name", ""),
                    version=dep_entry.get("version", ""),
                    type=dep_entry.get("type", ""),
                )
            )

    result = SBOMResult(
        metadata=metadata,
        sbom=sbom_data or data.get("sbom", {}),
        manifest=data.get("integrity_manifest", {}),
        provenance_graph=data.get("provenance_graph", {}),
        audit_summary=data.get("audit_summary", {}),
        compliance_reports=data.get("compliance_reports", []),
        format=data.get("format", "modelchain"),
        generated_at=data.get("generated_at", ""),
    )

    console = ConsoleReporter()
    console.report_sbom(result)


def _parse_datasets(datasets: list[str]) -> list[DatasetComponent]:
    """Parse dataset strings in format: name:version:source:hash."""
    result: list[DatasetComponent] = []
    for ds in datasets:
        parts = ds.split(":", 3)
        if len(parts) == 4:
            result.append(
                DatasetComponent(
                    name=parts[0],
                    version=parts[1],
                    source=parts[2],
                    hash=parts[3],
                )
            )
        elif len(parts) == 3:
            result.append(
                DatasetComponent(
                    name=parts[0],
                    version=parts[1],
                    source=parts[2],
                    hash="",
                )
            )
        elif len(parts) == 2:
            result.append(
                DatasetComponent(
                    name=parts[0],
                    version=parts[1],
                    source="",
                    hash="",
                )
            )
        elif len(parts) == 1:
            result.append(
                DatasetComponent(
                    name=parts[0],
                    version="",
                    source="",
                    hash="",
                )
            )
    return result


def _parse_adapters(adapters: list[str]) -> list[AdapterComponent]:
    """Parse adapter strings in format: name:type:source:hash."""
    result: list[AdapterComponent] = []
    for adp in adapters:
        parts = adp.split(":", 3)
        if len(parts) == 4:
            result.append(
                AdapterComponent(
                    name=parts[0],
                    type=parts[1],
                    source=parts[2],
                    hash=parts[3],
                )
            )
        elif len(parts) == 3:
            result.append(
                AdapterComponent(
                    name=parts[0],
                    type=parts[1],
                    source=parts[2],
                    hash="",
                )
            )
        elif len(parts) == 2:
            result.append(
                AdapterComponent(
                    name=parts[0],
                    type=parts[1],
                    source="",
                    hash="",
                )
            )
        elif len(parts) == 1:
            result.append(
                AdapterComponent(
                    name=parts[0],
                    type="",
                    source="",
                    hash="",
                )
            )
    return result


def _parse_dependencies(deps: list[str]) -> list[FrameworkDependency]:
    """Parse dependency strings in format: name:version:type."""
    result: list[FrameworkDependency] = []
    for dep in deps:
        parts = dep.split(":", 2)
        if len(parts) == 3:
            result.append(
                FrameworkDependency(
                    name=parts[0],
                    version=parts[1],
                    type=parts[2],
                )
            )
        elif len(parts) == 2:
            result.append(
                FrameworkDependency(
                    name=parts[0],
                    version=parts[1],
                    type="library",
                )
            )
        elif len(parts) == 1:
            result.append(
                FrameworkDependency(
                    name=parts[0],
                    version="",
                    type="library",
                )
            )
    return result


def main() -> None:
    """Entry point for the CLI."""
    app()
