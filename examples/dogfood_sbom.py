#!/usr/bin/env python3
"""Generate an SBOM for ModelChain itself (dogfooding).

Demonstrates ModelChain by generating an SBOM of its own dependencies.
"""

import json
from pathlib import Path

from modelchain.generator import generate_sbom
from modelchain.models import FrameworkDependency, HyperParameters, ModelMetadata


def main() -> None:
    metadata = ModelMetadata(
        model_name="modelchain-sbom",
        model_version="0.1.0",
        model_type="llm",
        description="Software Bill of Materials (SBOM) generator for AI models",
        author="Carlos Rocha",
        framework="python",
        framework_version="3.11+",
        license="MIT",
        dependencies=[
            FrameworkDependency(name="typer", version="0.12", type="framework"),
            FrameworkDependency(name="rich", version="13", type="library"),
            FrameworkDependency(name="pydantic", version="2", type="library"),
            FrameworkDependency(name="jinja2", version="3", type="library"),
            FrameworkDependency(name="pyyaml", version="6", type="library"),
            FrameworkDependency(name="httpx", version="0.27", type="library"),
            FrameworkDependency(name="packaging", version="24", type="library"),
        ],
        hyperparameters=HyperParameters(),
    )

    for fmt in ["modelchain", "cyclonedx", "spdx"]:
        print(f"Generating {fmt} SBOM for modelchain-sbom...")
        result = generate_sbom(metadata, output_format=fmt)

        out_dir = Path("output")
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / f"modelchain_sbom_{fmt}.json"
        out_path.write_text(json.dumps(result.sbom, indent=2))
        print(f"  Wrote {out_path}")

    print("\nDone! Generated self-SBOMs in all formats.")


if __name__ == "__main__":
    main()
