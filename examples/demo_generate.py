#!/usr/bin/env python3
"""Demo: Generate a full ModelChain SBOM and export to all formats."""

import json
from pathlib import Path

from modelchain.generator import generate_sbom
from modelchain.models import (
    AdapterComponent,
    DatasetComponent,
    FrameworkDependency,
    HyperParameters,
    ModelMetadata,
)


def main() -> None:
    metadata = ModelMetadata(
        model_name="demo-llama",
        model_version="1.0.0",
        model_type="llm",
        base_model="meta-llama/Meta-Llama-3-8B",
        base_model_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        description="Demo model for ModelChain SBOM generation",
        author="Carlos Rocha",
        framework="transformers",
        framework_version="4.36.0",
        license="MIT",
        datasets=[
            DatasetComponent(
                name="security-instruct",
                version="2.1.0",
                source="huggingface",
                hash="b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3",
                size=524288000,
                description="Security instruction dataset",
                license="MIT",
            ),
        ],
        adapters=[
            AdapterComponent(
                name="security-lora",
                type="LoRA",
                source="local",
                hash="c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                base_model="meta-llama/Meta-Llama-3-8B",
                parameters={"r": 16, "alpha": 32},
            ),
        ],
        dependencies=[
            FrameworkDependency(name="transformers", version="4.36.0", type="framework"),
            FrameworkDependency(name="torch", version="2.1.0", type="framework"),
        ],
        hyperparameters=HyperParameters(
            learning_rate=2e-5,
            batch_size=8,
            epochs=3,
            precision="bf16",
        ),
    )

    for fmt in ["modelchain", "cyclonedx", "spdx"]:
        print(f"Generating {fmt} SBOM...")
        result = generate_sbom(metadata, output_format=fmt)

        out_dir = Path("output")
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / f"sbom_{fmt}.json"
        out_path.write_text(json.dumps(result.sbom, indent=2))
        print(f"  Wrote {out_path}")

    print("\nDone! Generated SBOMs in all formats.")


if __name__ == "__main__":
    main()
