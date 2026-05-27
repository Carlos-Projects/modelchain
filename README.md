# ModelChain

[![GitHub Release](https://img.shields.io/github/v/release/Carlos-Projects/modelchain)](https://github.com/Carlos-Projects/modelchain/releases)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Carlos-Projects/modelchain/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/modelchain/actions/workflows/ci.yml)

**Software Bill of Materials (SBOM) generator for AI models** with provenance tracking, cryptographic integrity verification, and compliance reporting.

ModelChain creates a complete provenance record of the AI model supply chain: `base model → datasets → fine-tuning → adapters → deployment`. It verifies integrity at each step and generates cryptographic manifests for audit and compliance.

## Features

- **SBOM Generation** — Complete model SBOM (base model, datasets, adapters, hyperparameters, dependencies)
- **Provenance Tracking** — Trace each component's origin with cryptographic verification
- **Supply Chain Audit** — Detect compromised components in the supply chain
- **Integrity Manifests** — SHA-256 manifests for every component
- **Dependency Analysis** — Analyze model dependencies for known vulnerabilities
- **Compliance Reporting** — EU AI Act & NIST AI RMF reports
- **Multi-Format Output** — CycloneDX, SPDX 2.3, ModelChain native format, JSON, HTML

## Installation

```bash
git clone https://github.com/Carlos-Projects/modelchain.git
cd modelchain
pip install -e ".[dev]"
```

> **Note:** Package not yet published on PyPI. Install from source. Coming soon.

## Quick Start

### Basic SBOM Generation

```bash
modelchain generate my-model 1.0.0 \
  --type llm \
  --base meta-llama/Meta-Llama-3-8B \
  --framework transformers --framework-version 4.36.0 \
  --author "Carlos Rocha" \
  --description "My fine-tuned model"
```

### With Datasets, Adapters, and Dependencies

```bash
modelchain generate security-model 1.0.0 \
  --type llm \
  --base meta-llama/Meta-Llama-3-8B \
  --dataset "security-instruct:2.1.0:huggingface:a1b2c3d4" \
  --adapter "security-lora:LoRA:local:e5f6a1b2" \
  --dependency "transformers:4.36.0:framework" \
  --dependency "torch:2.1.0:framework" \
  --output ./reports/sbom \
  -v
```

### Verify Integrity

```bash
modelchain verify manifest.json --base-path ./models
```

### Audit Supply Chain

```bash
modelchain audit sbom.json
```

### Compliance Reports

```bash
modelchain report sbom.json --format console
modelchain report sbom.json --format json --output report.json
modelchain report sbom.json --format html --output report.html
```

## Output Formats

| Format | Command | Description |
|--------|---------|-------------|
| ModelChain | `--format modelchain` (default) | Native JSON format with all provenance data |
| CycloneDX | `--format cyclonedx` | CycloneDX 1.6 AI SBOM standard |
| SPDX | `--format spdx` | SPDX 2.3 format |

## Compliance Frameworks

- **EU AI Act** — Checks transparency (Art. 13), documentation (Art. 11), human oversight (Art. 14), accuracy/robustness/cybersecurity (Art. 15), data governance (Art. 10), risk management (Art. 9)
- **NIST AI RMF 1.0** — Checks Govern, Map, Measure, Manage categories

## Ecosystem Integration

| Project | Integration |
|---------|-------------|
| [reverse-abliterate](https://github.com/Carlos-Projects/reverse-abliterate) | Shared integrity manifest patterns (SHA-256), same CLI style |
| [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy) | MCP security taxonomy integration |
| [MCPGuard](https://github.com/Carlos-Projects/mcpguard) | Compatible policy generation |
| [MCPscop](https://github.com/Carlos-Projects/mcpscope) | Consumable report formats |

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=modelchain -v

# Lint
ruff check src/

# Type check
mypy src/modelchain/
```

## Project Structure

```
src/modelchain/
├── cli.py              # Typer CLI (generate, verify, audit, report, sbom)
├── generator.py        # Core SBOM generator
├── provenance/         # Provenance tracking & verification
├── sbom/               # SBOM builders (modelchain, cyclonedx, spdx)
├── supply_chain/       # Supply chain auditing & vulnerability correlation
├── integrity/          # SHA-256 manifests, fingerprints, diffs
├── compliance/         # EU AI Act & NIST AI RMF checkers
├── reporters/          # Console (Rich), JSON, HTML (Jinja2) output
└── utils/              # Cryptographic utilities
```

## License

MIT License — see [LICENSE](LICENSE) for details.
