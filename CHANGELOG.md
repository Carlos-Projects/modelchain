# Changelog

## [0.1.0] - 2026-05-26

### Added
- Initial release of ModelChain
- CLI with 5 commands: `generate`, `verify`, `audit`, `report`, `sbom`
- SBOM generation for AI models (base model, datasets, adapters, hyperparameters, dependencies)
- Provenance tracking with cryptographic verification (SHA-256)
- SBOM export to CycloneDX 1.6, SPDX 2.3, and ModelChain custom format
- Supply chain auditing with vulnerability correlation (built-in ML vulnerability DB)
- SHA-256 integrity manifests (shared patterns with reverse-abliterate)
- Model fingerprinting and version diffing
- Compliance reporting for EU AI Act (Art. 9-15) and NIST AI RMF 1.0
- Rich console, JSON, and HTML (Jinja2) reporters
- mcp-taxonomy integration adapter
- MCPGuard-compatible YAML policy generation
- MCPscop consumable report format
- 167 tests with 81% coverage
- type hints throughout
- GitHub Actions CI/CD (ruff, mypy, pytest, coverage)
- PyPI publishing workflow
