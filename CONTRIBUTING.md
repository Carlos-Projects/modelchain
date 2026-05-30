# Contributing to ModelChain

👋 **Welcome to ModelChain!**

We're building SBOM generators for AI models with provenance tracking, integrity verification, and compliance reporting — and we'd love your help. Whether you're squashing bugs, adding a new SBOM exporter, or improving documentation, your contributions help make AI supply chains more transparent and trustworthy.

## First Time Contributor?

Not sure where to start? Here are some ideas:

- Look for issues tagged `good first issue`
- Improve test coverage or add edge case tests
- Add a new compliance check for AI regulations
- Improve documentation or add examples

We value every contribution, no matter how small. We're here to support you!

## Need Help?

Have a question or need guidance?

- Open a [GitHub Issue](https://github.com/Carlos-Projects/modelchain/issues)
- Check existing issues first
- Include details: Python version, OS, what you're trying to do

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/modelchain.git
cd modelchain
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Code Style

We use ruff for linting and formatting:

```bash
ruff check src/
ruff check tests/
```

## Type Checking

```bash
mypy src/modelchain/
```

## Testing

```bash
python -m pytest tests/ -v
python -m pytest tests/ --cov=modelchain -v
```

## Pull Request Process

1. Create a feature branch
2. Add tests for new functionality
3. Ensure all tests pass (`python -m pytest tests/ -v`)
4. Ensure linting passes (`ruff check src/ tests/`)
5. Update documentation if needed
6. Open a PR against `main`

## Commit Messages

Follow conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`

## Release Process

See `RELEASE.md` for the release checklist.

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
