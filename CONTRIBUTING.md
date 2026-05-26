# Contributing to ModelChain

We love contributions! Here's how to get started.

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
