# Contributing

## Architecture
TBD

### Commands

```bash
uv sync --all-extras      # Install all dependencies
uv run pytest             # Run all tests
```

## Workflow

**Always run pre-commit before committing and fix all failures before proceeding:**

```bash
uv run pre-commit run --all-files
```

Only commit once all hooks pass.

## Code Style

See [CODE_STYLE.md](CODE_STYLE.md).