# Contributing to Driln

## Setup

```bash
git clone https://github.com/khushalv21/DRILN.git
cd DRILN
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

## Before opening a PR

Run the same checks CI runs, in this order:

```bash
ruff check driln tests scripts
ruff format --check driln tests scripts
mypy driln scripts
PYTHONPATH=. pytest tests/ -v
```

`ruff format driln tests scripts` (without `--check`) will fix formatting for you.
`mypy` runs in strict mode — new code needs type annotations, not `# type: ignore`.

## Adding a new tool integration

Tools live in `driln/tools/` and subclass `BaseTool` (see `driln/tools/nuclei.py` for a
reference implementation). At minimum:

1. Set `name`, `description`, `binary` class attributes.
2. Implement `build_command(target, options) -> list[str]`.
3. Implement `parse_output(raw_output, exit_code) -> ToolResult`, mapping the tool's
   output into `ToolResult.findings` (a list of dicts with `severity`, `title`, `host`,
   `port`, `service` at minimum).
4. Register it in `driln/tools/registry.py`'s `_load_builtin_tools()`.
5. Add it to a pipeline in `driln/engine/pipeline.py` if it should run by default.

## Adding a workflow rule

Workflow rules (`driln/workflow/rules.py`) detect a condition in scan results and either
auto-expand the scan or suggest a follow-up for the user to approve. See the existing
rules for the shape — a `condition` callable over `(ScanContext, TechProfile)` and one or
more `WorkflowAction`s. Set `requires_approval=False` only for actions that are safe and
inexpensive to run automatically.

## Tests

New logic needs tests that would actually fail if the logic were wrong — not just "doesn't
crash" checks. `tests/conftest.py` provides a `db_session` fixture (in-memory SQLite) for
anything touching the database layer.

## Commit messages

Explain *why*, not just *what* — the diff already shows what changed.
