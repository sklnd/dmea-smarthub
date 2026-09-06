default: bootstrap

bootstrap:
    uv sync --locked

check: lint typecheck test

test: bootstrap
    uv run pytest

lint: bootstrap
    uv run ruff format --check .
    uv run ruff check .

typecheck: bootstrap
    uv run ty check

fix: bootstrap
    uv run ruff format .
    uv run ruff check --fix .
