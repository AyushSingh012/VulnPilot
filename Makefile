.PHONY: check lint type test fixtures

check: lint type test

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy

test:
	uv run pytest

fixtures:
	uv run python scripts/regen_fixtures.py
