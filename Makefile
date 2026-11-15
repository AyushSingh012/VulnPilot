.PHONY: check lint type test integration fixtures osv-data

check: lint type test

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy

test:
	uv run pytest

integration:
	uv run pytest -m integration

osv-data:
	uv run python scripts/capture_osv.py

fixtures:
	uv run python scripts/regen_fixtures.py
