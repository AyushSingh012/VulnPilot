.PHONY: check lint type test integration github-test fixtures osv-data

check: lint type test

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy

test:
	uv run pytest

integration:
	uv run pytest -m 'integration and not github'

# Needs VULNPILOT_SANDBOX, VULNPILOT_SANDBOX_REMOTE and (optionally) VULNPILOT_GH_USER.
github-test:
	uv run pytest -m github -rs

osv-data:
	uv run python scripts/capture_osv.py

fixtures:
	uv run python scripts/regen_fixtures.py
