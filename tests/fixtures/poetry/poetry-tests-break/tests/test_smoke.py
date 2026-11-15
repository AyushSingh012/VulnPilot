from importlib.metadata import version

import requests


def test_requests_imports() -> None:
    assert requests.__name__ == "requests"


def test_jinja2_is_exactly_312() -> None:
    # Stands in for code that breaks on a newer jinja2.
    assert version("jinja2") == "3.1.2"
