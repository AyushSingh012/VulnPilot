import tomllib

from tests.conftest import fixture_dir
from vulnpilot.config import ValidateConfig
from vulnpilot.fixers.poetry_fix import PIN_GROUP, with_pins
from vulnpilot.plan import registry_packages
from vulnpilot.validate import install_command


def test_pin_group_sits_beside_existing_groups() -> None:
    original = (fixture_dir("poetry-tests-break") / "pyproject.toml").read_text("utf-8")
    pinned = tomllib.loads(with_pins(original, {"jinja2": "3.1.6", "urllib3": "2.5.0"}))
    groups = pinned["tool"]["poetry"]["group"]
    assert groups[PIN_GROUP]["dependencies"] == {"jinja2": "==3.1.6", "urllib3": "==2.5.0"}
    assert groups["dev"]["dependencies"] == {"pytest": ">=8"}
    assert pinned["project"] == tomllib.loads(original)["project"]


def test_poetry_lock_index_and_path_packages() -> None:
    lock = fixture_dir("poetry-transitive-capped") / "poetry.lock"
    from_index = registry_packages(lock)
    assert "jinja2" in from_index and "capped-parent" not in from_index


def test_configured_install_command_wins() -> None:
    cfg = ValidateConfig(install="make deps")
    assert install_command(cfg, "poetry", {}) == "make deps"
    assert install_command(ValidateConfig(), "uv", {}) == "uv sync --frozen"
