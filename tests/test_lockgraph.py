from tests.conftest import FIXTURES
from vulnpilot.detect import detect_project
from vulnpilot.lockgraph import LockGraph, load_graph, load_poetry_graph


def graph(name: str) -> LockGraph:
    return load_graph(detect_project(FIXTURES / "uv" / name))


def test_direct_and_transitive() -> None:
    g = graph("transitive")
    assert g.root == "fx-transitive"
    assert g.is_direct("requests")
    assert not g.is_direct("urllib3")
    assert g.paths_to("urllib3") == [["fx-transitive", "requests", "urllib3"]]


def test_dev_group_packages_are_dev_only() -> None:
    g = graph("transitive")
    assert g.is_direct("pytest")
    assert g.is_dev_only("pytest")
    assert g.is_dev_only("pluggy")
    assert not g.is_dev_only("urllib3")


def test_capped_parent_path() -> None:
    g = graph("transitive-capped")
    assert g.paths_to("Jinja2") == [["fx-transitive-capped", "capped-parent", "jinja2"]]


def test_direct_package_path_is_one_hop() -> None:
    assert graph("direct-in-range").paths_to("requests") == [["fx-direct-in-range", "requests"]]


def test_unknown_package_has_no_path() -> None:
    assert graph("transitive").paths_to("not-a-package") == []


def test_poetry_direct_from_pyproject() -> None:
    pyproject = {
        "project": {"dependencies": ["Requests>=2", "bad spec ((("]},
        "tool": {
            "poetry": {
                "dependencies": {"python": "^3.12", "jinja2": "^3.1"},
                "group": {"dev": {"dependencies": {"pytest": "^8"}}},
            }
        },
    }
    g = load_poetry_graph(pyproject, "demo")
    assert g.direct == {"requests", "jinja2"}
    assert g.direct_dev == {"pytest"}
