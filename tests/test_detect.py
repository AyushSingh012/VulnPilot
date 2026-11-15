from pathlib import Path

import pytest

from tests.conftest import FIXTURES
from vulnpilot.detect import DetectError, detect_project

PYPROJECT = '[project]\nname = "demo"\nversion = "0"\n'


def make(tmp_path: Path, *files: str, pyproject: str = PYPROJECT) -> Path:
    (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    for name in files:
        (tmp_path / name).write_text("version = 1\n", encoding="utf-8")
    return tmp_path


def test_uv_fixture() -> None:
    project = detect_project(FIXTURES / "uv" / "transitive")
    assert project.manager == "uv"
    assert project.lockfile.name == "uv.lock"
    assert project.root.is_absolute()


def test_poetry(tmp_path: Path) -> None:
    project = detect_project(make(tmp_path, "poetry.lock"))
    assert project.manager == "poetry"


def test_uv_preferred_when_both_lockfiles(tmp_path: Path) -> None:
    assert detect_project(make(tmp_path, "uv.lock", "poetry.lock")).manager == "uv"


def test_commit_sha_is_none_outside_git(tmp_path: Path) -> None:
    project = detect_project(make(tmp_path, "uv.lock"))
    assert project.commit_sha is None or len(project.commit_sha) == 40


@pytest.mark.parametrize(
    ("files", "pyproject", "match"),
    [
        ((), PYPROJECT, "no uv.lock or poetry.lock"),
        (("uv.lock",), PYPROJECT + '\n[tool.uv.workspace]\nmembers = ["pkgs/*"]\n', "workspace"),
        (("uv.lock",), "not = [valid", "not valid TOML"),
    ],
)
def test_errors(tmp_path: Path, files: tuple[str, ...], pyproject: str, match: str) -> None:
    with pytest.raises(DetectError, match=match):
        detect_project(make(tmp_path, *files, pyproject=pyproject))


def test_no_pyproject(tmp_path: Path) -> None:
    with pytest.raises(DetectError, match=r"no pyproject\.toml"):
        detect_project(tmp_path)
