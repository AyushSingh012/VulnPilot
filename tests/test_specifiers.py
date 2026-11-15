import pytest
from packaging.specifiers import SpecifierSet

from vulnpilot.specifiers import (
    SpecifierEditError,
    adjust_specifier,
    allows,
    raise_to,
    requirement_strings,
)

PYPROJECT = """\
[project]
name = "demo"
version = "0"
dependencies = [
    # keep this comment
    "requests==2.31.0",
    "jinja2>=3.1,<4",
    "rich[jupyter]~=13.0.0 ; python_version >= '3.12'",
]

[project.optional-dependencies]
http = ["requests>=2.31,<2.32"]

[dependency-groups]
dev = ["pytest>=8", {include-group = "lint"}]
lint = ["ruff"]
"""


@pytest.mark.parametrize(
    ("spec", "target", "expected"),
    [
        ("==2.31.0", "2.33.0", "==2.33.0"),
        ("===2.31.0", "2.33.0", "==2.33.0"),
        ("~=2.31.0", "2.32.4", "~=2.32.4"),
        ("~=2.31", "2.32.4", "~=2.31"),  # 2-part ~= already allows it: unchanged
        ("~=2.31", "3.0.1", "~=3.0,>=3.0.1"),  # blocks only across a major
        ("<2.32,>=2.31", "2.32.4", "<2.33,>=2.32.4"),
        ("<2.32.3", "2.32.4", "<2.32.5"),
        ("<=2.31.0", "2.32.4", "<2.32.5"),
        ("==2.31.*", "2.32.4", "==2.32.*,>=2.32.4"),
    ],
)
def test_adjust_specifier(spec: str, target: str, expected: str) -> None:
    new = adjust_specifier(SpecifierSet(spec), target)
    assert new == SpecifierSet(expected)
    assert new.contains(target)


def test_not_equal_to_target_is_refused() -> None:
    with pytest.raises(SpecifierEditError, match="excluded"):
        adjust_specifier(SpecifierSet("!=2.32.4,<3"), "2.32.4")


def test_allows() -> None:
    assert not allows(PYPROJECT, "requests", "2.33.0")
    assert allows(PYPROJECT, "jinja2", "3.1.6")
    assert not allows(PYPROJECT, "jinja2", "4.0.0")
    assert allows(PYPROJECT, "not-listed", "1.0")


def test_requirement_strings_cover_all_sections() -> None:
    assert sorted(requirement_strings(PYPROJECT, "Requests")) == [
        "requests<2.32,>=2.31",
        "requests==2.31.0",
    ]
    assert requirement_strings(PYPROJECT, "ruff") == ["ruff"]


def test_raise_to_edits_only_blocking_requirements_and_keeps_comments() -> None:
    text, changes = raise_to(PYPROJECT, "requests", "2.32.4")
    assert changes == [
        ("requests==2.31.0", "requests==2.32.4"),
        ("requests>=2.31,<2.32", "requests<2.33,>=2.32.4"),
    ]
    assert "# keep this comment" in text
    assert '"jinja2>=3.1,<4"' in text
    assert '{include-group = "lint"}' in text


def test_raise_to_keeps_extras_and_markers() -> None:
    _, changes = raise_to(PYPROJECT, "rich", "13.0.5")
    assert changes == []  # ~=13.0.0 already allows 13.0.5
    _, changes = raise_to(PYPROJECT, "rich", "13.1.2")
    [(_, new)] = changes
    assert new == 'rich[jupyter]~=13.1.2; python_version >= "3.12"'
