import pytest
from packaging.specifiers import SpecifierSet

from vulnpilot.specifiers import (
    SpecifierEditError,
    adjust_specifier,
    allows,
    poetry_allows,
    raise_poetry,
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


@pytest.mark.parametrize(
    ("constraint", "inside", "outside"),
    [
        ("^1.2.3", ["1.2.3", "1.9"], ["1.2.2", "2.0"]),
        ("^0.2.3", ["0.2.9"], ["0.3.0"]),
        ("^0.0.3", ["0.0.3"], ["0.0.4"]),
        ("~1.2.3", ["1.2.9"], ["1.3.0"]),
        ("~1", ["1.9"], ["2.0"]),
        ("2.31.0", ["2.31.0"], ["2.31.1"]),
        (">=2.31,<2.32", ["2.31.5"], ["2.32.0"]),
        (">=2.31 <2.32", ["2.31.5"], ["2.32.0"]),
        ("*", ["0.1", "99"], []),
        ("^1.0 || ^3.0", ["1.5", "3.1"], ["2.0"]),
    ],
)
def test_poetry_constraints(constraint: str, inside: list[str], outside: list[str]) -> None:
    assert all(poetry_allows(constraint, v) for v in inside)
    assert not any(poetry_allows(constraint, v) for v in outside)


@pytest.mark.parametrize(
    ("constraint", "target", "expected"),
    [
        ("^2.31.0", "3.0.1", "^3.0.1"),
        ("~2.31.0", "2.32.4", "~2.32.4"),
        ("2.31.0", "2.33.0", "2.33.0"),
        ("==2.31.0", "2.33.0", "2.33.0"),
        (">=2.31,<2.32", "2.32.4", "<2.33,>=2.32.4"),
    ],
)
def test_raise_poetry_keeps_the_style(constraint: str, target: str, expected: str) -> None:
    new = raise_poetry(constraint, target)
    assert new == expected and poetry_allows(new, target)


def test_raise_poetry_refuses_alternatives() -> None:
    with pytest.raises(SpecifierEditError, match="cannot safely rewrite"):
        raise_poetry("^1.0 || ^3.0", "2.0")


POETRY_PYPROJECT = """\
[tool.poetry]
name = "demo"

[tool.poetry.dependencies]
python = "^3.12"
requests = "2.31.0"  # pinned on purpose
rich = { version = "^13.0", extras = ["jupyter"] }
local = { path = "../local" }

[tool.poetry.group.dev.dependencies]
requests = ">=2.31,<2.32"
"""


def test_poetry_tables_are_read_and_edited_in_place() -> None:
    assert not allows(POETRY_PYPROJECT, "requests", "2.32.4")
    assert allows(POETRY_PYPROJECT, "local", "9.9")  # path entries carry no version
    assert allows(POETRY_PYPROJECT, "python", "2.0")  # python is not a package
    text, changes = raise_to(POETRY_PYPROJECT, "requests", "2.32.4")
    assert changes == [
        ('requests = "2.31.0"', 'requests = "2.32.4"'),
        ('requests = ">=2.31,<2.32"', 'requests = "<2.33,>=2.32.4"'),
    ]
    assert "# pinned on purpose" in text
    text, changes = raise_to(text, "rich", "14.1.0")
    assert changes == [('rich = "^13.0"', 'rich = "^14.1.0"')]
    assert 'extras = ["jupyter"]' in text and allows(text, "rich", "14.1.0")
