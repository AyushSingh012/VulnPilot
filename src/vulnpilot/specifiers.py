"""Read and minimally edit dependency specifiers in pyproject.toml.

Covers PEP 621 (``[project]``), PEP 735 dependency groups, and Poetry's own tables
(``[tool.poetry.dependencies]``, ``[tool.poetry.group.<name>.dependencies]``).

Edits use tomlkit so comments and formatting survive. Only the requirement strings for
the package being fixed are touched.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import tomlkit
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from tomlkit.items import Array

from vulnpilot.models import normalize_package
from vulnpilot.versions import bump_at, parse


class SpecifierEditError(Exception):
    """The requirement can't be changed to allow the fix without a bigger change."""


def _arrays(doc: Any) -> Iterator[Array]:
    project = doc.get("project", {})
    if isinstance(project.get("dependencies"), Array):
        yield project["dependencies"]
    for arr in (project.get("optional-dependencies") or {}).values():
        if isinstance(arr, Array):
            yield arr
    for arr in (doc.get("dependency-groups") or {}).values():
        if isinstance(arr, Array):
            yield arr


def _matching(doc: Any, package: str) -> Iterator[tuple[Array, int, Requirement]]:
    name = normalize_package(package)
    for arr in _arrays(doc):
        for i, item in enumerate(arr):
            if not isinstance(item, str):
                continue  # e.g. {include-group = "..."}
            try:
                req = Requirement(str(item))
            except InvalidRequirement:
                continue
            if normalize_package(req.name) == name:
                yield arr, i, req


def requirement_strings(pyproject_text: str, package: str) -> list[str]:
    doc = tomlkit.parse(pyproject_text)
    out = [str(req) for _, _, req in _matching(doc, package)]
    for table, key in _poetry_entries(doc, package):
        constraint = _poetry_constraint(table[key])
        if constraint is not None:
            out.append(f'{key} = "{constraint}"')
    return out


def allows(pyproject_text: str, package: str, version: str) -> bool:
    """Do all requirements on ``package`` in pyproject.toml allow ``version``?"""
    doc = tomlkit.parse(pyproject_text)
    v = Version(version)
    if not all(
        req.specifier.contains(v, prereleases=True) for _, _, req in _matching(doc, package)
    ):
        return False
    for table, key in _poetry_entries(doc, package):
        try:
            constraint = _poetry_constraint(table[key])
        except SpecifierEditError:
            return False
        if constraint is not None and not poetry_allows(constraint, version):
            return False
    return True


def _components(text: str) -> int:
    return len(text.rstrip(".*").split("."))


def adjust_specifier(spec: SpecifierSet, target: str) -> SpecifierSet:
    """Smallest change to ``spec`` so it allows ``target`` (and nothing below it)."""
    t = Version(target)
    out: list[str] = []
    for s in spec:
        op, ver = s.operator, s.version
        if s.contains(t, prereleases=True):
            if op in (">=", ">") and (pv := parse(ver)) is not None and pv < t:
                out.append(f">={target}")  # raise the floor so a later lock can't go back
            else:
                out.append(str(s))
            continue
        if op in ("==", "==="):
            if ver.endswith(".*"):
                n = _components(ver)
                out.append("==" + ".".join(str(p) for p in t.release[:n]) + ".*")
                out.append(f">={target}")
            else:
                out.append(f"=={target}")
        elif op == "~=":
            n = _components(ver)
            if n >= 3:
                out.append(f"~={target}")
            else:
                out.append("~=" + ".".join(str(p) for p in t.release[:n]))
                out.append(f">={target}")
        elif op in ("<", "<="):
            out.append("<" + bump_at(target, _components(ver)))
        elif op == "!=":
            raise SpecifierEditError(f"the fixed version {target} is excluded with !=")
        elif op in (">=", ">"):
            out.append(f">={target}")
        else:  # pragma: no cover - packaging knows no other operators
            raise SpecifierEditError(f"unsupported specifier {s}")
    new = SpecifierSet(",".join(dict.fromkeys(out)))
    if not new.contains(t, prereleases=True):
        raise SpecifierEditError(f"could not rewrite '{spec}' to allow {target}")
    return new


def _format(req: Requirement, spec: SpecifierSet) -> str:
    extras = f"[{','.join(sorted(req.extras))}]" if req.extras else ""
    specs = ",".join(sorted(str(s) for s in spec))
    marker = f"; {req.marker}" if req.marker else ""
    return f"{req.name}{extras}{specs}{marker}"


def raise_to(pyproject_text: str, package: str, target: str) -> tuple[str, list[tuple[str, str]]]:
    """Rewrite every requirement on ``package`` that blocks ``target``.

    Returns the new file text and a list of (old, new) requirement strings.
    """
    doc = tomlkit.parse(pyproject_text)
    t = Version(target)
    changes: list[tuple[str, str]] = []
    for arr, i, req in list(_matching(doc, package)):
        if req.specifier.contains(t, prereleases=True):
            continue
        new = _format(req, adjust_specifier(req.specifier, target))
        changes.append((str(arr[i]), new))
        arr[i] = new
    for table, key in list(_poetry_entries(doc, package)):
        value = table[key]
        constraint = _poetry_constraint(value)
        if constraint is None or poetry_allows(constraint, target):
            continue
        new_constraint = raise_poetry(constraint, target)
        if isinstance(value, str):
            table[key] = new_constraint
        else:
            value["version"] = new_constraint
        changes.append((f'{key} = "{constraint}"', f'{key} = "{new_constraint}"'))
    return tomlkit.dumps(doc), changes


# --- Poetry-style constraints: [tool.poetry.dependencies] and [tool.poetry.group.*] -----

_POETRY_TOKEN = re.compile(r"(\^|~=|~|==|!=|>=|<=|>|<|=)?\s*(\*|[0-9][0-9A-Za-z.*+!-]*)")


def _caret_upper(v: Version, given: int) -> str:
    parts = list(v.release[:given]) or [0]
    for i, p in enumerate(parts):
        if p != 0:
            return ".".join(str(x) for x in [*parts[:i], p + 1])
    bumped = [*parts[:-1], parts[-1] + 1]
    return ".".join(str(x) for x in bumped)


def poetry_specifier(constraint: str) -> SpecifierSet:
    """One Poetry constraint (no ``||``) as a PEP 440 specifier set.

    ``^1.2.3`` -> ``>=1.2.3,<2``; ``~1.2.3`` -> ``>=1.2.3,<1.3``; ``1.2.3`` -> ``==1.2.3``.
    """
    specs: list[str] = []
    for op, ver in _POETRY_TOKEN.findall(constraint.replace(",", " ")):
        if ver == "*":
            continue
        v = Version(ver.rstrip(".*")) if ver.rstrip(".*") else None
        given = _components(ver)
        if op == "^" and v is not None:
            specs += [f">={ver}", f"<{_caret_upper(v, given)}"]
        elif op == "~" and v is not None:
            upper = v.release[0] + 1 if given == 1 else None
            if upper is not None:
                specs += [f">={ver}", f"<{upper}"]
            else:
                specs += [f">={ver}", f"<{v.release[0]}.{v.release[1] + 1}"]
        elif op in ("", "="):
            specs.append(f"=={ver}")
        else:
            specs.append(f"{op}{ver}")
    return SpecifierSet(",".join(specs))


def poetry_allows(constraint: str, version: str) -> bool:
    v = Version(version)
    return any(
        poetry_specifier(alt).contains(v, prereleases=True) for alt in constraint.split("||")
    )


def raise_poetry(constraint: str, target: str) -> str:
    """Smallest Poetry-style rewrite of ``constraint`` that allows ``target``, same style."""
    c = constraint.strip()
    if "||" in c:
        raise SpecifierEditError(f"cannot safely rewrite the Poetry constraint '{c}'")
    if c.startswith("^") and "," not in c:
        return f"^{target}"
    if c.startswith("~") and not c.startswith("~=") and "," not in c:
        return f"~{target}" if _components(c[1:]) > 1 else f"~{Version(target).major}"
    if re.fullmatch(r"=?=?\s*[0-9][0-9A-Za-z.+!-]*", c):
        return target
    new = adjust_specifier(poetry_specifier(c), target)
    return ",".join(sorted(str(s) for s in new))


def _poetry_tables(doc: Any) -> Iterator[Any]:
    poetry = (doc.get("tool") or {}).get("poetry") or {}
    if "dependencies" in poetry:
        yield poetry["dependencies"]
    for group in (poetry.get("group") or {}).values():
        if "dependencies" in group:
            yield group["dependencies"]


def _poetry_entries(doc: Any, package: str) -> Iterator[tuple[Any, str]]:
    """(table, key) for every Poetry dependency entry on ``package`` (not ``python``)."""
    name = normalize_package(package)
    for table in _poetry_tables(doc):
        for key in list(table.keys()):
            if key != "python" and normalize_package(key) == name:
                yield table, key


def _poetry_constraint(value: Any) -> str | None:
    """The version constraint of an entry; None for path / git / url entries."""
    if isinstance(value, str):
        return value
    if hasattr(value, "get") and not isinstance(value, list):
        version = value.get("version")
        return str(version) if version is not None else None
    raise SpecifierEditError("multiple-constraint Poetry entries are not supported")
