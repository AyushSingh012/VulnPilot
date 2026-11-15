"""Read and minimally edit dependency specifiers in pyproject.toml (PEP 621 / dependency groups).

Edits use tomlkit so comments and formatting survive. Only the requirement strings for
the package being fixed are touched.
"""

from __future__ import annotations

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
    return [str(req) for _, _, req in _matching(doc, package)]


def allows(pyproject_text: str, package: str, version: str) -> bool:
    """Do all requirements on ``package`` in pyproject.toml allow ``version``?"""
    v = Version(version)
    return all(
        req.specifier.contains(v, prereleases=True)
        for _, _, req in _matching(tomlkit.parse(pyproject_text), package)
    )


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
    return tomlkit.dumps(doc), changes
