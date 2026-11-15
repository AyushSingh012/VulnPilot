from collections.abc import Sequence

import pytest

from vulnpilot import doctor
from vulnpilot.proc import ProcResult, Runner, ToolNotFoundError

GOOD = {
    "osv-scanner": "osv-scanner version: 2.2.3\ncommit: abc\n",
    "uv": "uv 0.11.6 (Homebrew 2026-04-09 aarch64-apple-darwin)\n",
    "poetry": "Poetry (version 2.2.1)\n",
    "git": "git version 2.50.1\n",
    "gh": "gh version 2.97.0 (2026-07-31)\n",
}


def fake_runner(
    versions: dict[str, str],
    *,
    missing: frozenset[str] = frozenset(),
    gh_logged_in: bool = True,
) -> Runner:
    def run(cmd: Sequence[str]) -> ProcResult:
        tool = cmd[0]
        if tool in missing:
            raise ToolNotFoundError(tool)
        if list(cmd) == ["gh", "auth", "status"]:
            return ProcResult(0 if gh_logged_in else 1, "", "secret-looking output")
        return ProcResult(0, versions[tool], "")

    return run


def by_name(results: list[doctor.CheckResult]) -> dict[str, doctor.CheckResult]:
    return {r.name: r for r in results}


def test_all_good() -> None:
    results = doctor.run_checks(fake_runner(GOOD))
    found = by_name(results)
    assert doctor.all_required_ok(results)
    assert found["osv-scanner"].version == "2.2.3"
    assert found["uv"].version == "0.11.6"
    assert found["gh login"].ok


def test_missing_required_tool_fails() -> None:
    results = doctor.run_checks(fake_runner(GOOD, missing=frozenset({"osv-scanner"})))
    found = by_name(results)
    assert not found["osv-scanner"].ok
    assert "not found on PATH" in found["osv-scanner"].detail
    assert not doctor.all_required_ok(results)


def test_missing_poetry_is_only_a_warning() -> None:
    results = doctor.run_checks(fake_runner(GOOD, missing=frozenset({"poetry"})))
    assert not by_name(results)["poetry"].ok
    assert doctor.all_required_ok(results)


def test_osv_scanner_v1_is_refused() -> None:
    versions = GOOD | {"osv-scanner": "osv-scanner version: 1.9.2\n"}
    found = by_name(doctor.run_checks(fake_runner(versions)))
    assert not found["osv-scanner"].ok
    assert "2.x is required" in found["osv-scanner"].detail


def test_gh_not_logged_in_and_output_never_surfaces() -> None:
    results = doctor.run_checks(fake_runner(GOOD, gh_logged_in=False))
    login = by_name(results)["gh login"]
    assert not login.ok
    assert "gh auth login" in login.detail
    assert all("secret" not in r.detail for r in results)


def test_login_not_checked_when_gh_missing() -> None:
    names = [r.name for r in doctor.run_checks(fake_runner(GOOD, missing=frozenset({"gh"})))]
    assert "gh login" not in names


@pytest.mark.parametrize(
    ("text", "expected"),
    [("uv 0.11.6 (x)", "0.11.6"), ("Poetry (version 2.2.1)", "2.2.1"), ("nothing", None)],
)
def test_parse_version(text: str, expected: str | None) -> None:
    assert doctor.parse_version(text) == expected
