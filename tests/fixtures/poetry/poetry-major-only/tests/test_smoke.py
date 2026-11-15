import urllib3


def test_imports() -> None:
    assert urllib3.__version__.startswith("1.")
