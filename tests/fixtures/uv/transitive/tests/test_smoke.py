import requests
import urllib3


def test_imports() -> None:
    assert requests.__name__ == "requests"
    assert urllib3.__name__ == "urllib3"
