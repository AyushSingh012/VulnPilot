import jinja2
import requests


def test_imports() -> None:
    assert requests.__name__ == "requests"
    assert jinja2.Template("hi {{ x }}").render(x=1) == "hi 1"
