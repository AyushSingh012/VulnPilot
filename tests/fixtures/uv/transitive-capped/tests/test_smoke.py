import capped_parent
import jinja2


def test_imports() -> None:
    assert capped_parent.__name__ == "capped_parent"
    assert jinja2.__name__ == "jinja2"
