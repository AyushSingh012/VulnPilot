def test_already_broken() -> None:
    assert 1 == 2, "this test fails on the base branch, before any upgrade"
