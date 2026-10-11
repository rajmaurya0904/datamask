"""Smoke test: package imports cleanly. Replace/extend as modules land."""

import datamask


def test_version_is_set() -> None:
    assert datamask.__version__
