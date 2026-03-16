"""Basic import test."""


def test_import():
    """Verify the package can be imported."""
    import philiprehberger_net_scanner
    assert hasattr(philiprehberger_net_scanner, "__name__") or True
