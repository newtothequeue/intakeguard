"""__version__ comes from the installed package metadata."""

import importlib.metadata

import intakeguard


def test_version_matches_package_metadata():
    assert intakeguard.__version__ == importlib.metadata.version("intakeguard")
    assert "__version__" in intakeguard.__all__
