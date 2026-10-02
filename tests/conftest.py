"""Shared pytest configuration."""

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def sample_apk() -> Path:
    """A real APK for integration tests. Provide one via APK_SENTINEL_SAMPLE_APK.

    The repository never contains APKs, so these tests are skipped unless you point the
    variable at a local file (e.g. DIVA, InsecureBankv2, or the bundled fixture-app build).
    """
    value = os.environ.get("APK_SENTINEL_SAMPLE_APK")
    if not value or not Path(value).is_file():
        pytest.skip("set APK_SENTINEL_SAMPLE_APK to a local .apk to run integration tests")
    return Path(value)
