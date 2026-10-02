"""Run against a real APK. Skipped unless APK_SENTINEL_SAMPLE_APK is set (see conftest.py)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from apk_sentinel.cli import app
from apk_sentinel.loader import ApkLoadError, load_apk
from apk_sentinel.scanner import scan_apk

pytestmark = pytest.mark.integration


def test_loader_decodes_a_real_apk(sample_apk: Path) -> None:
    apk = load_apk(sample_apk)
    assert apk.manifest.package
    assert len(apk.sha256) == 64
    assert apk.dex_strings


def test_full_scan_has_no_analyzer_errors(sample_apk: Path) -> None:
    result = scan_apk(sample_apk)
    assert result.errors == []
    assert result.target.package


def test_cli_scan_runs(sample_apk: Path) -> None:
    result = CliRunner().invoke(app, ["scan", str(sample_apk)])
    assert result.exit_code == 0, result.output


def test_non_apk_is_rejected_cleanly(tmp_path: Path) -> None:
    bogus = tmp_path / "fake.apk"
    bogus.write_text("this is not a zip")
    with pytest.raises(ApkLoadError):
        load_apk(bogus)


FIXTURE_PACKAGE = "com.example.vulnapp"

# Every rule id the intentionally vulnerable fixture app (tests/fixture_app) must trigger.
EXPECTED_FIXTURE_RULES = {
    "MANIFEST-001", "MANIFEST-002", "MANIFEST-003", "MANIFEST-004", "MANIFEST-005",
    "MANIFEST-006", "MANIFEST-007",
    "SECRET-AWS-ACCESS-KEY", "SECRET-PRIVATE-KEY", "SECRET-GOOGLE-API-KEY", "SECRET-JWT",
    "SECRET-GITHUB-TOKEN",
    "CRYPTO-001", "CRYPTO-002", "CRYPTO-003", "CRYPTO-004", "CRYPTO-005", "CRYPTO-006",
    "NETWORK-001", "NETWORK-002", "NETWORK-003", "NETWORK-004", "NETWORK-005", "NETWORK-007",
}  # fmt: skip


def test_fixture_app_triggers_every_rule_family(sample_apk: Path) -> None:
    """Only meaningful for the fixture: build it with scripts/build_fixture_apk.py."""
    result = scan_apk(sample_apk)
    if result.target.package != FIXTURE_PACKAGE:
        pytest.skip("sample APK is not the bundled fixture app")
    found = {f.rule_id for f in result.findings}
    assert found >= EXPECTED_FIXTURE_RULES, sorted(EXPECTED_FIXTURE_RULES - found)
    assert result.errors == []
