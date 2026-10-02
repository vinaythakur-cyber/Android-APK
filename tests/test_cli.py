from pathlib import Path

from typer.testing import CliRunner

from apk_sentinel import __version__
from apk_sentinel.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scan_rejects_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path / "nope.apk")])
    assert result.exit_code != 0


def test_scan_reports_non_apk_with_exit_code_2(tmp_path: Path) -> None:
    bogus = tmp_path / "fake.apk"
    bogus.write_text("not a zip")
    result = runner.invoke(app, ["scan", str(bogus)])
    assert result.exit_code == 2


def test_fail_on_rejects_unknown_severity(tmp_path: Path) -> None:
    bogus = tmp_path / "fake.apk"
    bogus.write_text("x")
    result = runner.invoke(app, ["scan", str(bogus), "--fail-on", "bogus"])
    assert result.exit_code != 0
