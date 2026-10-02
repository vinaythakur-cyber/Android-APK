import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import apk_sentinel.cli as cli_module
from apk_sentinel.cli import app
from apk_sentinel.models import AnalyzerError, Confidence, Finding, ScanResult, Severity, TargetInfo
from apk_sentinel.reporting import write_reports
from apk_sentinel.reporting.html_report import render_html
from apk_sentinel.reporting.json_report import to_json

XSS = '<script>alert("pwned")</script>'


def make_result(*findings: Finding, errors: list[AnalyzerError] | None = None) -> ScanResult:
    return ScanResult(
        target=TargetInfo(
            file_name="app.apk",
            sha256="ab" * 32,
            size_bytes=12345,
            package="com.example.app",
            version_name="2.0",
            min_sdk=21,
            target_sdk=33,
        ),
        findings=list(findings),
        errors=errors or [],
        analyzers_run=["manifest"],
        tool_version="0.1.0",
    )


def finding(severity: Severity = Severity.HIGH, **kwargs: object) -> Finding:
    base: dict[str, object] = {
        "rule_id": "T-1",
        "title": "A finding",
        "severity": severity,
        "description": "desc",
        "analyzer": "manifest",
        "masvs": ("MASVS-NETWORK-1",),
        "evidence": "evidence text",
        "location": "somewhere",
        "recommendation": "do better",
    }
    base.update(kwargs)
    return Finding(**base)  # type: ignore[arg-type]


def test_json_report_round_trips() -> None:
    result = make_result(finding(Severity.LOW), finding(Severity.CRITICAL, rule_id="T-2"))
    data = json.loads(to_json(result))
    assert data["target"]["package"] == "com.example.app"
    assert data["summary"]["by_severity"]["critical"] == 1
    assert [f["rule_id"] for f in data["findings"]] == ["T-2", "T-1"]  # most severe first
    assert data["findings"][0]["masvs"] == ["MASVS-NETWORK-1"]


def test_html_report_contains_key_facts() -> None:
    html = render_html(make_result(finding(), finding(Severity.LOW, rule_id="T-2")))
    assert "com.example.app" in html
    assert "ab" * 32 in html
    assert "MASVS-NETWORK-1" in html
    assert "secures all network traffic" in html  # control statement from the catalogue
    assert 'data-sev="high"' in html
    assert "permission to test" in html


def test_html_report_escapes_hostile_apk_strings() -> None:
    html = render_html(make_result(finding(evidence=XSS, title=XSS, location=XSS)))
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_html_report_is_self_contained() -> None:
    html = render_html(make_result(finding()))
    assert "http://" not in html.replace("http://schemas", "")
    assert "https://" not in html
    assert "<link " not in html


def test_html_report_without_findings() -> None:
    html = render_html(make_result())
    assert "No findings" in html
    assert 'id="q"' not in html  # no filter toolbar when there is nothing to filter


def test_html_report_shows_analyzer_errors() -> None:
    html = render_html(make_result(errors=[AnalyzerError("crypto", "ValueError: boom")]))
    assert "analyzer(s) failed" in html
    assert "ValueError: boom" in html


def test_confidence_is_rendered() -> None:
    html = render_html(make_result(finding(confidence=Confidence.LOW)))
    assert "confidence: low" in html


def test_write_reports_creates_requested_files(tmp_path: Path) -> None:
    paths = write_reports(make_result(finding()), tmp_path / "nested" / "out")
    assert [p.name for p in paths] == ["report.json", "report.html"]
    assert all(p.is_file() for p in paths)
    only_json = write_reports(make_result(finding()), tmp_path / "j", ("json",))
    assert [p.name for p in only_json] == ["report.json"]


def test_write_reports_rejects_unknown_format(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="unknown report format"):
        write_reports(make_result(), tmp_path, ("pdf",))


@pytest.fixture
def fake_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_module, "scan_apk", lambda *a, **k: make_result(finding()))


def test_cli_scan_writes_reports_and_applies_fail_on(tmp_path: Path, fake_scan: None) -> None:
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    out = tmp_path / "rep"
    runner = CliRunner()
    ok = runner.invoke(app, ["scan", str(apk), "--out", str(out)])
    assert ok.exit_code == 0, ok.output
    assert (out / "report.json").is_file()
    assert (out / "report.html").is_file()
    failing = runner.invoke(app, ["scan", str(apk), "--out", str(out), "--fail-on", "high"])
    assert failing.exit_code == 1
    passing = runner.invoke(app, ["scan", str(apk), "--out", str(out), "--fail-on", "critical"])
    assert passing.exit_code == 0


def test_cli_format_option(tmp_path: Path, fake_scan: None) -> None:
    apk = tmp_path / "a.apk"
    apk.write_bytes(b"x")
    out = tmp_path / "rep"
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(apk), "-o", str(out), "-f", "json"])
    assert result.exit_code == 0
    assert (out / "report.json").is_file()
    assert not (out / "report.html").exists()
    bad = runner.invoke(app, ["scan", str(apk), "-o", str(out), "-f", "pdf"])
    assert bad.exit_code != 0
