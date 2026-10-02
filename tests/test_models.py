import pytest

from apk_sentinel.models import Finding, ScanResult, Severity, TargetInfo


def _target() -> TargetInfo:
    return TargetInfo(file_name="a.apk", sha256="0" * 64, size_bytes=1, package="com.example")


def _finding(sev: Severity, rule: str = "X-1", loc: str = "") -> Finding:
    return Finding(
        rule_id=rule, title="t", severity=sev, description="d", analyzer="a", location=loc
    )


def test_severity_is_ordered() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.HIGH >= Severity.HIGH
    assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


def test_severity_parse_is_case_insensitive_and_validates() -> None:
    assert Severity.parse(" HIGH ") is Severity.HIGH
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("catastrophic")


def test_scan_result_sorts_most_severe_first() -> None:
    result = ScanResult(
        target=_target(),
        findings=[_finding(Severity.LOW), _finding(Severity.CRITICAL), _finding(Severity.HIGH)],
    )
    assert [f.severity for f in result.sorted_findings()] == [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.LOW,
    ]


def test_counts_and_threshold() -> None:
    result = ScanResult(target=_target(), findings=[_finding(Severity.MEDIUM)])
    assert result.counts_by_severity()["medium"] == 1
    assert result.counts_by_severity()["critical"] == 0
    assert result.exceeds(Severity.MEDIUM)
    assert not result.exceeds(Severity.HIGH)
    assert not ScanResult(target=_target()).exceeds(Severity.INFO)


def test_to_dict_is_json_ready() -> None:
    import json

    result = ScanResult(target=_target(), findings=[_finding(Severity.HIGH)], tool_version="9.9")
    data = json.loads(json.dumps(result.to_dict()))
    assert data["summary"]["total"] == 1
    assert data["findings"][0]["severity"] == "high"
    assert data["tool"]["version"] == "9.9"
