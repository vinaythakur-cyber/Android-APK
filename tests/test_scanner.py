from typing import ClassVar

from apk_sentinel.analyzers.base import Analyzer
from apk_sentinel.apk_model import LoadedApk
from apk_sentinel.models import Finding, Severity
from apk_sentinel.scanner import analyze
from tests.factories import make_apk


class _Good(Analyzer):
    name: ClassVar[str] = "good"

    def analyze(self, apk: LoadedApk) -> list[Finding]:
        return [Finding("G-1", "ok", Severity.LOW, "d", self.name)]


class _Boom(Analyzer):
    name: ClassVar[str] = "boom"

    def analyze(self, apk: LoadedApk) -> list[Finding]:
        raise RuntimeError("kaput")


def test_crashing_analyzer_is_isolated_and_reported() -> None:
    result = analyze(make_apk(), [_Boom(), _Good()])
    assert [f.rule_id for f in result.findings] == ["G-1"]
    assert result.analyzers_run == ["good"]
    assert result.errors[0].analyzer == "boom"
    assert "RuntimeError: kaput" in result.errors[0].message


def test_target_info_is_populated() -> None:
    result = analyze(make_apk(), [_Good()])
    assert result.target.package == "com.example.app"
    assert result.target.sha256 == "0" * 64
