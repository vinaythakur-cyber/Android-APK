"""Orchestration: load an APK, run every analyzer, collect a :class:`ScanResult`.

Each analyzer runs in isolation: if one crashes, the failure is recorded in
``ScanResult.errors`` and the remaining analyzers still run. A security tool that silently
drops results is worse than one that reports "analyzer X failed".
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path

from apk_sentinel import __version__
from apk_sentinel.analyzers import Analyzer, default_analyzers
from apk_sentinel.apk_model import LoadedApk
from apk_sentinel.loader import load_apk
from apk_sentinel.models import AnalyzerError, Finding, ScanResult, TargetInfo


def target_info(apk: LoadedApk) -> TargetInfo:
    manifest = apk.manifest
    return TargetInfo(
        file_name=apk.path.name,
        sha256=apk.sha256,
        size_bytes=apk.size_bytes,
        package=manifest.package,
        version_name=manifest.version_name,
        version_code=manifest.version_code,
        min_sdk=manifest.min_sdk,
        target_sdk=manifest.target_sdk,
    )


def analyze(apk: LoadedApk, analyzers: Sequence[Analyzer] | None = None) -> ScanResult:
    """Run ``analyzers`` (default: all) over an already-loaded APK."""
    started = time.perf_counter()
    selected = default_analyzers() if analyzers is None else list(analyzers)
    findings: list[Finding] = []
    errors: list[AnalyzerError] = []
    ran: list[str] = []
    for analyzer in selected:
        try:
            findings.extend(analyzer.analyze(apk))
            ran.append(analyzer.name)
        except Exception as exc:  # isolate analyzer crashes by design
            errors.append(AnalyzerError(analyzer.name, f"{type(exc).__name__}: {exc}"))
    return ScanResult(
        target=target_info(apk),
        findings=findings,
        errors=errors,
        analyzers_run=ran,
        tool_version=__version__,
        duration_seconds=time.perf_counter() - started,
    )


def scan_apk(
    path: Path,
    analyzers: Sequence[Analyzer] | None = None,
    *,
    include_libraries: bool = False,
) -> ScanResult:
    """Load ``path`` and analyze it."""
    started = time.perf_counter()
    result = analyze(load_apk(path, include_libraries=include_libraries), analyzers)
    result.duration_seconds = time.perf_counter() - started
    return result
