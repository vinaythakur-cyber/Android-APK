"""Report writers: JSON (machines/CI) and HTML (humans)."""

from __future__ import annotations

from pathlib import Path

from apk_sentinel.models import ScanResult
from apk_sentinel.reporting.html_report import write_html
from apk_sentinel.reporting.json_report import write_json

FORMATS = ("json", "html")


def write_reports(
    result: ScanResult, out_dir: Path, formats: tuple[str, ...] = FORMATS
) -> list[Path]:
    """Write ``report.<fmt>`` for each requested format into ``out_dir``; return the paths."""
    unknown = sorted(set(formats) - set(FORMATS))
    if unknown:
        raise ValueError(f"unknown report format(s): {', '.join(unknown)}; choose from {FORMATS}")
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        written.append(write_json(result, out_dir / "report.json"))
    if "html" in formats:
        written.append(write_html(result, out_dir / "report.html"))
    return written


__all__ = ["FORMATS", "write_reports"]
