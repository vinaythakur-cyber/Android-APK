"""Human-readable, self-contained HTML report rendered with Jinja2.

Python prepares plain data (this module); the template only decides how it looks. The page has
no external requests (no CDN, fonts or trackers), so it can be opened offline or attached to a
submission as a single file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from apk_sentinel import masvs
from apk_sentinel.models import Finding, ScanResult, Severity

TEMPLATE_NAME = "report.html.j2"


@dataclass(frozen=True, slots=True)
class MasvsRow:
    control_id: str
    statement: str
    count: int
    worst: Severity


def _environment() -> Environment:
    return Environment(
        loader=PackageLoader("apk_sentinel.reporting", "templates"),
        # NOT select_autoescape(): it keys off the final extension (".j2") and would leave
        # escaping off. Evidence strings come from the scanned (possibly hostile) APK.
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _finding_view(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "analyzer": finding.analyzer,
        "description": finding.description,
        "evidence": finding.evidence,
        "location": finding.location,
        "recommendation": finding.recommendation,
        "masvs": [(cid, masvs.describe(cid)) for cid in finding.masvs],
        "search": " ".join(
            (finding.title, finding.rule_id, finding.location, finding.evidence, finding.analyzer)
        ).lower(),
    }


def _masvs_rows(findings: list[Finding]) -> list[MasvsRow]:
    worst: dict[str, Severity] = {}
    count: dict[str, int] = {}
    for finding in findings:
        for control in finding.masvs:
            count[control] = count.get(control, 0) + 1
            worst[control] = max(worst.get(control, Severity.INFO), finding.severity)
    return [
        MasvsRow(control, masvs.describe(control), count[control], worst[control])
        for control in sorted(count)
    ]


def build_context(result: ScanResult) -> dict[str, Any]:
    total = len(result.findings)
    counts = result.counts_by_severity()
    return {
        "result": result,
        "target": result.target,
        "scanned_at": result.scanned_at.strftime("%Y-%m-%d %H:%M UTC"),
        "findings": [_finding_view(f) for f in result.sorted_findings()],
        "total": total,
        "severities": [
            {
                "name": name,
                "count": n,
                "percent": round(100 * n / total, 2) if total else 0,
            }
            for name, n in counts.items()
        ],
        "masvs_rows": _masvs_rows(result.findings),
    }


def render_html(result: ScanResult) -> str:
    template = _environment().get_template(TEMPLATE_NAME)
    return template.render(**build_context(result))


def write_html(result: ScanResult, path: Path) -> Path:
    path.write_text(render_html(result), encoding="utf-8")
    return path
