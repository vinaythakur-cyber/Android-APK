"""Output-side domain model: what a scan produces.

This module imports nothing from the rest of the package, so every other module can depend
on it without creating cycles. Reporters, analyzers and the CLI all speak in these types.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """How bad a finding is. Ordered: INFO < LOW < MEDIUM < HIGH < CRITICAL."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r}; choose one of: {valid}") from None

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class Confidence(StrEnum):
    """How sure the analyzer is. Heuristic checks (e.g. static IV) report MEDIUM/LOW."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True, slots=True)
class Finding:
    """One security observation about the scanned app."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    analyzer: str
    masvs: tuple[str, ...] = ()
    evidence: str = ""
    location: str = ""
    recommendation: str = ""
    confidence: Confidence = Confidence.HIGH

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "analyzer": self.analyzer,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "recommendation": self.recommendation,
            "masvs": list(self.masvs),
        }


@dataclass(frozen=True, slots=True)
class TargetInfo:
    """Identity of the scanned APK."""

    file_name: str
    sha256: str
    size_bytes: int
    package: str
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_name": self.file_name,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "package": self.package,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
        }


@dataclass(frozen=True, slots=True)
class AnalyzerError:
    """An analyzer crashed. The scan continues; the failure is recorded, never hidden."""

    analyzer: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"analyzer": self.analyzer, "message": self.message}


@dataclass(slots=True)
class ScanResult:
    """Everything a reporter needs."""

    target: TargetInfo
    findings: list[Finding] = field(default_factory=list)
    errors: list[AnalyzerError] = field(default_factory=list)
    analyzers_run: list[str] = field(default_factory=list)
    tool_version: str = ""
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    duration_seconds: float = 0.0

    def sorted_findings(self) -> list[Finding]:
        """Most severe first; stable within a severity (analyzer, then rule id, then location)."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, f.analyzer, f.rule_id, f.location),
        )

    def counts_by_severity(self) -> dict[str, int]:
        counter = Counter(f.severity for f in self.findings)
        return {s.value: counter.get(s, 0) for s in reversed(list(Severity))}

    def highest_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def exceeds(self, threshold: Severity) -> bool:
        """True if any finding is at or above ``threshold`` (used for ``--fail-on``)."""
        highest = self.highest_severity()
        return highest is not None and highest >= threshold

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "apk-sentinel", "version": self.tool_version},
            "scanned_at": self.scanned_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 3),
            "target": self.target.to_dict(),
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts_by_severity(),
            },
            "analyzers_run": list(self.analyzers_run),
            "errors": [e.to_dict() for e in self.errors],
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
