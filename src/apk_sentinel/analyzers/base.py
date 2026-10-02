"""The analyzer interface every check implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from apk_sentinel.apk_model import LoadedApk
from apk_sentinel.models import Finding


class Analyzer(ABC):
    """A self-contained group of related checks.

    Contract:
      * ``analyze`` is a pure function of ``apk``: no I/O, no global state.
      * It returns zero or more findings and never raises for "normal" bad input
        (the scanner still isolates crashes, but a crash is a bug in the analyzer).
    """

    #: Short stable identifier, used in reports and as ``Finding.analyzer``.
    name: ClassVar[str]

    @abstractmethod
    def analyze(self, apk: LoadedApk) -> list[Finding]:
        """Inspect ``apk`` and return findings."""
