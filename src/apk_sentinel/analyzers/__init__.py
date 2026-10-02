"""Security checks. Each module exposes one :class:`Analyzer` subclass."""

from __future__ import annotations

from pathlib import Path

from apk_sentinel.analyzers.base import Analyzer
from apk_sentinel.analyzers.crypto import CryptoAnalyzer
from apk_sentinel.analyzers.manifest import ManifestAnalyzer
from apk_sentinel.analyzers.network import NetworkAnalyzer
from apk_sentinel.analyzers.secrets import SecretsAnalyzer, load_rules


def default_analyzers(secret_rules_path: Path | None = None) -> list[Analyzer]:
    """The analyzers that run on every scan, in report order."""
    return [
        ManifestAnalyzer(),
        SecretsAnalyzer(load_rules(secret_rules_path)),
        CryptoAnalyzer(),
        NetworkAnalyzer(),
    ]


__all__ = ["Analyzer", "default_analyzers"]
