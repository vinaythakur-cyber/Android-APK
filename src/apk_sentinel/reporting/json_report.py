"""Machine-readable report. Stable schema: see ``ScanResult.to_dict``."""

from __future__ import annotations

import json
from pathlib import Path

from apk_sentinel.models import ScanResult


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n"


def write_json(result: ScanResult, path: Path) -> Path:
    path.write_text(to_json(result), encoding="utf-8")
    return path
