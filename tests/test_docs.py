"""Guards against documentation drift."""

import re
from pathlib import Path

from apk_sentinel.analyzers.secrets import load_rules

ROOT = Path(__file__).resolve().parent.parent
RULE_ID = re.compile(r'rule_id="([A-Z]+-\d+)"')


def _code_rule_ids() -> set[str]:
    ids: set[str] = set()
    for path in (ROOT / "src" / "apk_sentinel" / "analyzers").glob("*.py"):
        ids.update(RULE_ID.findall(path.read_text(encoding="utf-8")))
    ids.update(rule.id for rule in load_rules())
    return ids


def test_every_rule_id_is_documented() -> None:
    documented = (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8")
    missing = sorted(rule for rule in _code_rule_ids() if f"`{rule}`" not in documented)
    assert not missing, f"add these rule ids to docs/RULES.md: {missing}"


def test_rule_discovery_actually_finds_rules() -> None:
    ids = _code_rule_ids()
    assert "MANIFEST-001" in ids
    assert "NETWORK-008" in ids
    assert "SECRET-JWT" in ids
    assert len(ids) >= 30


def test_no_apk_or_archive_is_tracked_by_gitignore_rules() -> None:
    patterns = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    for required in ("*.apk", "*.zip", "samples/"):
        assert required in patterns
