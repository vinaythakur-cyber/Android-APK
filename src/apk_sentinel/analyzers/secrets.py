"""Hardcoded-secret detection driven by ``rules/secrets.yaml``.

Why this works: the DEX string pool contains every string literal in the app's code, and
``resources.arsc`` holds string resources. Compiled code keeps these in plain text, so a regex
over them finds embedded keys without running the app.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, ClassVar

import yaml

from apk_sentinel.analyzers.base import Analyzer
from apk_sentinel.apk_model import LoadedApk
from apk_sentinel.models import Confidence, Finding, Severity

MAX_MATCHES_PER_RULE = 25
MAX_STRING_LENGTH = 100_000  # skip absurdly long blobs (embedded assets) for speed


class RuleError(ValueError):
    """A secrets rule file is malformed."""


@dataclass(frozen=True, slots=True)
class SecretRule:
    id: str
    name: str
    regex: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    masvs: tuple[str, ...]
    description: str
    recommendation: str
    redact: bool = True


def _parse_rule(raw: dict[str, Any], index: int) -> SecretRule:
    where = f"rule #{index + 1}"
    try:
        rule_id = str(raw["id"])
        where = f"rule {rule_id}"
        return SecretRule(
            id=rule_id,
            name=str(raw["name"]),
            regex=re.compile(str(raw["pattern"])),
            severity=Severity.parse(str(raw["severity"])),
            confidence=Confidence(str(raw.get("confidence", "high")).lower()),
            masvs=tuple(raw.get("masvs", ())),
            description=" ".join(str(raw.get("description", "")).split()),
            recommendation=" ".join(str(raw.get("recommendation", "")).split()),
            redact=bool(raw.get("redact", True)),
        )
    except KeyError as exc:
        raise RuleError(f"{where}: missing required field {exc}") from exc
    except (re.error, ValueError) as exc:
        raise RuleError(f"{where}: {exc}") from exc


def load_rules(path: Path | None = None) -> list[SecretRule]:
    """Load rules from ``path`` or from the packaged ``rules/secrets.yaml``."""
    if path is None:
        text = resources.files("apk_sentinel").joinpath("rules/secrets.yaml").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"invalid YAML: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise RuleError("rule file must be a mapping with a top-level 'rules:' list")
    rules = [_parse_rule(raw, i) for i, raw in enumerate(document["rules"])]
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        raise RuleError("duplicate rule ids in rule file")
    return rules


def redact(value: str) -> str:
    """Mask a secret for display: keep a short prefix/suffix so you can recognise it."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(len(value) - 6, 12)}{value[-2:]} ({len(value)} chars)"


class SecretsAnalyzer(Analyzer):
    name: ClassVar[str] = "secrets"

    def __init__(self, rules: Sequence[SecretRule] | None = None) -> None:
        self.rules: list[SecretRule] = list(rules) if rules is not None else load_rules()

    def _sources(self, apk: LoadedApk) -> Iterator[tuple[str, str]]:
        for value in apk.dex_strings:
            yield "classes.dex string pool", value
        for key, value in apk.resource_strings.items():
            yield f"resources.arsc string/{key}", value

    def analyze(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        suppressed: dict[str, int] = {}
        counts: dict[str, int] = {}

        for location, text in self._sources(apk):
            if len(text) > MAX_STRING_LENGTH:
                continue
            for rule in self.rules:
                match = rule.regex.search(text)
                if match is None:
                    continue
                key = (rule.id, match.group(0))
                if key in seen:
                    continue
                seen.add(key)
                if counts.get(rule.id, 0) >= MAX_MATCHES_PER_RULE:
                    suppressed[rule.id] = suppressed.get(rule.id, 0) + 1
                    continue
                counts[rule.id] = counts.get(rule.id, 0) + 1
                shown = redact(match.group(0)) if rule.redact else match.group(0)
                findings.append(
                    Finding(
                        rule_id=rule.id,
                        title=f"Hardcoded secret: {rule.name}",
                        severity=rule.severity,
                        analyzer=self.name,
                        description=rule.description,
                        evidence=shown,
                        location=location,
                        recommendation=rule.recommendation,
                        confidence=rule.confidence,
                        masvs=rule.masvs,
                    )
                )

        by_id = {r.id: r for r in self.rules}
        for rule_id, extra in suppressed.items():
            rule = by_id[rule_id]
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=f"{rule.name}: {extra} more match(es) not listed",
                    severity=Severity.INFO,
                    analyzer=self.name,
                    description=f"Output capped at {MAX_MATCHES_PER_RULE} matches per rule.",
                    masvs=rule.masvs,
                )
            )
        return findings
