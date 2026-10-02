from pathlib import Path

import pytest

from apk_sentinel.analyzers.secrets import (
    MAX_MATCHES_PER_RULE,
    RuleError,
    SecretsAnalyzer,
    load_rules,
    redact,
)
from apk_sentinel.models import Severity
from tests.factories import make_apk

# Secret-shaped literals are assembled at runtime so scanners (e.g. GitHub push protection)
# never see them in source.
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GOOGLE = "AIza" + "x" * 35
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"


def scan(*strings: str, resources: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    apk = make_apk(dex_strings=tuple(strings), resource_strings=resources)
    return SecretsAnalyzer().analyze(apk)


@pytest.mark.parametrize(
    ("text", "rule_id", "severity"),
    [
        (AWS, "SECRET-AWS-ACCESS-KEY", Severity.HIGH),
        ("-----BEGIN RSA PRIVATE KEY-----", "SECRET-PRIVATE-KEY", Severity.CRITICAL),
        ("-----BEGIN PRIVATE KEY-----", "SECRET-PRIVATE-KEY", Severity.CRITICAL),
        (GOOGLE, "SECRET-GOOGLE-API-KEY", Severity.MEDIUM),
        (JWT, "SECRET-JWT", Severity.MEDIUM),
        ("ghp_" + "a" * 36, "SECRET-GITHUB-TOKEN", Severity.HIGH),
        ("xox" + "b-1234567890-abcdefghij", "SECRET-SLACK-TOKEN", Severity.HIGH),
        ("sk_live_" + "A1b2C3d4" * 3, "SECRET-STRIPE-LIVE-KEY", Severity.CRITICAL),
        ("https://admin:hunter2pw@db.example.com/x", "SECRET-URL-CREDENTIALS", Severity.HIGH),
        ("https://myapp-123.firebaseio.com", "SECRET-FIREBASE-DATABASE", Severity.INFO),
        ("password=SuperSecret123", "SECRET-HARDCODED-CREDENTIAL", Severity.LOW),
    ],
)
def test_each_shipped_rule_detects_its_secret(text: str, rule_id: str, severity: Severity) -> None:
    findings = scan(text)
    matched = [f for f in findings if f.rule_id == rule_id]
    assert len(matched) == 1, [f.rule_id for f in findings]
    assert matched[0].severity is severity
    assert matched[0].masvs


@pytest.mark.parametrize(
    "benign",
    [
        "hello world",
        "AKIA_TOO_SHORT",
        "https://example.com/path",
        "AIzaTooShort",
        "password",
        "eyJhbGci.notajwt",
        "Landroid/content/Context;",
    ],
)
def test_benign_strings_are_not_flagged(benign: str) -> None:
    assert scan(benign) == []


def test_secret_is_redacted_in_evidence() -> None:
    (finding,) = scan(GOOGLE)
    assert GOOGLE not in finding.evidence
    assert finding.evidence.startswith("AIza")
    assert "39 chars" in finding.evidence


def test_non_secret_evidence_is_shown_in_full() -> None:
    (finding,) = scan("-----BEGIN RSA PRIVATE KEY-----")
    assert finding.evidence == "-----BEGIN RSA PRIVATE KEY-----"


def test_resource_strings_are_scanned_with_their_name() -> None:
    (finding,) = scan(resources={"google_api_key": GOOGLE})
    assert finding.location == "resources.arsc string/google_api_key"


def test_duplicate_matches_are_reported_once() -> None:
    assert len(scan(AWS, f"x {AWS} y")) == 1


def test_match_cap_adds_a_summary_finding() -> None:
    keys = [f"AKIA{'A' * 12}{i:04d}".replace("0", "B") for i in range(MAX_MATCHES_PER_RULE + 5)]
    findings = scan(*dict.fromkeys(keys))
    assert len(findings) == MAX_MATCHES_PER_RULE + 1
    assert findings[-1].severity is Severity.INFO
    assert "5 more" in findings[-1].title


def test_redact_helper() -> None:
    assert redact("short") == "*****"
    assert redact("abcdefghijklmnop").startswith("abcd")


def test_packaged_rules_load_and_have_unique_ids() -> None:
    rules = load_rules()
    assert len(rules) >= 8
    assert len({r.id for r in rules}) == len(rules)


def test_custom_rule_file(tmp_path: Path) -> None:
    rule_file = tmp_path / "r.yaml"
    rule_file.write_text(
        "rules:\n"
        "  - {id: X-1, name: Custom, pattern: 'FOO\\d+', severity: low, masvs: [MASVS-CODE-4]}\n"
    )
    analyzer = SecretsAnalyzer(load_rules(rule_file))
    findings = analyzer.analyze(make_apk(dex_strings=("xx FOO123",)))
    assert [f.rule_id for f in findings] == ["X-1"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("rules: 5", "top-level"),
        ("rules:\n  - {id: A}\n", "missing required field"),
        ("rules:\n  - {id: A, name: n, pattern: '(', severity: low}\n", "rule A"),
        ("rules:\n  - {id: A, name: n, pattern: x, severity: nope}\n", "unknown severity"),
        (
            "rules:\n  - {id: A, name: n, pattern: x, severity: low}\n"
            "  - {id: A, name: m, pattern: y, severity: low}\n",
            "duplicate",
        ),
        ("rules: [", "invalid YAML"),
    ],
)
def test_malformed_rule_files_raise_clear_errors(
    tmp_path: Path, content: str, message: str
) -> None:
    rule_file = tmp_path / "bad.yaml"
    rule_file.write_text(content)
    with pytest.raises(RuleError, match=message):
        load_rules(rule_file)
