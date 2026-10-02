from apk_sentinel.analyzers.manifest import ManifestAnalyzer
from apk_sentinel.apk_model import ComponentKind, IntentFilter
from apk_sentinel.models import Severity
from tests.factories import LAUNCHER, component, make_apk, make_manifest, rule_ids


def run(**manifest_kwargs: object):  # type: ignore[no-untyped-def]
    return ManifestAnalyzer().analyze(make_apk(manifest=make_manifest(**manifest_kwargs)))


def test_clean_manifest_has_no_findings() -> None:
    assert run(debuggable=False, allow_backup=False, uses_cleartext_traffic=False) == []


def test_debuggable_is_high() -> None:
    findings = run(debuggable=True, allow_backup=False)
    assert rule_ids(findings) == ["MANIFEST-001"]
    assert findings[0].severity is Severity.HIGH
    assert "MASVS-RESILIENCE-4" in findings[0].masvs


def test_allow_backup_explicit_vs_default() -> None:
    explicit = run(allow_backup=True)[0]
    default = run(allow_backup=None)[0]
    assert explicit.rule_id == default.rule_id == "MANIFEST-002"
    assert explicit.severity is Severity.MEDIUM
    assert default.severity is Severity.LOW


def test_cleartext_explicit_and_legacy_default() -> None:
    assert rule_ids(run(allow_backup=False, uses_cleartext_traffic=True)) == ["MANIFEST-003"]
    legacy = run(allow_backup=False, target_sdk=26, uses_cleartext_traffic=None)
    assert "MANIFEST-003" in rule_ids(legacy)
    modern = run(allow_backup=False, target_sdk=33, uses_cleartext_traffic=None)
    assert "MANIFEST-003" not in rule_ids(modern)


def test_min_sdk_tiers() -> None:
    old = next(f for f in run(allow_backup=False, min_sdk=15) if f.rule_id == "MANIFEST-004")
    mid = next(f for f in run(allow_backup=False, min_sdk=22) if f.rule_id == "MANIFEST-004")
    assert old.severity is Severity.MEDIUM
    assert mid.severity is Severity.LOW
    assert "MANIFEST-004" not in rule_ids(run(allow_backup=False, min_sdk=24))


def test_outdated_target_sdk() -> None:
    assert "MANIFEST-005" in rule_ids(run(allow_backup=False, target_sdk=28))
    assert "MANIFEST-005" not in rule_ids(run(allow_backup=False, target_sdk=30))


def test_exported_service_without_permission_is_flagged() -> None:
    svc = component(ComponentKind.SERVICE, "com.example.app.Sync", exported=True)
    findings = run(allow_backup=False, components=(svc,))
    assert rule_ids(findings) == ["MANIFEST-006"]
    assert findings[0].severity is Severity.MEDIUM


def test_exported_provider_is_high() -> None:
    prov = component(ComponentKind.PROVIDER, "com.example.app.P", exported=True)
    (finding,) = run(allow_backup=False, components=(prov,))
    assert finding.severity is Severity.HIGH


def test_permission_protected_component_is_not_flagged() -> None:
    rcv = component(ComponentKind.RECEIVER, exported=True, permission="android.permission.X")
    assert run(allow_backup=False, components=(rcv,)) == []


def test_launcher_activity_is_exempt_but_other_exported_activity_is_not() -> None:
    main = component(
        ComponentKind.ACTIVITY, "com.example.app.Main", exported=True, intent_filters=(LAUNCHER,)
    )
    pay = component(
        ComponentKind.ACTIVITY,
        "com.example.app.Pay",
        exported=True,
        intent_filters=(IntentFilter(actions=("x.PAY",)),),
    )
    findings = run(allow_backup=False, components=(main, pay))
    assert [f.location for f in findings] == ["AndroidManifest.xml <activity com.example.app.Pay>"]


def test_implicit_export_rules() -> None:
    with_filter = component(ComponentKind.SERVICE, intent_filters=(IntentFilter(actions=("x.A",)),))
    without_filter = component(ComponentKind.SERVICE, name="com.example.app.Priv")
    old_provider = component(ComponentKind.PROVIDER, name="com.example.app.OldP")
    findings = run(
        allow_backup=False,
        target_sdk=16,
        min_sdk=26,
        components=(with_filter, without_filter, old_provider),
    )
    flagged = {f.location for f in findings if f.rule_id == "MANIFEST-006"}
    assert flagged == {
        "AndroidManifest.xml <service com.example.app.Thing>",
        "AndroidManifest.xml <provider com.example.app.OldP>",
    }
    modern = run(allow_backup=False, components=(old_provider,))
    assert "MANIFEST-006" not in rule_ids(modern)


def test_permissions_are_graded() -> None:
    findings = run(
        allow_backup=False,
        permissions=(
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.CAMERA",
        ),
    )
    by_title = {f.title: f.severity for f in findings}
    assert by_title["Sensitive permission requested: READ_SMS"] is Severity.MEDIUM
    assert by_title["Sensitive permission requested: CAMERA"] is Severity.LOW
    assert len(findings) == 2  # INTERNET is not reported
