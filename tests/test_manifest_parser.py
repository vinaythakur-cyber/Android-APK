import pytest

from apk_sentinel.apk_model import ComponentKind
from apk_sentinel.manifest_parser import parse_manifest_xml

MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="7" android:versionName="1.2" package="com.example.app">
  <uses-sdk android:minSdkVersion="19" android:targetSdkVersion="UpsideDownCake"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission-sdk-23 android:name="android.permission.CAMERA"/>
  <application android:debuggable="true" android:allowBackup="false"
      android:usesCleartextTraffic="@bool/x" android:networkSecurityConfig="@xml/nsc">
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>
    <service android:name="Sync"/>
    <receiver android:name="com.other.R" android:permission="p.PERM"/>
    <provider android:name=".P" android:authorities="a" android:grantUriPermissions="true"
        android:readPermission="r" android:writePermission="w"/>
  </application>
</manifest>"""


def test_parses_core_fields() -> None:
    m = parse_manifest_xml(MANIFEST)
    assert m.package == "com.example.app"
    assert (m.version_name, m.version_code) == ("1.2", "7")
    assert m.min_sdk == 19
    assert m.target_sdk is None  # codename, not an int
    assert m.permissions == ("android.permission.INTERNET", "android.permission.CAMERA")
    assert m.debuggable is True
    assert m.allow_backup is False
    assert m.uses_cleartext_traffic is None  # unresolved @bool reference
    assert m.network_security_config == "@xml/nsc"


def test_parses_components_and_qualifies_names() -> None:
    m = parse_manifest_xml(MANIFEST)
    by_name = {c.name: c for c in m.components}
    assert set(by_name) == {
        "com.example.app.Main",
        "com.example.app.Sync",
        "com.other.R",
        "com.example.app.P",
    }
    main = by_name["com.example.app.Main"]
    assert main.kind is ComponentKind.ACTIVITY
    assert main.exported is True
    assert main.is_launcher
    assert by_name["com.other.R"].permission == "p.PERM"
    provider = by_name["com.example.app.P"]
    assert provider.grant_uri_permissions
    assert provider.is_protected()


def test_rejects_non_manifest() -> None:
    with pytest.raises(ValueError, match="manifest"):
        parse_manifest_xml("<foo/>")
    with pytest.raises(ValueError, match="well-formed"):
        parse_manifest_xml("<manifest")


def test_minimal_manifest_without_application() -> None:
    m = parse_manifest_xml('<manifest package="a.b"/>')
    assert m.package == "a.b"
    assert m.components == ()
    assert m.debuggable is None
