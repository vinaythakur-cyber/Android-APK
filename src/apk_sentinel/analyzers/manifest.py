"""Manifest checks: debuggable, backup, exported components, cleartext, SDK levels, permissions.

The manifest is the app's declared attack surface. Everything here is a fact read straight
from ``AndroidManifest.xml``, so confidence is HIGH; whether a finding is *exploitable* still
depends on the app's code (the evidence tells you where to look).
"""

from __future__ import annotations

from typing import ClassVar

from apk_sentinel.analyzers.base import Analyzer
from apk_sentinel.apk_model import Component, ComponentKind, LoadedApk
from apk_sentinel.models import Finding, Severity

LOCATION = "AndroidManifest.xml"

MIN_SDK_MEDIUM = 21  # Android 5.0: below this, no default TLS 1.2, weak sandboxing, etc.
MIN_SDK_LOW = 24  # Android 7.0: network security config + per-app trust anchors
TARGET_SDK_OUTDATED = 30  # Android 11

# permission -> (severity, why it matters, MASVS controls)
_PERMISSIONS: dict[str, tuple[Severity, str, tuple[str, ...]]] = {}


def _perm(
    names: str,
    severity: Severity,
    why: str,
    masvs: tuple[str, ...] = ("MASVS-PRIVACY-1",),
) -> None:
    for name in names.split():
        _PERMISSIONS[f"android.permission.{name}"] = (severity, why, masvs)


_perm(
    "READ_SMS RECEIVE_SMS SEND_SMS RECEIVE_MMS RECEIVE_WAP_PUSH",
    Severity.MEDIUM,
    "Can read or send SMS, a common vector for OTP theft and premium-rate fraud.",
)
_perm(
    "READ_CALL_LOG WRITE_CALL_LOG PROCESS_OUTGOING_CALLS",
    Severity.MEDIUM,
    "Exposes call history and outgoing call metadata.",
)
_perm(
    "ACCESS_BACKGROUND_LOCATION",
    Severity.MEDIUM,
    "Tracks the user's location while the app is not in use.",
)
_perm(
    "SYSTEM_ALERT_WINDOW",
    Severity.MEDIUM,
    "Draws over other apps; abused for tap-jacking and credential-phishing overlays.",
    ("MASVS-PLATFORM-3", "MASVS-PRIVACY-1"),
)
_perm(
    "REQUEST_INSTALL_PACKAGES",
    Severity.MEDIUM,
    "Can prompt to install other APKs; a malware dropper capability.",
    ("MASVS-PRIVACY-1", "MASVS-CODE-3"),
)
_perm(
    "MANAGE_EXTERNAL_STORAGE",
    Severity.MEDIUM,
    "All-files access to shared storage, bypassing scoped storage.",
    ("MASVS-STORAGE-2", "MASVS-PRIVACY-1"),
)
_perm(
    "READ_LOGS",
    Severity.MEDIUM,
    "Reading system logs can leak data from other apps.",
    ("MASVS-STORAGE-2",),
)
_perm(
    "WRITE_EXTERNAL_STORAGE READ_EXTERNAL_STORAGE",
    Severity.LOW,
    "Shared storage is readable by other apps; never put secrets there.",
    ("MASVS-STORAGE-2", "MASVS-PRIVACY-1"),
)
_perm(
    "CAMERA RECORD_AUDIO",
    Severity.LOW,
    "Captures camera or microphone input; verify it is needed and user-visible.",
)
_perm("ACCESS_FINE_LOCATION ACCESS_COARSE_LOCATION", Severity.LOW, "Collects the user's location.")
_perm(
    "READ_CONTACTS WRITE_CONTACTS GET_ACCOUNTS",
    Severity.LOW,
    "Accesses the user's contacts or accounts.",
)
_perm("READ_CALENDAR WRITE_CALENDAR", Severity.LOW, "Accesses calendar data.")
_perm(
    "READ_PHONE_STATE READ_PHONE_NUMBERS CALL_PHONE ANSWER_PHONE_CALLS",
    Severity.LOW,
    "Accesses phone identity or can place calls.",
)
_perm("BODY_SENSORS ACTIVITY_RECOGNITION", Severity.LOW, "Accesses health or activity sensors.")
_perm(
    "READ_MEDIA_IMAGES READ_MEDIA_VIDEO READ_MEDIA_AUDIO",
    Severity.LOW,
    "Reads the user's media library.",
)


class ManifestAnalyzer(Analyzer):
    name: ClassVar[str] = "manifest"

    def analyze(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._debuggable(apk)
        findings += self._allow_backup(apk)
        findings += self._cleartext(apk)
        findings += self._sdk_levels(apk)
        findings += self._exported_components(apk)
        findings += self._permissions(apk)
        return findings

    # -- application flags -------------------------------------------------------------

    def _debuggable(self, apk: LoadedApk) -> list[Finding]:
        if apk.manifest.debuggable is not True:
            return []
        return [
            Finding(
                rule_id="MANIFEST-001",
                title="Application is debuggable",
                severity=Severity.HIGH,
                analyzer=self.name,
                description=(
                    "android:debuggable is true. Anyone with USB access can attach a debugger, "
                    "run commands as the app (run-as), read its private data and bypass "
                    "client-side checks."
                ),
                evidence='<application android:debuggable="true">',
                location=f"{LOCATION} <application>",
                recommendation="Never ship debuggable builds. Remove the attribute; release "
                "build types set it to false by default.",
                masvs=("MASVS-RESILIENCE-4",),
            )
        ]

    def _allow_backup(self, apk: LoadedApk) -> list[Finding]:
        flag = apk.manifest.allow_backup
        if flag is False:
            return []
        explicit = flag is True
        return [
            Finding(
                rule_id="MANIFEST-002",
                title="App data can be extracted with adb backup"
                if explicit
                else "allowBackup not disabled (defaults to true)",
                severity=Severity.MEDIUM if explicit else Severity.LOW,
                analyzer=self.name,
                description=(
                    "With backup enabled, app-private files (databases, shared preferences, "
                    "tokens) can be copied off the device via 'adb backup' or cloud backup, "
                    "defeating the app sandbox."
                ),
                evidence='<application android:allowBackup="true">'
                if explicit
                else "android:allowBackup attribute absent (platform default is true)",
                location=f"{LOCATION} <application>",
                recommendation='Set android:allowBackup="false", or define precise '
                "android:dataExtractionRules / fullBackupContent exclusions for sensitive files.",
                masvs=("MASVS-STORAGE-2",),
            )
        ]

    def _cleartext(self, apk: LoadedApk) -> list[Finding]:
        manifest = apk.manifest
        if manifest.uses_cleartext_traffic is True:
            return [
                Finding(
                    rule_id="MANIFEST-003",
                    title="Cleartext (HTTP) traffic explicitly allowed",
                    severity=Severity.MEDIUM,
                    analyzer=self.name,
                    description=(
                        "android:usesCleartextTraffic is true, so the app may send data over "
                        "unencrypted HTTP where an on-path attacker can read or modify it."
                    ),
                    evidence='<application android:usesCleartextTraffic="true">',
                    location=f"{LOCATION} <application>",
                    recommendation="Use HTTPS everywhere and set usesCleartextTraffic to false, "
                    "or restrict exceptions in network_security_config.xml.",
                    masvs=("MASVS-NETWORK-1",),
                )
            ]
        if (
            manifest.uses_cleartext_traffic is None
            and manifest.target_sdk is not None
            and manifest.target_sdk < 28
        ):
            return [
                Finding(
                    rule_id="MANIFEST-003",
                    title="Cleartext traffic allowed by default (targetSdk < 28)",
                    severity=Severity.LOW,
                    analyzer=self.name,
                    description=(
                        "Apps targeting API 27 or lower allow cleartext HTTP unless they opt "
                        "out; this app did not."
                    ),
                    evidence=f"targetSdkVersion={manifest.target_sdk}, no usesCleartextTraffic",
                    location=f"{LOCATION} <uses-sdk>",
                    recommendation="Raise targetSdkVersion to 28+ and use HTTPS only.",
                    masvs=("MASVS-NETWORK-1",),
                )
            ]
        return []

    # -- SDK levels --------------------------------------------------------------------

    def _sdk_levels(self, apk: LoadedApk) -> list[Finding]:
        manifest = apk.manifest
        findings: list[Finding] = []
        if manifest.min_sdk is not None and manifest.min_sdk < MIN_SDK_LOW:
            severity = Severity.MEDIUM if manifest.min_sdk < MIN_SDK_MEDIUM else Severity.LOW
            findings.append(
                Finding(
                    rule_id="MANIFEST-004",
                    title=f"Low minSdkVersion ({manifest.min_sdk})",
                    severity=severity,
                    analyzer=self.name,
                    description=(
                        "The app installs on old Android releases that lack modern platform "
                        "security fixes and protections (e.g. TLS 1.2 defaults, network "
                        "security config, runtime permissions)."
                    ),
                    evidence=f"android:minSdkVersion={manifest.min_sdk}",
                    location=f"{LOCATION} <uses-sdk>",
                    recommendation=f"Raise minSdkVersion to at least {MIN_SDK_LOW}.",
                    masvs=("MASVS-CODE-1",),
                )
            )
        if manifest.target_sdk is not None and manifest.target_sdk < TARGET_SDK_OUTDATED:
            findings.append(
                Finding(
                    rule_id="MANIFEST-005",
                    title=f"Outdated targetSdkVersion ({manifest.target_sdk})",
                    severity=Severity.LOW,
                    analyzer=self.name,
                    description=(
                        "Targeting an old API level opts the app out of newer platform "
                        "hardening (scoped storage, implicit-export rules, background limits)."
                    ),
                    evidence=f"android:targetSdkVersion={manifest.target_sdk}",
                    location=f"{LOCATION} <uses-sdk>",
                    recommendation=f"Target API {TARGET_SDK_OUTDATED} or newer.",
                    masvs=("MASVS-CODE-1",),
                )
            )
        return findings

    # -- exported components -----------------------------------------------------------

    def _exported_components(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        for component in apk.manifest.components:
            if not component.is_effectively_exported(apk.manifest.target_sdk):
                continue
            if component.is_protected():
                continue
            if component.kind is ComponentKind.ACTIVITY and component.is_launcher:
                continue  # the launcher activity must be exported
            findings.append(self._exported_finding(component, apk.manifest.target_sdk))
        return findings

    def _exported_finding(self, component: Component, target_sdk: int | None) -> Finding:
        kind = component.kind.value
        implicit = component.exported is None
        reason = (
            "it declares an intent filter and android:exported is not set (implicitly exported)"
            if implicit and component.kind is not ComponentKind.PROVIDER
            else "android:exported is true"
            if not implicit
            else f"it is exported by default for targetSdk {target_sdk}"
        )
        severity = Severity.HIGH if component.kind is ComponentKind.PROVIDER else Severity.MEDIUM
        extra = ""
        if component.kind is ComponentKind.PROVIDER:
            extra = " Any app can query this provider's data." + (
                " grantUriPermissions=true widens access further."
                if component.grant_uri_permissions
                else ""
            )
        return Finding(
            rule_id="MANIFEST-006",
            title=f"Exported {kind} without permission: {component.name.rsplit('.', 1)[-1]}",
            severity=severity,
            analyzer=self.name,
            description=(
                f"This {kind} is reachable by any app on the device because {reason}, and no "
                "android:permission protects it. Untrusted callers can send it crafted "
                f"intents.{extra}"
            ),
            evidence=f'<{kind} android:name="{component.name}"> exported, no permission',
            location=f"{LOCATION} <{kind} {component.name}>",
            recommendation='Set android:exported="false" unless external access is required; '
            "otherwise guard it with a signature-level android:permission and validate all "
            "incoming data.",
            masvs=("MASVS-PLATFORM-1",),
        )

    # -- permissions -------------------------------------------------------------------

    def _permissions(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        for permission in apk.manifest.permissions:
            entry = _PERMISSIONS.get(permission)
            if entry is None:
                continue
            severity, why, masvs = entry
            findings.append(
                Finding(
                    rule_id="MANIFEST-007",
                    title=f"Sensitive permission requested: {permission.rsplit('.', 1)[-1]}",
                    severity=severity,
                    analyzer=self.name,
                    description=why
                    + " Request only what the app needs and justify it in the privacy policy.",
                    evidence=f'<uses-permission android:name="{permission}">',
                    location=f"{LOCATION} <uses-permission>",
                    recommendation="Remove the permission if unused; request dangerous "
                    "permissions at runtime, in context.",
                    masvs=masvs,
                )
            )
        return findings
