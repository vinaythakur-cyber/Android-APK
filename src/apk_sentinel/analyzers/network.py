"""Network-security checks: TLS validation bypasses and ``network_security_config.xml``.

Two kinds of evidence:

* **Bytecode** - classic TLS-breaking code patterns: a ``TrustManager`` whose
  ``checkServerTrusted`` does nothing, a ``HostnameVerifier`` that always returns true, a
  ``WebViewClient`` that calls ``handler.proceed()`` on SSL errors.
* **Configuration** - the Network Security Configuration XML (API 24+), which can allow
  cleartext traffic, trust user-installed CAs, and declare certificate pins.
"""

from __future__ import annotations

import datetime as dt
import xml.etree.ElementTree as ET
from typing import ClassVar

from apk_sentinel.analyzers._code import calls, iter_methods, where
from apk_sentinel.analyzers.base import Analyzer
from apk_sentinel.apk_model import ClassInfo, LoadedApk, MethodInfo
from apk_sentinel.models import Confidence, Finding, Severity

X509_TRUST_MANAGER = "Ljavax/net/ssl/X509TrustManager;"
X509_EXTENDED = "Ljavax/net/ssl/X509ExtendedTrustManager;"
HOSTNAME_VERIFIER = "Ljavax/net/ssl/HostnameVerifier;"
SSL_PROCEED = "Landroid/webkit/SslErrorHandler;->proceed"
SSL_CANCEL = "Landroid/webkit/SslErrorHandler;->cancel"
ALLOW_ALL_FIELD = "ALLOW_ALL_HOSTNAME_VERIFIER"

_PINNING_LIBRARY_MARKERS = (
    "okhttp3/CertificatePinner",
    "com/datatheorem/android/trustkit",
    "ssl/pinning",
)

_NET_1 = ("MASVS-NETWORK-1",)
_NET_2 = ("MASVS-NETWORK-2",)


class NetworkAnalyzer(Analyzer):
    name: ClassVar[str] = "network"

    def __init__(self, today: dt.date | None = None) -> None:
        self._today = today  # injectable for tests (pin-set expiry)

    def analyze(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._trust_all_managers(apk)
        findings += self._permissive_verifiers(apk)
        findings += self._ssl_error_bypass(apk)
        findings += self._allow_all_field(apk)
        findings += self._network_security_config(apk)
        return findings

    # -- bytecode ----------------------------------------------------------------------

    def _trust_all_managers(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        for cls in apk.classes:
            if not (
                X509_TRUST_MANAGER in cls.interfaces
                or cls.superclass == X509_EXTENDED
                or X509_EXTENDED in cls.interfaces
            ):
                continue
            for method in cls.methods:
                if method.name == "checkServerTrusted" and method.trivial_return == "void":
                    findings.append(self._trust_all(cls, method))
        return findings

    def _trust_all(self, cls: ClassInfo, method: MethodInfo) -> Finding:
        return Finding(
            rule_id="NETWORK-001",
            title="TrustManager accepts any server certificate",
            severity=Severity.HIGH,
            analyzer=self.name,
            description=(
                "checkServerTrusted() has an empty body, so TLS certificates are never "
                "validated. A network attacker can impersonate any server and read or modify "
                "supposedly encrypted traffic (man-in-the-middle)."
            ),
            evidence=f"{cls.dotted_name} implements X509TrustManager; checkServerTrusted is empty",
            location=where(cls, method),
            recommendation="Delete the custom TrustManager and use the platform default. To "
            "trust a private CA, add it via network_security_config.xml; to pin, use <pin-set>.",
            masvs=_NET_1,
        )

    def _permissive_verifiers(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        for cls in apk.classes:
            if HOSTNAME_VERIFIER not in cls.interfaces:
                continue
            for method in cls.methods:
                if method.name == "verify" and method.trivial_return == "true":
                    findings.append(
                        Finding(
                            rule_id="NETWORK-002",
                            title="HostnameVerifier accepts every hostname",
                            severity=Severity.HIGH,
                            analyzer=self.name,
                            description=(
                                "verify() unconditionally returns true, so a valid certificate "
                                "issued for *any* domain is accepted for *every* domain, "
                                "enabling man-in-the-middle attacks."
                            ),
                            evidence=f"{cls.dotted_name}.verify(...) always returns true",
                            location=where(cls, method),
                            recommendation="Use the default HostnameVerifier "
                            "(HttpsURLConnection.getDefaultHostnameVerifier()).",
                            masvs=_NET_1,
                        )
                    )
        return findings

    def _ssl_error_bypass(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        for cls, method in iter_methods(apk):
            if method.name != "onReceivedSslError" or not calls(method, SSL_PROCEED):
                continue
            conditional = calls(method, SSL_CANCEL)
            findings.append(
                Finding(
                    rule_id="NETWORK-003",
                    title="WebView ignores SSL errors (handler.proceed())",
                    severity=Severity.HIGH,
                    analyzer=self.name,
                    description=(
                        "onReceivedSslError calls SslErrorHandler.proceed(), continuing to load "
                        "pages that failed certificate validation. Attackers can inject content "
                        "into the WebView."
                    ),
                    evidence=f"{cls.dotted_name}.onReceivedSslError calls handler.proceed()"
                    + (" (also calls cancel() on some path)" if conditional else ""),
                    location=where(cls, method),
                    recommendation="Call handler.cancel() and show an error instead.",
                    masvs=(*_NET_1, "MASVS-PLATFORM-2"),
                    confidence=Confidence.MEDIUM if conditional else Confidence.HIGH,
                )
            )
        return findings

    def _allow_all_field(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        for cls, method in iter_methods(apk):
            if any(ALLOW_ALL_FIELD in ref for ref in method.references):
                findings.append(
                    Finding(
                        rule_id="NETWORK-002",
                        title="ALLOW_ALL_HOSTNAME_VERIFIER in use",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        description="The Apache SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER "
                        "disables hostname verification entirely.",
                        evidence=f"{cls.dotted_name}.{method.name} references {ALLOW_ALL_FIELD}",
                        location=where(cls, method),
                        recommendation="Use STRICT_HOSTNAME_VERIFIER or, better, migrate to "
                        "HttpsURLConnection / OkHttp defaults.",
                        masvs=_NET_1,
                    )
                )
        return findings

    # -- network_security_config.xml ----------------------------------------------------

    def _network_security_config(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        any_pin_set = False
        for path, text in apk.network_security_configs.items():
            try:
                root = ET.fromstring(text)
            except ET.ParseError as exc:
                findings.append(
                    Finding(
                        rule_id="NETWORK-008",
                        title="Could not parse network security config",
                        severity=Severity.INFO,
                        analyzer=self.name,
                        description=f"The file is not well-formed XML: {exc}",
                        location=path,
                        masvs=_NET_1,
                        confidence=Confidence.LOW,
                    )
                )
                continue
            findings += self._nsc_cleartext(root, path)
            findings += self._nsc_user_ca(root, path)
            pin_findings, has_pins = self._nsc_pins(root, path)
            findings += pin_findings
            any_pin_set = any_pin_set or has_pins

        if not any_pin_set and not self._has_code_pinning(apk):
            findings.append(
                Finding(
                    rule_id="NETWORK-007",
                    title="No certificate pinning detected",
                    severity=Severity.INFO,
                    analyzer=self.name,
                    description=(
                        "Neither a <pin-set> in the network security config nor a known pinning "
                        "library (OkHttp CertificatePinner, TrustKit) was found. Without pinning "
                        "a rogue or compromised CA can intercept traffic to your backend."
                    ),
                    recommendation="For apps handling sensitive data, pin your backend's public "
                    "key (<pin-set>) and include a backup pin.",
                    masvs=_NET_2,
                    confidence=Confidence.LOW,
                )
            )
        return findings

    def _nsc_cleartext(self, root: ET.Element, path: str) -> list[Finding]:
        findings: list[Finding] = []
        for base in root.findall("base-config"):
            if base.get("cleartextTrafficPermitted", "").lower() == "true":
                findings.append(
                    Finding(
                        rule_id="NETWORK-004",
                        title="Cleartext traffic permitted for all domains",
                        severity=Severity.MEDIUM,
                        analyzer=self.name,
                        description='<base-config cleartextTrafficPermitted="true"> allows '
                        "plain HTTP to every domain.",
                        evidence='<base-config cleartextTrafficPermitted="true">',
                        location=path,
                        recommendation="Set cleartextTrafficPermitted to false and use HTTPS.",
                        masvs=_NET_1,
                    )
                )
        for domain_config in root.iter("domain-config"):
            if domain_config.get("cleartextTrafficPermitted", "").lower() != "true":
                continue
            domains = ", ".join((d.text or "").strip() for d in domain_config.findall("domain"))
            findings.append(
                Finding(
                    rule_id="NETWORK-004",
                    title=f"Cleartext traffic permitted for {domains or 'listed domains'}",
                    severity=Severity.LOW,
                    analyzer=self.name,
                    description="A <domain-config> opts specific domains into plain HTTP.",
                    evidence=f'<domain-config cleartextTrafficPermitted="true"> {domains}',
                    location=path,
                    recommendation="Migrate these hosts to HTTPS and remove the exception.",
                    masvs=_NET_1,
                )
            )
        return findings

    def _nsc_user_ca(self, root: ET.Element, path: str) -> list[Finding]:
        findings: list[Finding] = []
        for scope in ("base-config", "domain-config", "debug-overrides"):
            for block in root.iter(scope):
                for cert in block.iter("certificates"):
                    if cert.get("src") != "user":
                        continue
                    debug_only = scope == "debug-overrides"
                    findings.append(
                        Finding(
                            rule_id="NETWORK-005",
                            title="User-installed CAs are trusted"
                            + (" (debug builds only)" if debug_only else ""),
                            severity=Severity.INFO
                            if debug_only
                            else Severity.HIGH
                            if scope == "base-config"
                            else Severity.MEDIUM,
                            analyzer=self.name,
                            description=(
                                'A <certificates src="user"> trust anchor makes the app accept '
                                "certificates from CAs the device user installed, which is how "
                                "interception proxies (and malware) MITM TLS."
                            ),
                            evidence=f'<{scope}> ... <certificates src="user"/>',
                            location=path,
                            recommendation="Trust only system CAs in release builds; limit "
                            "user CAs to <debug-overrides>.",
                            masvs=_NET_1,
                        )
                    )
        return findings

    def _nsc_pins(self, root: ET.Element, path: str) -> tuple[list[Finding], bool]:
        findings: list[Finding] = []
        pin_sets = list(root.iter("pin-set"))
        today = self._today or dt.datetime.now(dt.UTC).date()
        for pin_set in pin_sets:
            expiration = pin_set.get("expiration")
            if not expiration:
                continue
            try:
                expires = dt.date.fromisoformat(expiration)
            except ValueError:
                continue
            if expires < today:
                findings.append(
                    Finding(
                        rule_id="NETWORK-006",
                        title="Certificate pin-set has expired",
                        severity=Severity.MEDIUM,
                        analyzer=self.name,
                        description="After the expiration date Android stops enforcing the "
                        "pins, silently disabling pinning.",
                        evidence=f'<pin-set expiration="{expiration}">',
                        location=path,
                        recommendation="Rotate pins and set a later expiration (or none).",
                        masvs=_NET_2,
                    )
                )
        return findings, bool(pin_sets)

    @staticmethod
    def _has_code_pinning(apk: LoadedApk) -> bool:
        return any(
            marker in string for string in apk.dex_strings for marker in _PINNING_LIBRARY_MARKERS
        )
