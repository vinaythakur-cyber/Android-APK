import datetime as dt

from apk_sentinel.analyzers.network import NetworkAnalyzer
from apk_sentinel.models import Severity
from tests.factories import klass, make_apk, method, rule_ids

TM = "Ljavax/net/ssl/X509TrustManager;"
HV = "Ljavax/net/ssl/HostnameVerifier;"
PROCEED = "Landroid/webkit/SslErrorHandler;->proceed()V"
CANCEL = "Landroid/webkit/SslErrorHandler;->cancel()V"
ALLOW_ALL = (
    "Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER "
    "Lorg/apache/http/conn/ssl/X509HostnameVerifier;"
)
TODAY = dt.date(2026, 1, 1)


def scan(classes=(), nsc=None, strings=()):  # type: ignore[no-untyped-def]
    apk = make_apk(classes=tuple(classes), network_security_configs=nsc, dex_strings=strings)
    return NetworkAnalyzer(today=TODAY).analyze(apk)


def non_info(findings):  # type: ignore[no-untyped-def]
    return [f for f in findings if f.severity is not Severity.INFO]


def test_empty_check_server_trusted_is_flagged() -> None:
    cls = klass(
        "Lcom/app/TrustAll;",
        interfaces=(TM,),
        methods=(
            method("checkClientTrusted", trivial_return="void"),
            method("checkServerTrusted", trivial_return="void"),
        ),
    )
    findings = non_info(scan([cls]))
    assert rule_ids(findings) == ["NETWORK-001"]
    assert findings[0].location == "com.app.TrustAll.checkServerTrusted()"


def test_delegating_trust_manager_is_fine() -> None:
    cls = klass(
        "Lcom/app/Pinned;",
        interfaces=(TM,),
        methods=(method("checkServerTrusted", references=("Lfoo;->validate()V",)),),
    )
    assert non_info(scan([cls])) == []


def test_empty_method_on_unrelated_class_is_ignored() -> None:
    cls = klass("Lcom/app/Other;", methods=(method("checkServerTrusted", trivial_return="void"),))
    assert non_info(scan([cls])) == []


def test_always_true_hostname_verifier() -> None:
    cls = klass(
        "Lcom/app/AllowAll;", interfaces=(HV,), methods=(method("verify", trivial_return="true"),)
    )
    assert rule_ids(non_info(scan([cls]))) == ["NETWORK-002"]


def test_real_hostname_verifier_is_fine() -> None:
    cls = klass(
        "Lcom/app/V;",
        interfaces=(HV,),
        methods=(
            method("verify", references=("Ljava/lang/String;->equals(Ljava/lang/Object;)Z",)),
        ),
    )
    assert non_info(scan([cls])) == []


def test_allow_all_field_reference() -> None:
    cls = klass("Lcom/app/Http;", methods=(method("client", references=(ALLOW_ALL,)),))
    assert rule_ids(non_info(scan([cls]))) == ["NETWORK-002"]


def test_webview_proceed_on_ssl_error() -> None:
    cls = klass(
        "Lcom/app/Web;",
        superclass="Landroid/webkit/WebViewClient;",
        methods=(method("onReceivedSslError", references=(PROCEED,)),),
    )
    (finding,) = non_info(scan([cls]))
    assert finding.rule_id == "NETWORK-003"
    assert finding.confidence.value == "high"


def test_webview_conditional_proceed_is_lower_confidence() -> None:
    cls = klass(
        "Lcom/app/Web;",
        methods=(method("onReceivedSslError", references=(PROCEED, CANCEL)),),
    )
    (finding,) = non_info(scan([cls]))
    assert finding.confidence.value == "medium"


NSC_BAD = """<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
  </base-config>
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">legacy.example.com</domain>
  </domain-config>
</network-security-config>"""


def test_bad_network_security_config() -> None:
    findings = scan(nsc={"res/xml/nsc.xml": NSC_BAD})
    by_rule = {f.rule_id: f for f in findings if f.rule_id != "NETWORK-004"}
    assert by_rule["NETWORK-005"].severity is Severity.HIGH
    cleartext = [f for f in findings if f.rule_id == "NETWORK-004"]
    assert sorted(f.severity for f in cleartext) == [Severity.LOW, Severity.MEDIUM]
    assert any("legacy.example.com" in f.title for f in cleartext)
    assert all(f.location == "res/xml/nsc.xml" for f in cleartext)


def test_user_ca_in_debug_overrides_is_informational() -> None:
    nsc = """<network-security-config><debug-overrides><trust-anchors>
      <certificates src="user"/></trust-anchors></debug-overrides></network-security-config>"""
    findings = scan(nsc={"res/xml/n.xml": nsc})
    (user_ca,) = (f for f in findings if f.rule_id == "NETWORK-005")
    assert user_ca.severity is Severity.INFO


def test_pinning_present_suppresses_no_pinning_finding() -> None:
    nsc = """<network-security-config><domain-config>
      <domain>api.example.com</domain>
      <pin-set expiration="2030-01-01"><pin digest="SHA-256">AAAA=</pin></pin-set>
      </domain-config></network-security-config>"""
    assert scan(nsc={"res/xml/n.xml": nsc}) == []


def test_expired_pin_set_is_flagged() -> None:
    nsc = """<network-security-config><domain-config>
      <pin-set expiration="2020-01-01"><pin digest="SHA-256">AAAA=</pin></pin-set>
      </domain-config></network-security-config>"""
    findings = scan(nsc={"res/xml/n.xml": nsc})
    assert rule_ids(findings) == ["NETWORK-006"]


def test_okhttp_pinner_counts_as_pinning() -> None:
    assert scan(strings=("okhttp3/CertificatePinner",)) == []


def test_no_pinning_is_info_with_low_confidence() -> None:
    (finding,) = scan()
    assert finding.rule_id == "NETWORK-007"
    assert finding.severity is Severity.INFO
    assert finding.confidence.value == "low"


def test_malformed_nsc_does_not_crash() -> None:
    findings = scan(nsc={"res/xml/n.xml": "<network-security-config"})
    assert "NETWORK-008" in rule_ids(findings)
