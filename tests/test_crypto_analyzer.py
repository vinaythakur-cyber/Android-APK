import pytest

from apk_sentinel.analyzers.crypto import CryptoAnalyzer
from apk_sentinel.models import Confidence, Finding, Severity
from tests.factories import klass, make_apk, method, rule_ids

CIPHER = "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"
DIGEST = (
    "Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"
)
SIG = "Ljava/security/Signature;->getInstance(Ljava/lang/String;)Ljava/security/Signature;"
KEYSPEC = "Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V"
IVSPEC = "Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V"
GCMSPEC = "Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[B)V"
GETBYTES = "Ljava/lang/String;->getBytes()[B"
SECURE = "Ljava/security/SecureRandom;->nextBytes([B)V"
RANDOM = "Ljava/util/Random;-><init>()V"


def scan(*methods) -> list[Finding]:  # type: ignore[no-untyped-def]
    apk = make_apk(classes=(klass("Lcom/example/app/Crypto;", methods=tuple(methods)),))
    return CryptoAnalyzer().analyze(apk)


def test_des_ecb_reports_cipher_and_mode() -> None:
    findings = scan(method(const_strings=("DES/ECB/PKCS5Padding",), references=(CIPHER,)))
    assert rule_ids(findings) == ["CRYPTO-001", "CRYPTO-002"]
    assert {f.severity for f in findings} == {Severity.HIGH}
    assert findings[0].location == "com.example.app.Crypto.run()"


@pytest.mark.parametrize(
    ("literal", "severity"),
    [
        ("DES", Severity.HIGH),
        ("RC4", Severity.HIGH),
        ("DESede/CBC/PKCS5Padding", Severity.MEDIUM),
        ("Blowfish", Severity.MEDIUM),
    ],
)
def test_weak_ciphers_graded(literal: str, severity: Severity) -> None:
    findings = scan(method(const_strings=(literal,), references=(CIPHER,)))
    weak = next(f for f in findings if f.rule_id == "CRYPTO-001")
    assert weak.severity is severity


def test_bare_aes_defaults_to_ecb_with_medium_confidence() -> None:
    (finding,) = scan(method(const_strings=("AES",), references=(CIPHER,)))
    assert finding.rule_id == "CRYPTO-002"
    assert finding.confidence is Confidence.MEDIUM


def test_secure_modes_are_not_flagged() -> None:
    assert scan(method(const_strings=("AES/GCM/NoPadding",), references=(CIPHER,))) == []
    assert scan(method(const_strings=("AES/CBC/PKCS5Padding",), references=(CIPHER,))) == []


def test_rsa_ecb_is_not_flagged_as_ecb() -> None:
    findings = scan(method(const_strings=("RSA/ECB/PKCS1Padding",), references=(CIPHER,)))
    assert findings == []


def test_algorithm_string_without_jca_call_is_ignored() -> None:
    assert scan(method(const_strings=("DES/ECB/PKCS5Padding",))) == []


def test_aes_in_secretkeyspec_is_not_flagged_as_ecb() -> None:
    assert scan(method(const_strings=("AES",), references=(KEYSPEC,))) == []


@pytest.mark.parametrize("name", ["MD5", "md5", "SHA-1", "SHA1", "MD2"])
def test_weak_hashes(name: str) -> None:
    (finding,) = scan(method(const_strings=(name,), references=(DIGEST,)))
    assert finding.rule_id == "CRYPTO-003"


def test_sha256_is_fine() -> None:
    assert scan(method(const_strings=("SHA-256",), references=(DIGEST,))) == []


def test_weak_signature_algorithm() -> None:
    (finding,) = scan(method(const_strings=("SHA1withRSA",), references=(SIG,)))
    assert finding.rule_id == "CRYPTO-003"
    assert "signature" in finding.title.lower()


def test_static_iv_from_string_literal() -> None:
    (finding,) = scan(method(const_strings=("0123456789abcdef",), references=(GETBYTES, IVSPEC)))
    assert finding.rule_id == "CRYPTO-004"
    assert "0123456789abcdef" not in finding.evidence  # redacted
    assert finding.confidence is Confidence.MEDIUM


def test_static_iv_from_array_literal_is_low_confidence() -> None:
    (finding,) = scan(method(references=(GCMSPEC,), has_array_data=True))
    assert finding.rule_id == "CRYPTO-004"
    assert finding.confidence is Confidence.LOW


def test_random_iv_is_not_flagged() -> None:
    assert (
        scan(method(const_strings=("0123456789abcdef",), references=(GETBYTES, IVSPEC, SECURE)))
        == []
    )


def test_hardcoded_key_from_string() -> None:
    (finding,) = scan(
        method(const_strings=("MySuperSecretKey1", "AES"), references=(GETBYTES, KEYSPEC))
    )
    assert finding.rule_id == "CRYPTO-005"
    assert finding.severity is Severity.HIGH
    assert "MySuperSecretKey1" not in finding.evidence


def test_short_or_algorithm_strings_are_not_keys() -> None:
    assert scan(method(const_strings=("AES", "UTF-8"), references=(GETBYTES, KEYSPEC))) == []


def test_random_usage_is_grouped_per_class_and_graded_by_context() -> None:
    plain = CryptoAnalyzer().analyze(
        make_apk(
            classes=(klass("Lcom/game/Dice;", methods=(method("roll", references=(RANDOM,)),)),)
        )
    )
    (low,) = plain
    assert (low.rule_id, low.severity) == ("CRYPTO-006", Severity.LOW)

    hinted = CryptoAnalyzer().analyze(
        make_apk(
            classes=(
                klass(
                    "Lcom/app/Auth;",
                    methods=(
                        method("makeToken", references=(RANDOM,)),
                        method("makeSalt", references=(RANDOM,)),
                    ),
                ),
            )
        )
    )
    (medium,) = hinted
    assert medium.severity is Severity.MEDIUM
    assert "makeSalt()" in medium.evidence


def test_identical_findings_are_deduplicated() -> None:
    m = method(const_strings=("MD5", "MD5"), references=(DIGEST,))
    assert len(scan(m)) == 1
