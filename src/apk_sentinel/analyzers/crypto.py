"""Cryptography misuse checks, found by reading algorithm names passed to the JCA.

Android code picks algorithms with string literals: ``Cipher.getInstance("DES/ECB/...")``,
``MessageDigest.getInstance("MD5")``. The loader gives us, per method, its string constants
and the APIs it calls, so we can pair "this method calls Cipher.getInstance" with "this method
contains the string DES/ECB/PKCS5Padding" without decompiling to Java.

This is a *heuristic* static analysis: it sees literals, not values computed at runtime.
Findings carry a confidence level and always name the class and method to review.
"""

from __future__ import annotations

import re
from typing import ClassVar

from apk_sentinel.analyzers._code import calls, iter_methods, where
from apk_sentinel.analyzers.base import Analyzer
from apk_sentinel.analyzers.secrets import redact
from apk_sentinel.apk_model import ClassInfo, LoadedApk, MethodInfo
from apk_sentinel.models import Confidence, Finding, Severity

CIPHER_GET = "Ljavax/crypto/Cipher;->getInstance"
KEYGEN_GET = "Ljavax/crypto/KeyGenerator;->getInstance"
SKF_GET = "Ljavax/crypto/SecretKeyFactory;->getInstance"
KEYSPEC_NEW = "Ljavax/crypto/spec/SecretKeySpec;-><init>"
DIGEST_GET = "Ljava/security/MessageDigest;->getInstance"
SIGNATURE_GET = "Ljava/security/Signature;->getInstance"
IV_NEW = "Ljavax/crypto/spec/IvParameterSpec;-><init>"
GCM_NEW = "Ljavax/crypto/spec/GCMParameterSpec;-><init>"
RANDOM_NEW = "Ljava/util/Random;-><init>"
MATH_RANDOM = "Ljava/lang/Math;->random"
SECURE_RANDOM = "Ljava/security/SecureRandom;"
GET_BYTES = "Ljava/lang/String;->getBytes"

_ALGORITHM_FACTORIES = (CIPHER_GET, KEYGEN_GET, SKF_GET, KEYSPEC_NEW)
_TRANSFORMATION = re.compile(r"^[A-Za-z0-9\-]{2,24}(?:/[A-Za-z0-9\-]{1,16}/[A-Za-z0-9\-]{1,24})?$")
_SECURITY_HINT = re.compile(r"token|passw|secret|key|salt|nonce|session|otp|csrf|auth|crypt", re.I)
_MIN_LITERAL_KEY_LENGTH = 8

# algorithm (upper-case) -> (severity, explanation)
_WEAK_CIPHERS: dict[str, tuple[Severity, str]] = {
    "DES": (Severity.HIGH, "DES has a 56-bit key and can be brute-forced in hours."),
    "RC2": (Severity.HIGH, "RC2 is obsolete and has known weaknesses."),
    "RC4": (Severity.HIGH, "RC4 has statistical biases and is prohibited in TLS (RFC 7465)."),
    "ARC4": (Severity.HIGH, "RC4 has statistical biases and is prohibited in TLS (RFC 7465)."),
    "ARCFOUR": (Severity.HIGH, "RC4 has statistical biases and is prohibited in TLS (RFC 7465)."),
    "DESEDE": (Severity.MEDIUM, "Triple-DES has a 64-bit block (Sweet32) and is deprecated."),
    "TRIPLEDES": (Severity.MEDIUM, "Triple-DES has a 64-bit block (Sweet32) and is deprecated."),
    "BLOWFISH": (Severity.MEDIUM, "Blowfish has a 64-bit block size (birthday attacks)."),
}
_WEAK_HASHES = {"MD2", "MD4", "MD5", "SHA-1", "SHA1"}
_WEAK_SIGNATURE = re.compile(r"^(?:md[245]|sha-?1)with", re.I)

_CRYPTO_1 = ("MASVS-CRYPTO-1",)
_CRYPTO_2 = ("MASVS-CRYPTO-2",)


# Strings that name an algorithm/charset rather than carry key material.
_ALGORITHM_NAMES = frozenset(
    {
        "AES", "DES", "DESEDE", "RSA", "BLOWFISH", "RC4", "CHACHA20", "CHACHA20-POLY1305",
        "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACMD5",
        "PBKDF2WITHHMACSHA1", "PBKDF2WITHHMACSHA256", "PBKDF2WITHHMACSHA512",
        "SHA-256", "SHA-384", "SHA-512", "ISO-8859-1", "US-ASCII",
    }
)  # fmt: skip


def _literal_candidates(method: MethodInfo) -> list[str]:
    """String constants that could be a key/IV: long enough and not an algorithm name."""
    return [
        s
        for s in method.const_strings
        if len(s) >= _MIN_LITERAL_KEY_LENGTH and "/" not in s and s.upper() not in _ALGORITHM_NAMES
    ]


class CryptoAnalyzer(Analyzer):
    name: ClassVar[str] = "crypto"

    def analyze(self, apk: LoadedApk) -> list[Finding]:
        findings: list[Finding] = []
        random_by_class: dict[str, list[tuple[ClassInfo, MethodInfo]]] = {}
        for cls, method in iter_methods(apk):
            findings += self._ciphers(cls, method)
            findings += self._digests(cls, method)
            findings += self._static_iv(cls, method)
            findings += self._hardcoded_key(cls, method)
            if calls(method, RANDOM_NEW, MATH_RANDOM):
                random_by_class.setdefault(cls.name, []).append((cls, method))
        findings += self._insecure_random(random_by_class)
        return _dedupe(findings)

    # -- ciphers -----------------------------------------------------------------------

    def _ciphers(self, cls: ClassInfo, method: MethodInfo) -> list[Finding]:
        if not calls(method, *_ALGORITHM_FACTORIES):
            return []
        findings: list[Finding] = []
        is_cipher = calls(method, CIPHER_GET)
        for literal in method.const_strings:
            if not _TRANSFORMATION.match(literal):
                continue
            parts = literal.split("/")
            algorithm = parts[0].upper()
            mode = parts[1].upper() if len(parts) > 1 else None

            if algorithm in _WEAK_CIPHERS:
                severity, why = _WEAK_CIPHERS[algorithm]
                findings.append(
                    Finding(
                        rule_id="CRYPTO-001",
                        title=f"Weak cipher algorithm: {parts[0]}",
                        severity=severity,
                        analyzer=self.name,
                        description=why,
                        evidence=f'"{literal}"',
                        location=where(cls, method),
                        recommendation="Use AES-256-GCM (or ChaCha20-Poly1305) via the Android "
                        "Keystore.",
                        masvs=_CRYPTO_1,
                    )
                )
            if not is_cipher:
                continue
            if mode == "ECB" and algorithm != "RSA":
                findings.append(
                    Finding(
                        rule_id="CRYPTO-002",
                        title="ECB block-cipher mode",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        description="ECB encrypts identical plaintext blocks to identical "
                        "ciphertext blocks, leaking structure and allowing block rearrangement.",
                        evidence=f'Cipher.getInstance("{literal}")',
                        location=where(cls, method),
                        recommendation="Use an authenticated mode such as AES/GCM/NoPadding with "
                        "a fresh random IV for every message.",
                        masvs=_CRYPTO_1,
                    )
                )
            elif algorithm == "AES" and mode is None:
                findings.append(
                    Finding(
                        rule_id="CRYPTO-002",
                        title='Cipher "AES" without mode defaults to ECB',
                        severity=Severity.MEDIUM,
                        analyzer=self.name,
                        description='Cipher.getInstance("AES") falls back to AES/ECB/PKCS5Padding '
                        "on Android's providers, which is not semantically secure.",
                        evidence=f'Cipher.getInstance("{literal}")',
                        location=where(cls, method),
                        recommendation="Always specify the full transformation, e.g. "
                        '"AES/GCM/NoPadding".',
                        masvs=_CRYPTO_1,
                        confidence=Confidence.MEDIUM,
                    )
                )
        return findings

    # -- hashes / signatures -----------------------------------------------------------

    def _digests(self, cls: ClassInfo, method: MethodInfo) -> list[Finding]:
        findings: list[Finding] = []
        if calls(method, DIGEST_GET):
            for literal in method.const_strings:
                if literal.upper() in _WEAK_HASHES:
                    findings.append(
                        Finding(
                            rule_id="CRYPTO-003",
                            title=f"Weak hash function: {literal}",
                            severity=Severity.MEDIUM,
                            analyzer=self.name,
                            description=f"{literal} is collision-prone and unsuitable for "
                            "passwords, signatures or integrity checks. (Harmless for "
                            "non-security checksums.)",
                            evidence=f'MessageDigest.getInstance("{literal}")',
                            location=where(cls, method),
                            recommendation="Use SHA-256 or stronger; for passwords use "
                            "PBKDF2/Argon2/bcrypt.",
                            masvs=_CRYPTO_1,
                            confidence=Confidence.MEDIUM,
                        )
                    )
        if calls(method, SIGNATURE_GET):
            for literal in method.const_strings:
                if _WEAK_SIGNATURE.match(literal):
                    findings.append(
                        Finding(
                            rule_id="CRYPTO-003",
                            title=f"Weak signature algorithm: {literal}",
                            severity=Severity.MEDIUM,
                            analyzer=self.name,
                            description="Signatures over MD5/SHA-1 digests are forgeable.",
                            evidence=f'Signature.getInstance("{literal}")',
                            location=where(cls, method),
                            recommendation="Use SHA256withRSA / SHA256withECDSA or stronger.",
                            masvs=_CRYPTO_1,
                        )
                    )
        return findings

    # -- IVs and keys ------------------------------------------------------------------

    def _static_iv(self, cls: ClassInfo, method: MethodInfo) -> list[Finding]:
        if not calls(method, IV_NEW, GCM_NEW) or calls(method, SECURE_RANDOM):
            return []
        literals = _literal_candidates(method) if calls(method, GET_BYTES) else []
        if literals:
            evidence = f'IV derived from string literal "{redact(literals[0])}"'
            confidence = Confidence.MEDIUM
        elif method.has_array_data:
            evidence = "IV built from a byte-array literal"
            confidence = Confidence.LOW
        else:
            return []
        return [
            Finding(
                rule_id="CRYPTO-004",
                title="Static (hardcoded) IV / nonce",
                severity=Severity.MEDIUM,
                analyzer=self.name,
                description="A constant IV makes encryption deterministic: identical plaintexts "
                "yield identical ciphertexts, and with GCM, nonce reuse reveals the key stream "
                "and breaks authentication.",
                evidence=evidence,
                location=where(cls, method),
                recommendation="Generate a fresh random IV per message with SecureRandom (or "
                "let Cipher.init pick it) and store it alongside the ciphertext.",
                masvs=_CRYPTO_1,
                confidence=confidence,
            )
        ]

    def _hardcoded_key(self, cls: ClassInfo, method: MethodInfo) -> list[Finding]:
        if not calls(method, KEYSPEC_NEW):
            return []
        literals = _literal_candidates(method) if calls(method, GET_BYTES) else []
        if literals:
            evidence = f'SecretKeySpec built from string literal "{redact(literals[0])}"'
            confidence = Confidence.MEDIUM
        elif method.has_array_data and not calls(method, SECURE_RANDOM, KEYGEN_GET, SKF_GET):
            evidence = "SecretKeySpec built from a byte-array literal"
            confidence = Confidence.LOW
        else:
            return []
        return [
            Finding(
                rule_id="CRYPTO-005",
                title="Hardcoded encryption key",
                severity=Severity.HIGH,
                analyzer=self.name,
                description="The symmetric key is embedded in the app. Anyone can extract it "
                "from the APK and decrypt all data protected by it.",
                evidence=evidence,
                location=where(cls, method),
                recommendation="Generate keys at runtime inside the Android Keystore; never "
                "ship key material in code or resources.",
                masvs=_CRYPTO_2,
                confidence=confidence,
            )
        ]

    # -- randomness --------------------------------------------------------------------

    def _insecure_random(
        self, by_class: dict[str, list[tuple[ClassInfo, MethodInfo]]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for entries in by_class.values():
            cls = entries[0][0]
            hinted = any(
                _SECURITY_HINT.search(text)
                for _, m in entries
                for text in (cls.dotted_name, m.name, *m.const_strings)
            )
            methods = ", ".join(sorted({m.name + "()" for _, m in entries}))
            findings.append(
                Finding(
                    rule_id="CRYPTO-006",
                    title="Predictable random number generator (java.util.Random)",
                    severity=Severity.MEDIUM if hinted else Severity.LOW,
                    analyzer=self.name,
                    description="java.util.Random / Math.random are not cryptographically "
                    "secure: their output can be predicted from a few samples. Fine for game "
                    "logic, dangerous for tokens, keys, salts or IVs.",
                    evidence=f"Random used in {cls.dotted_name}: {methods}",
                    location=cls.dotted_name,
                    recommendation="Use java.security.SecureRandom for anything security-related.",
                    masvs=_CRYPTO_1,
                    confidence=Confidence.MEDIUM if hinted else Confidence.LOW,
                )
            )
        return findings


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.location, finding.evidence)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
