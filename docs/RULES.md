# Rule catalogue

Every finding has a stable `rule_id`. Severity is the *typical* rating; some rules grade by
context (noted). MASVS ids refer to **OWASP MASVS v2**. A test (`tests/test_docs.py`) fails if a
rule id exists in the code but is missing here.

## Manifest (`analyzers/manifest.py`)

| Rule | Detects | Severity | MASVS |
|---|---|---|---|
| `MANIFEST-001` | `android:debuggable="true"` | High | RESILIENCE-4 |
| `MANIFEST-002` | `allowBackup` true (explicit: Medium) or left at default (Low) | Medium / Low | STORAGE-2 |
| `MANIFEST-003` | Cleartext HTTP allowed (`usesCleartextTraffic="true"`, or default for targetSdk < 28) | Medium / Low | NETWORK-1 |
| `MANIFEST-004` | Low `minSdkVersion` (< 21 Medium, < 24 Low) | Medium / Low | CODE-1 |
| `MANIFEST-005` | Outdated `targetSdkVersion` (< 30) | Low | CODE-1 |
| `MANIFEST-006` | Exported Activity/Service/Receiver/Provider with no permission (provider High, others Medium; launcher exempt; implicit export rules applied) | High / Medium | PLATFORM-1 |
| `MANIFEST-007` | Sensitive permission requested (SMS, call log, background location, overlay, install packages, all-files: Medium; camera, mic, location, contacts, storage ...: Low) | Medium / Low | PRIVACY-1 (+ STORAGE-2, PLATFORM-3) |

## Secrets (`analyzers/secrets.py`, patterns in `rules/secrets.yaml`)

| Rule | Detects | Severity | MASVS |
|---|---|---|---|
| `SECRET-AWS-ACCESS-KEY` | AWS access key id (`AKIA…`/`ASIA…`) | High | CRYPTO-2, STORAGE-2 |
| `SECRET-PRIVATE-KEY` | PEM private key header | Critical | CRYPTO-2 |
| `SECRET-GOOGLE-API-KEY` | Google API key (`AIza…`) | Medium | STORAGE-2, CRYPTO-2 |
| `SECRET-JWT` | JSON Web Token | Medium (conf. medium) | STORAGE-2, AUTH-1 |
| `SECRET-GITHUB-TOKEN` | GitHub PAT/OAuth token | High | CRYPTO-2, STORAGE-2 |
| `SECRET-SLACK-TOKEN` | Slack token | High | CRYPTO-2, STORAGE-2 |
| `SECRET-STRIPE-LIVE-KEY` | Stripe live secret key | Critical | CRYPTO-2, STORAGE-2 |
| `SECRET-URL-CREDENTIALS` | `https://user:pass@host` | High (conf. medium) | STORAGE-2, AUTH-1 |
| `SECRET-FIREBASE-DATABASE` | Firebase Realtime DB URL (verify rules) | Info | STORAGE-2 |
| `SECRET-HARDCODED-CREDENTIAL` | `password=…`, `api_key: …` heuristic | Low (conf. low) | STORAGE-2, CRYPTO-2 |

Evidence for secrets is masked (`AKIA************LE (20 chars)`).

## Cryptography (`analyzers/crypto.py`)

| Rule | Detects | Severity | MASVS |
|---|---|---|---|
| `CRYPTO-001` | Weak cipher: DES/RC2/RC4 (High), 3DES/Blowfish (Medium) | High / Medium | CRYPTO-1 |
| `CRYPTO-002` | ECB mode (`AES/ECB/…`; not RSA) or bare `"AES"` (defaults to ECB) | High / Medium | CRYPTO-1 |
| `CRYPTO-003` | MD2/MD4/MD5/SHA-1 digests, or `MD5withRSA`/`SHA1withRSA` signatures | Medium | CRYPTO-1 |
| `CRYPTO-004` | Static IV/nonce from a string or byte-array literal (heuristic) | Medium (conf. medium/low) | CRYPTO-1 |
| `CRYPTO-005` | Hardcoded `SecretKeySpec` key from a literal | High (conf. medium/low) | CRYPTO-2 |
| `CRYPTO-006` | `java.util.Random` / `Math.random` (Medium if the class/method looks security-related, else Low) | Medium / Low | CRYPTO-1 |

## Network (`analyzers/network.py`)

| Rule | Detects | Severity | MASVS |
|---|---|---|---|
| `NETWORK-001` | `X509TrustManager.checkServerTrusted` with an empty body | High | NETWORK-1 |
| `NETWORK-002` | `HostnameVerifier.verify` that always returns true, or `ALLOW_ALL_HOSTNAME_VERIFIER` | High | NETWORK-1 |
| `NETWORK-003` | `WebViewClient.onReceivedSslError` calling `handler.proceed()` | High | NETWORK-1, PLATFORM-2 |
| `NETWORK-004` | `network_security_config.xml` permits cleartext (base-config Medium, per-domain Low) | Medium / Low | NETWORK-1 |
| `NETWORK-005` | Config trusts user-installed CAs (base-config High, domain Medium, debug-only Info) | High / Medium / Info | NETWORK-1 |
| `NETWORK-006` | `<pin-set>` past its `expiration` date | Medium | NETWORK-2 |
| `NETWORK-007` | No certificate pinning detected (no `<pin-set>`, OkHttp `CertificatePinner` or TrustKit) | Info (conf. low) | NETWORK-2 |
| `NETWORK-008` | Network security config could not be parsed | Info | NETWORK-1 |

## Reading severity and confidence

*Severity* is impact if the issue is real. *Confidence* is how sure the check is that it is real.
A `Medium / low-confidence` finding is a pointer to review, not a verdict.
