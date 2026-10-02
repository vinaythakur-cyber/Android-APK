# Concepts you need to understand this project

Read this once; every module's docstring refers back to it.

## 1. What an APK is

An APK is a **ZIP file** with a fixed layout. Rename `app.apk` to `app.zip` and open it:

```
app.apk
├── AndroidManifest.xml    ← binary XML: permissions, components, flags  (manifest analyzer)
├── classes.dex            ← compiled code (+ classes2.dex ...)           (secrets, crypto, network)
├── resources.arsc         ← compiled resource table (strings.xml values) (secrets: resource strings)
├── res/                   ← layouts, images, res/xml/network_security_config.xml
├── lib/<abi>/*.so         ← native libraries (not analyzed yet)
├── assets/                ← raw files bundled by the developer
└── META-INF/              ← signature (CERT.RSA / v2-v3 signing block)
```

**Physical analogy:** the APK is a shipping container. The manifest is the customs form (what is
inside, who may open which door), `classes.dex` is the machinery, `resources.arsc` the labels.
Static analysis = inspecting the container's paperwork and machinery *without switching it on*.

## 2. Binary XML (AXML)

To save space and parse fast, the build tool compiles every XML file into a binary format made
of typed "chunks" (string pool, resource-id map, start-tag, end-tag ...). `unzip` + `cat` shows
garbage. Androguard's `AXMLPrinter` decodes it back to text, which `manifest_parser.py` reads.

Attribute values that were resources appear as ids (`@7F020000`) instead of names, which is why
the loader finds `network_security_config.xml` by *scanning* `res/xml/*` for the right root tag.

## 3. DEX and Dalvik bytecode

Java/Kotlin compiles to JVM bytecode, then `d8`/`r8` converts it to **DEX**, the format Android
runs. A DEX file contains:

| Table | Holds | We use it for |
|---|---|---|
| string pool | **every** string literal and every type/method name | secrets (regex over all strings) |
| type / field / method ids | references to classes and members | "which APIs does this method call?" |
| class defs | classes, their superclass and interfaces, methods | "does this class implement `X509TrustManager`?" |
| code items | per-method instruction stream (register machine) | "is `checkServerTrusted` just `return-void`?" |

Readable form is **smali**. This is the exact trust-all TrustManager from the fixture app:

```smali
.class public Lcom/example/vulnapp/TrustAll;
.implements Ljavax/net/ssl/X509TrustManager;

.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    return-void          # validates nothing -> accepts any certificate
.end method
```

Type names use JVM descriptors: `Ljava/lang/String;` = `java.lang.String`, `[B` = `byte[]`,
`V` = void, `Z` = boolean. A call looks like `invoke-static v0, Ljavax/crypto/Cipher;->getInstance(...)`.

## 4. The four Android components and "exported"

| Component | Purpose | Example attack when exported |
|---|---|---|
| Activity | a screen | open a screen that skips login |
| Service | background work | trigger a privileged action |
| BroadcastReceiver | reacts to system/app events | send a forged event |
| ContentProvider | shares structured data | `content://...` query reads the app's database |

A component is reachable by **other apps** when it is *exported*. Rules (see
`Component.is_effectively_exported`): `android:exported="true"` ⇒ exported; if the attribute is
missing, it depends on whether an intent filter exists (and, for providers, on `targetSdk`).
Guarding it with an `android:permission` that only your app holds is the fix. The launcher
activity must be exported, so it is exempt.

## 5. TLS validation and why "trust-all" is dangerous

When the app opens `https://bank.example`, the TLS handshake gives it a certificate. Two checks
protect the user: **(1)** is the certificate chain trusted? (`X509TrustManager.checkServerTrusted`)
and **(2)** does it belong to *this* hostname? (`HostnameVerifier.verify`). Code that makes either
one always succeed lets anyone on the same Wi-Fi present a self-made certificate and read or
modify the traffic (a *man-in-the-middle*). These are among the most common real-world findings.

## 6. OWASP MASVS v2

The **Mobile Application Security Verification Standard** lists what a secure mobile app does,
grouped into categories. Each finding carries the control ids it violates:

| Category | Question it answers |
|---|---|
| STORAGE | Is sensitive data stored/leaked safely? |
| CRYPTO | Is cryptography strong and are keys managed properly? |
| AUTH | Are authentication and sessions handled safely? |
| NETWORK | Is traffic protected, and is the server identity verified/pinned? |
| PLATFORM | Are IPC, WebViews and the UI used safely? |
| CODE | Is the platform version current; are inputs validated? |
| RESILIENCE | Does the app resist tampering and reverse engineering? |
| PRIVACY | Does it minimise data collection? |

MASVS says **what** to verify; its companion the **MASTG** (testing guide) says **how**.

## 7. Static vs dynamic analysis

| | Static (this tool) | Dynamic (e.g. Frida, MobSF dynamic, Burp) |
|---|---|---|
| Runs the app? | No | Yes |
| Sees runtime values / server responses? | No | Yes |
| Speed / safety | Fast, no risk to a device | Slower, needs a device/emulator |
| Typical blind spot | computed values, obfuscation, server flaws | code paths you did not trigger |

Use static analysis to *find where to look*, then confirm dynamically.

## 8. ADB in one minute

`adb` (Android Debug Bridge) talks to a phone over USB (or Wi-Fi). It needs **Developer
options → USB debugging**. The phone shows an RSA fingerprint prompt the first time; accept it.
Useful commands (the `apk-sentinel devices|packages|pull` commands wrap these):

```
adb devices                              # is the phone connected and authorised?
adb shell pm list packages -3            # user-installed apps
adb shell pm path com.example.app        # where its APK(s) live (base.apk + split_*.apk)
adb pull /data/app/.../base.apk app.apk  # copy it to the laptop
```

**Split APKs:** Play Store apps are often delivered as `base.apk` + `split_config.*.apk`. The
manifest and the app's code are in `base.apk`, so that is the file to scan.

## 9. Words you will see in reports

| Term | Meaning |
|---|---|
| Finding | One observation: rule id, severity, evidence, location, fix, MASVS ids |
| Severity | info < low < medium < high < critical (impact if exploited as described) |
| Confidence | high/medium/low: how likely the finding is a true positive |
| Evidence | The literal string / flag / class that triggered the rule (secrets are masked) |
| False positive | A finding that is not exploitable in context, e.g. MD5 used as a cache key |
