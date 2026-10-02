# Architecture

apk-sentinel is a **pipeline**: decode the APK once into plain data, run independent analyzers
over that data, collect uniform findings, render reports.

```
                      ┌──────────────────────────── scanner.py ────────────────────────────┐
 app.apk ──► loader.py ──► LoadedApk ──┬─► ManifestAnalyzer ─┐                              │
 (zip)       (Androguard)  (plain data) ├─► SecretsAnalyzer ──┤                              │
                                        ├─► CryptoAnalyzer ───┼─► list[Finding] ─► ScanResult ─► reporting/
                                        └─► NetworkAnalyzer ──┘   (models.py)                    ├─ json_report.py
                                             ▲                                                   └─ html_report.py
                                  rules/secrets.yaml                                                  └─ templates/report.html.j2
 cli.py (Typer) drives all of it; device.py (adb) only feeds it APK files.
```

## Dependency rules (the whole design in four lines)

1. `models.py` and `apk_model.py` import **nothing** from the package. Everyone may import them.
2. `loader.py` is the **only** module that imports Androguard.
3. Analyzers import only `models`, `apk_model` and helpers. They never import the loader, so
   they are pure functions of data and trivially unit-testable.
4. `cli.py` contains no analysis logic: parse arguments → call library → set exit code.

## Modules

| Path | Responsibility | Why it is separate |
|---|---|---|
| `models.py` | `Severity`, `Confidence`, `Finding`, `TargetInfo`, `ScanResult` (the **output** contract) | Reporters and analyzers agree on one type; no cycles. |
| `apk_model.py` | `LoadedApk`, `ManifestInfo`, `Component`, `ClassInfo`, `MethodInfo` (the **input** contract) | Analyzers test against hand-made objects, no APK needed. |
| `loader.py` | Androguard → `LoadedApk`; silences loguru; skips library code by default | Isolates a third-party parser behind one seam. |
| `manifest_parser.py` | Manifest XML text → `ManifestInfo` (pure stdlib) | Testable with hand-written XML. |
| `analyzers/base.py` | `Analyzer` ABC: `name`, `analyze(apk) -> list[Finding]` | The plug-in interface. |
| `analyzers/manifest.py` | Debuggable, backup, exported components, cleartext, SDK levels, permissions | Declared attack surface. |
| `analyzers/secrets.py` + `rules/secrets.yaml` | Regex rules over DEX strings and string resources | Rules are *data*: add a pattern without writing Python. |
| `analyzers/crypto.py` | Pairs "calls `Cipher.getInstance`" with the string literal it uses | Bytecode-level heuristics. |
| `analyzers/network.py` | Trust-all managers, hostname verifiers, WebView SSL bypass, `network_security_config.xml` | Bytecode + configuration. |
| `analyzers/_code.py` | Shared helpers (`calls`, `iter_methods`, `where`) | Keeps analyzers short. |
| `scanner.py` | Runs analyzers with crash isolation → `ScanResult` | One place that decides what happens when a check fails. |
| `reporting/` | JSON for machines, self-contained Jinja2 HTML for humans | Presentation is independent of analysis. |
| `masvs.py` | OWASP MASVS v2 control catalogue | Report shows requirement text next to each id. |
| `device.py` | `adb` wrapper: list devices/packages, pull base + split APKs | Optional convenience; no effect on analysis. |
| `cli.py` | Typer commands: `scan`, `devices`, `packages`, `pull` | Thin shell. |

## Data flow in detail

1. **Load.** `load_apk(path)` opens the zip with Androguard, decodes the binary manifest to XML
   text, parses it into `ManifestInfo`, reads every DEX string, and (for non-library classes)
   reduces each method to facts: its string constants, the members it references, whether its
   body is trivially `return-void` / `return true`, whether it embeds a byte-array literal.
2. **Analyze.** Every analyzer receives the same `LoadedApk` and returns `Finding`s. A crash in
   one analyzer is caught by the scanner, recorded in `ScanResult.errors`, and shown in the
   report; the others still run.
3. **Report.** Findings are sorted (severity, analyzer, rule, location) and rendered.

## Why heuristics, and what that means

The crypto and network checks look at *literals and call sites*, not data flow. That is fast
and needs no decompiler, but it can miss values computed at runtime and can flag harmless code
(for example MD5 used as a cache key). Hence every finding has a **confidence** (`high`,
`medium`, `low`) and always names the class/method so a human can verify in seconds.

## Threat model of the tool itself

An APK under analysis is **untrusted input**. Mitigations:

| Risk | Mitigation |
|---|---|
| HTML report injection from strings inside a hostile APK | Jinja2 `autoescape=True` (explicit, because `select_autoescape` does not recognise `*.html.j2`); covered by a test with `<script>` payloads |
| Leaking real secrets into reports | Secret evidence is masked (`AKIA************LE (20 chars)`); only non-secret matches (e.g. a PEM header) are shown verbatim |
| Command injection through `adb shell` | Package names validated against Android's naming rules before being sent; `subprocess` is always called with an argv list, never `shell=True` |
| Malicious YAML | `yaml.safe_load` only |
| One bad XML file aborting a scan | Per-file `try/except` in the loader; the scan continues |
| Report written to a read-only path | Caught, reported, exit code 2 |

Not handled (documented limits): decompression bombs and pathological APKs can still exhaust
memory because parsing is delegated to Androguard. Run unknown samples in a container
(`docker run --memory=2g ...`).

## Extending

**Add a secret pattern** (no code): append an entry to `rules/secrets.yaml`, or pass your own
file with `--secrets-rules`. See the header of that file for the fields.

**Add an analyzer**:

1. Create `analyzers/my_check.py` with `class MyAnalyzer(Analyzer)`; set `name`, implement
   `analyze(apk) -> list[Finding]` using only `apk_model` types.
2. Register it in `analyzers/__init__.py::default_analyzers`.
3. Write unit tests with `tests/factories.py` helpers (`make_apk`, `klass`, `method`, ...).
4. Add its rule ids to `docs/RULES.md` (a test fails if you forget).

## Testing strategy

| Layer | How |
|---|---|
| Analyzers, parser, models, reports, CLI | Unit tests on synthetic data; no APK files |
| Loader + whole pipeline | Integration tests on a real APK built from `tests/fixture_app` (`scripts/build_fixture_apk.py`); skipped unless `APK_SENTINEL_SAMPLE_APK` is set; run in CI |
| Docs drift | `tests/test_docs.py` fails if a rule id exists in code but not in `docs/RULES.md` |
| Quality gates | ruff (lint + format), mypy `--strict`, coverage reported in CI |

Repository policy: **no APK is ever committed** (`.gitignore` blocks `*.apk`, `*.zip`, `samples/`).

## Roadmap ideas

SARIF output for GitHub code scanning; zero-IV and key-size checks; WebView settings
(`setJavaScriptEnabled`, `addJavascriptInterface`); `allowFileAccess`; exported-component
*reachability* (intent-filter data schemes); native-library hardening flags (NX, RELRO, PIE);
baseline/suppression files; a FastAPI upload wrapper.
