#!/usr/bin/env python3
"""Build the intentionally vulnerable fixture APK from ``tests/fixture_app`` (never committed).

    python scripts/build_fixture_apk.py            # -> samples/vulnapp.apk
    APK_SENTINEL_SAMPLE_APK=samples/vulnapp.apk pytest

The fixture is a tiny, non-functional "app" (manifest + a few smali classes) that deliberately
contains every pattern apk-sentinel detects, so the whole pipeline can be exercised against a
*real* binary manifest and DEX without downloading anything third-party.

Requirements: Java 11+ on PATH, and network access the first time (to fetch apktool, which is
pinned by SHA-256 and cached in ``.cache/``).

Fake secrets are generated here rather than stored in the repo, so scanners such as GitHub
push protection never see secret-shaped strings in source files.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixture_app"
CACHE = ROOT / ".cache"
OUTPUT = ROOT / "samples" / "vulnapp.apk"

APKTOOL_VERSION = "2.9.3"
APKTOOL_URL = (
    f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/"
    f"apktool_{APKTOOL_VERSION}.jar"
)
APKTOOL_SHA256 = "7956eb04194300ce0d0a84ad18771eebc94b89fb8d1ddcce8ea4c056818646f4"

# Placeholders in the fixture sources -> fake, correctly-shaped secrets.
FAKE_SECRETS = {
    "@@AWS_KEY@@": "AKIA" + "IOSFODNN7EXAMPLE",
    "@@GOOGLE_API_KEY@@": "AIza" + "SyD" + "fake" * 7 + "1234",
    "@@GITHUB_TOKEN@@": "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "@@JWT@@": (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ),
}


def ensure_apktool() -> Path:
    jar = CACHE / f"apktool_{APKTOOL_VERSION}.jar"
    if not jar.exists():
        CACHE.mkdir(exist_ok=True)
        print(f"downloading apktool {APKTOOL_VERSION} ...")
        with urllib.request.urlopen(APKTOOL_URL, timeout=120) as response:
            jar.write_bytes(response.read())
    digest = hashlib.sha256(jar.read_bytes()).hexdigest()
    if digest != APKTOOL_SHA256:
        jar.unlink()
        sys.exit(f"apktool checksum mismatch ({digest}); refusing to run it. Delete .cache/")
    return jar


def stage_sources(destination: Path) -> None:
    shutil.copytree(FIXTURE, destination, dirs_exist_ok=True)
    for path in destination.rglob("*"):
        if path.is_file() and path.suffix in {".smali", ".xml", ".yml"}:
            text = path.read_text()
            for placeholder, value in FAKE_SECRETS.items():
                text = text.replace(placeholder, value)
            path.write_text(text)


def main() -> None:
    if shutil.which("java") is None:
        sys.exit("Java is required (apktool is a Java program). Install a JRE and retry.")
    jar = ensure_apktool()
    OUTPUT.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / "app"
        stage_sources(staged)
        subprocess.run(
            ["java", "-jar", str(jar), "b", str(staged), "-o", str(OUTPUT), "-f"],
            check=True,
        )
    print(
        f"built {OUTPUT.relative_to(ROOT)}  (scan it: apk-sentinel scan {OUTPUT.relative_to(ROOT)})"
    )


if __name__ == "__main__":
    main()
