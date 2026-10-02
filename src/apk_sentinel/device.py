"""Pull an installed app's APK off a connected Android device with ``adb``.

You cannot "create" an APK from an installed app, but you do not need to: Android keeps the
original, signed APK on the device (``/data/app/.../base.apk``). ``adb pull`` copies it out.
Reading it needs no root because ``pm path`` runs as the shell user.

Security: ``adb shell`` hands its arguments to a shell *on the phone*. Package names are
therefore validated against Android's naming rules before they are ever sent, so a hostile
name such as ``x; rm -rf /sdcard`` is rejected locally.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

# Java-style package name: segments of letters/digits/underscore separated by dots, >= 2 segments.
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$")

#: (argv, timeout seconds) -> (return code, stdout, stderr)
Runner = Callable[[Sequence[str], float], tuple[int, str, str]]


class AdbError(RuntimeError):
    """Something went wrong talking to adb or the device (message is user-presentable)."""


@dataclass(frozen=True, slots=True)
class Device:
    serial: str
    state: str  # "device" (ready), "unauthorized", "offline", ...


def _subprocess_runner(argv: Sequence[str], timeout: float) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(  # argv list, no shell
            list(argv), capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise AdbError(
            "adb not found. Install Android platform-tools and make sure `adb` is on your PATH "
            "(https://developer.android.com/tools/releases/platform-tools)."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise AdbError(f"adb timed out after {timeout:.0f}s: {' '.join(argv)}") from exc
    return proc.returncode, proc.stdout, proc.stderr


def validate_package(package: str) -> str:
    if not PACKAGE_RE.fullmatch(package):
        raise AdbError(
            f"{package!r} is not a valid Android package name (expected e.g. com.example.app)."
        )
    return package


class Adb:
    def __init__(
        self,
        adb_path: str = "adb",
        serial: str | None = None,
        runner: Runner = _subprocess_runner,
    ) -> None:
        self._adb = adb_path
        self._serial = serial
        self._run_raw = runner

    def _run(self, *args: str, timeout: float = 60) -> str:
        argv = [self._adb, *(("-s", self._serial) if self._serial else ()), *args]
        code, out, err = self._run_raw(argv, timeout)
        if code != 0:
            message = (err or out).strip() or f"adb exited with status {code}"
            if "more than one device" in message:
                message += " Pick one with --serial (see `apk-sentinel devices`)."
            raise AdbError(message)
        return out

    def devices(self) -> list[Device]:
        # `adb devices` is host-level; do not pass -s.
        code, out, err = self._run_raw([self._adb, "devices"], 30)
        if code != 0:
            raise AdbError((err or out).strip() or f"adb exited with status {code}")
        devices = []
        for line in out.splitlines()[1:]:  # skip "List of devices attached"
            parts = line.split()
            if len(parts) >= 2:
                devices.append(Device(serial=parts[0], state=parts[1]))
        return devices

    def list_packages(self, *, include_system: bool = False, name_filter: str = "") -> list[str]:
        args = ["shell", "pm", "list", "packages"]
        if not include_system:
            args.append("-3")  # third-party (user-installed) apps only
        names = sorted(
            line.removeprefix("package:").strip()
            for line in self._run(*args).splitlines()
            if line.startswith("package:")
        )
        needle = name_filter.lower()
        return [n for n in names if needle in n.lower()]

    def apk_paths(self, package: str) -> list[str]:
        """Device paths of the base APK and any split APKs, base first."""
        validate_package(package)
        paths = [
            line.removeprefix("package:").strip()
            for line in self._run("shell", "pm", "path", package).splitlines()
            if line.startswith("package:") and line.strip().endswith(".apk")
        ]
        if not paths:
            raise AdbError(
                f"package {package} is not installed on the device "
                "(check the name with `apk-sentinel packages --filter ...`)."
            )
        paths.sort(key=lambda p: (not p.endswith("/base.apk"), p))
        return paths

    def pull(self, package: str, out_dir: Path) -> list[Path]:
        """Copy the app's APK(s) into ``out_dir``. Returns local paths, base APK first.

        The base APK is saved as ``<package>.apk``; split APKs as ``<package>.<split>.apk``.
        Scan the base APK: it holds the manifest and the app's code.
        """
        out_dir.mkdir(parents=True, exist_ok=True)
        pulled: list[Path] = []
        for remote in self.apk_paths(package):
            remote_name = remote.rsplit("/", 1)[-1]
            local_name = (
                f"{package}.apk" if remote_name == "base.apk" else f"{package}.{remote_name}"
            )
            local = out_dir / local_name
            self._run("pull", remote, str(local), timeout=300)
            pulled.append(local)
        return pulled
