from collections.abc import Sequence
from pathlib import Path

import pytest
from typer.testing import CliRunner

import apk_sentinel.cli as cli_module
from apk_sentinel.cli import app
from apk_sentinel.device import Adb, AdbError, Device, validate_package


class FakeAdb:
    """Records argv and replies from a {command-tail: (code, stdout, stderr)} table."""

    def __init__(self, replies: dict[str, tuple[int, str, str]]) -> None:
        self.replies = replies
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], timeout: float) -> tuple[int, str, str]:
        self.calls.append(list(argv))
        key = " ".join(a for a in argv[1:] if a not in {"-s"} and not a.startswith("SER"))
        for prefix, reply in self.replies.items():
            if key.startswith(prefix):
                return reply
        return 1, "", f"unexpected command: {key}"


PM_PATH = (
    "package:/data/app/~~x/com.example.app-y/base.apk\n"
    "package:/data/app/~~x/com.example.app-y/split_config.arm64_v8a.apk\n"
)


@pytest.mark.parametrize("name", ["com.example.app", "a.b", "org.foo_bar.Baz9"])
def test_valid_package_names(name: str) -> None:
    assert validate_package(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "singleword", "com.example.app; rm -rf /sdcard", "com..x", "-3", "a b.c", "$(id).x"],
)
def test_hostile_or_invalid_package_names_are_rejected(name: str) -> None:
    with pytest.raises(AdbError, match="not a valid"):
        validate_package(name)


def test_devices_parsing() -> None:
    fake = FakeAdb(
        {"devices": (0, "List of devices attached\nR58M123\tdevice\nemu-5554\toffline\n\n", "")}
    )
    assert Adb(runner=fake).devices() == [
        Device("R58M123", "device"),
        Device("emu-5554", "offline"),
    ]


def test_list_packages_filters_in_python_and_defaults_to_third_party() -> None:
    fake = FakeAdb({"shell pm list packages": (0, "package:com.b.app\npackage:org.a.tool\n", "")})
    adb = Adb(runner=fake)
    assert adb.list_packages() == ["com.b.app", "org.a.tool"]
    assert adb.list_packages(name_filter="TOOL") == ["org.a.tool"]
    assert "-3" in fake.calls[0]
    adb.list_packages(include_system=True)
    assert "-3" not in fake.calls[-1]


def test_apk_paths_base_first() -> None:
    fake = FakeAdb({"shell pm path": (0, PM_PATH, "")})
    paths = Adb(runner=fake).apk_paths("com.example.app")
    assert paths[0].endswith("/base.apk")
    assert len(paths) == 2


def test_not_installed_gives_helpful_error() -> None:
    fake = FakeAdb({"shell pm path": (0, "", "")})
    with pytest.raises(AdbError, match="not installed"):
        Adb(runner=fake).apk_paths("com.example.app")


def test_package_is_validated_before_anything_is_sent() -> None:
    fake = FakeAdb({})
    with pytest.raises(AdbError):
        Adb(runner=fake).apk_paths("x; reboot")
    assert fake.calls == []


def test_pull_names_files_and_uses_serial(tmp_path: Path) -> None:
    fake = FakeAdb(
        {
            "shell pm path": (0, PM_PATH, ""),
            "pull": (0, "1 file pulled", ""),
        }
    )
    files = Adb(serial="SER1", runner=fake).pull("com.example.app", tmp_path / "out")
    assert [f.name for f in files] == [
        "com.example.app.apk",
        "com.example.app.split_config.arm64_v8a.apk",
    ]
    assert all(call[1:3] == ["-s", "SER1"] for call in fake.calls)
    pull_calls = [c for c in fake.calls if "pull" in c]
    assert len(pull_calls) == 2


def test_multiple_devices_error_hints_at_serial() -> None:
    fake = FakeAdb({"shell pm path": (1, "", "adb: more than one device/emulator")})
    with pytest.raises(AdbError, match="--serial"):
        Adb(runner=fake).apk_paths("com.example.app")


def test_missing_adb_binary_message() -> None:
    adb = Adb(adb_path="definitely-not-adb-xyz")
    with pytest.raises(AdbError, match="adb not found"):
        adb.devices()


def test_cli_pull_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAdb({"shell pm path": (0, PM_PATH, ""), "pull": (0, "ok", "")})
    monkeypatch.setattr(cli_module, "_adb_or_exit", lambda serial: Adb(serial=serial, runner=fake))
    result = CliRunner().invoke(app, ["pull", "com.example.app", "-o", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "com.example.app.apk" in result.output
    assert "apk-sentinel scan" in result.output
    assert "split APKs detected" in result.output


def test_cli_pull_reports_adb_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAdb({"shell pm path": (0, "", "")})
    monkeypatch.setattr(cli_module, "_adb_or_exit", lambda serial: Adb(serial=serial, runner=fake))
    result = CliRunner().invoke(app, ["pull", "com.example.app", "-o", str(tmp_path)])
    assert result.exit_code == 2
    assert "not installed" in result.output


def test_cli_devices_no_device(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAdb({"devices": (0, "List of devices attached\n\n", "")})
    monkeypatch.setattr(cli_module, "_adb_or_exit", lambda serial: Adb(serial=serial, runner=fake))
    result = CliRunner().invoke(app, ["devices"])
    assert result.exit_code == 1
    assert "USB debugging" in result.output


def test_cli_packages_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAdb({"shell pm list packages": (0, "package:com.a.b\npackage:org.c.d\n", "")})
    monkeypatch.setattr(cli_module, "_adb_or_exit", lambda serial: Adb(serial=serial, runner=fake))
    result = CliRunner().invoke(app, ["packages", "-f", "org"])
    assert result.exit_code == 0
    assert "org.c.d" in result.output
    assert "com.a.b" not in result.output
