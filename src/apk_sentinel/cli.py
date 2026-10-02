"""Command-line interface (Typer). Thin on purpose: parse args, call the library, set exit code."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from apk_sentinel import __version__
from apk_sentinel.analyzers import default_analyzers
from apk_sentinel.analyzers.secrets import RuleError
from apk_sentinel.device import Adb, AdbError
from apk_sentinel.loader import ApkLoadError
from apk_sentinel.models import ScanResult, Severity
from apk_sentinel.reporting import FORMATS, write_reports
from apk_sentinel.scanner import scan_apk

app = typer.Typer(
    name="apk-sentinel",
    help="Static security analyzer for Android APKs. Use only on apps you own "
    "or have permission to test.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

EXIT_USAGE = 2

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"apk-sentinel {__version__}")
        raise typer.Exit()


def _parse_severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _print_summary(result: ScanResult) -> None:
    target = result.target
    console.print(
        f"[bold]{target.package}[/bold] {target.version_name or ''} "
        f"(minSdk {target.min_sdk}, targetSdk {target.target_sdk})  sha256:{target.sha256[:12]}…"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("Finding")
    for finding in result.sorted_findings():
        style = _SEVERITY_STYLE[finding.severity]
        table.add_row(
            f"[{style}]{finding.severity.value.upper()}[/]", finding.rule_id, finding.title
        )
    console.print(table)
    counts = ", ".join(f"{n} {sev}" for sev, n in result.counts_by_severity().items() if n)
    console.print(f"{len(result.findings)} finding(s): {counts or 'none'}")
    for error in result.errors:
        err_console.print(f"[red]analyzer '{error.analyzer}' failed:[/red] {error.message}")


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """apk-sentinel entry point."""


@app.command()
def scan(
    apk: Annotated[
        Path,
        typer.Argument(
            exists=True, dir_okay=False, readable=True, help="Path to the .apk file to analyze."
        ),
    ],
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Directory for report.json / report.html.")
    ] = Path("report"),
    formats: Annotated[
        list[str] | None,
        typer.Option(
            "--format",
            "-f",
            help=f"Report format(s); repeat for several. Choices: {', '.join(FORMATS)}. "
            "Default: all.",
        ),
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(
            "--fail-on",
            help="Exit with status 1 if any finding is at/above this severity "
            "(info, low, medium, high, critical). For CI use.",
        ),
    ] = None,
    include_libraries: Annotated[
        bool,
        typer.Option(
            "--include-libraries",
            help="Also analyze bundled library code (slower, noisier).",
        ),
    ] = False,
    secrets_rules: Annotated[
        Path | None,
        typer.Option(
            "--secrets-rules",
            exists=True,
            dir_okay=False,
            help="Custom secrets rule file (same format as rules/secrets.yaml).",
        ),
    ] = None,
) -> None:
    """Analyze APK, print findings, and write report files into OUT."""
    threshold = _parse_severity(fail_on) if fail_on else None
    chosen = tuple(formats) if formats else FORMATS
    unknown = sorted(set(chosen) - set(FORMATS))
    if unknown:
        raise typer.BadParameter(f"unknown format(s) {unknown}; choose from {list(FORMATS)}")
    try:
        analyzers = default_analyzers(secrets_rules)
        result = scan_apk(apk, analyzers, include_libraries=include_libraries)
    except (ApkLoadError, RuleError) as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc

    _print_summary(result)
    try:
        written = write_reports(result, out, chosen)
    except OSError as exc:
        err_console.print(f"[red]error:[/red] cannot write reports to {out}: {exc}")
        raise typer.Exit(EXIT_USAGE) from exc
    for path in written:
        console.print(f"wrote [bold]{path}[/bold]")
    if threshold is not None and result.exceeds(threshold):
        raise typer.Exit(1)


# -- Android device helpers (adb) --------------------------------------------------------

SerialOption = Annotated[
    str | None,
    typer.Option("--serial", "-s", help="Device serial when several are connected."),
]


def _adb_or_exit(serial: str | None) -> Adb:
    return Adb(serial=serial)


@app.command()
def devices() -> None:
    """List Android devices visible to adb."""
    try:
        found = _adb_or_exit(None).devices()
    except AdbError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc
    if not found:
        err_console.print(
            "No devices. Enable USB debugging, connect the phone and accept the RSA prompt."
        )
        raise typer.Exit(1)
    for device in found:
        note = "" if device.state == "device" else "  (not ready: accept the prompt on the phone)"
        console.print(f"{device.serial}\t{device.state}{note}")


@app.command()
def packages(
    name_filter: Annotated[
        str, typer.Option("--filter", "-f", help="Only packages whose name contains this text.")
    ] = "",
    include_system: Annotated[
        bool, typer.Option("--all", help="Include system apps (default: user-installed only).")
    ] = False,
    serial: SerialOption = None,
) -> None:
    """List installed packages on the connected device."""
    try:
        names = _adb_or_exit(serial).list_packages(
            include_system=include_system, name_filter=name_filter
        )
    except AdbError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc
    for name in names:
        console.print(name)
    err_console.print(f"{len(names)} package(s)")


@app.command()
def pull(
    package: Annotated[str, typer.Argument(help="Package name, e.g. com.example.app.")],
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Directory to save the APK(s) into.")
    ] = Path("samples"),
    serial: SerialOption = None,
) -> None:
    """Copy an installed app's APK from the device so it can be scanned.

    Only pull apps you own or have permission to test.
    """
    try:
        files = _adb_or_exit(serial).pull(package, out)
    except AdbError as exc:
        err_console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_USAGE) from exc
    for path in files:
        console.print(f"saved [bold]{path}[/bold]")
    if len(files) > 1:
        console.print(f"[dim]split APKs detected; scan the base APK: {files[0]}[/dim]")
    console.print(f"next: apk-sentinel scan {files[0]} --out report/")
