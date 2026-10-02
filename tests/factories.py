"""Builders for synthetic ``LoadedApk`` objects, so analyzer tests need no real APK."""

from __future__ import annotations

from pathlib import Path

from apk_sentinel.apk_model import (
    ClassInfo,
    Component,
    ComponentKind,
    IntentFilter,
    LoadedApk,
    ManifestInfo,
    MethodInfo,
)
from apk_sentinel.models import Finding


def make_apk(
    *,
    manifest: ManifestInfo | None = None,
    dex_strings: tuple[str, ...] = (),
    resource_strings: dict[str, str] | None = None,
    network_security_configs: dict[str, str] | None = None,
    classes: tuple[ClassInfo, ...] = (),
) -> LoadedApk:
    return LoadedApk(
        path=Path("synthetic.apk"),
        sha256="0" * 64,
        size_bytes=1,
        manifest=manifest or ManifestInfo(package="com.example.app", min_sdk=26, target_sdk=34),
        dex_strings=dex_strings,
        resource_strings=resource_strings or {},
        network_security_configs=network_security_configs or {},
        classes=classes,
    )


def make_manifest(**overrides: object) -> ManifestInfo:
    defaults: dict[str, object] = {"package": "com.example.app", "min_sdk": 26, "target_sdk": 34}
    defaults.update(overrides)
    return ManifestInfo(**defaults)  # type: ignore[arg-type]


def component(
    kind: ComponentKind = ComponentKind.SERVICE,
    name: str = "com.example.app.Thing",
    **kwargs: object,
) -> Component:
    return Component(kind=kind, name=name, **kwargs)  # type: ignore[arg-type]


LAUNCHER = IntentFilter(
    actions=("android.intent.action.MAIN",), categories=("android.intent.category.LAUNCHER",)
)


def method(
    name: str = "run",
    *,
    ops: tuple[str, ...] = (),
    const_strings: tuple[str, ...] = (),
    references: tuple[str, ...] = (),
    insn_count: int | None = None,
    trivial_return: str | None = None,
    has_array_data: bool = False,
) -> MethodInfo:
    return MethodInfo(
        name=name,
        descriptor="()V",
        insn_count=insn_count if insn_count is not None else max(len(ops), 1),
        ops=ops,
        const_strings=const_strings,
        references=references,
        trivial_return=trivial_return,
        has_array_data=has_array_data,
    )


def klass(
    name: str = "Lcom/example/app/Foo;",
    *,
    interfaces: tuple[str, ...] = (),
    superclass: str = "Ljava/lang/Object;",
    methods: tuple[MethodInfo, ...] = (),
) -> ClassInfo:
    return ClassInfo(name=name, superclass=superclass, interfaces=interfaces, methods=methods)


def rule_ids(findings: list[Finding]) -> list[str]:
    return sorted(f.rule_id for f in findings)
