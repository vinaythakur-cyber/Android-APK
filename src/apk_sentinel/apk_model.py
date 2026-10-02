"""Input-side domain model: a plain-data view of an APK.

The :mod:`apk_sentinel.loader` module is the only place that talks to Androguard. It turns an
APK into the dataclasses below, and analyzers consume *only* these. That has two payoffs:

* analyzers are pure functions of data, so unit tests build tiny synthetic ``LoadedApk``
  objects instead of needing real APK files (which this repo never commits);
* swapping Androguard for another parser later only touches ``loader.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class ComponentKind(StrEnum):
    ACTIVITY = "activity"
    ACTIVITY_ALIAS = "activity-alias"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


@dataclass(frozen=True, slots=True)
class IntentFilter:
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()

    @property
    def is_launcher(self) -> bool:
        return (
            "android.intent.action.MAIN" in self.actions
            and "android.intent.category.LAUNCHER" in self.categories
        )


@dataclass(frozen=True, slots=True)
class Component:
    """An Activity / Service / Receiver / Provider declared in the manifest."""

    kind: ComponentKind
    name: str
    exported: bool | None = None  # None = ``android:exported`` not written in the manifest
    permission: str | None = None
    intent_filters: tuple[IntentFilter, ...] = ()
    read_permission: str | None = None  # providers only
    write_permission: str | None = None  # providers only
    grant_uri_permissions: bool = False  # providers only

    @property
    def is_launcher(self) -> bool:
        return any(f.is_launcher for f in self.intent_filters)

    def is_effectively_exported(self, target_sdk: int | None) -> bool:
        """Apply Android's defaults when ``android:exported`` is missing.

        * Explicit value always wins.
        * Providers default to exported only when targeting API < 17.
        * Everything else is exported iff it declares an intent filter
          (apps targeting API 31+ must write the attribute explicitly).
        """
        if self.exported is not None:
            return self.exported
        if self.kind is ComponentKind.PROVIDER:
            return target_sdk is not None and target_sdk < 17
        return bool(self.intent_filters)

    def is_protected(self) -> bool:
        """True when some permission guards access to this component."""
        if self.kind is ComponentKind.PROVIDER:
            return bool(self.permission or (self.read_permission and self.write_permission))
        return bool(self.permission)


@dataclass(frozen=True, slots=True)
class ManifestInfo:
    package: str
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: int | None = None
    target_sdk: int | None = None
    permissions: tuple[str, ...] = ()
    debuggable: bool | None = None
    allow_backup: bool | None = None
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None  # raw attribute value, e.g. "@xml/..."
    components: tuple[Component, ...] = ()


@dataclass(frozen=True, slots=True)
class MethodInfo:
    """A Dalvik method, reduced to the facts our analyzers care about."""

    name: str
    descriptor: str
    insn_count: int
    # Opcode mnemonics, only kept for tiny methods (<= SMALL_METHOD_LIMIT) so analyzers can
    # recognise bodies like ``return-void`` or ``const/4 v0, 1; return v0``.
    ops: tuple[str, ...] = ()
    const_strings: tuple[str, ...] = ()
    # Method / field references, e.g. ``Ljavax/crypto/Cipher;->getInstance(...)``.
    references: tuple[str, ...] = ()
    # For trivially short bodies: "void" (just ``return-void``), "true" / "false" (returns the
    # constant 1 / 0), "null" (returns constant 0 as an object), "const" (another constant).
    # ``None`` for anything that does real work.
    trivial_return: str | None = None
    # True if the method embeds a literal byte array (``fill-array-data``), e.g. ``{1,2,3,4}``.
    has_array_data: bool = False


SMALL_METHOD_LIMIT = 8


@dataclass(frozen=True, slots=True)
class ClassInfo:
    name: str  # dalvik form: Lcom/example/Foo;
    superclass: str
    interfaces: tuple[str, ...] = ()
    methods: tuple[MethodInfo, ...] = ()

    @property
    def dotted_name(self) -> str:
        return self.name.removeprefix("L").removesuffix(";").replace("/", ".")


@dataclass(slots=True)
class LoadedApk:
    """Everything the analyzers may look at, already decoded."""

    path: Path
    sha256: str
    size_bytes: int
    manifest: ManifestInfo
    file_names: tuple[str, ...] = ()
    dex_strings: tuple[str, ...] = ()
    resource_strings: dict[str, str] = field(default_factory=dict)  # name -> value
    # path inside the APK -> decoded (plain text) XML, for every ``<network-security-config>``
    network_security_configs: dict[str, str] = field(default_factory=dict)
    classes: tuple[ClassInfo, ...] = ()
    library_code_skipped: bool = False
