"""Turn decoded ``AndroidManifest.xml`` text into a :class:`ManifestInfo`.

Pure stdlib, no Androguard: the loader decodes the binary XML (AXML) to text first. Keeping
the parser separate lets tests feed hand-written manifests, and keeps the loader thin.

Security note: the XML we parse is *generated* by Androguard from binary XML, so it contains
no DTDs/entities even for a hostile APK.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from apk_sentinel.apk_model import (
    Component,
    ComponentKind,
    IntentFilter,
    ManifestInfo,
)

ANDROID_NS = "http://schemas.android.com/apk/res/android"

_KIND_BY_TAG = {kind.value: kind for kind in ComponentKind}


def _attr(element: ET.Element, name: str) -> str | None:
    """Read ``android:<name>``; fall back to the un-namespaced attribute (e.g. ``package``)."""
    value = element.get(f"{{{ANDROID_NS}}}{name}")
    return value if value is not None else element.get(name)


def _bool(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1", "0xffffffff", "-1"}:
        return True
    if lowered in {"false", "0", "0x0"}:
        return False
    return None  # e.g. an unresolved resource reference such as "@bool/debug"


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None  # a codename such as "UpsideDownCake"


def _qualify(package: str, name: str) -> str:
    """Resolve ``.Foo`` / ``Foo`` to a fully-qualified class name."""
    if name.startswith("."):
        return package + name
    if "." not in name:
        return f"{package}.{name}"
    return name


def _parse_component(element: ET.Element, kind: ComponentKind, package: str) -> Component | None:
    raw_name = _attr(element, "name")
    if not raw_name:
        return None
    filters = tuple(
        IntentFilter(
            actions=tuple(n for a in f.findall("action") if (n := _attr(a, "name"))),
            categories=tuple(n for c in f.findall("category") if (n := _attr(c, "name"))),
        )
        for f in element.findall("intent-filter")
    )
    return Component(
        kind=kind,
        name=_qualify(package, raw_name),
        exported=_bool(_attr(element, "exported")),
        permission=_attr(element, "permission"),
        intent_filters=filters,
        read_permission=_attr(element, "readPermission"),
        write_permission=_attr(element, "writePermission"),
        grant_uri_permissions=bool(_bool(_attr(element, "grantUriPermissions"))),
    )


def parse_manifest_xml(xml: str | bytes) -> ManifestInfo:
    """Parse manifest XML text. Raises ``ValueError`` if it is not a manifest."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ValueError(f"manifest is not well-formed XML: {exc}") from exc
    if root.tag != "manifest":
        raise ValueError(f"expected <manifest> root element, found <{root.tag}>")

    package = root.get("package", "")
    uses_sdk = root.find("uses-sdk")
    min_sdk = _int(_attr(uses_sdk, "minSdkVersion")) if uses_sdk is not None else None
    target_sdk = _int(_attr(uses_sdk, "targetSdkVersion")) if uses_sdk is not None else None

    permissions = tuple(
        dict.fromkeys(  # de-duplicate, keep order
            name
            for tag in ("uses-permission", "uses-permission-sdk-23")
            for el in root.findall(tag)
            if (name := _attr(el, "name"))
        )
    )

    application = root.find("application")
    components: list[Component] = []
    if application is not None:
        for child in application:
            kind = _KIND_BY_TAG.get(child.tag)
            if kind is None:
                continue
            component = _parse_component(child, kind, package)
            if component is not None:
                components.append(component)

    def app_flag(name: str) -> bool | None:
        return _bool(_attr(application, name)) if application is not None else None

    return ManifestInfo(
        package=package,
        version_name=_attr(root, "versionName"),
        version_code=_attr(root, "versionCode"),
        min_sdk=min_sdk,
        target_sdk=target_sdk,
        permissions=permissions,
        debuggable=app_flag("debuggable"),
        allow_backup=app_flag("allowBackup"),
        uses_cleartext_traffic=app_flag("usesCleartextTraffic"),
        network_security_config=(
            _attr(application, "networkSecurityConfig") if application is not None else None
        ),
        components=tuple(components),
    )
