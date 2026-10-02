"""The only module that imports Androguard.

``load_apk`` opens an APK and converts it into the plain-data :class:`LoadedApk`. Everything
Androguard-specific (binary XML decoding, DEX parsing, logging noise) is contained here.

Concepts used (see docs/CONCEPTS.md):
  * An APK is a ZIP. ``AndroidManifest.xml`` inside is *binary XML* (AXML), not text.
  * ``classes*.dex`` holds the compiled Dalvik bytecode: a string pool, a type/method table and
    per-method instruction streams.
"""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from androguard.core.apk import APK
from androguard.core.axml import AXMLPrinter
from androguard.core.dex import DEX
from loguru import logger

from apk_sentinel.apk_model import (
    SMALL_METHOD_LIMIT,
    ClassInfo,
    LoadedApk,
    MethodInfo,
)
from apk_sentinel.manifest_parser import parse_manifest_xml

# Androguard 4 logs every parsed XML attribute at DEBUG through loguru; silence it.
logger.disable("androguard")

# Class-name prefixes (Dalvik form) for platform / popular library code. Decoding bytecode is
# the slow part of a scan and findings inside libraries are rarely actionable, so by default we
# only decode the app's own code. Override with ``include_libraries=True``.
DEFAULT_LIBRARY_PREFIXES: tuple[str, ...] = (
    "Landroid/",
    "Landroidx/",
    "Ljava/",
    "Ljavax/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lcom/google/android/",
    "Lcom/google/firebase/",
    "Lcom/google/gson/",
    "Lcom/google/common/",
    "Lcom/google/protobuf/",
    "Lcom/squareup/",
    "Lokhttp3/",
    "Lokio/",
    "Lretrofit2/",
    "Lorg/bouncycastle/",
    "Lorg/apache/",
    "Lorg/jetbrains/",
    "Lcom/bumptech/",
    "Lcom/facebook/",
    "Ldagger/",
    "Lio/reactivex/",
)

_MAX_RESOURCE_STRING = 2048


class ApkLoadError(Exception):
    """The file is not a readable APK (corrupt, not a ZIP, no manifest, ...)."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_const_string(output: str) -> str:
    """``v0, "text"`` -> ``text``."""
    _, _, literal = output.partition(", ")
    if len(literal) >= 2 and literal.startswith('"') and literal.endswith('"'):
        return literal[1:-1]
    return literal


def _trivial_return(names: list[str], outputs: list[str]) -> str | None:
    """Classify bodies that do nothing but return (see ``MethodInfo.trivial_return``)."""
    if names == ["return-void"]:
        return "void"
    if (
        len(names) == 2
        and names[0].startswith("const")
        and names[1] in {"return", "return-object", "return-wide"}
    ):
        _, _, literal = outputs[0].partition(", ")
        try:
            value = int(literal, 0)
        except ValueError:
            return "const"
        if value == 0:
            return "null" if names[1] == "return-object" else "false"
        return "true" if value == 1 and names[1] == "return" else "const"
    return None


def _method_info(method: Any) -> MethodInfo | None:
    code = method.get_code()
    if code is None:  # abstract or native
        return None
    instructions = list(code.get_bc().get_instructions())
    ops: list[str] = []
    const_strings: list[str] = []
    references: list[str] = []
    for ins in instructions:
        name = ins.get_name()
        output = ins.get_output()
        ops.append(name)
        if name.startswith("const-string"):
            const_strings.append(_parse_const_string(output))
        elif "->" in output:
            references.append(output.rsplit(", ", 1)[-1])
    small = len(instructions) <= SMALL_METHOD_LIMIT
    return MethodInfo(
        name=method.get_name(),
        descriptor=method.get_descriptor(),
        insn_count=len(instructions),
        ops=tuple(ops) if small else (),
        const_strings=tuple(const_strings),
        references=tuple(references),
        trivial_return=(
            _trivial_return(ops, [i.get_output() for i in instructions]) if len(ops) <= 2 else None
        ),
        has_array_data="fill-array-data" in ops,
    )


def _class_infos(dex: Any, skip_prefixes: tuple[str, ...]) -> tuple[list[ClassInfo], bool]:
    classes: list[ClassInfo] = []
    skipped = False
    for cls in dex.get_classes():
        name = cls.get_name()
        if name.startswith(skip_prefixes):
            skipped = True
            continue
        methods = tuple(m for method in cls.get_methods() if (m := _method_info(method)))
        classes.append(
            ClassInfo(
                name=name,
                superclass=cls.get_superclassname() or "",
                interfaces=tuple(cls.get_interfaces() or ()),
                methods=methods,
            )
        )
    return classes, skipped


def _network_security_configs(apk: APK) -> dict[str, str]:
    """Find every ``<network-security-config>`` file, whatever the manifest says it is called.

    The manifest attribute is a resource id (``@7F020000``), which would need the resource
    table to resolve. Scanning ``res/xml/*`` for the root element is simpler and also survives
    resource-name obfuscation.
    """
    found: dict[str, str] = {}
    for name in apk.get_files():
        if not (name.startswith("res/xml/") and name.endswith(".xml")):
            continue
        try:
            printer = AXMLPrinter(apk.get_file(name))
            if not printer.is_valid():
                continue
            text = printer.get_xml().decode("utf-8", errors="replace")
        except Exception:  # one unreadable XML file must not abort the scan
            continue
        if "<network-security-config" in text:
            found[name] = text
    return found


def _resource_strings(apk: APK) -> dict[str, str]:
    resources = apk.get_android_resources()
    if resources is None:
        return {}
    values: dict[str, str] = {}
    for package in resources.get_packages_names():
        try:
            root = ET.fromstring(resources.get_string_resources(package))
        except Exception:  # best effort: not every package has string resources
            continue
        for element in root.findall("string"):
            key, text = element.get("name"), element.text
            if key and text:
                values.setdefault(key, text[:_MAX_RESOURCE_STRING])
    return values


def _unique(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


def load_apk(
    path: Path,
    *,
    include_libraries: bool = False,
    library_prefixes: tuple[str, ...] = DEFAULT_LIBRARY_PREFIXES,
) -> LoadedApk:
    """Decode ``path`` into a :class:`LoadedApk`. Raises :class:`ApkLoadError` on bad input."""
    path = Path(path)
    try:
        apk = APK(str(path))
        manifest_xml = apk.get_android_manifest_axml().get_xml()
        manifest = parse_manifest_xml(manifest_xml)
    except Exception as exc:
        raise ApkLoadError(f"cannot read {path.name} as an APK: {exc}") from exc

    strings: list[str] = []
    classes: list[ClassInfo] = []
    skipped = False
    skip_prefixes = () if include_libraries else library_prefixes
    try:
        for raw_dex in apk.get_all_dex():
            dex = DEX(raw_dex)
            strings.extend(dex.get_strings())
            dex_classes, dex_skipped = _class_infos(dex, skip_prefixes)
            classes.extend(dex_classes)
            skipped = skipped or dex_skipped
    except Exception as exc:
        raise ApkLoadError(f"cannot parse DEX code in {path.name}: {exc}") from exc

    return LoadedApk(
        path=path,
        sha256=_sha256(path),
        size_bytes=path.stat().st_size,
        manifest=manifest,
        file_names=tuple(apk.get_files()),
        dex_strings=_unique(strings),
        resource_strings=_resource_strings(apk),
        network_security_configs=_network_security_configs(apk),
        classes=tuple(classes),
        library_code_skipped=skipped,
    )
