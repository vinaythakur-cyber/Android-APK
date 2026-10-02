"""Small helpers shared by the bytecode-based analyzers (crypto, network)."""

from __future__ import annotations

from collections.abc import Iterator

from apk_sentinel.apk_model import ClassInfo, LoadedApk, MethodInfo


def iter_methods(apk: LoadedApk) -> Iterator[tuple[ClassInfo, MethodInfo]]:
    for cls in apk.classes:
        for method in cls.methods:
            yield cls, method


def calls(method: MethodInfo, *prefixes: str) -> bool:
    """True if the method references any member whose signature starts with a prefix.

    Prefixes look like ``Ljavax/crypto/Cipher;->getInstance`` (class + ``->`` + member name).
    """
    return any(ref.startswith(prefixes) for ref in method.references)


def where(cls: ClassInfo, method: MethodInfo) -> str:
    """Human-readable code location: ``com.example.Foo.bar()``."""
    return f"{cls.dotted_name}.{method.name}()"
