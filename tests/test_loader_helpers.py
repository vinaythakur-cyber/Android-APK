"""Pure helpers inside loader.py (no APK needed)."""

import pytest

from apk_sentinel.loader import _parse_const_string, _trivial_return


@pytest.mark.parametrize(
    ("names", "outputs", "expected"),
    [
        (["return-void"], [""], "void"),
        (["const/4", "return"], ["v0, 1", "v0"], "true"),
        (["const/4", "return"], ["v0, 0", "v0"], "false"),
        (["const/4", "return-object"], ["v0, 0", "v0"], "null"),
        (["const/16", "return"], ["v0, 42", "v0"], "const"),
        (["const-string", "return-object"], ['v0, "x"', "v0"], "const"),
        (["invoke-static", "return-void"], ["x", ""], None),
        (["nop"], [""], None),
    ],
)
def test_trivial_return(names: list[str], outputs: list[str], expected: str | None) -> None:
    assert _trivial_return(names, outputs) == expected


def test_parse_const_string() -> None:
    assert _parse_const_string('v0, "hello, world"') == "hello, world"
    assert _parse_const_string("v0, bare") == "bare"
