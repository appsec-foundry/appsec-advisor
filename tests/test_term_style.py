"""Tests for renderers/term_style — the one colour rule of the headless console."""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from renderers.term_style import Style, color_enabled, logo, main  # noqa: E402

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize(
    ("stream", "mode", "env", "expected"),
    [
        (_Tty(), "auto", {}, True),
        (io.StringIO(), "auto", {}, False),
        (_Tty(), "auto", {"NO_COLOR": "1"}, False),
        (io.StringIO(), "auto", {"FORCE_COLOR": "1"}, True),
        (io.StringIO(), "auto", {"FORCE_COLOR": "0"}, False),
        (_Tty(), "auto", {"NO_COLOR": "1", "FORCE_COLOR": "1"}, False),
        (_Tty(), "auto", {"TERM": "dumb"}, False),
        (io.StringIO(), "always", {"NO_COLOR": "1"}, True),
        (_Tty(), "never", {"FORCE_COLOR": "1"}, False),
        (None, "auto", {}, False),
    ],
)
def test_color_rule(stream, mode, env, expected) -> None:
    assert color_enabled(stream, mode, env) is expected


def test_disabled_style_returns_text_unchanged() -> None:
    st = Style(False)
    assert st("x", "critical", "bold") == "x"
    assert st.gradient("appsec") == "appsec"
    assert st.bar(1, 2, width=4) == "━━──"


def test_truecolor_only_with_colorterm() -> None:
    assert "38;2;" in Style.for_stream(_Tty(), env={"COLORTERM": "truecolor"})("x", "ok")
    basic = Style.for_stream(_Tty(), env={})("x", "ok")
    assert basic == "\x1b[32mx\x1b[0m"


def test_gradient_falls_back_to_the_accent_without_truecolor() -> None:
    assert Style(True, False).gradient("ab") == "\x1b[36mab\x1b[0m"
    coloured = Style(True, True).gradient("ab")
    assert _ANSI.sub("", coloured) == "ab"
    assert coloured.endswith("\x1b[0m")


def test_bar_keeps_its_width_and_clamps() -> None:
    st = Style(True, True)
    for done, total in ((0, 4), (2, 4), (4, 4), (9, 4), (1, 0)):
        assert len(_ANSI.sub("", st.bar(done, total, width=10))) == 10


def test_logo_command_is_plain_off_a_terminal(capsys, monkeypatch) -> None:
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    main(["logo", "headless"])
    lines = capsys.readouterr().out.splitlines()
    assert "\x1b" not in "".join(lines)
    assert lines[0] == "   ╭  ▄█▄  ╮  appsec-advisor"
    assert lines[1] == "   │ █████ │  code-derived STRIDE threat modeling"
    assert lines[2].startswith("   ╰  ▀█▀  ╯  v") and lines[2].endswith(" · headless")


def test_logo_lines_keep_their_width_in_colour() -> None:
    plain = logo(Style(False), "v1 · headless")
    coloured = logo(Style(True, True), "v1 · headless")
    assert [_ANSI.sub("", line) for line in coloured] == plain
