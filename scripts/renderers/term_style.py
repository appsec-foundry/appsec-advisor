#!/usr/bin/env python3
"""Terminal colour for the headless console.

One rule decides whether a stream gets colour, so the live progress view, the
completion summary and the cost tables never disagree:

1. ``--color always`` / ``never`` from the caller wins. ``run-headless.sh``
   passes ``always`` when it captures a script's output into a variable and
   prints it to a terminal itself.
2. ``NO_COLOR`` (any non-empty value) disables colour.
3. ``FORCE_COLOR`` (non-empty, not ``0``) enables it.
4. ``TERM=dumb`` disables it.
5. Otherwise colour follows ``stream.isatty()``.

Off a terminal every helper returns its text unchanged, so logs, CI output and
the tests that read them stay byte-identical to the uncoloured view.

``COLORTERM=truecolor`` or ``24bit`` selects the 24-bit palette; any other
terminal gets the 16 base colours, and a gradient falls back to the accent.
"""

from __future__ import annotations

import os
import re
from typing import IO, Mapping

RESET = "\033[0m"
ANSI_RE = re.compile(r"\033\[[0-9;]*m")
# Frames of the spinner that marks a live status line on a terminal.
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# role -> (24-bit RGB, base-16 SGR). Muted, Nord-like tones: status and
# severity carry colour, everything else stays grey.
_PALETTE: dict[str, tuple[tuple[int, int, int], str]] = {
    "accent": ((124, 196, 228), "36"),
    "agent": ((180, 162, 240), "35"),
    "ok": ((143, 209, 158), "32"),
    "warn": ((240, 198, 110), "33"),
    "critical": ((236, 109, 118), "31"),
    "high": ((239, 150, 109), "91"),
    "medium": ((240, 198, 110), "33"),
    "low": ((124, 196, 228), "36"),
    "muted": ((109, 118, 134), "90"),
}
_ATTRS = {"bold": "1"}
COLOR_MODES = ("auto", "always", "never")


def color_enabled(stream: IO[str] | None, mode: str = "auto", env: Mapping[str, str] | None = None) -> bool:
    """Whether output written to ``stream`` should carry colour."""
    if mode == "always":
        return True
    if mode == "never":
        return False
    env = os.environ if env is None else env
    if env.get("NO_COLOR"):
        return False
    force = env.get("FORCE_COLOR", "")
    if force and force != "0":
        return True
    if env.get("TERM") == "dumb":
        return False
    try:
        return bool(stream is not None and stream.isatty())
    except (AttributeError, ValueError):
        return False


class Style:
    """Wrap text in colour for one output stream, or leave it untouched."""

    def __init__(self, enabled: bool, truecolor: bool = False) -> None:
        self.enabled = enabled
        self.truecolor = enabled and truecolor

    @classmethod
    def for_stream(cls, stream: IO[str] | None, mode: str = "auto", env: Mapping[str, str] | None = None) -> Style:
        env = os.environ if env is None else env
        enabled = color_enabled(stream, mode, env)
        return cls(enabled, env.get("COLORTERM", "").lower() in ("truecolor", "24bit"))

    def _sgr(self, role: str) -> str:
        if role in _ATTRS:
            return _ATTRS[role]
        rgb, base = _PALETTE[role]
        return "38;2;{};{};{}".format(*rgb) if self.truecolor else base

    def __call__(self, text: str, *roles: str) -> str:
        """``text`` in the given roles (``"accent"``, ``"bold"`` …)."""
        if not self.enabled or not text or not roles:
            return text
        return f"\033[{';'.join(self._sgr(r) for r in roles)}m{text}{RESET}"

    def gradient(self, text: str, start: str = "accent", end: str = "agent") -> str:
        """``text`` blended from one role's colour to another's, per character."""
        if not self.enabled or not text:
            return text
        if not self.truecolor:
            return self(text, start)
        (r0, g0, b0), _ = _PALETTE[start]
        (r1, g1, b1), _ = _PALETTE[end]
        n = max(len(text) - 1, 1)
        parts = []
        for i, ch in enumerate(text):
            t = i / n
            rgb = (round(r0 + (r1 - r0) * t), round(g0 + (g1 - g0) * t), round(b0 + (b1 - b0) * t))
            parts.append("\033[38;2;{};{};{}m{}".format(*rgb, ch))
        return "".join(parts) + RESET

    def bar(self, done: int, total: int, width: int = 20) -> str:
        """A progress bar: the done share in the gradient, the rest muted."""
        total = max(total, 1)
        filled = max(0, min(width, round(width * done / total)))
        return self.gradient("━" * filled) + self("─" * (width - filled), "muted")


TAGLINE = "code-derived STRIDE threat modeling"


def plugin_version() -> str:
    """The plugin's version from its manifest, or empty when unreadable."""
    import json
    from pathlib import Path

    try:
        manifest = Path(__file__).resolve().parents[2] / ".claude-plugin" / "plugin.json"
        return str(json.loads(manifest.read_text(encoding="utf-8")).get("version") or "")
    except (OSError, ValueError, AttributeError):
        return ""


def logo(st: Style, detail: str) -> list[str]:
    """The three-line headless logo: a framed mark, the name, the tagline and ``detail``.

    Shown only on a terminal; callers print their plain title line otherwise.
    """
    frame = lambda text: st(text, "agent")  # noqa: E731
    return [
        f"   {frame('╭───╮')}  {st(st.gradient('appsec-advisor'), 'bold')}",
        f"   {frame('│')} {st('◆', 'accent')} {frame('│')}  {st(TAGLINE, 'muted')}",
        f"   {frame('╰───╯')}  {st(detail, 'muted')}",
    ]


def main(argv: list[str] | None = None) -> int:
    """``term_style.py logo <detail>``: the headless banner's logo."""
    import argparse
    import sys

    p = argparse.ArgumentParser(prog="term_style.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    cmd = sub.add_parser("logo")
    cmd.add_argument("detail")
    cmd.add_argument("--color", choices=COLOR_MODES, default="auto")
    args = p.parse_args(argv)

    version = plugin_version()
    st = Style.for_stream(sys.stdout, args.color)
    sys.stdout.write("\n".join(logo(st, f"v{version} · {args.detail}" if version else args.detail)) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
