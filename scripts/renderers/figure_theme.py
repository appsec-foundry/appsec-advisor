"""Dark-background variants of the report figures and the Markdown that selects them.

Every figure SVG is drawn for a white page. ``dark_svg`` derives a variant for a
dark page from the same SVG text: light surfaces become dark surfaces, dark
text and lines become light, accents are lifted to stay visible on black, and
the white canvas is removed so the viewer's background shows through. Filled
shapes that carry white text (header bars, badges, STRIDE cells) keep their
colour, so their text keeps its contrast. The geometry and text are unchanged.

``themed_image`` emits a one-line ``<picture>`` that viewers honouring
``prefers-color-scheme`` (GitHub, browsers) resolve to the matching file; every
other consumer reads the light image through ``light_images``. Nothing is
written or fetched by this module.

``stash_figures`` keeps that markup byte-identical through report-wide prose
passes (payload escaping, dotted-identifier and em-dash normalisation, linkify),
which would otherwise backtick the ``<img>`` or rewrite the ``alt`` text.
"""

from __future__ import annotations

import colorsys
import html
import re
from collections.abc import Callable

_HEX_ATTR = re.compile(r'\b(fill|stroke|stop-color)="(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3}|white|black)"')
_TAG = re.compile(r"<(\w+)\b[^>]*>")
_ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
_SVG_OPEN = re.compile(r"<svg\b[^>]*>")
_WHITE = {"#ffffff", "#fff", "white"}
_PICTURE = re.compile(
    r'<picture><source media="\(prefers-color-scheme: dark\)" srcset="[^"]*">'
    r'<img src="(?P<src>[^"]*)" alt="(?P<alt>[^"]*)"></picture>'
)
# Only figures that point at local SVG files are preserved: model-authored text
# can forge the shape, and a forged remote URL must still meet the prose passes.
_LOCAL_PICTURE = re.compile(
    r'<picture><source media="\(prefers-color-scheme: dark\)" srcset="[\w.-]+\.svg">'
    r'<img src="[\w.-]+\.svg" alt="[^"<>]*"></picture>'
)
_FIGURE_TOKEN = re.compile(r"\x00FIGURE(\d+)\x00")


def dark_basename(basename: str) -> str:
    """``<stem>.figure1.svg`` → ``<stem>.figure1-dark.svg``."""
    return f"{basename[:-4]}-dark.svg" if basename.endswith(".svg") else f"{basename}-dark"


def _rgb(value: str) -> tuple[float, float, float]:
    value = {"white": "#ffffff", "black": "#000000"}.get(value, value).lstrip("#")
    if len(value) == 3:
        value = "".join(c * 2 for c in value)
    return tuple(int(value[i : i + 2], 16) / 255 for i in (0, 2, 4))  # type: ignore[return-value]


def _dark_colour(value: str, solid: bool) -> str:
    hue, light, sat = colorsys.rgb_to_hls(*_rgb(value))
    if solid and light < 0.8:
        return value  # a filled shape that carries white text keeps its contrast
    if light >= 0.8:  # page surfaces, pale bands and light borders
        light, sat = 0.11 + (1 - light) * 0.75, sat * 0.55
    elif light <= 0.35:  # body text and dark headings
        light, sat = 0.90 - light * 0.3, sat * 0.6
    else:  # accents and secondary text
        light = 0.30 + light * 0.6
    r, g, b = colorsys.hls_to_rgb(hue, min(light, 0.95), min(sat, 1.0))
    return "#{:02x}{:02x}{:02x}".format(*(round(c * 255) for c in (r, g, b)))


def _canvas_size(svg: str) -> tuple[str, str] | None:
    opening = _SVG_OPEN.search(svg)
    if not opening:
        return None
    attrs = dict(_ATTR.findall(opening.group(0)))
    box = attrs.get("viewBox", "").split()
    return (box[2], box[3]) if len(box) == 4 else (attrs.get("width", ""), attrs.get("height", ""))


def _is_canvas(attrs: dict[str, str], size: tuple[str, str] | None) -> bool:
    if not size or attrs.get("fill", "").lower() not in _WHITE or "stroke" in attrs:
        return False
    try:
        same = all(float(attrs.get(k, "nan")) == float(v) for k, v in zip(("width", "height"), size, strict=True))
        origin = all(float(attrs.get(k, "0")) == 0 for k in ("x", "y"))
    except ValueError:
        return False
    return same and origin


def dark_svg(svg: str) -> str:
    """The dark-background variant of a light figure SVG."""
    size = _canvas_size(svg)

    def convert(match: re.Match[str]) -> str:
        tag, name = match.group(0), match.group(1)
        if name == "rect" and _is_canvas(dict(_ATTR.findall(tag)), size):
            return ""
        is_text = name in ("text", "tspan")

        def colour(attr: re.Match[str]) -> str:
            key, value = attr.group(1), attr.group(2).lower()
            if is_text and key == "fill" and value in _WHITE:
                return attr.group(0)  # text on a filled badge or bar
            solid = key == "fill" and not is_text
            return f'{key}="{_dark_colour(value, solid)}"'

        return _HEX_ATTR.sub(colour, tag)

    return _TAG.sub(convert, svg)


def themed_image(alt: str, light_src: str, dark_src: str) -> str:
    """One-line ``<picture>`` that shows ``dark_src`` to viewers preferring a dark scheme."""
    return (
        f'<picture><source media="(prefers-color-scheme: dark)" srcset="{html.escape(dark_src)}">'
        f'<img src="{html.escape(light_src)}" alt="{html.escape(alt)}"></picture>'
    )


def stash_figures(markdown: str) -> tuple[str, Callable[[str], str]]:
    """Replace each local ``themed_image`` with a token; the returned function puts it back.

    Text between the two calls may pass through any prose transform: the figures
    come back byte-identical, and only tokens issued here are restored.
    """
    figures: list[str] = []

    def stash(match: re.Match[str]) -> str:
        figures.append(match.group(0))
        return f"\x00FIGURE{len(figures) - 1}\x00"

    def restore(text: str) -> str:
        return _FIGURE_TOKEN.sub(
            lambda m: figures[int(m.group(1))] if int(m.group(1)) < len(figures) else m.group(0), text
        )

    return _LOCAL_PICTURE.sub(stash, markdown), restore


def light_images(markdown: str) -> str:
    """Replace each ``themed_image`` with the plain Markdown image of its light file."""
    return _PICTURE.sub(lambda m: f"![{html.unescape(m.group('alt'))}]({html.unescape(m.group('src'))})", markdown)
