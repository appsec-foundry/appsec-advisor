"""Dark figure variants keep every element and stay legible; the report selects them per viewer scheme."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from renderers.figure_theme import dark_basename, dark_svg, light_images, themed_image

FIXTURE = Path(__file__).parent / "fixtures" / "run_invariants" / "juice-shop-thorough" / "threat-model.figure1.svg"
GITHUB_DARK = "#0d1117"

SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="200" viewBox="0 0 400 200">'
    '<rect x="0" y="0" width="400" height="200" fill="#ffffff"/>'
    '<rect x="10" y="10" width="120" height="60" rx="6" fill="#ffffff" stroke="#334d6e"/>'
    '<rect x="150" y="10" width="120" height="20" fill="#334d6e"/>'
    '<text x="160" y="24" fill="#ffffff">Legend</text>'
    '<text x="20" y="30" fill="#1f2937">Orders API</text>'
    '<text x="20" y="50" fill="#b3453f" stroke="#ffffff" paint-order="stroke">Direct attack</text>'
    '<path d="M0 0 L10 5" stroke="#94a3b8" fill="none"/>'
    "</svg>"
)


def _luminance(colour: str) -> float:
    value = colour.lstrip("#")
    channels = [int(value[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(a: str, b: str) -> float:
    high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _shape(svg: str) -> list[tuple]:
    """Elements, text and every non-colour attribute — what the dark variant must not change."""
    colour = {"fill", "stroke", "stop-color"}
    return [
        (el.tag, (el.text or "").strip(), sorted((k, v) for k, v in el.attrib.items() if k not in colour))
        for el in ET.fromstring(svg).iter()
    ]


def test_dark_variant_removes_only_the_canvas_and_inverts_surfaces_and_text():
    dark = dark_svg(SVG)
    rects = re.findall(r"<rect [^>]*>", dark)
    assert len(rects) == 2  # the white canvas is gone so the page background shows through
    box, bar = rects
    assert _luminance(re.search(r'fill="(#\w+)"', box).group(1)) < 0.05  # white box → dark surface
    assert 'fill="#334d6e"' in bar  # a filled bar carrying white text keeps its colour
    assert '<text x="160" y="24" fill="#ffffff">Legend</text>' in dark
    body = re.search(r'<text x="20" y="30" fill="(#\w+)">', dark).group(1)
    assert _contrast(body, GITHUB_DARK) >= 7  # dark body text becomes light
    halo = re.search(r'<text x="20" y="50" [^>]*stroke="(#\w+)"', dark).group(1)
    assert _luminance(halo) < 0.05  # the label halo matches the dark surface, not white


def test_a_white_shape_that_is_not_the_full_canvas_is_kept():
    for rect in (
        '<rect x="5" y="0" width="400" height="200" fill="#ffffff"/>',  # offset
        '<rect width="400" height="199" fill="#ffffff"/>',  # smaller
        '<rect width="400" height="200" fill="#ffffff" stroke="#000000"/>',  # outlined box
    ):
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 200">{rect}</svg>'
        assert dark_svg(svg).count("<rect") == 1


def test_canvas_without_view_box_is_matched_by_width_and_height():
    svg = '<svg xmlns="http://www.w3.org/2000/svg" width="300" height="80"><rect width="300" height="80" fill="white"/></svg>'
    assert "<rect" not in dark_svg(svg)


def test_rendered_figure_keeps_every_element_and_its_text_stays_legible_on_a_dark_page():
    light = FIXTURE.read_text(encoding="utf-8")
    dark = dark_svg(light)
    shape_light, shape_dark = _shape(light), _shape(dark)
    canvas = [item for item in shape_light if item not in shape_dark]
    assert len(canvas) == 1 and canvas[0][0].endswith("rect")
    assert [item for item in shape_light if item not in canvas] == shape_dark
    fills = re.findall(r'<text\b[^>]*\bfill="(#[0-9a-f]{6})"', dark)
    plain = [f for f in fills if f != "#ffffff"]  # white text sits on its own filled badge or bar
    assert plain and min(_contrast(f, GITHUB_DARK) for f in plain) >= 4.0


def test_themed_image_selects_the_dark_file_and_reads_back_as_the_light_image():
    alt = 'Figure 3 - Deployment "edge" & <ingress>'
    picture = themed_image(alt, "report.figure3.svg", dark_basename("report.figure3.svg"))
    assert "\n" not in picture  # one line, so line-based report passes keep it intact
    assert 'srcset="report.figure3-dark.svg"' in picture and "&quot;edge&quot; &amp; &lt;ingress&gt;" in picture
    report = f"Intro.\n\n{picture}\n\n![Diagram](other.svg)\n"
    assert light_images(report) == f"Intro.\n\n![{alt}](report.figure3.svg)\n\n![Diagram](other.svg)\n"


def test_dark_basename_keeps_the_report_stem_for_stamping():
    assert dark_basename("threat-model.figure1b.svg") == "threat-model.figure1b-dark.svg"
    assert dark_basename("figure2.svg") == "figure2-dark.svg"
