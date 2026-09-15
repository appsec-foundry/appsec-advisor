"""Deterministic Figure 2: actors, attack routes, weaknesses and consequences.

The composer supplies the same reconciled scenarios used by Figure 1 and the
Top Threats table. Each row shows one explicit example finding, never a chain
inferred by joining unrelated findings through their architecture tier. All
presentation data is schema-validated before SVG emission and retained in the
SVG for the publication check. Nothing is written or fetched by this module.
"""

from __future__ import annotations

import html
import json
import re
import unicodedata
import xml.etree.ElementTree as ET
from functools import lru_cache
from pathlib import Path

from _severity_rollup import SEVERITY_ORDER, display_id, register_severity
from figure1_dfd import FONT, INK, LINE, MUTED, NAVY, RED, scenarios_from_attack_paths
from jsonschema import Draft202012Validator

# Widths and gaps are presentation geometry, not analysis limits. Height grows
# with wrapped text. Explicit excerpts retain the full source in SVG tooltips.
_PAD = 24
_GAP = 54
_WIDTHS = (180, 340, 310, 350)
_FONT = 13
_LINE = 17
_NS = {"s": "http://www.w3.org/2000/svg"}


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads((Path(__file__).resolve().parent.parent / "schemas/figure2-diagram.schema.json").read_text())
    return Draft202012Validator(schema)


def _text(value: object) -> str:
    """Keep imported prose as text, including literal markup and code."""
    return " ".join(str(value or "").split())


def _fid(value: object) -> str:
    value = _text(value).upper()
    return display_id(value) if re.fullmatch(r"[FT]-\d+", value) else ""


def _weaknesses(model: dict, finding_id: str) -> list[dict]:
    """Use explicit confirmed/practice links, never a CWE or title match."""
    result = []
    for w in model.get("weaknesses") or []:
        sources = list(w.get("instances") or []) + list(
            (w.get("observable_backing") or {}).get("practice_evidence") or []
        )
        if any(_fid(i.get("id")) == finding_id for i in sources if isinstance(i, dict)):
            if re.fullmatch(r"W-\d+", str(w.get("id") or "")) and w.get("title"):
                result.append(w)
    return sorted(result, key=lambda w: w["id"])


def _prerequisite(finding: dict, raw_actor: str, victim: bool) -> str:
    # CVSS PR describes the finding, while overview actor equivalence only
    # describes reach. In particular self-registration never removes PR:L.
    vector = _text((finding.get("cvss_v4") or {}).get("vector"))
    pr = re.search(r"/PR:([NLH])(?:/|$)", vector)
    access = {"N": "No account required", "L": "Regular account required", "H": "Elevated privileges required"}
    parts = []
    if pr:
        parts.append(access[pr.group(1)])
    elif raw_actor == "internet-user":
        parts.append(access["L"])
    elif raw_actor == "internet-priv-user":
        parts.append(access["H"])
    elif raw_actor == "repo-read":
        parts.append("Source-repository access required")
    elif raw_actor == "build-time":
        parts.append("Build or dependency access required")
    if victim:
        parts.append("Victim interaction required")
    return "; ".join(parts) or "Access prerequisites: see the finding"


def _unproven(finding: dict) -> bool:
    return finding.get("evidence_tier") != "confirmed-exploitable" or finding.get("evidence_check") not in {
        "verified",
        "verified-prior",
    }


def build_figure2_data(
    model: dict, attack_paths: dict, attack_taxonomy: dict, impact_taxonomy: dict, actor_labels: dict | None = None
) -> dict:
    """Project one example per reconciled scenario without changing the model.

    Selection prefers verified findings, then severity and numeric ID. Group impacts
    remain explicitly labelled as group impacts, since class-level impact
    membership does not prove that every finding reaches every consequence.
    """
    scenarios, actors = scenarios_from_attack_paths(model, attack_paths, attack_taxonomy, actor_labels)
    actor_by_slug = {a["slug"]: a for a in actors}
    threats = {_fid(t.get("id") or t.get("t_id")): t for t in model.get("threats") or []}
    components = {}
    for i, c in enumerate(model.get("components") or [], 1):
        cid = str(c.get("id") or "")
        visible = cid if re.fullmatch(r"C-\d+", cid) else f"C-{i:02d}"
        components[cid] = f"{visible} · {c.get('name') or cid}"
    impacts = {i["id"]: i for i in impact_taxonomy.get("impacts") or []}
    rows = []
    for scenario, ap in zip(scenarios, attack_paths.get("attack_paths") or []):
        ids = sorted({_fid(i) for i in ap.get("findings") or []}, key=lambda s: int(s[2:]) if s else -1)
        if not ids or any(not fid or fid not in threats for fid in ids):
            raise ValueError(f"Figure 2 scenario {scenario['n']} has a missing or unresolved finding")
        selected = min(
            ids,
            key=lambda fid: (
                _unproven(threats[fid]),
                SEVERITY_ORDER.get(register_severity(threats[fid]), 99),
                int(fid[2:]),
            ),
        )
        finding = threats[selected]
        linked = _weaknesses(model, selected)
        cause = "\n".join(f"{_text(w['title'])} ({w['id']})" for w in linked)
        if not cause:
            cause = (
                _text(
                    finding.get("root_cause")
                    or finding.get("evidence_summary")
                    or finding.get("evidence_prose")
                    or finding.get("title")
                )
                or "Underlying weakness not established."
            )
        steps = finding.get("attack_steps") or []
        action = steps[0] if steps and isinstance(steps[0], str) else finding.get("scenario")
        harms = []
        for impact_id in ap.get("impact") or []:
            if impact_id not in impacts:
                raise ValueError(f"Figure 2 scenario {scenario['n']} references an unknown impact")
            impact = impacts[impact_id]
            harms.append(_text(impact.get("business_harm") or impact.get("label")))
        actor = actor_by_slug[scenario["actor_slug"]]
        raw_actor = _text(ap.get("actor"))
        rows.append(
            {
                "number": int(scenario["n"]),
                "actor_slug": scenario["actor_slug"],
                "actor": actor["name"],
                "actor_note": actor["sub"],
                "title": _text(scenario["title"]),
                "route": _text(action) or _text(finding.get("title")),
                "component": components.get(
                    finding.get("component") or finding.get("component_id"), "Component not established"
                ),
                "finding_id": selected,
                "finding_ids": ids,
                "weakness_ids": [w["id"] for w in linked],
                "prerequisite": _prerequisite(finding, raw_actor, scenario["victim"]),
                "weakness": cause,
                "victim": bool(scenario["victim"]),
                "consequence": _text(finding.get("impact_description") or finding.get("impact_summary"))
                or "Technical consequence not established.",
                "business_harm": "\n".join(harms) or "Business impact not established.",
                "risk": register_severity(finding),
                "unproven": _unproven(finding),
            }
        )
    result = {"schema_version": 2, "routes": rows}
    _validator().validate(result)
    return result


def _lines(text: str, width: int, size: int = _FONT) -> list[str]:
    lines = []
    for paragraph in text.split("\n"):
        current = ""
        for word in paragraph.split():
            candidate = f"{current} {word}" if current else word
            if _text_width(candidate, size) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            current = ""
            for character in word:
                if current and _text_width(current + character, size) > width:
                    lines.append(current)
                    current = ""
                current += character
        if current:
            lines.append(current)
    return lines


def _text_width(value: str, size: int = _FONT) -> float:
    """Conservative Helvetica/Arial widths, including bold and wide Unicode."""

    def advance(ch):
        if unicodedata.combining(ch):
            return 0
        if ch in "MW@%":
            return 1.05
        if ch in "mw":
            return 0.95
        if ch in " ilI.,:;'`!|":
            return 0.4
        if "A" <= ch <= "Z":
            return 0.85
        if ch.isascii():
            return 0.65
        return 1.1

    return sum(advance(ch) for ch in value) * size


def _excerpt(value: str, width: int, limit: int) -> list[str]:
    lines = _lines(value, width)
    if len(lines) > limit:
        return lines[: limit - 1] + [lines[limit - 1].rstrip(" .;,:") + " …"]
    return lines


def build_figure2_svg(data: dict) -> str:
    """Render schema-valid presentation data with Figure 1's palette and font."""
    _validator().validate(data)
    rows = data["routes"]
    x = [_PAD]
    for width in _WIDTHS[:-1]:
        x.append(x[-1] + width + _GAP)
    total_w = x[-1] + _WIDTHS[-1] + _PAD
    elements = []

    def text(px, py, value, size=_FONT, color=INK, bold=False, attrs=""):
        elements.append(
            f'<text x="{px}" y="{py}" font-size="{size}" fill="{color}" '
            f'font-weight="{"bold" if bold else "normal"}" {attrs}>{html.escape(str(value))}</text>'
        )

    def rect(px, py, width, height, fill="#ffffff", stroke=LINE, radius=7, attrs=""):
        elements.append(
            f'<rect x="{px}" y="{py}" width="{width}" height="{height}" rx="{radius}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="1.4" {attrs}/>'
        )

    def arrow(start, end, y, color, dashed=False):
        marker = "attack" if color == RED else "consequence"
        dash = ' stroke-dasharray="5 4"' if dashed else ""
        elements.append(
            f'<path d="M{start} {y} H{end}" fill="none" stroke="{color}" '
            f'stroke-width="1.8" marker-end="url(#f2-{marker})"{dash}/>'
        )

    headers = ("Threat Actors", "Attack Route", "Underlying Weakness", "Impact")
    for px, header in zip(x, headers):
        text(px, 22, header, 13, NAVY, True)
    y = 42
    if not rows:
        text(_PAD, 66, "No attack routes in the Top Threats groups.", color=MUTED)
        y = 84
    for row in rows:
        # Repeat an actor card per route instead of merging independent routes
        # through one common tier. The shared slug retains the identity.
        contents = [
            [(row["actor"], True, RED, 4)],
            [
                (row["title"], True, INK, 2),
                (f"Example: {row['finding_id']}" + (" (unproven)" if row["unproven"] else ""), False, MUTED, 1),
                (row["route"], False, INK, 2),
                (row["prerequisite"], False, MUTED, 3),
            ],
            [
                (re.sub(r" \(W-\d+\)", "", row["weakness"]), True, NAVY, 4),
                ("(" + ", ".join(row["weakness_ids"]) + ")" if row["weakness_ids"] else "", False, MUTED, 20),
            ],
            [
                (row["consequence"], False, INK, 3),
                ("Potential harm (group)", False, MUTED, 1),
                (row["business_harm"], True, NAVY, 3),
            ],
        ]
        wrapped = [
            [(line, bold, color) for value, bold, color, limit in cell for line in _excerpt(value, width - 48, limit)]
            for cell, width in zip(contents, _WIDTHS)
        ]
        height = max(90, max(len(lines) for lines in wrapped) * _LINE + 42)
        number = row["number"]
        elements.append(
            f'<g data-route-number="{number}" data-finding-id="{row["finding_id"]}" '
            f'data-weakness-ids="{" ".join(row["weakness_ids"])}">'
        )
        detail = "\n".join(
            row[key]
            for key in (
                "actor",
                "actor_note",
                "title",
                "route",
                "component",
                "prerequisite",
                "weakness",
                "consequence",
                "business_harm",
            )
        )
        elements.append(f"<title>{html.escape(detail)}</title>")
        for col, (px, width, lines) in enumerate(zip(x, _WIDTHS, wrapped)):
            fill = "#fbf6f6" if col == 0 else "#f3f6fa" if col in (2, 3) else "#ffffff"
            stroke = "#a04d4a" if col == 0 else "#4f6d9c" if col in (2, 3) else LINE
            cell_height = max(60, len(lines) * _LINE + 24) if col == 0 else height
            rect(px, y + (height - cell_height) / 2, width, cell_height, fill, stroke, attrs=f'data-column="{col}"')
            start = y + (height - len(lines) * _LINE) / 2 + 12
            for line, bold, color in lines:
                text(px + 16, start, line, color=color, bold=bold)
                start += _LINE
        mid = y + height / 2
        for col in range(3):
            start, end = x[col] + _WIDTHS[col], x[col + 1] - 2
            arrow(start, end, mid, RED if col < 2 else LINE, dashed=(col == 2 or (col == 0 and row["victim"])))
        bx = x[1] - _GAP / 2
        elements.append(f'<circle cx="{bx}" cy="{mid}" r="10" fill="{RED}" stroke="#ffffff" stroke-width="1.5"/>')
        text(bx, mid + 4, str(number), 11, "#ffffff", True, f'text-anchor="middle" data-badge-number="{number}"')
        elements.append("</g>")
        y += height + 24
    defs = (
        "<defs>"
        + "".join(
            f'<marker id="f2-{name}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="8" markerHeight="8" '
            f'markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="{color}"/></marker>'
            for name, color in (("attack", RED), ("consequence", LINE))
        )
        + "</defs>"
    )
    glyphs = " ".join(str(r["number"]) for r in rows)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{y + _PAD}" '
        f'viewBox="0 0 {total_w} {y + _PAD}" font-family="{FONT}" data-figure2-version="2" '
        f'data-glyphs="{glyphs}" role="img" aria-labelledby="f2-title">'
        '<title id="f2-title">Actors, attack routes, underlying weaknesses and impact</title>'
        f'<metadata id="figure2-data">{html.escape(json.dumps(data, ensure_ascii=False, sort_keys=True))}</metadata>'
        f'<rect width="{total_w}" height="{y + _PAD}" fill="#ffffff"/>{defs}' + "\n".join(elements) + "</svg>"
    )
    problems = check_figure2_svg(svg)
    if problems:
        raise ValueError("Figure 2 self-check: " + "; ".join(problems))
    return svg


def check_figure2_svg(svg: str) -> list[str]:
    """Check the delivered SVG, including visible routes, badges and references."""
    try:
        root = ET.fromstring(svg)
        metadata = root.find("s:metadata[@id='figure2-data']", _NS)
        data = json.loads(metadata.text if metadata is not None else "")
        _validator().validate(data)
    except Exception as exc:
        return [f"invalid Figure 2 data: {exc}"]
    rows = data["routes"]
    groups = root.findall("s:g[@data-route-number]", _NS)
    expected = [str(r["number"]) for r in rows]
    errors = []
    if len(set(expected)) != len(expected) or [g.get("data-route-number") for g in groups] != expected:
        errors.append("visible route numbers differ from the presentation data")
    if root.get("data-glyphs", "").split() != expected:
        errors.append("glyph metadata differs from visible routes")
    for group, row in zip(groups, rows):
        badge = group.find("s:text[@data-badge-number]", _NS)
        if badge is None or badge.text != str(row["number"]) or badge.get("data-badge-number") != str(row["number"]):
            errors.append("scenario badge differs from its route")
        if (
            group.get("data-finding-id") != row["finding_id"]
            or group.get("data-weakness-ids", "").split() != row["weakness_ids"]
        ):
            errors.append("route references differ from the presentation data")
        visible_text = " ".join(t.text or "" for t in group.findall("s:text", _NS))
        if any(ref not in visible_text for ref in [row["finding_id"], *row["weakness_ids"]]):
            errors.append("a finding or weakness reference is missing from the visible route")
        cells = group.findall("s:rect[@data-column]", _NS)
        if [c.get("data-column") for c in cells] != [str(i) for i in range(4)]:
            errors.append("route does not contain all four columns")
        for text in group.findall("s:text", _NS):
            if text.get("data-badge-number"):
                continue
            try:
                tx, ty = float(text.get("x")), float(text.get("y"))
                if not any(
                    float(c.get("x")) < tx < float(c.get("x")) + float(c.get("width"))
                    and tx + _text_width(text.text or "", float(text.get("font-size", _FONT)))
                    <= float(c.get("x")) + float(c.get("width")) - 8
                    and float(c.get("y")) + 8 < ty < float(c.get("y")) + float(c.get("height")) - 4
                    for c in cells
                ):
                    errors.append("text falls outside its card")
            except (TypeError, ValueError):
                errors.append("invalid card or text geometry")
    return errors
