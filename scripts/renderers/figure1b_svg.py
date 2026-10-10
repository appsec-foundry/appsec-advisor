#!/usr/bin/env python3
"""Figure 1b, Supply Chain and Build: the supply-chain view drawn as a clean grid (RA-31).

Input is the view from ``model.build_supply_chain_view`` plus the build-time
actor and scenario numbers the composer resolved for Figure 1a and Figure 2.
``render`` returns ``(svg, problems)``; ``svg`` is empty whenever a gate fails,
and the composer then shows ``render_table`` instead.

Layout: fixed columns (attacker, sources, build, artifacts, execution), each
sized from its measured text within ``WIDTH_BUDGET``. Within a column the
upstream group sits above the repository, the CI system that consumes inputs
spans both, and every other box stacks below. Flows run between neighbouring
columns, straight where both ends share a height and otherwise through a lane
in the gap. Attack routes leave the attacker through one bus in the gap left
of the sources and one lane above the zones.

Gates: the geometry gate rejects crossing lines, lines through foreign boxes,
texts or badges, badges touching arrowheads, overflowing text, attack routes
over a foreign zone border, boundary lines through boxes, texts, badges or
along a flow, and content outside the canvas. The legibility gate
rejects any text whose effective size at a supported display width falls below
``MIN_EFFECTIVE_PX``.
"""

from __future__ import annotations

import html
import itertools
from typing import Any

# Supported display widths in CSS pixels: report page and README, HTML, and the
# A3 wide-figure wrap the PDF export gives Figure 1 and Figure 1b.
DISPLAY_WIDTHS = {"report": 880, "readme": 880, "html": 880, "pdf": 1100}
MIN_EFFECTIVE_PX = 6.0
WIDTH_BUDGET = 1240
FONT = {
    "title": 16,
    "subtitle": 10.5,
    "zone": 12,
    "zone_sub": 9,
    "box": 11.5,
    "detail": 9,
    "row": 10,
    "fact": 9,
    "label": 8.5,
    "badge": 9.5,
    "legend": 9.5,
    "legend_head": 11,
}
CAPS = {"upstream_rows": 4, "ci": 3, "artifacts": 4, "channels": 5, "facts_per_row": 3}
MIN_COLUMN = {"attacker": 150, "sources": 220, "build": 190, "artifacts": 170, "execution": 160}
MAX_COLUMN = {"attacker": 160, "sources": 300, "build": 260, "artifacts": 240, "execution": 230}
GAP = 64
ATTACK_GAP = 48
ZONE_PAD = 14
TOP_LANE = 53
ZTOP = 64
BOX_TOP = 110
ARROW = 10
BADGE_R = 8
BOUNDARY_INSET = 4  # boundary line distance left of the zone it leads into
BOUNDARY_OVERHANG = 18  # boundary line reach beyond its outermost crossing flow
INFERRED_STYLE = 'stroke-width="1.8" stroke-dasharray="2 4" stroke-opacity="0.55"'

INK, MUTED, RED, FLOW, OK, NAVY = "#1f2a37", "#5b6675", "#9c3d3d", "#6b7a8c", "#3f8a4f", "#22344a"
SEV = {"Critical": "#b03a3a", "High": "#d08a3a", "Medium": "#c9a43a", "Low": "#7a8a99", "Informational": "#9aa5b1"}
ZONES = {
    "sources": ("Sources and inputs", "what the build consumes", "#5a7d5a", "#f5f9f4"),
    "build": ("Build", "runs with repository secrets", "#4b7a94", "#f3f8fa"),
    "artifacts": ("Release artifacts", "what is shipped", "#6a5a8c", "#f7f5fa"),
    "execution": ("Execution", "where the release runs", NAVY, "#eef2f7"),
}
ENTRY_TITLES = {
    "dependency": "Manipulated dependency",
    "ci-input": "Manipulated CI input",
    "repository": "Change through the repository",
    "artifact": "Replaced release artifact",
}
ENTRY_LETTERS = "abcd"


def text_width(text: str, size: float, bold: bool = False) -> float:
    """Helvetica estimate; generous so that a box sized from it never clips."""
    narrow = sum(ch in "il.,:;|!'()[] " for ch in text)
    return (len(text) - narrow * 0.45) * size * (0.6 if bold else 0.55)


def actor_title(actor: dict) -> str:
    """``A<n> · name`` with the code §1 and Figure 1a use, or the name alone when the actor has none."""
    return (f"{actor['code']} · " if actor.get("code") else "") + actor["name"]


def goal_text(actor: dict | None) -> str:
    """``Goal of A<n> · <impact> · <risk>`` of the build-time scenarios, or "" when they name no impact."""
    goal = (actor or {}).get("goal")
    if not goal:
        return ""
    return " · ".join(
        [f"Goal of {actor.get('code') or actor['name']}", *goal["impacts"], goal.get("risk") or ""]
    ).rstrip(" ·")


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}{'' if n == 1 else 's'}"


def wrap(text: str, size: float, width: float, bold: bool = False) -> list[str]:
    """Wrap at spaces, then at path separators for long unbroken references."""
    words, lines, line = str(text).split(), [], ""
    for word in words:
        while text_width(word, size, bold) > width and len(word) > 8:
            cut = max(
                (
                    word.rfind(sep, 0, max(8, int(len(word) * width / max(1.0, text_width(word, size, bold)))))
                    for sep in "/.-_:"
                ),
                default=-1,
            )
            cut = cut + 1 if cut > 3 else max(8, int(len(word) * width / text_width(word, size, bold)) - 1)
            head, word = word[:cut], word[cut:]
            if line:
                lines.append(line)
                line = ""
            lines.append(head)
        candidate = f"{line} {word}".strip()
        if line and text_width(candidate, size, bold) > width:
            lines.append(line)
            line = word
        else:
            line = candidate
    if line:
        lines.append(line)
    return lines or [""]


class Canvas:
    """SVG primitives plus the obstacle model the gates read."""

    def __init__(self):
        self.parts: list[str] = []
        self.texts: list[tuple[str, tuple[float, float, float, float], str | None]] = []
        self.boxes: dict[str, tuple[float, float, float, float]] = {}
        self.zones: dict[str, tuple[float, float, float, float]] = {}
        self.badges: dict[str, tuple[float, float, float, float]] = {}
        self.edges: list[dict[str, Any]] = []
        self.boundaries: list[tuple[float, float, float]] = []  # (x, top, bottom) of each boundary line
        self.min_font = 99.0

    def text(
        self, x, y, s, size, *, weight="normal", fill=INK, anchor="start", italic=False, owner=None, obstacle=True
    ):
        self.min_font = min(self.min_font, size)
        style = ' font-style="italic"' if italic else ""
        self.parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
            f'text-anchor="{anchor}"{style}>{html.escape(str(s))}</text>'
        )
        if obstacle:
            w = text_width(str(s), size, weight == "bold")
            x0 = x - w / 2 if anchor == "middle" else (x - w if anchor == "end" else x)
            self.texts.append((str(s), (x0, y - size * 0.8, w, size * 1.05), owner))

    def rect(self, x, y, w, h, stroke, fill="#ffffff", rx=6, dash=None, sw=1.4):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{sw}"{d}/>'
        )

    def mark(self, x, y, sev):
        if sev == "ok":
            self.parts.append(
                f'<path d="M{x - 3:.1f} {y - 4:.1f} l3 3 l6 -7" stroke="{OK}" stroke-width="1.8" fill="none"/>'
            )
        elif sev:
            self.parts.append(f'<circle cx="{x:.1f}" cy="{y - 3.5:.1f}" r="3.6" fill="{SEV.get(sev, MUTED)}"/>')

    def path(self, points, color, width, marker, dash=None):
        d = "M" + " L".join(f"{px:.1f} {py:.1f}" for px, py in points)
        da = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}"{da} marker-end="url(#m-{marker})"/>'
        )

    def badge(self, key, x, y, label, filled=True):
        self.min_font = min(self.min_font, FONT["badge"])
        self.badges[key] = (x - BADGE_R, y - BADGE_R, 2 * BADGE_R, 2 * BADGE_R)
        if filled:
            self.parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{BADGE_R}" fill="{RED}"/>')
            fill = "#ffffff"
        else:
            self.parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{BADGE_R}" fill="#ffffff" stroke="{RED}" stroke-width="1.8"/>'
            )
            fill = RED
        self.parts.append(
            f'<text x="{x:.1f}" y="{y + 3.5:.1f}" font-size="{FONT["badge"]}" font-weight="bold" fill="{fill}" '
            f'text-anchor="middle">{html.escape(label)}</text>'
        )


# ---- model to boxes ---------------------------------------------------------------------


def short_title(title: str) -> str:
    """A finding title without the trailing location the register appends (`… — Dockerfile:5`)."""
    head, sep, tail = str(title).rpartition(" — ")
    return head if sep and ("/" in tail or ":" in tail or "." in tail) and head else str(title)


def _finding_lines(findings: list[dict], limit: int = 3) -> list[tuple[str, str, str]]:
    rows = sorted(findings, key=lambda f: (list(SEV).index(f["severity"]) if f["severity"] in SEV else 9, f["id"]))
    lines = [(f["severity"], short_title(f["title"]), f["id"]) for f in rows[:limit]]
    if len(rows) > limit:
        lines.append(("", f"+{len(rows) - limit} more findings", ""))
    return lines


def _referenced(view: dict) -> set[str]:
    """Elements an attack entry or a highlighted path step points at."""
    ids = {entry["element"] for entry in view["entries"]}
    for step in (view.get("highlighted_path") or {}).get("steps") or []:
        ids |= {step["from"], step["to"]}
    return ids


def _cap(items: list[dict], limit: int, rank) -> tuple[list[dict], list[str]]:
    """Keep ``limit - 1`` items by ``rank`` (the last row says "+N more"), in their given order."""
    if len(items) <= limit:
        return items, []
    keep = sorted(items, key=rank)[: limit - 1]
    return [e for e in items if e in keep], [e["label"] for e in items if e not in keep]


def _plan(view: dict) -> dict[str, Any]:
    """Which boxes each column holds, with overflow aggregated into explicit "+N more" rows.

    A cap never drops an element an entry or the highlighted path points at: the arrow
    would have no box to land on.
    """
    elements = {e["id"]: e for e in view["elements"]}
    by_element: dict[str, list[dict]] = {}
    for finding in view["findings"]:
        by_element.setdefault(finding["element"], []).append(finding)
    referenced = _referenced(view)

    def worst(element):
        ranks = [list(SEV).index(f["severity"]) for f in by_element.get(element["id"], []) if f["severity"] in SEV]
        return min(ranks, default=len(SEV))

    overflow: dict[str, list[str]] = {}
    inputs, dropped = _cap(
        [e for e in view["elements"] if e["column"] == "sources" and e["kind"] != "repository"],
        CAPS["upstream_rows"],
        lambda e: (e["id"] not in referenced, worst(e), -len(by_element.get(e["id"], []))),
    )
    if dropped:
        overflow["upstream"] = dropped
    cis = sorted((e for e in view["elements"] if e["column"] == "build"), key=lambda e: e.get("coverage") != "full")
    cis, dropped = _cap(cis, CAPS["ci"], lambda e: (e["id"] not in referenced, e.get("coverage") != "full"))
    if dropped:
        overflow["ci"] = dropped
    artifacts, dropped = _cap(
        [e for e in view["elements"] if e["column"] == "artifacts"],
        CAPS["artifacts"],
        lambda e: e["id"] not in referenced,
    )
    if dropped:
        overflow["artifacts"] = dropped
    return {
        "elements": elements,
        "by_element": by_element,
        "inputs": inputs,
        "cis": cis,
        "artifacts": artifacts,
        "overflow": overflow,
    }


def _box_lines(element: dict, findings: list[dict]) -> list[tuple[str, Any]]:
    """Content lines of a box: (role, payload)."""
    lines: list[tuple[str, Any]] = [("title", element["label"])]
    if element.get("detail"):
        lines.append(("detail", element["detail"]))
    if element.get("manifest_detail"):
        lines.append(("detail", element["manifest_detail"]))
    if element.get("coverage") == "inventory-only":
        lines.append(("detail", "inventory only, no supply-chain checks"))
    for fact in (element.get("facts") or [])[: CAPS["facts_per_row"]]:
        if fact != element.get("detail"):
            lines.append(("detail", fact))  # an inventory fact, not a finding
    for row in _finding_lines(findings):
        lines.append(("fact", row))
    return lines


def _boundary_text(boundary: dict) -> str:
    """Existence and confidence of a mapped boundary; its verdict stays in the catalogue."""
    confidence = boundary.get("confidence")
    return boundary["id"] + ("" if confidence == "confirmed" else f" · {confidence}")


# ---- layout ------------------------------------------------------------------------------


def _measure(lines, width) -> list[tuple[str, Any, float]]:
    """Wrapped lines with their heights for a box ``width`` wide."""
    out = []
    for role, payload in lines:
        if role == "title":
            for part in wrap(payload, FONT["box"], width - 20, True):
                out.append(("title", part, 15.0))
        elif role == "detail":
            for part in wrap(payload, FONT["detail"], width - 20):
                out.append(("detail", part, 12.5))
        elif role == "fact":
            sev, text, ref = payload
            ref_w = text_width(ref, FONT["label"], True) + 8 if ref else 0
            parts = wrap(text, FONT["fact"], width - 30 - ref_w)
            for i, part in enumerate(parts):
                out.append(("fact", (sev if i == 0 else "", part, ref if i == 0 else ""), 13.0))
        elif role == "row_title":
            out.append(("row_title", payload, 16.0))
    return out


def _height(measured) -> float:
    return 14 + sum(h for *_rest, h in measured) + 8


def _column_widths(plan, actor) -> dict[str, float]:
    def need(texts, column):
        widest = max(
            [text_width(t, FONT["box"], True) + 24 for t in texts[:1]]
            + [text_width(t, FONT["fact"]) + 60 for t in texts[1:]]
            + [MIN_COLUMN[column]]
        )
        return min(MAX_COLUMN[column], widest)

    sources = [e["label"] for e in plan["inputs"]] + [
        f["title"] for e in plan["inputs"] for f in plan["by_element"].get(e["id"], [])
    ]
    sources += [plan["elements"]["repository"]["label"]]
    build = [e["label"] for e in plan["cis"]] + [
        f["title"] for e in plan["cis"] for f in plan["by_element"].get(e["id"], [])
    ]
    artifacts = [e["label"] for e in plan["artifacts"]] + [
        f["title"] for e in plan["artifacts"] for f in plan["by_element"].get(e["id"], [])
    ]
    widths = {
        "attacker": MIN_COLUMN["attacker"] if actor else 0,
        "sources": need(["Upstream inputs"] + sources, "sources"),
        "build": need(build or ["Build"], "build"),
        "artifacts": need(artifacts or ["Artifacts"], "artifacts"),
        "execution": need(
            ["Running system"]
            + list(plan["elements"]["execution"].get("channels") or [])
            + [plan.get("goal", ("", ""))[1]],
            "execution",
        ),
    }
    total = _total_width(widths, actor)
    columns = ["sources", "build", "artifacts", "execution"]
    while total > WIDTH_BUDGET and any(widths[c] > MIN_COLUMN[c] for c in columns):
        widest = max(columns, key=lambda c: widths[c] - MIN_COLUMN[c])
        widths[widest] = max(MIN_COLUMN[widest], widths[widest] - 10)
        total = _total_width(widths, actor)
    return widths


def _total_width(widths, actor) -> float:
    left = 20 + (widths["attacker"] + ATTACK_GAP if actor else 0) + ZONE_PAD
    return (
        left + widths["sources"] + widths["build"] + widths["artifacts"] + widths["execution"] + 3 * GAP + ZONE_PAD + 20
    )


def render(view: dict, actor: dict | None, scenario_numbers: list[str], project: str = "") -> tuple[str, list[str]]:
    """Figure 1b as SVG, or ``("", problems)`` when a gate fails."""
    plan = _plan(view)
    plan["goal"] = (((actor or {}).get("goal") or {}).get("risk") or "", goal_text(actor))
    widths = _column_widths(plan, actor)
    x = {}
    cursor = 20.0
    if actor:
        x["attacker"] = cursor
        cursor += widths["attacker"] + ATTACK_GAP
    cursor += ZONE_PAD
    for column in ("sources", "build", "artifacts", "execution"):
        x[column] = cursor
        cursor += widths[column] + GAP
    width = round(cursor - GAP + ZONE_PAD + 20)
    cv = Canvas()
    layout = _place(plan, x, widths)
    problems = list(layout["problems"])
    height_diagram = max(layout["bottom"] + 30, BOX_TOP + 160)
    borders = _boundary_borders(view, x)
    classes = {_line_class(conf) for border in borders.values() for conf in border["confidence"].values()}
    legend_svg, legend_height, legend_canvas = _legend(view, plan, actor, scenario_numbers, width, classes)
    height = round(height_diagram + 16 + legend_height + 20)

    cv.parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        'font-family="Helvetica, Arial, sans-serif">'
    )
    cv.parts.append(f'<rect width="{width}" height="{height}" fill="#ffffff"/>')
    cv.parts.append(
        "<defs>"
        f'<marker id="m-flow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="{ARROW}" markerHeight="{ARROW}" '
        f'markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="{FLOW}"/></marker>'
        f'<marker id="m-attack" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="{ARROW}" markerHeight="{ARROW}" '
        f'markerUnits="userSpaceOnUse" orient="auto"><path d="M0 0 L10 5 L0 10 z" fill="{RED}"/></marker>'
        "</defs>"
    )
    shown = len(view["findings"])
    systems = [e["label"] for e in plan["cis"] if e.get("coverage") != "none"]
    sources = [e for e in view["elements"] if e["column"] == "sources" and e["kind"] != "repository"]
    channels = plan["elements"]["execution"].get("channels") or []
    # Scoped to this view: one catalogue boundary counts once however many elements it marks.
    mapped = len({b["id"] for e in view["elements"] for b in e.get("boundaries") or []})
    cv.text(20, 24, "Figure 1b — Supply Chain and Build", FONT["title"], weight="bold", fill=NAVY)
    subtitle = " · ".join(
        p
        for p in (
            project,
            _count(len(systems), "CI system"),
            _count(len(sources), "upstream source type"),
            _count(len(channels), "delivery channel"),
            f"{mapped} trust {'boundary' if mapped == 1 else 'boundaries'} mapped here" if mapped else "",
            f"{_count(shown, 'finding')} shown here",
        )
        if p
    )
    cv.text(20, 40, subtitle, FONT["subtitle"], fill=MUTED)

    for column, (title, sub, stroke, fill) in ZONES.items():
        zx, zw = x[column] - ZONE_PAD, widths[column] + 2 * ZONE_PAD
        zh = layout["bottom"] + 16 - ZTOP
        cv.rect(zx, ZTOP, zw, zh, stroke, fill, rx=8, dash="6 4", sw=1.1)
        cv.zones[column] = (zx, ZTOP, zw, zh)
        cv.text(x[column] - 4, ZTOP + 17, title, FONT["zone"], weight="bold", fill=stroke)
        cv.text(x[column] - 4, ZTOP + 30, sub, FONT["zone_sub"], fill=MUTED, italic=True)
    lines_at = len(cv.parts)  # boundary lines go under boxes and flows, drawn once the flows are routed

    for key, box in layout["boxes"].items():
        _draw_box(cv, key, box, plan, view)
    if actor:
        _draw_actor(cv, actor, scenario_numbers, x["attacker"], widths["attacker"], layout)

    highlighted = {(s["from"], s["to"]): s["n"] for s in (view.get("highlighted_path") or {}).get("steps") or []}
    _draw_edges(cv, view, plan, layout, highlighted, problems, [border["x"] for border in borders.values()])
    if actor:
        _draw_entries(cv, view, layout, x, widths, problems)
    _draw_boundaries(cv, view, borders, layout, lines_at)

    cv.parts.append(f'<g transform="translate(0,{height_diagram + 16:.1f})">{legend_svg}</g>')
    cv.min_font = min(cv.min_font, legend_canvas.min_font)
    cv.parts.append("</svg>")
    problems += _geometry_gate(cv, width, height_diagram)
    problems += _legibility_gate(cv, width)
    return ("" if problems else "\n".join(cv.parts)), problems


def _place(plan, x, widths) -> dict[str, Any]:
    """Vertical placement and port heights; see the module docstring for the order."""
    boxes: dict[str, dict] = {}
    problems: list[str] = []
    by_element = plan["by_element"]
    # Sources: one upstream group with a row per input, then the repository.
    y = BOX_TOP
    if plan["inputs"]:
        rows, cursor = [], y + 30
        for element in plan["inputs"]:
            measured = _measure(_box_lines(element, by_element.get(element["id"], []))[1:], widths["sources"])
            title_lines = wrap(element["label"], FONT["row"], widths["sources"] - 20, True)
            row_h = 16 * len(title_lines) + sum(h for *_r, h in measured) + 8
            rows.append({"element": element, "y": cursor, "h": row_h, "title": title_lines, "measured": measured})
            cursor += row_h
        if plan["overflow"].get("upstream"):
            rows.append(
                {
                    "element": None,
                    "y": cursor,
                    "h": 18,
                    "title": [f"+{len(plan['overflow']['upstream'])} more inputs (listed below)"],
                    "measured": [],
                }
            )
            cursor += 18
        boxes["upstream"] = {
            "x": x["sources"],
            "y": y,
            "w": widths["sources"],
            "h": cursor - y + 6,
            "rows": rows,
            "kind": "group",
        }
        y = cursor + 6 + 28
    repo = plan["elements"]["repository"]
    measured = _measure(_box_lines(repo, by_element.get("repository", [])), widths["sources"])
    boxes["repository"] = {
        "x": x["sources"],
        "y": y,
        "w": widths["sources"],
        "h": _height(measured),
        "measured": measured,
        "element": repo,
    }
    sources_bottom = y + boxes["repository"]["h"]
    # Build: the consuming CI spans the sources; the rest stacks below.
    y = BOX_TOP
    for i, element in enumerate(plan["cis"]):
        measured = _measure(_box_lines(element, by_element.get(element["id"], [])), widths["build"])
        h = _height(measured)
        if i == 0 and element.get("coverage") == "full":
            h = max(h, sources_bottom - BOX_TOP)
        boxes[element["id"]] = {
            "x": x["build"],
            "y": y,
            "w": widths["build"],
            "h": h,
            "measured": measured,
            "element": element,
        }
        y += h + 28
    build_bottom = y - 28
    # Artifacts: stacked from the top so they face the CI that produced them.
    y = BOX_TOP
    for element in plan["artifacts"]:
        owner = element.get("owner")
        if owner and owner in boxes:
            y = max(y, boxes[owner]["y"])
        measured = _measure(_box_lines(element, by_element.get(element["id"], [])), widths["artifacts"])
        boxes[element["id"]] = {
            "x": x["artifacts"],
            "y": y,
            "w": widths["artifacts"],
            "h": _height(measured),
            "measured": measured,
            "element": element,
        }
        y += boxes[element["id"]]["h"] + 28
    artifacts_bottom = y - 28 if plan["artifacts"] else BOX_TOP
    # Execution: one box over the full height, so every artifact reaches it straight.
    execution = plan["elements"]["execution"]
    channels = list(execution.get("channels") or [])[: CAPS["channels"]]
    lines = [("title", "Running system"), ("detail", "→ Figure 1a")]
    lines += [("detail", f"Deploy channel: {c}") for c in channels] or [
        ("detail", "No deploy channel in the repository")
    ]
    risk, goal = plan.get("goal") or ("", "")
    if goal:
        lines.append(("fact", (risk, goal, "")))
    measured = _measure(lines, widths["execution"])
    bottom = max(sources_bottom, build_bottom, artifacts_bottom)
    h = max(_height(measured) + 120, bottom - BOX_TOP)
    boxes["execution"] = {
        "x": x["execution"],
        "y": BOX_TOP,
        "w": widths["execution"],
        "h": h,
        "measured": measured,
        "element": execution,
    }
    return {"boxes": boxes, "bottom": max(bottom, BOX_TOP + h), "problems": problems}


# ---- drawing ------------------------------------------------------------------------------


def _draw_lines(cv, key, x, y, w, measured):
    for role, payload, h in measured:
        if role == "title":
            cv.text(x + w / 2, y + 12, payload, FONT["box"], weight="bold", anchor="middle", owner=key)
        elif role == "detail":
            cv.text(x + w / 2, y + 10, payload, FONT["detail"], fill=MUTED, anchor="middle", italic=True, owner=key)
        elif role == "fact":
            sev, text, ref = payload
            cv.mark(x + 10, y + 10, sev)
            cv.text(x + 20, y + 10, text, FONT["fact"], fill=INK if sev else MUTED, owner=key)
            if ref:
                cv.text(x + w - 10, y + 10, ref, FONT["label"], weight="bold", fill=RED, anchor="end", owner=key)
        y += h
    return y


def _draw_box(cv, key, box, plan, view):
    x, y, w, h = box["x"], box["y"], box["w"], box["h"]
    cv.boxes[key] = (x, y, w, h)
    if box.get("kind") == "group":
        cv.rect(x, y, w, h, "#3d4b5c")
        cv.text(x + w / 2, y + 18, "Upstream inputs", FONT["box"], weight="bold", anchor="middle", owner=key)
        for row in box["rows"]:
            ry = row["y"]
            cv.parts.append(
                f'<line x1="{x + 8:.1f}" y1="{ry - 4:.1f}" x2="{x + w - 8:.1f}" y2="{ry - 4:.1f}" stroke="#e1e5ea"/>'
            )
            for i, line in enumerate(row["title"]):
                cv.text(x + 10, ry + 9 + 16 * i, line, FONT["row"], weight="bold", owner=key)
            _draw_lines(cv, key, x, ry + 16 * len(row["title"]) - 4, w, row["measured"])
        return
    element = box["element"]
    stroke, sw, fill = "#3d4b5c", 1.4, "#ffffff"
    if element["kind"] == "ci":
        stroke = "#4b7a94"
    if element["kind"] == "execution":
        stroke, sw = NAVY, 2.2
    cv.rect(x, y, w, h, stroke, fill, sw=sw)
    _draw_lines(cv, key, x, y + 6, w, box["measured"])


def _boundary_borders(view, x) -> dict[str, dict[str, Any]]:
    """The column borders a mapped build boundary crosses: into the build, or out to the release artifacts.

    Lines sit at these borders as in Figure 1a; the IDs go into the tooltip and
    the report catalogue, never onto the drawing.
    """
    borders: dict[str, dict[str, Any]] = {}
    for element in view["elements"]:
        for boundary in element.get("boundaries") or []:
            column = "build" if boundary["crossing"] == "ingress" else "artifacts"
            border = borders.setdefault(column, {"x": x[column] - ZONE_PAD - BOUNDARY_INSET, "confidence": {}})
            border["confidence"].setdefault(boundary["id"], boundary["confidence"])
    return borders


def _line_class(confidence: str) -> str:
    return "confirmed" if confidence == "confirmed" else "inferred"


def _crossing_ids(view, column) -> dict[tuple[str, str], set[str]]:
    """Boundary IDs per flow across one border, keyed by the flow's element ids.

    A boundary marks the flows of the element that names the supplier or the
    release target. One carried only by the CI system marks that system's
    flows across the border, except its checkout of the own repository.
    """
    crossing = "ingress" if column == "build" else "egress"
    elements = {e["id"]: e for e in view["elements"]}
    carried = {
        eid: {b["id"] for b in e.get("boundaries") or [] if b["crossing"] == crossing} for eid, e in elements.items()
    }
    near_column, before = ("sources", "sources") if column == "build" else ("artifacts", "build")
    on_near = set().union(*(ids for eid, ids in carried.items() if elements[eid]["column"] == near_column))
    out: dict[tuple[str, str], set[str]] = {}
    for edge in view["edges"]:
        src, dst = elements.get(edge["from"]), elements.get(edge["to"])
        if not src or not dst or src["column"] != before or dst["column"] != column:
            continue
        near, far = (src, dst) if column == "build" else (dst, src)
        ids = set(carried[near["id"]])
        if src["kind"] != "repository":
            ids |= carried[far["id"]] - on_near
        if ids:
            out[(edge["from"], edge["to"])] = ids
    return out


def _y_at(points, x):
    for (x1, y1), (x2, y2) in _segs(points):
        if x1 != x2 and min(x1, x2) <= x <= max(x1, x2):
            return y1 + (y2 - y1) * (x - x1) / (x2 - x1)
    return None


def _draw_boundaries(cv, view, borders, layout, at):
    """Draw each border's line over the flows its boundaries mark, confirmed and inferred apart.

    The line spans only those flows, so a CI system or registry no boundary
    names is not drawn as behind it. An inferred boundary keeps its own pale
    line wherever it crosses, so the drawing never shows it as confirmed.
    """
    parts: list[str] = []
    for column, border in borders.items():
        bx, confidence = border["x"], border["confidence"]
        spans: dict[str, list[float]] = {}
        ids_by_class: dict[str, set[str]] = {}
        flows = _crossing_ids(view, column)
        for edge in cv.edges:
            ids = flows.get(edge.get("elements"))
            y = _y_at(edge["points"], bx) if ids else None
            if y is None:
                continue
            for tid in ids:
                spans.setdefault(_line_class(confidence[tid]), []).append(y)
                ids_by_class.setdefault(_line_class(confidence[tid]), set()).add(tid)
        for tid, conf in confidence.items():
            if not any(tid in ids for ids in ids_by_class.values()):
                # No drawn flow carries it: span the boxes that hold its evidence instead.
                for element in view["elements"]:
                    box = layout["boxes"].get(_box_of(element["id"], layout["boxes"]) or "")
                    if box and tid in {b["id"] for b in element.get("boundaries") or []}:
                        spans.setdefault(_line_class(conf), []).extend((box["y"] + 12, box["y"] + box["h"] - 12))
                        ids_by_class.setdefault(_line_class(conf), set()).add(tid)
        for cls in ("inferred", "confirmed"):
            if cls not in spans:
                continue
            top, bottom = min(spans[cls]) - BOUNDARY_OVERHANG, max(spans[cls]) + BOUNDARY_OVERHANG
            ids = sorted(ids_by_class[cls], key=lambda tid: int(tid.split("-")[1]))
            title = ("Trust boundary crossing: " if cls == "confirmed" else "Inferred trust boundary crossing: ") + (
                ", ".join(ids)
            )
            style = 'stroke-width="2.2" stroke-dasharray="6 5"' if cls == "confirmed" else INFERRED_STYLE
            parts.append(
                f"<g><title>{html.escape(title)}</title>"
                f'<path d="M {bx:.1f} {top:.1f} V {bottom:.1f}" fill="none" stroke="{RED}" {style}/></g>'
            )
            cv.boundaries.append((bx, top, bottom))
    cv.parts[at:at] = parts


def _draw_actor(cv, actor, numbers, x, w, layout):
    h = 128
    cv.boxes["A2"] = (x, BOX_TOP, w, h)
    cv.rect(x, BOX_TOP, w, h, RED)
    cx = x + w / 2
    cv.parts.append(
        f'<circle cx="{cx:.1f}" cy="{BOX_TOP + 18:.1f}" r="7" fill="none" stroke="{RED}" stroke-width="1.6"/>'
    )
    cv.parts.append(
        f'<path d="M{cx - 11:.1f} {BOX_TOP + 38:.1f} q11 -14 22 0" fill="none" stroke="{RED}" stroke-width="1.6"/>'
    )
    y = BOX_TOP + 56
    name = actor_title(actor) + (" " + " ".join(numbers) if numbers else "")
    for line in wrap(name, FONT["row"] + 1, w - 16, True)[:3]:
        cv.text(cx, y, line, FONT["row"] + 1, weight="bold", fill=RED, anchor="middle", owner="A2")
        y += 14
    for line in wrap(actor.get("subtitle") or "", FONT["label"], w - 16)[: max(0, int((BOX_TOP + h - y - 6) // 11))]:
        cv.text(cx, y + 2, line, FONT["label"], fill=MUTED, anchor="middle", italic=True, owner="A2")
        y += 11
    layout["actor_port"] = (x + w, BOX_TOP + h - 24)
    layout["actor_top"] = (cx, BOX_TOP)


def _row_port(box, element_id):
    for row in box.get("rows") or []:
        if row["element"] and row["element"]["id"] == element_id:
            return row["y"] + 8
    return None


def _ports(cv, layout, edges):
    """Port heights: straight where both boxes share a height, otherwise spread over the box side."""
    boxes = layout["boxes"]

    def span(key):
        b = boxes[key]
        return b["y"] + 30, b["y"] + b["h"] - 12

    desired = {}
    for i, edge in enumerate(edges):
        (s0, s1), (d0, d1) = span(edge["src_box"]), span(edge["dst_box"])
        if edge.get("row_port") is not None:
            desired[i] = edge["row_port"] if d0 <= edge["row_port"] <= d1 else None
        else:
            low, high = max(s0, d0), min(s1, d1)
            desired[i] = (low + high) / 2 if low <= high else None
    out_y, in_y = {}, {}
    for side, target in (("src_box", out_y), ("dst_box", in_y)):
        groups: dict[str, list[int]] = {}
        for i, edge in enumerate(edges):
            groups.setdefault(edge[side], []).append(i)
        for key, indices in groups.items():
            low, high = span(key)
            taken: list[float] = []
            spread = sorted(
                indices,
                key=lambda i: desired[i]
                if desired[i] is not None
                else boxes[edges[i]["dst_box" if side == "src_box" else "src_box"]]["y"],
            )
            for k, i in enumerate(spread):
                if side == "src_box" and edges[i].get("row_port") is not None:
                    y = edges[i]["row_port"]
                elif desired[i] is not None and all(abs(desired[i] - t) >= 16 for t in taken):
                    y = desired[i]
                else:
                    y = low + (high - low) * (k + 1) / (len(spread) + 1)
                    while any(abs(y - t) < 16 for t in taken) and y + 16 <= high:
                        y += 16
                taken.append(y)
                target[i] = y
    return out_y, in_y


def _route(edges, out_y, in_y, boxes, problems):
    """Straight when both ends share a height, else through a lane in the gap; lanes searched for no crossing."""
    by_gap: dict[float, list[int]] = {}
    for i, edge in enumerate(edges):
        sx = boxes[edge["src_box"]]["x"] + boxes[edge["src_box"]]["w"]
        tx = boxes[edge["dst_box"]]["x"]
        edge["points"] = [(sx, out_y[i]), (tx, in_y[i])]
        if abs(out_y[i] - in_y[i]) > 0.5:
            by_gap.setdefault(sx, []).append(i)
    for sx, indices in by_gap.items():
        tx = boxes[edges[indices[0]]["dst_box"]]["x"]
        lanes = [sx + (tx - sx) * (k + 1) / (len(indices) + 1) for k in range(len(indices))]
        best = None
        for order in itertools.permutations(indices) if len(indices) <= 6 else [tuple(indices)]:
            trial = {i: lanes[k] for k, i in enumerate(order)}
            for i in indices:
                e = edges[i]
                e["points"] = [(sx, out_y[i]), (trial[i], out_y[i]), (trial[i], in_y[i]), (tx, in_y[i])]
            crossings = sum(
                _segments_cross(edges[a]["points"], edges[b]["points"])
                for a, b in itertools.combinations(range(len(edges)), 2)
            )
            if best is None or crossings < best[0]:
                best = (crossings, trial)
            if crossings == 0:
                break
        for i in indices:
            e, lane = edges[i], best[1][i]
            e["points"] = [(sx, out_y[i]), (lane, out_y[i]), (lane, in_y[i]), (tx, in_y[i])]


def _draw_edges(cv, view, plan, layout, highlighted, problems, stops=()):
    boxes = layout["boxes"]
    drawable = []
    for edge in view["edges"]:
        src = _box_of(edge["from"], boxes)
        dst = _box_of(edge["to"], boxes)
        if not src or not dst:
            continue
        if boxes[src]["x"] >= boxes[dst]["x"]:
            continue
        row_port = _row_port(boxes[src], edge["from"]) if src == "upstream" else None
        drawable.append(
            {
                **edge,
                "src_box": src,
                "dst_box": dst,
                "row_port": row_port,
                "step": highlighted.get((edge["from"], edge["to"])),
            }
        )
    out_y, in_y = _ports(cv, layout, drawable)
    _route(drawable, out_y, in_y, boxes, problems)
    for edge in drawable:
        points = edge["points"]
        key = f"{edge['from']}->{edge['to']}"
        if edge["step"]:
            cv.path(points, RED, 2, "attack", dash="6 3")
            cv.badge(key, points[0][0] + 16, points[0][1], str(edge["step"]), filled=False)
        elif edge["status"] == "unknown":
            cv.path(points, "#9aa5b1", 1.4, "flow", dash="5 4")
            _edge_label(cv, points, edge["label"], key, stops)
        else:
            cv.path(points, FLOW, 1.5, "flow")
            _edge_label(cv, points, edge["label"], key, stops)
        cv.edges.append(
            {
                "key": key,
                "from": edge["src_box"],
                "to": edge["dst_box"],
                "elements": (edge["from"], edge["to"]),
                "points": points,
                "attack": False,
            }
        )


def _edge_label(cv, points, label, key, stops=()):
    """Centre the label on the last horizontal run, left of any boundary line it crosses."""
    (ax, ay), (bx, by) = points[-2], points[-1]
    lo, hi = sorted((ax, bx))
    pad = 8
    for stop in stops:
        if lo < stop < hi:
            # No arrowhead shares the run left of the line, so a narrower margin suffices.
            hi, pad = stop - 2, 4
    if ay == by and label and text_width(label, FONT["label"]) + pad <= hi - lo:
        cv.text((lo + hi) / 2, by - 6, label, FONT["label"], fill=MUTED, anchor="middle", owner=key)


def _box_of(element_id, boxes):
    if element_id in boxes:
        return element_id
    for row in (boxes.get("upstream") or {}).get("rows") or []:
        if row["element"] and row["element"]["id"] == element_id:
            return "upstream"
    return None


def _draw_entries(cv, view, layout, x, widths, problems):
    boxes = layout["boxes"]
    port_x, port_y = layout["actor_port"]
    bus_x = port_x + 16
    top_x, top_y = layout["actor_top"]
    lane_used = False
    for index, entry in enumerate(view["entries"]):
        letter = ENTRY_LETTERS[index]
        target = "repository" if entry["entry"] == "repository" else entry["element"]
        box_key = _box_of(target, boxes)
        if not box_key:
            problems.append(f"entry {letter} targets {target}, which is not drawn")
            continue
        box = boxes[box_key]
        key = f"attack-{letter}"
        if box["x"] == x["sources"]:
            ty = _row_port(box, target) if box_key == "upstream" else box["y"] + min(40, box["h"] / 2)
            points = [(port_x, port_y), (bus_x, port_y), (bus_x, ty), (box["x"], ty)]
            badge = (bus_x + (box["x"] - bus_x) / 2 - 2, ty)
        else:
            if lane_used:
                problems.append("more than one entry needs the lane above the zones")
                continue
            lane_used = True
            tx = box["x"] + box["w"] - 24
            points = [(top_x, BOX_TOP), (top_x, TOP_LANE), (tx, TOP_LANE), (tx, box["y"])]
            badge = (tx - 40, TOP_LANE)
        cv.path(points, RED, 2, "attack")
        cv.badge(key, badge[0], badge[1], letter)
        cv.edges.append({"key": key, "from": "A2", "to": box_key, "points": points, "attack": True})


# ---- gates -------------------------------------------------------------------------------


def _segs(points):
    return list(zip(points, points[1:]))


def _cross(s1, s2):
    (a, b), (c, d) = s1, s2
    if a[1] == b[1] and c[0] == d[0]:
        return min(a[0], b[0]) < c[0] < max(a[0], b[0]) and min(c[1], d[1]) < a[1] < max(c[1], d[1])
    if a[0] == b[0] and c[1] == d[1]:
        return _cross(s2, s1)
    if a[1] == b[1] == c[1] == d[1]:  # collinear horizontal overlap hides a flow
        return (
            abs(a[1] - c[1]) < 0.5
            and max(min(a[0], b[0]), min(c[0], d[0])) < min(max(a[0], b[0]), max(c[0], d[0])) - 0.5
        )
    if a[0] == b[0] == c[0] == d[0]:
        return (
            abs(a[0] - c[0]) < 0.5
            and max(min(a[1], b[1]), min(c[1], d[1])) < min(max(a[1], b[1]), max(c[1], d[1])) - 0.5
        )
    return False


def _segments_cross(p1, p2):
    return any(_cross(s, u) for s in _segs(p1) for u in _segs(p2))


def _hits(seg, box, pad=1.5):
    (a, b), (x, y, w, h) = seg, box
    x, y, w, h = x - pad, y - pad, w + 2 * pad, h + 2 * pad
    if a[1] == b[1]:
        return y < a[1] < y + h and max(min(a[0], b[0]), x) < min(max(a[0], b[0]), x + w)
    return x < a[0] < x + w and max(min(a[1], b[1]), y) < min(max(a[1], b[1]), y + h)


def _overlap(b1, b2, pad=3.0):
    return (
        b1[0] - pad < b2[0] + b2[2]
        and b2[0] - pad < b1[0] + b1[2]
        and b1[1] - pad < b2[1] + b2[3]
        and b2[1] - pad < b1[1] + b1[3]
    )


def _head_box(points):
    (ax, ay), (bx, by) = points[-2], points[-1]
    if ay == by:
        return (bx - ARROW if bx > ax else bx, by - 6, ARROW + 2, 12)
    return (bx - 6, by - ARROW if by > ay else by, 12, ARROW + 2)


def _inside(inner, outer):
    return (
        outer[0] - 0.5 <= inner[0]
        and outer[1] - 0.5 <= inner[1]
        and inner[0] + inner[2] <= outer[0] + outer[2] + 0.5
        and inner[1] + inner[3] <= outer[1] + outer[3] + 0.5
    )


def _geometry_gate(cv, width, height) -> list[str]:
    problems = []
    for i, e1 in enumerate(cv.edges):
        for e2 in cv.edges[i + 1 :]:
            if e1["attack"] and e2["attack"]:
                continue  # entry routes share the bus by design
            if _segments_cross(e1["points"], e2["points"]):
                problems.append(f"crossing {e1['key']} / {e2['key']}")
        for key, box in cv.boxes.items():
            if key not in (e1["from"], e1["to"]) and any(_hits(s, box, 0) for s in _segs(e1["points"])):
                problems.append(f"{e1['key']} runs through box {key}")
        for text, box, owner in cv.texts:
            if owner != e1["key"] and any(_hits(s, box) for s in _segs(e1["points"])):
                problems.append(f"{e1['key']} runs through text {text!r}")
        for key, box in cv.badges.items():
            if key != e1["key"] and any(_hits(s, box) for s in _segs(e1["points"])):
                problems.append(f"{e1['key']} runs through badge {key}")
            if _overlap(box, _head_box(e1["points"])):
                problems.append(f"badge {key} touches the arrowhead of {e1['key']}")
        if e1["attack"]:
            target_zone = next((c for c, z in cv.zones.items() if _inside(cv.boxes[e1["to"]], z)), None)
            for column, zone in cv.zones.items():
                x, y, w, h = zone
                sides = [
                    ((x, y), (x + w, y)),
                    ((x, y + h), (x + w, y + h)),
                    ((x, y), (x, y + h)),
                    ((x + w, y), (x + w, y + h)),
                ]
                n = sum(_cross(s, side) for s in _segs(e1["points"]) for side in sides)
                if n and (column != target_zone or n > 1):
                    problems.append(f"{e1['key']} crosses the {column} zone border {n}x")
        for px, py in e1["points"]:
            if not (0 <= px <= width and 0 <= py <= height):
                problems.append(f"{e1['key']} leaves the canvas")
    for bx, top, bottom in cv.boundaries:
        line = ((bx, top), (bx, bottom))
        for key, box in cv.boxes.items():
            if _hits(line, box, 0):
                problems.append(f"boundary line at x={bx:.0f} runs through box {key}")
        for text, box, _owner in cv.texts:
            if _hits(line, box):
                problems.append(f"boundary line at x={bx:.0f} runs through text {text!r}")
        for key, box in cv.badges.items():
            if _hits(line, box):
                problems.append(f"boundary line at x={bx:.0f} runs through badge {key}")
        for edge in cv.edges:
            for (ax, ay), (cx, cy) in _segs(edge["points"]):
                if ax == cx and abs(ax - bx) < 3 and max(min(ay, cy), top) < min(max(ay, cy), bottom):
                    problems.append(f"boundary line at x={bx:.0f} runs along {edge['key']}")
    for text, box, owner in cv.texts:
        if owner in cv.boxes and not _inside(box, cv.boxes[owner]):
            problems.append(f"text {text!r} overflows box {owner}")
        if box[0] + box[2] > width or box[0] < 0:
            problems.append(f"text {text!r} leaves the canvas")
    return list(dict.fromkeys(problems))


def _legibility_gate(cv, width) -> list[str]:
    problems = []
    for name, display in DISPLAY_WIDTHS.items():
        effective = cv.min_font * min(1.0, display / width)
        if effective < MIN_EFFECTIVE_PX:
            problems.append(
                f"smallest text is {effective:.1f}px at the {name} width ({display}px), below {MIN_EFFECTIVE_PX}px"
            )
    return problems


# ---- legend ------------------------------------------------------------------------------


def _legend(view, plan, actor, numbers, width, boundaries=frozenset()):
    cv = Canvas()
    elements = plan["elements"]
    half = (width - 60) / 2
    lx, rx = 20, 40 + half
    y = 0.0
    cv.rect(lx, y, half, 24, "#2f4a68", "#2f4a68", rx=3, sw=0)
    head = "Entry points" + (f" of {actor_title(actor)}" if actor else "")
    cv.text(lx + half / 2, y + 16, head, FONT["legend_head"], weight="bold", fill="#ffffff", anchor="middle")
    y += 46
    if not view["entries"]:
        cv.text(lx + 8, y, "No reported finding establishes an attack entry.", FONT["legend"], fill=MUTED)
        y += 20
    for index, entry in enumerate(view["entries"]):
        cv.badge(f"legend-{index}", lx + 16, y - 4, ENTRY_LETTERS[index])
        cv.text(lx + 34, y, ENTRY_TITLES[entry["entry"]], FONT["legend"] + 1, weight="bold")
        cv.text(
            lx + half - 8,
            y,
            entry["severity"],
            FONT["legend"],
            weight="bold",
            fill=SEV.get(entry["severity"], MUTED),
            anchor="end",
        )
        element = elements.get(entry["element"]) or {}
        line = f"{element.get('label', '')}: {element.get('detail', '')}".strip(": ")
        for part in wrap(line, FONT["fact"], half - 44)[:2]:
            y += 14
            cv.text(lx + 34, y, part, FONT["fact"], fill=INK)
        y += 14
        cv.text(lx + 34, y, "Findings: " + ", ".join(entry["findings"]), FONT["fact"], fill=MUTED)
        y += 24
    path = view.get("highlighted_path") or {}
    if path.get("steps"):
        cv.text(lx + 8, y, f"Path of {path['finding']}, step by step:", FONT["legend"], weight="bold", fill=RED)
        y += 18
        for step in path["steps"]:
            src = (elements.get(step["from"]) or {}).get("label", step["from"])
            dst = (elements.get(step["to"]) or {}).get("label", step["to"])
            via = step.get("via") or {}
            where = (
                f" ({via.get('file')}:{via['line']})"
                if via.get("line")
                else (f" ({via['file']})" if via.get("file") else "")
            )
            cv.badge(f"legend-step-{step['n']}", lx + 16, y - 4, str(step["n"]), filled=False)
            for part in wrap(f"{src} → {dst}{where}", FONT["fact"], half - 44)[:2]:
                cv.text(lx + 34, y, part, FONT["fact"])
                y += 13
            y += 7
        cv.text(
            lx + 8,
            y,
            "The connection to the running system is not evidenced in the repository.",
            FONT["fact"],
            fill=MUTED,
        )
        y += 18
    unowned = [f for f in view["findings"] if f["element"] == "unowned"]
    if unowned:
        cv.text(
            lx + 8,
            y,
            "Findings without an evidenced CI owner: " + ", ".join(f["id"] for f in unowned),
            FONT["fact"],
            fill=MUTED,
        )
        y += 16
    for kind, labels in plan["overflow"].items():
        for part in wrap(f"Not drawn ({kind}): " + ", ".join(labels), FONT["fact"], half - 16):
            cv.text(lx + 8, y, part, FONT["fact"], fill=MUTED)
            y += 13
    left_bottom = y
    y = 0.0
    cv.rect(rx, y, half, 24, "#2f4a68", "#2f4a68", rx=3, sw=0)
    cv.text(rx + half / 2, y + 16, "Notation", FONT["legend_head"], weight="bold", fill="#ffffff", anchor="middle")
    y += 46
    sx, tx = rx + 8, rx + 64
    rows = [
        ("flow", "evidenced flow (checkout, fetch, push)"),
        ("unknown", "relationship not evidenced in the repository"),
        ("attack", "attack route of the build-time attacker"),
        ("path", "highlighted path of the most severe entry"),
        ("entry", "entry point (a, b, ...)"),
        ("step", "step on the highlighted path"),
        ("High", "High finding"),
        ("Medium", "Medium finding or decision"),
    ]
    if "inferred" in boundaries:
        rows.insert(4, ("inferred", "inferred trust boundary, existence not confirmed"))
    if "confirmed" in boundaries:
        rows.insert(4, ("boundary", "trust boundary crossed by these flows"))
    for sym, label in rows:
        if sym in {"boundary", "inferred"}:
            style = 'stroke-width="2.2" stroke-dasharray="6 5"' if sym == "boundary" else INFERRED_STYLE
            cv.parts.append(f'<path d="M {sx:.1f} {y - 4:.1f} H {sx + 44:.1f}" fill="none" stroke="{RED}" {style}/>')
        elif sym == "flow":
            cv.path([(sx, y - 4), (sx + 44, y - 4)], FLOW, 1.5, "flow")
        elif sym == "unknown":
            cv.path([(sx, y - 4), (sx + 44, y - 4)], "#9aa5b1", 1.4, "flow", dash="5 4")
        elif sym == "attack":
            cv.path([(sx, y - 4), (sx + 44, y - 4)], RED, 2, "attack")
        elif sym == "path":
            cv.path([(sx, y - 4), (sx + 44, y - 4)], RED, 2, "attack", dash="6 3")
        elif sym == "entry":
            cv.badge("n-entry", sx + 22, y - 4, "a")
        elif sym == "step":
            cv.badge("n-step", sx + 22, y - 4, "1", filled=False)
        else:
            cv.mark(sx + 22, y, sym)
        cv.text(tx, y, label, FONT["legend"])
        y += 21
    y += 6
    for part in wrap(
        "Boxes and flows come from repository files: workflow uses:, Dockerfile FROM, install and push steps. "
        "Known CVEs in dependencies are runtime findings and appear in Figure 1a.",
        FONT["fact"],
        half - 16,
    ):
        cv.text(rx + 8, y, part, FONT["fact"], fill=MUTED)
        y += 13
    return "\n".join(cv.parts), max(left_bottom, y), cv


# ---- table form ----------------------------------------------------------------------------


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _where(source: dict | None) -> str:
    if not source or not source.get("file"):
        return "—"
    return f"`{source['file']}:{source['line']}`" if source.get("line") else f"`{source['file']}`"


def render_table(view: dict, actor: dict | None, scenario_numbers: list[str]) -> str:
    """The figure as one table of the elements that carry a finding, an entry, a path step or a boundary.

    Fallback when a gate fails; elements with none of these are named in one line below it.
    """
    elements = {e["id"]: e for e in view["elements"]}
    by_element: dict[str, list[dict]] = {}
    for finding in view["findings"]:
        by_element.setdefault(finding["element"], []).append(finding)
    entries: dict[str, list[str]] = {}
    for index, entry in enumerate(view["entries"]):
        target = "repository" if entry["entry"] == "repository" else entry["element"]
        entries.setdefault(target, []).append(f"{ENTRY_LETTERS[index]} · {ENTRY_TITLES[entry['entry']]}")
    referenced = _referenced(view)

    def label(element_id):
        return elements.get(element_id, {}).get("label", element_id)

    lines = []
    if actor:
        lines.append(f"Build-time attacker: **{actor_title(actor)}** {' '.join(scenario_numbers)}".rstrip())
        if goal := goal_text(actor):
            lines += ["", goal]
        lines.append("")
    path = view.get("highlighted_path") or {}
    if path.get("steps"):
        route = label(path["steps"][0]["from"]) + "".join(
            f" → {label(step['to'])} ({_where(step.get('via'))})" for step in path["steps"]
        )
        lines += [f"Highlighted path of {path['finding']}: {route}", ""]
    lines += ["| Stage | Element | Entry | Trust boundary | Findings |", "|---|---|---|---|---|"]
    quiet = []
    for element in view["elements"]:
        findings = sorted(
            by_element.get(element["id"], []),
            key=lambda f: (list(SEV).index(f["severity"]) if f["severity"] in SEV else len(SEV), f["id"]),
        )
        boundaries = element.get("boundaries") or []
        if not (findings or boundaries or element["id"] in entries or element["id"] in referenced):
            quiet.append(element["label"])
            continue
        lines.append(
            f"| {ZONES[element['column']][0]} | {_cell(element['label'])} | "
            f"{_cell(', '.join(entries.get(element['id'], [])) or '—')} | "
            f"{_cell(', '.join(_boundary_text(b) for b in boundaries) or '—')} | "
            f"{', '.join(f['id'] for f in findings) or '—'} |"
        )
    if quiet:
        lines += ["", "No findings, entry or boundary: " + ", ".join(quiet) + "."]
    unowned = by_element.get("unowned")
    if unowned:
        lines += ["", "Findings without an evidenced CI owner: " + ", ".join(f["id"] for f in unowned)]
    return "\n".join(lines)
