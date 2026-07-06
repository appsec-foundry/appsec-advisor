"""Deterministic SVG generator for Figure 2 — the risk-flow heatmap
(actors → architecture tiers → business impact).

Why a hand-built SVG instead of the inline Mermaid heatmap: the Mermaid block
requires the ELK layout engine (nested `direction TB` inside three invisible
subgraph columns). ELK ships with the plugin's PDF pipeline, but common
Markdown viewers (GitHub, VS Code preview, Obsidian) do NOT bundle it — they
silently fall back to dagre, which cannot honour the nested directions, so the
whole figure collapses onto one flat row with floating arrows. This generator
computes the 3-column layout itself and emits plain SVG primitives (rect / line
/ circle / text) that render natively everywhere — mirroring the choice already
made for Figure 1 (`figure1_svg.py`), so no viewer needs ELK.

Public entry point: ``build_figure2_svg(diagram_data) -> str`` where
``diagram_data`` is the same structure `compose_threat_model` feeds to
`templates/fragments/security-posture-diagram.md.j2` (see that template's header
for the field contract).
"""

from __future__ import annotations

import math

# Reuse the primitives + palette that Figure 1 already established so both
# figures share one visual language and one escaping/geometry helper set.
from figure1_svg import _ATTACK, _INK, _Canvas, _wrap

_FONT = "Helvetica, Arial, sans-serif"

# ---- palette (mirrors the Mermaid classDefs the heatmap used) --------------
# actorAnon / actorShopUser fills+strokes match security-posture-diagram.md.j2.
_ACTOR_STYLE = {
    "actorAnon": ("#f3dada", "#b71c1c", "#7f0000"),
    "actorShopUser": ("#e8f1ea", "#2e7d32", "#1b5e20"),
}
_ACTOR_FALLBACK = ("#f3dada", "#b71c1c", "#7f0000")
_TIER_FILL, _TIER_STROKE, _TIER_INK = "#f2f2f2", "#424242", "#111111"
_IMPACT_FILL, _IMPACT_STROKE, _IMPACT_INK = "#0f172a", "#000000", "#ffffff"
_CONSEQ = "#6b7280"  # grey dashed consequence edges
# Severity dot colours for the impact-label emoji (🔴/🟠) — drawn, never emoji.
_SEV_DOT = {"🔴": "#d64545", "🟠": "#e8943a", "🟡": "#e8c33a"}

# ---- geometry --------------------------------------------------------------
_PAD = 22
_HDR_H = 40  # header row height (column titles pinned on one baseline)
_COL_GAP = 132  # horizontal gap between columns (hosts arrows + glyph badges)
_ACTOR_W = 190
_TIER_W = 306
_IMPACT_W = 214
_VGAP = 26  # vertical gap between stacked cards in a column
_ACTOR_H = 56
_IMPACT_H = 48
_TIER_MIN_H = 60
_LINE_PX = 12  # component-line font size inside tier boxes
_MAX_DISPLAY_W = 840  # cap on-page width; viewBox keeps full detail (zoomable)

# Circled-unicode → plain digit. The heatmap labels arrows with ①..⑳; we draw
# the number inside a red circle instead (font glyph coverage for circled
# unicode is unreliable and rasterises to tofu in some engines — see Figure 1).
_GLYPH_NUM = {chr(0x2460 + i): str(i + 1) for i in range(20)}


def _glyph_digits(glyph_field: str) -> list[str]:
    """Split a space-joined circled-unicode glyph string (``"① ② ③"``) into
    plain digit strings (``["1", "2", "3"]``). Unknown tokens are dropped."""
    out: list[str] = []
    for tok in (glyph_field or "").split():
        if tok in _GLYPH_NUM:
            out.append(_GLYPH_NUM[tok])
    return out


def _split_impact_label(label: str) -> tuple[str, str]:
    """Return (severity-dot-colour-or-'', clean label) for an impact label such
    as ``"🟠 Customer Session Hijack"`` — the emoji becomes a drawn dot."""
    label = (label or "").strip()
    for emoji, colour in _SEV_DOT.items():
        if label.startswith(emoji):
            return colour, label[len(emoji) :].strip()
    return "", label


def build_figure2_svg(diagram_data: dict) -> str:
    """Build the risk-flow heatmap as a deterministic SVG. Returns "" when there
    is nothing to draw (no actor or tier cards) — the caller then falls back to
    the inline Mermaid block."""
    actors = list((diagram_data.get("subgraph_actors") or {}).get("cards") or [])
    tiers = list((diagram_data.get("subgraph_tiers") or {}).get("cards") or [])
    impacts = list((diagram_data.get("subgraph_impact") or {}).get("cards") or [])
    if not actors or not tiers:
        return ""

    attack_arrows = list(diagram_data.get("attack_arrows") or [])
    relay_arrows = list(diagram_data.get("relay_arrows") or [])
    conseq_arrows = list(diagram_data.get("consequence_arrows") or [])

    hdr_actors = (diagram_data.get("subgraph_actors") or {}).get("header_label") or "Threat Actors"
    hdr_tiers = (diagram_data.get("subgraph_tiers") or {}).get("header_label") or "Architecture Tiers"
    hdr_impact = (diagram_data.get("subgraph_impact") or {}).get("header_label") or "Business Impact"

    # ---- column x-origins --------------------------------------------------
    ax0 = _PAD
    tx0 = ax0 + _ACTOR_W + _COL_GAP
    ix0 = tx0 + _TIER_W + _COL_GAP
    content_top = _PAD + _HDR_H

    # ---- pre-compute tier box heights (name + wrapped components line) ------
    def _tier_lines(t: dict) -> tuple[str, list[str]]:
        # Match the Mermaid template: the tier box shows the SHORT tier name
        # ("Application Tier") + its components line — not the long
        # `header_summary` (which carries a "(comp, comp, +N) · N findings"
        # suffix that overflows the fixed box width).
        title = t.get("name") or ""
        comp_line = t.get("components_line") or ""
        wrapped = _wrap(comp_line, _TIER_W - 24, _LINE_PX) if comp_line else []
        return title, wrapped

    tier_h: list[float] = []
    tier_meta: list[tuple[str, list[str]]] = []
    for t in tiers:
        title, wrapped = _tier_lines(t)
        h = 20 + 14 + len(wrapped) * (_LINE_PX * 1.2) + 12
        tier_h.append(max(_TIER_MIN_H, h))
        tier_meta.append((title, wrapped))

    # ---- column stack heights (for vertical centring) ----------------------
    actor_stack = len(actors) * _ACTOR_H + (len(actors) - 1) * _VGAP
    tier_stack = sum(tier_h) + (len(tiers) - 1) * _VGAP
    impact_stack = (len(impacts) * _IMPACT_H + (len(impacts) - 1) * _VGAP) if impacts else 0
    content_h = max(actor_stack, tier_stack, impact_stack)

    # node_id -> (x, y, w, h) box rectangle
    box: dict[str, tuple[float, float, float, float]] = {}

    c = _Canvas()

    # ---- column headers (one baseline) -------------------------------------
    hy = _PAD + 22
    c.text(ax0 + _ACTOR_W / 2, hy, hdr_actors, size=14, fill=_INK, weight="bold")
    c.text(tx0 + _TIER_W / 2, hy, hdr_tiers, size=14, fill=_INK, weight="bold")
    if impacts:
        c.text(ix0 + _IMPACT_W / 2, hy, hdr_impact, size=14, fill=_INK, weight="bold")

    # ---- actor column (rounded pills) --------------------------------------
    y = content_top + (content_h - actor_stack) / 2
    for a in actors:
        nid = a.get("id")
        fill, stroke, ink = _ACTOR_STYLE.get(a.get("severity_class") or "", _ACTOR_FALLBACK)
        c.rect(ax0, y, _ACTOR_W, _ACTOR_H, fill=fill, stroke=stroke, sw=2, rx=_ACTOR_H / 2)
        for i, ln in enumerate(_wrap(a.get("label") or nid or "", _ACTOR_W - 26, 12)[:3]):
            c.text(ax0 + _ACTOR_W / 2, y + _ACTOR_H / 2 - 4 + i * 14 + 4, ln, size=11.5, fill=ink, weight="bold")
        if nid:
            box[nid] = (ax0, y, _ACTOR_W, _ACTOR_H)
        y += _ACTOR_H + _VGAP

    # ---- tier column (grey boxes: title + wrapped component line) ----------
    y = content_top + (content_h - tier_stack) / 2
    for t, h, (title, wrapped) in zip(tiers, tier_h, tier_meta):
        nid = t.get("node_id")
        c.rect(tx0, y, _TIER_W, h, fill=_TIER_FILL, stroke=_TIER_STROKE, sw=2, rx=6)
        c.text(tx0 + _TIER_W / 2, y + 22, title, size=12.5, fill=_TIER_INK, weight="bold")
        for i, ln in enumerate(wrapped):
            c.text(tx0 + _TIER_W / 2, y + 22 + 16 + i * (_LINE_PX * 1.2), ln, size=_LINE_PX, fill=_TIER_INK)
        if nid:
            box[nid] = (tx0, y, _TIER_W, h)
        y += h + _VGAP

    # ---- impact column (dark boxes, white text, drawn severity dot) --------
    if impacts:
        y = content_top + (content_h - impact_stack) / 2
        for imp in impacts:
            nid = imp.get("node_id")
            dot, clean = _split_impact_label(imp.get("label") or "")
            c.rect(ix0, y, _IMPACT_W, _IMPACT_H, fill=_IMPACT_FILL, stroke=_IMPACT_STROKE, sw=2.5, rx=4)
            tx = ix0 + 16
            if dot:
                c.circle(tx, y + _IMPACT_H / 2, 5, fill=dot, stroke=dot, sw=1)
                tx += 14
            for i, ln in enumerate(_wrap(clean, _IMPACT_W - (tx - ix0) - 12, 11)[:2]):
                c.text(tx, y + _IMPACT_H / 2 - 4 + i * 13 + 4, ln, size=11, fill=_IMPACT_INK, anchor="start", weight="bold")
            if nid:
                box[nid] = (ix0, y, _IMPACT_W, _IMPACT_H)
            y += _IMPACT_H + _VGAP

    # ---- edges -------------------------------------------------------------
    def _right_mid(nid: str) -> tuple[float, float] | None:
        b = box.get(nid)
        return (b[0] + b[2], b[1] + b[3] / 2) if b else None

    def _left_mid(nid: str) -> tuple[float, float] | None:
        b = box.get(nid)
        return (b[0], b[1] + b[3] / 2) if b else None

    # Consequence edges first (grey, behind attack edges) — tier → impact.
    for e in conseq_arrows:
        p1, p2 = _right_mid(e.get("src")), _left_mid(e.get("dst"))
        if p1 and p2:
            c.line(p1[0], p1[1], p2[0], p2[1], stroke=_CONSEQ, sw=1.5, dash="4 4", marker="f2conseq")

    # Attack + relay edges (red) — actor → tier. Solid for direct, dashed for
    # indirect (victim-required) and relay (delivery) hops. Glyph badges ride
    # the arrow's first third.
    def _draw_attack(e: dict, dashed: bool) -> None:
        p1, p2 = _right_mid(e.get("src")), _left_mid(e.get("dst"))
        if not (p1 and p2):
            return
        c.line(
            p1[0], p1[1], p2[0], p2[1],
            stroke=_ATTACK, sw=(2.5 if dashed else 3.0),
            dash="6 4" if dashed else None, marker="f2attack",
        )
        digits = _glyph_digits(e.get("glyph") or "")
        if not digits:
            return
        # Ride the badges along the arrow at a fixed pixel PITCH so adjacent
        # numbered circles never overlap regardless of arrow length/count. The
        # cluster is centred just past the source box (≈45% of the span) and
        # laid out along the unit direction vector.
        dx, dy = p2[0] - p1[0], p2[1] - p1[1]
        length = math.hypot(dx, dy) or 1.0
        ux, uy = dx / length, dy / length
        pitch = 21.0
        cx = p1[0] + dx * 0.45
        cy = p1[1] + dy * 0.45
        start = -(len(digits) - 1) / 2 * pitch
        for k, dg in enumerate(digits):
            off = start + k * pitch
            bx, by = cx + ux * off, cy + uy * off
            c.circle(bx, by, 9, fill=_ATTACK, stroke="#ffffff", sw=1.4)
            c.text(bx, by + 3.4, dg, size=10.5, fill="#ffffff", weight="bold")

    for e in attack_arrows:
        _draw_attack(e, dashed=bool(e.get("indirect")))
    for e in relay_arrows:
        _draw_attack(e, dashed=True)

    # ---- assemble ----------------------------------------------------------
    total_w = ix0 + (_IMPACT_W if impacts else _TIER_W) + _PAD
    total_h = content_top + content_h + _PAD
    defs = (
        "<defs>"
        '<marker id="f2attack" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{_ATTACK}"/></marker>'
        '<marker id="f2conseq" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{_CONSEQ}"/></marker>'
        "</defs>"
    )
    body = "\n".join(c.el)
    disp_w = min(total_w, _MAX_DISPLAY_W)
    disp_h = total_h * disp_w / total_w
    # `data-glyphs` records the attack-arrow glyph numbers (plain digits) as a
    # stable, machine-readable anchor so `qa_checks` can enforce diagram↔Top-
    # Threats-table glyph parity without re-parsing drawn badge text.
    all_digits: list[str] = []
    for e in attack_arrows + relay_arrows:
        all_digits.extend(_glyph_digits(e.get("glyph") or ""))
    glyphs_attr = " ".join(sorted(set(all_digits), key=int))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{disp_w:.0f}" height="{disp_h:.0f}" '
        f'viewBox="0 0 {total_w:.0f} {total_h:.0f}" font-family="{_FONT}" data-glyphs="{glyphs_attr}">\n'
        f'<rect x="0" y="0" width="{total_w:.0f}" height="{total_h:.0f}" fill="#ffffff"/>\n'
        f"{defs}\n{body}\n</svg>\n"
    )
