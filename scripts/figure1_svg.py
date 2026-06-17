"""Deterministic SVG generator for Figure 1 — the threat-model architecture
overview (tiers → components → top threats).

Why a hand-built SVG instead of Mermaid: Mermaid/ELK lays each tier out as ONE
horizontal row and (because every attacked component is one hop from the
attacker) cannot wrap a busy tier into a grid, so the figure grew unboundedly
wide. This generator computes the layout itself — components wrap into a grid
that grows in HEIGHT, and the attacker is shown as a single dashed "attack
surface" boundary plus per-box attack-ID badges instead of an arrow fan. Output
is plain SVG primitives (rect/line/circle/text) — no emoji, no circled-unicode
glyphs — so it rasterises faithfully in Chrome (PNG) and WeasyPrint (PDF).

Public entry point: ``build_figure1_svg(yaml_data, attack_paths_data,
attack_taxonomy, meta=None) -> str``.
"""

from __future__ import annotations

import html
import math
import re

# ---- palette ---------------------------------------------------------------
_FONT = "Helvetica, Arial, sans-serif"
_TIERS = ("actors", "client", "application", "data")
_TIER_TITLE = {
    "actors": "External Actors — Internet (untrusted)",
    "client": "Client Tier — browser",
    "application": "Application Tier — Node / Express",
    "data": "Data Tier",
}
# (band background, accent/border) per tier — a consistent colour LANGUAGE that
# reads outside-in: neutral grey = untrusted external zone, then a cool ramp
# blue → green → purple for client → application → data (deeper = closer to the
# crown-jewel data). RED IS NEVER A TIER colour — it means "attacker" only (the
# attacker card), so the legitimate Shop User no longer sits in a red band.
_TIER_COLOR = {
    "actors": ("#eef1f5", "#5b6b7f"),  # neutral slate — external / untrusted
    "client": ("#eaf2fb", "#2f6fb3"),  # blue   — browser, semi-trusted
    "application": ("#e9f6ef", "#2e8b57"),  # green  — our trusted server core
    "data": ("#f2ecf9", "#6f42a1"),  # purple — most sensitive (data)
}
_CRIT = "#d64545"
_HIGH = "#e8943a"
_ID_STROKE = "#5b6470"
_ID_TEXT = "#3a414b"
_ATTACK = "#c0392b"
_BACKBONE = "#8a8f98"
_INK = "#1f2733"
_MUTED = "#6b7280"

# ---- geometry --------------------------------------------------------------
_PAD = 18
_LG = 150  # left gutter (tier icon + number + title)
_IPAD = 14  # inner padding: gap between the boxes and the band edges
_BW, _BH = 168, 90  # component box (compact; name + severity + attack-IDs)
_GX, _GY = 18, 18  # grid gaps (box-to-box)
_MAXC = 4  # max columns before wrapping into a new row
_CAP = 6  # top-N components drawn per tier; the rest → "+N also assessed"
_OOS_INLINE_MAX = (
    3  # ≤ this many out-of-scope components per tier → individual dimmed boxes; more → one collapsed count box
)
_OOS_BOX_H = 30  # height of a dimmed out-of-scope box drawn inside a tier band
_OOS_GAP = 10  # gap above the out-of-scope box row inside a tier band
# (the dashed style is explained once in the Diagram Legend,
#  so no repeated per-band caption is drawn)
_BANDPAD = 20
_BANDGAP = 34  # room for the flow arrow + its label between bands
_LEGGAP = 70  # right lane: hosts the red attack corridor (2 lanes), then the legend
_LEGW = 226
_EXPOSED = "#c0392b"  # internet-exposed marker (red = attacker-reachable)
_ACTOR_H = 94
# Capped on-page display width (px). The viewBox keeps the true coordinate
# space, so the figure renders as a compact OVERVIEW but stays vector-crisp and
# is zoomable to full detail. Bigger models still grow in height, not width.
_MAX_DISPLAY_W = 760


def _esc(s: str) -> str:
    return html.escape(str(s or ""), quote=True)


def _wrap(text: str, max_w: float, font_px: float) -> list[str]:
    """Greedy word-wrap; ~0.55·font_px per char is a good Helvetica estimate."""
    cpl = max(6, int(max_w / (0.55 * font_px)))
    words, lines, cur = (text or "").split(), [], ""
    for w in words:
        cand = (cur + " " + w).strip()
        if len(cand) <= cpl:
            cur = cand
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [""]


class _Canvas:
    def __init__(self) -> None:
        self.el: list[str] = []

    def rect(self, x, y, w, h, *, fill="none", stroke="none", sw=1.0, rx=0, dash=None, opacity=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{opacity}"' if opacity is not None else ""
        self.el.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}{o}/>'
        )

    def line(self, x1, y1, x2, y2, *, stroke, sw=1.5, dash=None, marker=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        m = f' marker-end="url(#{marker})"' if marker else ""
        self.el.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
            f'stroke="{stroke}" stroke-width="{sw}"{d}{m}/>'
        )

    def circle(self, cx, cy, r, *, fill="none", stroke="none", sw=1.0):
        self.el.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>'
        )

    def text(self, x, y, s, *, size=11, fill=_INK, anchor="middle", weight="normal", italic=False, family=_FONT):
        st = ' font-style="italic"' if italic else ""
        self.el.append(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{family}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"{st}>{_esc(s)}</text>'
        )

    def lines(self, x, y, rows, *, size=11, fill=_INK, anchor="middle", weight="normal", lh=1.18, italic=False):
        for i, r in enumerate(rows):
            self.text(x, y + i * size * lh, r, size=size, fill=fill, anchor=anchor, weight=weight, italic=italic)


# ---- tier icons (simple, drawn — no emoji) ---------------------------------
def _icon(c: _Canvas, kind: str, cx: float, cy: float, col: str) -> None:
    if kind == "actors":  # globe
        c.circle(cx, cy, 11, stroke=col, sw=1.6)
        c.el.append(f'<ellipse cx="{cx}" cy="{cy}" rx="5" ry="11" fill="none" stroke="{col}" stroke-width="1.2"/>')
        c.line(cx - 11, cy, cx + 11, cy, stroke=col, sw=1.2)
    elif kind == "client":  # browser window
        c.rect(cx - 12, cy - 9, 24, 18, stroke=col, sw=1.6, rx=2)
        c.line(cx - 12, cy - 3, cx + 12, cy - 3, stroke=col, sw=1.2)
        for k in range(3):
            c.circle(cx - 9 + k * 3.2, cy - 6, 0.9, fill=col)
    elif kind == "application":  # stacked servers
        for dy in (-7, 1):
            c.rect(cx - 12, cy + dy, 24, 6, stroke=col, sw=1.4, rx=1)
            c.circle(cx + 8, cy + dy + 3, 1.1, fill=col)
    elif kind == "data":  # database cylinder
        c.el.append(
            f'<ellipse cx="{cx}" cy="{cy - 7}" rx="11" ry="3.4" fill="none" stroke="{col}" stroke-width="1.5"/>'
        )
        c.line(cx - 11, cy - 7, cx - 11, cy + 7, stroke=col, sw=1.5)
        c.line(cx + 11, cy - 7, cx + 11, cy + 7, stroke=col, sw=1.5)
        c.el.append(
            f'<path d="M {cx - 11} {cy + 7} A 11 3.4 0 0 0 {cx + 11} {cy + 7}" fill="none" stroke="{col}" stroke-width="1.5"/>'
        )
        c.el.append(
            f'<path d="M {cx - 11} {cy} A 11 3.4 0 0 0 {cx + 11} {cy}" fill="none" stroke="{col}" stroke-width="1.1"/>'
        )


def _globe(c: _Canvas, cx: float, cy: float, r: float, col: str) -> None:
    """Small 'internet-exposed' globe marker for a component box corner."""
    c.circle(cx, cy, r, fill="#fff", stroke=col, sw=1.3)
    c.el.append(
        f'<ellipse cx="{cx:.1f}" cy="{cy:.1f}" rx="{r * 0.46:.1f}" ry="{r:.1f}" fill="none" stroke="{col}" stroke-width="0.9"/>'
    )
    c.line(cx - r, cy, cx + r, cy, stroke=col, sw=0.9)
    c.line(cx, cy - r, cx, cy + r, stroke=col, sw=0.9)


def _grid(n: int) -> tuple[int, list[int]]:
    """Return (rows, sizes-per-row) wrapping n boxes at <=_MAXC columns,
    balanced so a tier grows in height, not width."""
    rows = max(1, math.ceil(n / _MAXC)) if n else 1
    per = math.ceil(n / rows) if n else 0
    sizes = []
    left = n
    for _ in range(rows):
        take = min(per, left)
        sizes.append(take)
        left -= take
    return rows, sizes


def build_figure1_svg(
    yaml_data: dict,
    attack_paths_data: dict,
    attack_taxonomy: dict,
    meta: dict | None = None,
    actor_labels: dict | None = None,
) -> str:
    meta = meta or (yaml_data.get("meta") or {})
    components = yaml_data.get("components") or []
    threats = yaml_data.get("threats") or []
    if not components or not (attack_paths_data.get("attack_paths") or []):
        return ""  # nothing to draw — caller falls back to the Mermaid builder
    cls_by_id = {c.get("id"): c for c in (attack_taxonomy.get("classes") or []) if isinstance(c, dict)}

    # component bookkeeping
    comp = {}
    order = []
    for i, c in enumerate(components, 1):
        cid = (c.get("id") or "").strip()
        if not cid:
            continue
        tier = (c.get("tier") or "application").strip().lower()
        if tier not in ("client", "application", "data"):
            tier = "application"
        comp[cid] = {"cnum": f"C-{i:02d}", "name": c.get("name") or cid, "tier": tier, "crit": 0, "high": 0, "ids": []}
        order.append(cid)
    for t in threats:
        cid = (t.get("component") or "").strip()
        s = (t.get("risk") or t.get("severity") or "").strip().title()
        if cid in comp and s in ("Critical", "High"):
            comp[cid]["crit" if s == "Critical" else "high"] += 1

    # finding-id -> component
    fid_comp = {}
    for t in threats:
        cid = (t.get("component") or "").strip()
        if not cid:
            continue
        for kn in ("id", "t_id", "original_id"):
            v = (t.get(kn) or "").strip().upper()
            m = re.match(r"^[FT]-(\d+)$", v)
            if m:
                for pre in ("F-", "T-"):
                    fid_comp.setdefault(f"{pre}{m.group(1)}", cid)

    # ---- actors & attack scenarios -------------------------------------------
    _FALLBACK_ACTOR = {
        "internet-anon": "Anonymous Internet Attacker",
        "internet-user": "Authenticated User",
        "internet-priv-user": "Privileged User",
        "repo-read": "Source-Code Reader",
        "supply-chain": "Supply-Chain Attacker",
        "build-time": "Supply-Chain / Build Attacker",
        "malicious-insider": "Malicious Insider",
        "insider": "Malicious Insider",
        "developer": "Developer",
        "b2b-partner": "B2B Partner",
    }

    def actor_name(slug: str) -> str:
        slug = (slug or "internet-anon").strip()
        if actor_labels and slug in actor_labels:
            return (actor_labels[slug] or {}).get("label") or _FALLBACK_ACTOR.get(slug) or slug
        return _FALLBACK_ACTOR.get(slug, slug)

    # Per attack path: a number, its attacking actor, and the drawn components it
    # hits. Multiple distinct attackers are supported. Scenarios are NOT capped
    # (they are already bounded upstream); the legend wraps over several rows.
    # victim-required folds into the anonymous attacker (it DELIVERS the payload;
    # the victim is the Shop User, shown separately).
    scenarios = []  # (digit, name, actor_slug)
    victim_ids = []
    actor_order = []  # distinct attacker slugs, first-seen
    # Per-target-tier attack summary that DRIVES THE ARROWS (independent of the
    # per-component badges below). For each attacked tier we record whether a
    # DIRECT path (an actor that reaches the tier itself) and/or an INDIRECT
    # path (victim-required — e.g. DOM XSS, where the attacker plants a payload
    # the victim's browser later executes) targets it. This is what lets the
    # figure draw a solid arrow into application/data and a DASHED arrow into
    # the client tier, instead of the old single exposure-derived arrow that
    # mislabelled a victim-required client attack as "direct".
    tier_attacks = {
        "client": {"direct": False, "indirect": False},
        "application": {"direct": False, "indirect": False},
        "data": {"direct": False, "indirect": False},
    }
    # Internet-exposed components: a trust boundary whose SOURCE is the outside
    # world makes its target component a directly-reachable entry point. A tier
    # is DIRECTLY attackable only if one of its components is exposed; a tier
    # behind the app (e.g. the data layer — SQLite/MarsDB has no network
    # listener) is reached THROUGH the app, never by a direct attacker arrow.
    exposed = set()
    for tb in yaml_data.get("trust_boundaries") or []:
        if isinstance(tb, dict) and (tb.get("from") or "").strip().lower() in (
            "",
            "external",
            "internet",
            "public-internet",
        ):
            to = (tb.get("to") or "").strip()
            if to in comp:
                exposed.add(to)
    exposed_tiers = {comp[cid]["tier"] for cid in exposed}
    for idx, ap in enumerate(attack_paths_data.get("attack_paths") or []):
        digit = idx + 1
        slug = (ap.get("class") or "").strip()
        cl = cls_by_id.get(slug) or {}
        name = cl.get("short_label") or cl.get("label") or slug or "attack"
        raw_actor = (ap.get("actor") or cl.get("default_actor") or "internet-anon").strip()
        actor = raw_actor
        if actor in ("victim-required", ""):
            actor = "internet-anon"
        if actor not in actor_order:
            actor_order.append(actor)
        tgt = (
            (ap.get("_llm_target") or ap.get("target") or cl.get("default_target_tier") or "application")
            .strip()
            .lower()
        )
        ttier = "client" if tgt in ("client", "victim") else "application"
        # Arrow classification is PATH-level (not per-finding): a victim-required
        # path is INDIRECT (dashed → the client tier, where the payload executes
        # in the victim's browser). Otherwise the path is DIRECT and its arrow
        # lands on the directly-attacked ENTRY tier. The `target` names the
        # compromised ASSET → it maps to the entry tier, EXCEPT a data-tier asset
        # behind the app (not internet-exposed): a SQL/NoSQL injection ENTERS at
        # the application endpoint and reaches the data THROUGH it, so it is a
        # direct APPLICATION attack — never a direct arrow on the data layer
        # (which has no network listener). A data component that is itself
        # internet-exposed keeps its own direct arrow.
        if raw_actor == "victim-required" or tgt == "victim":
            tier_attacks["client"]["indirect"] = True
        else:
            atier = {"client": "client", "data": "data"}.get(tgt, "application")
            if atier == "data" and "data" not in exposed_tiers:
                atier = "application"
            tier_attacks[atier]["direct"] = True
        hosts = []
        for f in ap.get("findings") or []:
            cid = fid_comp.get((f or "").upper())
            if cid in comp and comp[cid]["tier"] == ttier and cid not in hosts:
                hosts.append(cid)
        for cid in hosts:
            if digit not in comp[cid]["ids"]:
                comp[cid]["ids"].append(digit)
        if tgt in ("client", "victim"):
            victim_ids.append(digit)
        scenarios.append((digit, name, actor))

    # (`exposed` / `exposed_tiers` are computed above, before the scenario loop,
    # because the per-tier direct/indirect classification depends on them.)

    # Components enumerated but NOT given a STRIDE pass at this depth
    # (meta.component_selection.excluded). Pull them OUT of the assessed tier
    # grid so they neither draw as plain boxes nor fold into "+N also assessed"
    # (which means "assessed, lower priority" — the opposite of out-of-scope).
    # They are shown in a distinct dashed strip below the tiers for completeness.
    _cs = meta.get("component_selection") if isinstance(meta.get("component_selection"), dict) else {}
    oos_ids = {
        (e.get("id") or "").strip()
        for e in (_cs.get("excluded") or [])
        if isinstance(e, dict) and (e.get("id") or "").strip()
    }
    # Place each out-of-scope component INSIDE its own tier band (as a dimmed,
    # dashed box) so the reader sees it in the layer it belongs to — not
    # stranded in a separate strip divorced from its tier (the old layout was
    # confusing: an empty "Data Tier" band with C-03 Data Persistence floating
    # below it). `tier` is always coerced to one of the three rendered tiers
    # above, so every excluded component lands in a band; nothing is dropped.
    oos_by_tier = {
        tk: [cid for cid in order if cid in oos_ids and cid in comp and comp[cid]["tier"] == tk]
        for tk in ("client", "application", "data")
    }

    by_tier = {
        tk: [cid for cid in order if comp[cid]["tier"] == tk and cid not in oos_ids]
        for tk in ("client", "application", "data")
    }
    # busiest first within a tier (so the grid puts heavy boxes early)
    for tk in by_tier:
        by_tier[tk].sort(
            key=lambda cid: (-len(comp[cid]["ids"]), -comp[cid]["crit"], -comp[cid]["high"], order.index(cid))
        )

    # Top-N budget — this is a TOP-THREATS overview, not the full inventory. Draw
    # at most _CAP components per tier (the most-attacked/severe, already sorted
    # first); collapse the rest into one compact "+N also assessed" note. This is
    # what keeps ONE simple layout path that never needs an abbreviated/compact
    # mode regardless of repo size.
    drawn = {tk: by_tier[tk][:_CAP] for tk in by_tier}
    hidden = {tk: by_tier[tk][_CAP:] for tk in by_tier}

    open_reg = bool(meta.get("open_user_registration"))

    # ---- layout ----
    # Content width tracks the WIDEST row actually used so the grid fills the band.
    tier_grid = {t: _grid(len(drawn[t])) for t in ("client", "application", "data")}
    max_row = max([max(sizes) for _r, sizes in tier_grid.values() if sizes] + [1])
    cols = max(1, min(_MAXC, max_row))
    cw = cols * _BW + (cols - 1) * _GX

    c = _Canvas()
    band_left = _PAD
    cx0 = _PAD + _LG + _IPAD  # content-area left x (inset from the gutter)
    band_w = _LG + _IPAD + cw + _IPAD  # +inner padding on both sides of the content
    box_pos: dict[str, tuple[float, float, float, float]] = {}  # cid -> (cx, top, bottom, left)
    y = _PAD
    bands: list[tuple[str, float, float]] = []  # (tier, y_top, height)

    def band_title(
        tier: str, ytop: float, h: float, num: int, bw: float | None = None, title: str | None = None
    ) -> None:
        bg, accent = _TIER_COLOR[tier]
        c.rect(band_left, ytop, bw or band_w, h, fill=bg, stroke=accent, sw=1.6, rx=10)
        _icon(c, tier, band_left + 26, ytop + 24, accent)
        c.text(band_left + 14, ytop + 54, f"{num})", size=15, fill=accent, anchor="start", weight="bold")
        for i, ln in enumerate(_wrap(title or _TIER_TITLE[tier], _LG - 26, 12)):
            c.text(band_left + 40, ytop + 52 + i * 15, ln, size=12, fill=accent, anchor="start", weight="bold")

    # --- actors band: N attacker cards (red) + the legitimate user (green) ---
    gcol = _TIER_COLOR["application"][1]
    # legitimate user first (left), attackers after (right) — so the red direct-
    # attack arrow on the right originates next to an attacker card (user request).
    cards = [("good", None, "Shop User")] + [("bad", s, actor_name(s)) for s in actor_order]
    ncards = len(cards)
    cgap = 14
    # ALWAYS one row — actor cards auto-narrow to fit (user: multi-row wastes
    # space; narrower boxes, all on one line). The subtitle is dropped when a
    # card gets too narrow (many actors) so the names stay readable.
    # Adaptive band title: "Internet" only fits while every attacker is
    # internet-facing; once an internal/other actor is present, say so (user).
    _INTERNET = {"internet-anon", "internet-user", "internet-priv-user", "b2b-partner", "victim-required"}
    _mixed = any(s not in _INTERNET for s in actor_order)
    actors_title = "Threat Actors — Internet & Internal" if _mixed else "External Actors — Internet (untrusted)"

    # Show the attacker description only with few actors (cards stay wide enough).
    show_sub = len(actor_order) <= 2
    card_w = (cw - (ncards - 1) * cgap) / ncards
    card_h = 74 if show_sub else 48
    ah = _BANDPAD * 2 + card_h
    band_title("actors", y, ah, 1, title=actors_title)

    def _actor_sub(slug):
        if slug == "internet-anon" and open_reg:
            return "incl. self-registered users (registration ≈ anonymous)"
        return (actor_labels.get(slug) or {}).get("default_subtitle") if actor_labels else ""

    def draw_actor_card(kind, slug, label, bx, by, w, h):
        cyc = by + h / 2
        if kind == "bad":
            c.rect(bx, by, w, h, fill="#fff7f7", stroke=_ATTACK, sw=1.6, rx=7)
            sub = _actor_sub(slug) if show_sub else ""
            if sub:  # tall card: icon + name (top) + description
                c.circle(bx + 19, by + 23, 9, stroke=_ATTACK, sw=1.5)
                c.text(bx + 19, by + 27, "!", size=12, fill=_ATTACK, weight="bold")
                nl = _wrap(label, w - 46, 11)[:2]
                for i, ln in enumerate(nl):
                    c.text(bx + 36, by + 20 + i * 13, ln, size=11, fill=_ATTACK, weight="bold", anchor="start")
                # subtitle at a FIXED y (reserve 2 name lines) so it aligns across
                # all cards regardless of 1- vs 2-line names (user).
                for i, ln in enumerate(_wrap(sub, w - 28, 9)[:2]):
                    c.text(bx + 14, by + 50 + i * 11, ln, size=9, fill=_MUTED, italic=True, anchor="start")
            else:  # compact card: icon + name, vertically centred
                c.circle(bx + 16, cyc, 8, stroke=_ATTACK, sw=1.5)
                c.text(bx + 16, cyc + 3.6, "!", size=11, fill=_ATTACK, weight="bold")
                nl = _wrap(label, w - 38, 10.5)[:2]
                n0 = cyc - (len(nl) - 1) * 6.5 + 3.5
                for i, ln in enumerate(nl):
                    c.text(bx + 30, n0 + i * 13, ln, size=10.5, fill=_ATTACK, weight="bold", anchor="start")
        else:
            c.rect(bx, by, w, h, fill="#f4faf6", stroke=gcol, sw=1.5, rx=7)
            iy = (by + 23) if show_sub else (cyc - 3)
            ny = (by + 22) if show_sub else (cyc - 3)
            c.circle(bx + 16, iy - 3, 6, stroke=gcol, sw=1.4)
            c.rect(bx + 9, iy + 5, 14, 9, stroke=gcol, sw=1.4, rx=2)
            tx = bx + 30
            c.text(tx, ny, "Shop User", size=10.5, fill=gcol, weight="bold", anchor="start")
            if show_sub:
                c.text(tx, ny + 15, "legitimate customer", size=9, fill=_MUTED, italic=True, anchor="start")
            sub_y = ny + (31 if show_sub else 14)
            if victim_ids:
                c.text(tx, sub_y, "victim:", size=8.5, fill=_ATTACK, italic=True, anchor="start")
                bxx = tx + 34
                for d in victim_ids:
                    c.circle(bxx, sub_y - 3, 6, fill=_ATTACK, stroke=_ATTACK, sw=1.1)
                    c.text(bxx, sub_y, str(d), size=8, fill="#ffffff", weight="bold")
                    bxx += 15
            elif not show_sub:
                c.text(tx, sub_y, "legitimate customer", size=8.5, fill=_MUTED, italic=True, anchor="start")
            box_pos["__shopuser__"] = (bx + w / 2, by, by + h, bx)

    # Capture the attacker-card bounding box so the attack arrows can VISIBLY
    # originate from the attacker zone (user: "die Pfeile gehen nicht eindeutig
    # von den Akteuren aus"). `atk_x0/atk_x1` bracket the red cards; `atk_bottom`
    # is their lower edge; `atk_cx` is the zone centre.
    atk_x0 = atk_x1 = None
    for j, (kind, slug, label) in enumerate(cards):
        _cardx = cx0 + j * (card_w + cgap)
        draw_actor_card(kind, slug, label, _cardx, y + _BANDPAD, card_w, card_h)
        if kind == "bad":
            atk_x0 = _cardx if atk_x0 is None else min(atk_x0, _cardx)
            atk_x1 = (_cardx + card_w) if atk_x1 is None else max(atk_x1, _cardx + card_w)
    if atk_x0 is None:  # no attacker cards (degenerate) — fall back to content span
        atk_x0, atk_x1 = cx0, cx0 + cw
    atk_bottom = y + _BANDPAD + card_h
    atk_cx = (atk_x0 + atk_x1) / 2
    bands.append(("actors", y, ah))
    y += ah + _BANDGAP

    # --- component tiers ---
    # Shared metric renderers so a box and a wide bar draw severity/IDs alike.
    def sev_dots(xc: float, yc: float, crit: int, high: int) -> None:
        seg = [s for s in ((_CRIT, crit), (_HIGH, high)) if s[1]]
        if not seg:
            c.text(xc, yc + 4, "no Critical/High", size=9, fill=_MUTED, italic=True)
            return
        units = [24 + 9 * len(str(n)) for _, n in seg]
        xx = xc - sum(units) / 2
        for (col, n), u in zip(seg, units):
            c.circle(xx + 7, yc, 6, fill=col)
            c.text(xx + 19, yc + 4, str(n), size=11, fill=_INK, anchor="start", weight="bold")
            xx += u

    def id_circles(xc: float, yc: float, ids: list[int], gap: float = 27) -> None:
        # Attack-scenario circles: solid RED fill + WHITE number (user) — "attack
        # = red" read clearly; the white digit keeps them legible.
        xx = xc - (len(ids) - 1) * gap / 2
        for d in ids:
            c.circle(xx, yc, 8.5, fill=_ATTACK, stroke=_ATTACK, sw=1.3)
            c.text(xx, yc + 3.5, str(d), size=10.5, fill="#ffffff", weight="bold")
            xx += gap

    def draw_box(cid: str, bx: float, by: float) -> None:
        cm = comp[cid]
        accent = _TIER_COLOR[cm["tier"]][1]
        c.rect(bx, by, _BW, _BH, fill="#ffffff", stroke=accent, sw=1.5, rx=9)
        # Tinted metric footer groups severity + attack-IDs without a hard
        # divider line (user: boxes looked "unruhig" without the strich, but a
        # line wastes space) — same footprint, just a calm shaded zone.
        c.rect(bx + 1.5, by + 43, _BW - 3, _BH - 43 - 1.5, fill="#f5f7fb", stroke="none", rx=7)
        exp = cid in exposed
        if exp:  # internet-exposed marker, top-right corner
            _globe(c, bx + _BW - 14, by + 13, 7, _EXPOSED)
        name = f"{cm['cnum']} · {cm['name']}"
        nl = _wrap(name, _BW - (40 if exp else 22), 11)[:2]
        for i, ln in enumerate(nl):
            c.text(bx + _BW / 2, by + 19 + i * 14, ln, size=11, weight="bold", fill=_INK)
        sev_dots(bx + _BW / 2, by + 57, cm["crit"], cm["high"])
        if cm["ids"]:
            id_circles(bx + _BW / 2, by + 74, cm["ids"])
        box_pos[cid] = (bx + _BW / 2, by, by + _BH, bx)

    def draw_bar(cid: str, bx: float, by: float, w: float, h: float) -> None:
        # A tier with a SINGLE component is drawn as a wide bar that fills the
        # band (name | findings | scenarios) instead of one box marooned in empty
        # space — this is where most of the wasted space was (user request).
        cm = comp[cid]
        accent = _TIER_COLOR[cm["tier"]][1]
        c.rect(bx, by, w, h, fill="#ffffff", stroke=accent, sw=1.5, rx=10)
        cyc = by + h / 2
        exp = cid in exposed
        nxx = bx + 22
        if exp:  # internet-exposed marker, left of the name (vertically centred)
            _globe(c, bx + 15, cyc, 7, _EXPOSED)
            nxx = bx + 30
        name = f"{cm['cnum']} · {cm['name']}"
        nl = _wrap(name, 0.40 * w - 36, 12)[:2]
        n0 = cyc - (len(nl) - 1) * 8 + 4
        for i, ln in enumerate(nl):
            c.text(nxx, n0 + i * 16, ln, size=12, weight="bold", fill=_INK, anchor="start")
        d1, d2 = bx + 0.44 * w, bx + 0.72 * w
        c.line(d1, by + 12, d1, by + h - 12, stroke="#e6e9ef", sw=1.0)
        c.line(d2, by + 12, d2, by + h - 12, stroke="#e6e9ef", sw=1.0)
        c.text(bx + 0.58 * w, by + 19, "Findings", size=9, fill=_MUTED)
        sev_dots(bx + 0.58 * w, cyc + 10, cm["crit"], cm["high"])
        c.text(bx + 0.86 * w, by + 19, "Attack scenarios", size=9, fill=_MUTED)
        if cm["ids"]:
            id_circles(bx + 0.86 * w, cyc + 10, cm["ids"])
        box_pos[cid] = (bx + w / 2, by, by + h, bx)

    def also_note(tier, ytop, bh):
        h = hidden[tier]
        if not h:
            return
        parts = [f"{comp[cid]['cnum']} {comp[cid]['name']}" for cid in h]
        txt = f"+{len(h)} also assessed (lower priority): " + ", ".join(parts)
        wl = _wrap(txt, cw, 9)
        disp = wl[0] + ("…" if len(wl) > 1 else "")
        c.text(cx0, ytop + bh - 9, disp, size=9, fill=_MUTED, italic=True, anchor="start")

    def draw_tier_oos(oosc: list[str], oy: float) -> None:
        """Draw a tier's out-of-scope components as dimmed dashed boxes INSIDE
        the tier band, beneath any analyzed boxes. ``oy`` is the top y of the
        sub-row. Few (≤ _OOS_INLINE_MAX) → one box per component; many → a
        single collapsed count box pointing at §11. Muted + dashed so they read
        as 'present but not analyzed' — the dashed style is explained once in
        the Diagram Legend, so no per-band caption is repeated here.
        """
        # Visually align with the analyzed component boxes: same box width
        # (_BW), same corner radius (rx=9), same centred bold title at top —
        # only the COLOUR LANGUAGE differs (grey title + grey dashed border vs.
        # accent solid border) to read as 'present but not analyzed'. Same
        # compact height (_OOS_BOX_H), so no extra vertical space is used.
        by = oy + _OOS_GAP
        if len(oosc) <= _OOS_INLINE_MAX:
            n = len(oosc)
            bw = _BW
            roww = n * bw + (n - 1) * _GX
            bx = cx0 + (cw - roww) / 2  # centre the row, like the analyzed grid rows
            for cid in oosc:
                cm = comp[cid]
                c.rect(bx, by, bw, _OOS_BOX_H, fill="#ffffff", stroke="#b8bfca", sw=1.5, rx=9, dash="4 3")
                title = f"{cm['cnum']} · {cm['name']}"
                # Auto-shrink to keep the title on ONE line (the box is compact —
                # one component-title line, no metric footer), so a long name like
                # "Data Persistence Layer" is not truncated to "Data Persistenc…".
                size = next((s for s in (10.5, 9.5, 8.5) if len(_wrap(title, bw - 16, s)) == 1), 8.5)
                wl = _wrap(title, bw - 16, size)
                if wl:
                    c.text(
                        bx + bw / 2,
                        by + _OOS_BOX_H / 2 + 3.7,
                        wl[0] + ("…" if len(wl) > 1 else ""),
                        size=size,
                        fill=_MUTED,
                        weight="bold",
                    )
                bx += bw + _GX
        else:
            bw = min(2 * _BW + _GX, cw)
            bx = cx0 + (cw - bw) / 2
            c.rect(bx, by, bw, _OOS_BOX_H, fill="#ffffff", stroke="#b8bfca", sw=1.5, rx=9, dash="4 3")
            c.text(
                bx + bw / 2,
                by + _OOS_BOX_H / 2 + 3.7,
                f"{len(oosc)} components out of scope (not analyzed) — see §11 Out of Scope",
                size=10.5,
                fill=_MUTED,
                weight="bold",
            )

    for num, tier in ((2, "client"), (3, "application"), (4, "data")):
        cids = drawn[tier]
        oosc = oos_by_tier[tier]
        note_h = 16 if hidden[tier] else 0
        # OOS sub-row reserved inside the band when this tier has excluded comps.
        oos_h = (_OOS_GAP + _OOS_BOX_H) if oosc else 0
        ncids = len(cids)

        # Analyzed-content height for this tier (0 when every comp was excluded).
        if ncids == 0:
            analyzed_h = 0.0
        elif ncids == 1:
            analyzed_h = 66.0  # single-component bar
        else:
            rows, sizes = tier_grid[tier]
            analyzed_h = rows * _BH + (rows - 1) * _GY
        gap_ao = 12 if (analyzed_h > 0 and oos_h > 0) else 0

        if ncids == 1 and not oosc:
            # single-component tier → centred bar. Full-width band: the attack
            # arrows now run OUTSIDE the bands (right channel), so no per-band
            # narrowing is needed to clear them.
            barh = 66
            bh = _BANDPAD * 2 + barh + note_h
            barw = 0.52 * cw
            bx0 = cx0 + (cw - barw) / 2  # bar centred so the grey flow stays centred
            band_title(tier, y, bh, num)
            draw_bar(cids[0], bx0, y + _BANDPAD, barw, barh)
            also_note(tier, y, bh)
            bands.append((tier, y, bh))
            y += bh + _BANDGAP
            continue

        # Grid path (also covers ncids==0 and the "has OOS" cases). Full-width
        # band so the OOS sub-row always fits.
        if ncids == 0:
            bh = _BANDPAD * 2 + (oos_h or 40) + note_h
        else:
            bh = _BANDPAD * 2 + analyzed_h + gap_ao + oos_h + note_h
        band_title(tier, y, bh, num)
        yy = y + _BANDPAD
        if ncids == 1:
            # single comp but the tier also has OOS → draw the bar full-width-
            # centred above the OOS row (skip the arrow-narrowing).
            barw = 0.52 * cw
            draw_bar(cids[0], cx0 + (cw - barw) / 2, yy, barw, 66)
        elif ncids > 1:
            rows, sizes = tier_grid[tier]
            k = 0
            for rsize in sizes:
                roww = rsize * _BW + (rsize - 1) * _GX
                sx0 = cx0 + (cw - roww) / 2
                for j in range(rsize):
                    draw_box(cids[k], sx0 + j * (_BW + _GX), yy)
                    k += 1
                yy += _BH + _GY
        if oosc:
            draw_tier_oos(oosc, y + _BANDPAD + analyzed_h + gap_ao)
        also_note(tier, y, bh)
        bands.append((tier, y, bh))
        y += bh + _BANDGAP

    bands_bottom = y - _BANDGAP

    # ---- legitimate request flow (grey, centred, band-to-band) ----
    # This is the LEGITIMATE path (Shop User → Client → Application → Data) only —
    # the attacker is NOT on it. Its direct attack is the separate red arrow.
    flow_labels = ["uses", "API calls", "reads / writes"]
    bxc = cx0 + cw / 2
    for i in range(len(bands) - 1):
        _, yt0, h0 = bands[i]
        _, yt1, _h1 = bands[i + 1]
        yf, yt = yt0 + h0, yt1
        c.line(bxc, yf + 1, bxc, yt - 1, stroke=_BACKBONE, sw=1.8, marker="arrowgrey")
        if i < len(flow_labels):
            c.text(bxc + 12, (yf + yt) / 2 + 3.5, flow_labels[i], size=10.5, fill=_MUTED, anchor="start", weight="bold")

    # ---- attack vectors — emanate from the ATTACKER ZONE (both attackers) -----
    # These are the central vectors of the figure, so they READ as primary. They
    # originate from a red MANIFOLD under the attacker cards (the whole attacker
    # zone — NOT one specific actor) and run as clean, rounded, orthogonal routes
    # into the right corridor in TWO parallel lanes: an OUTER solid lane (DIRECT
    # attacks → application/data) and an INNER dashed lane (the INDIRECT, victim-
    # required attack → client, e.g. DOM XSS). Rounded corners + caps + soft
    # arrowheads so the vectors look deliberate, not like a stray edge fan.
    direct = [(t, yt, h) for (t, yt, h) in bands if t in tier_attacks and tier_attacks[t]["direct"]]
    indirect = [
        (t, yt, h)
        for (t, yt, h) in bands
        if t in tier_attacks and tier_attacks[t]["indirect"] and not tier_attacks[t]["direct"]
    ]

    def _rounded_orth(pts, sw, dash=None, marker=None, r=9.0):
        """Emit an orthogonal poly-line through pts with rounded corners + caps."""
        d = [f"M {pts[0][0]:.1f} {pts[0][1]:.1f}"]
        for i in range(1, len(pts) - 1):
            p0, p1, p2 = pts[i - 1], pts[i], pts[i + 1]

            def _pull(a, b):
                dx, dy = b[0] - a[0], b[1] - a[1]
                ln = math.hypot(dx, dy) or 1.0
                rr = min(r, ln / 2)
                return (b[0] - dx / ln * rr, b[1] - dy / ln * rr)

            e, s = _pull(p0, p1), _pull(p2, p1)
            d.append(f"L {e[0]:.1f} {e[1]:.1f}")
            d.append(f"Q {p1[0]:.1f} {p1[1]:.1f} {s[0]:.1f} {s[1]:.1f}")
        d.append(f"L {pts[-1][0]:.1f} {pts[-1][1]:.1f}")
        da = f' stroke-dasharray="{dash}"' if dash else ""
        mk = f' marker-end="url(#{marker})"' if marker else ""
        c.el.append(
            f'<path d="{" ".join(d)}" fill="none" stroke="{_EXPOSED}" stroke-width="{sw}" '
            f'stroke-linecap="round" stroke-linejoin="round"{da}{mk}/>'
        )

    if direct or indirect:
        a_bottom = bands[0][1] + bands[0][2]  # actors band bottom
        land_x = band_left + band_w - 12  # arrowheads land just inside the tier band
        # ONE clear origin between the attacker cards (the attacker zone — both
        # attackers, not a concrete actor): a ringed node so the arrow ORIGIN is
        # unmistakable. From it a SINGLE rounded manifold runs into the corridor;
        # the solid drop (direct → app/data) and the dashed drop (indirect →
        # client) hang off that one feeder, so there is no double "underline".
        mx = atk_cx
        feed_y = a_bottom + 16  # the single feeder runs here, in the band gap
        lane_dash = band_left + band_w + 8  # inner drop → client (indirect)
        lane_solid = band_left + band_w + 26  # outer drop → app/data (direct)
        if direct:
            ys = [yt + h / 2 for _t, yt, h in direct]
            _rounded_orth([(mx, atk_bottom), (mx, feed_y), (lane_solid, feed_y), (lane_solid, max(ys))], sw=3.4)
            for _t, yt, h in direct:
                cy = yt + h / 2
                _rounded_orth([(lane_solid, cy), (land_x, cy)], sw=4.0, marker="arrowred-rd")
        for j, (_t, yt, h) in enumerate(indirect):
            cy = yt + h / 2
            if direct:
                # A solid feeder already runs from the origin → the dashed drop
                # just taps it at the inner lane (no second horizontal).
                pts = [(lane_dash, feed_y), (lane_dash, cy), (land_x, cy)]
            elif j == 0:
                # No direct attack → the FIRST dashed vector carries the manifold
                # from the origin itself (so it is never detached).
                pts = [(mx, atk_bottom), (mx, feed_y), (lane_dash, feed_y), (lane_dash, cy), (land_x, cy)]
            else:
                pts = [(lane_dash, feed_y), (lane_dash, cy), (land_x, cy)]
            _rounded_orth(pts, sw=2.6, dash="7 5", marker="arrowred-rd")
        # Prominent origin node — drawn last so it sits on top of the feeder.
        c.circle(mx, atk_bottom, 7.5, fill="#ffffff", stroke=_EXPOSED, sw=2.2)
        c.circle(mx, atk_bottom, 3.0, fill=_EXPOSED, stroke=_EXPOSED, sw=1)

    # ---- legend rail ----
    lx = band_left + band_w + _LEGGAP
    ly = _PAD

    _RH = 24  # legend row pitch

    def panel(title: str, ytop: float, rows_fn, n_rows: int) -> float:
        head_h = 26
        ph = head_h + 14 + n_rows * _RH + 6
        c.rect(lx, ytop, _LEGW, ph, fill="#ffffff", stroke="#cbd2da", sw=1.2, rx=8)
        c.rect(lx, ytop, _LEGW, head_h, fill="#1f3a5f", stroke="none", rx=8)
        c.rect(lx, ytop + head_h - 10, _LEGW, 10, fill="#1f3a5f", stroke="none")
        c.text(lx + _LEGW / 2, ytop + 17, title, size=11.5, fill="#ffffff", weight="bold")
        rows_fn(ytop + head_h + 18)
        return ytop + ph + 18

    def scen_rows(y0):
        # Grouped BY actor → explicit attribution (which attacker drives which
        # scenarios), no colour decoding needed.
        yy = y0
        for slug in actor_order:
            c.text(lx + 16, yy, actor_name(slug), size=10.5, fill=_ATTACK, anchor="start", weight="bold")
            yy += _RH
            for d, name, a in scenarios:
                if a != slug:
                    continue
                c.circle(lx + 28, yy - 3.5, 8.5, fill=_ATTACK, stroke=_ATTACK, sw=1.3)
                c.text(lx + 28, yy - 0.3, str(d), size=9.5, fill="#ffffff", weight="bold")
                c.text(lx + 44, yy, name, size=10.5, fill=_INK, anchor="start")
                yy += _RH

    def sev_rows(y0):
        c.circle(lx + 22, y0 - 3.5, 7, fill=_CRIT)
        c.text(lx + 38, y0, "Critical", size=11, fill=_INK, anchor="start")
        c.circle(lx + 22, y0 + _RH - 3.5, 7, fill=_HIGH)
        c.text(lx + 38, y0 + _RH, "High", size=11, fill=_INK, anchor="start")

    def diag_rows(y0):
        # Honest legend — each row is shown ONLY when the figure actually
        # contains that element. Rows accumulate top-down via `r`. The
        # direct/indirect attack rows mirror the solid/dashed arrows drawn into
        # the tiers.
        r = 0
        if exposed:
            _globe(c, lx + 22, y0 + r * _RH - 3.5, 7, _EXPOSED)
            c.text(lx + 40, y0 + r * _RH, "internet-exposed entry point", size=10, fill=_INK, anchor="start")
            r += 1
        if has_direct:
            c.line(lx + 12, y0 + r * _RH - 3.5, lx + 34, y0 + r * _RH - 3.5, stroke=_EXPOSED, sw=2.6, marker="arrowred")
            c.text(lx + 40, y0 + r * _RH, "direct attack", size=10, fill=_INK, anchor="start")
            r += 1
        if has_indirect:
            c.line(
                lx + 12, y0 + r * _RH - 3.5, lx + 34, y0 + r * _RH - 3.5,
                stroke=_EXPOSED, sw=2.2, dash="6 3", marker="arrowred",
            )
            c.text(lx + 40, y0 + r * _RH, "indirect attack (via victim)", size=10, fill=_INK, anchor="start")
            r += 1
        c.line(lx + 12, y0 + r * _RH - 3.5, lx + 34, y0 + r * _RH - 3.5, stroke=_BACKBONE, sw=2, marker="arrowgrey")
        c.text(lx + 40, y0 + r * _RH, "legitimate request flow", size=10, fill=_INK, anchor="start")
        r += 1
        c.circle(lx + 23, y0 + r * _RH - 3.5, 8.5, fill=_ATTACK, stroke=_ATTACK, sw=1.3)
        c.text(lx + 23, y0 + r * _RH - 0.3, "n", size=9.5, fill="#ffffff", weight="bold", italic=True)
        c.text(lx + 40, y0 + r * _RH, "attack scenario (see above)", size=10, fill=_INK, anchor="start")
        r += 1
        if has_oos:
            # Explain the dashed boxes drawn inside the tier bands ONCE here,
            # instead of repeating a caption in every band.
            sw_w, sw_h = 24.0, 14.0
            sy = y0 + r * _RH - 3.5 - sw_h / 2
            c.rect(lx + 12, sy, sw_w, sw_h, fill="#ffffff", stroke="#b8bfca", sw=1.5, rx=4, dash="4 3")
            c.text(lx + 44, y0 + r * _RH, "out of scope (not analyzed)", size=10, fill=_INK, anchor="start")

    has_oos = any(oos_by_tier.values())
    has_direct = any(v["direct"] for v in tier_attacks.values())
    has_indirect = any(v["indirect"] for v in tier_attacks.values())
    diag_n_rows = (
        (1 if exposed else 0)
        + (1 if has_direct else 0)
        + (1 if has_indirect else 0)
        + 2
        + (1 if has_oos else 0)
    )
    ly = panel("Attack Scenarios — by actor", ly, scen_rows, len(actor_order) + len(scenarios))
    ly = panel("Severity", ly, sev_rows, 2)
    ly = panel("Diagram Legend", ly, diag_rows, diag_n_rows)

    total_w = lx + _LEGW + _PAD
    total_h = max(bands_bottom, ly) + _PAD

    defs = (
        "<defs>"
        '<marker id="arrowgrey" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{_BACKBONE}"/></marker>'
        '<marker id="arrowred" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{_ATTACK}"/></marker>'
        # Large, fixed-size red arrowhead for the primary direct-attack arrow —
        # markerUnits=userSpaceOnUse so it is a prominent fixed size, not tied to
        # (and shrunk with) the stroke width. The attack path is the single most
        # important element of the figure; its arrowhead must read at a glance.
        '<marker id="arrowred-lg" viewBox="0 0 12 12" refX="10" refY="6" markerWidth="14" markerHeight="14" markerUnits="userSpaceOnUse" orient="auto-start-reverse">'
        f'<path d="M 0 0 L 12 6 L 0 12 z" fill="{_ATTACK}"/></marker>'
        # Soft/rounded attack arrowhead — a filled triangle with rounded joins so
        # the central attack vectors read as deliberate rounded arrows, not sharp
        # angular ticks (user request).
        '<marker id="arrowred-rd" viewBox="-1 -1 15 15" refX="10.5" refY="6" markerWidth="15" markerHeight="15" markerUnits="userSpaceOnUse" orient="auto-start-reverse">'
        f'<path d="M 1 1 L 12.5 6 L 1 11 Z" fill="{_ATTACK}" stroke="{_ATTACK}" stroke-width="1.6" stroke-linejoin="round"/></marker>'
        "</defs>"
    )
    body = "\n".join(c.el)
    # Display size is capped to an OVERVIEW width (the viewBox keeps the full
    # coordinate space, so the vector stays crisp and the reader can open/zoom
    # figure1.svg for detail) — user: "nicht zu riesig, dient der Übersicht".
    disp_w = min(total_w, _MAX_DISPLAY_W)
    disp_h = total_h * disp_w / total_w
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{disp_w:.0f}" height="{disp_h:.0f}" '
        f'viewBox="0 0 {total_w:.0f} {total_h:.0f}" font-family="{_FONT}">\n'
        f'<rect x="0" y="0" width="{total_w:.0f}" height="{total_h:.0f}" fill="#ffffff"/>\n'
        f"{defs}\n{body}\n</svg>\n"
    )


if __name__ == "__main__":  # standalone preview against a real run
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import compose_threat_model as C
    import yaml

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/security")
    y = yaml.safe_load((out / "threat-model.yaml").read_text())
    ctx = C.RenderContext(output_dir=out, contract={}, yaml_data=y, triage={}, fragments_dir=out / ".fragments")
    tax = C._load_attack_class_taxonomy()
    apd = C._load_attack_paths_fragment(ctx, tax, y.get("threats") or [])
    # Same actor pre-processing compose applies before rendering Figure 2: on a
    # PUBLIC source repo, "repo-read" collapses into the anonymous internet
    # attacker (reading public source needs no privilege). Without this the
    # standalone preview shows a spurious distinct "Internal Developer".
    if (y.get("meta") or {}).get("public_source_repo") and hasattr(C, "_collapse_public_repo_actors"):
        C._collapse_public_repo_actors(apd)
    actor_labels = (C._load_posture_actor_labels() or {}).get("actors") or {}
    svg = build_figure1_svg(y, apd, tax, actor_labels=actor_labels)
    dst = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("figure1-example.svg")
    dst.write_text(svg)
    print(f"wrote {dst} ({len(svg)} bytes)")
