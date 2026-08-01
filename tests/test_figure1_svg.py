"""Full-coverage unit tests for the hand-built Figure-1 SVG generator
(``scripts/figure1_svg.py``), the PRIMARY renderer for the Top-Threats
architecture overview (replaces the legacy Mermaid builder).

The generator is pure (yaml + attack-paths + taxonomy → SVG string), so these
tests assert directly on the returned markup: structure, the top-N budget,
multi-actor handling, the adaptive band title, per-component internet-exposed
markers + the straight direct-attack arrow, the victim marking, single-component
bars, the actor-description gating, determinism, and SVG well-formedness.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import figure1_svg as F  # noqa: E402

_GLYPHS = list("①②③④⑤⑥⑦⑧⑨⑩")


def _model(*, app=2, attackers=("internet-anon",), exposed=(), xss=False, threats_per=2, meta=None):
    """Build (yaml_data, attack_paths_data, attack_taxonomy) for a synthetic
    model: 1 client + ``app`` application + 1 data component, one attack class
    per attacker (hitting the first app components), optional XSS→client."""
    comps = [{"id": "spa", "name": "Angular SPA", "tier": "client"}]
    comps += [{"id": f"app{i}", "name": f"Service {i}", "tier": "application"} for i in range(app)]
    comps += [{"id": "db", "name": "Data Layer", "tier": "data"}]

    threats, fid, cf = [], 1, {}
    for c in comps:
        cf[c["id"]] = []
        for _ in range(threats_per):
            tid = f"T-{fid:03d}"
            threats.append({"id": tid, "component": c["id"], "risk": "Critical" if fid % 4 == 0 else "High"})
            cf[c["id"]].append(tid)
            fid += 1

    classes, paths = [], []
    for i, actor in enumerate(attackers):
        cid = f"cls{i}"
        classes.append(
            {"id": cid, "short_label": f"Attack{i}", "default_actor": actor, "default_target_tier": "application"}
        )
        hosts = [f"app{j}" for j in range(min(app, i + 1))] or (["app0"] if app else [])
        paths.append({"class": cid, "actor": actor, "target": "application", "findings": [cf[h][0] for h in hosts]})
    if xss:
        classes.append(
            {"id": "xss", "short_label": "XSS", "default_actor": "victim-required", "default_target_tier": "client"}
        )
        paths.append({"class": "xss", "actor": "victim-required", "target": "client", "findings": [cf["spa"][0]]})

    yaml_data = {
        "components": comps,
        "threats": threats,
        "trust_boundaries": [
            {
                "id": f"tb-{i}",
                "from": "external",
                "to": target,
                "name": f"Public to {target}",
                "confidence": "confirmed",
                "resolution_status": "resolved",
            }
            for i, target in enumerate(exposed, start=1)
        ],
        "meta": meta or {},
    }
    tax = {"glyph_sequence": _GLYPHS[: len(classes)], "classes": classes}
    return yaml_data, {"attack_paths": paths}, tax


def _build(**kw):
    labels = kw.pop("actor_labels", None)
    y, apd, tax = _model(**kw)
    return F.build_figure1_svg(y, apd, tax, actor_labels=labels)


# ---- empty / guard cases ----------------------------------------------------
def test_no_components_returns_empty():
    assert F.build_figure1_svg({"components": []}, {"attack_paths": [{"class": "x"}]}, {}) == ""


def test_no_attack_paths_returns_empty():
    y, _apd, tax = _model()
    assert F.build_figure1_svg(y, {"attack_paths": []}, tax) == ""


# ---- valid, well-formed SVG -------------------------------------------------
def test_returns_well_formed_svg():
    svg = _build()
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    root = ET.fromstring(svg)  # raises on malformed XML
    assert root.attrib.get("width") and root.attrib.get("height")


def test_all_four_tier_bands_present():
    svg = _build(exposed=("app0",))
    for title in ("Client Tier", "Application Tier", "Data Tier"):
        assert title in svg
    # actors band title is adaptive but always contains "Actors"
    assert "Actors" in svg


def test_component_names_and_severity_and_ids_render():
    svg = _build(app=2, exposed=("app0",))
    assert "C-02 · Service 0" in svg or "Service 0" in svg  # name kept (not just C-id)
    assert "🔴" not in svg  # severity is drawn as <circle>, never emoji (WeasyPrint-safe)
    # at least one attack-scenario digit circle text exists
    assert any(g in svg for g in _GLYPHS) or ">1<" in svg


# ---- top-N budget -----------------------------------------------------------
def test_top_n_cap_collapses_overflow(monkeypatch):
    # 9 application components, default cap 6 → 6 boxes + an "also assessed" note.
    svg = _build(app=9, attackers=("internet-anon",))
    assert "also assessed" in svg
    # the note names overflow components
    assert "+3 also assessed" in svg


def test_raising_cap_draws_more_no_note(monkeypatch):
    monkeypatch.setattr(F, "_CAP", 9)
    svg = _build(app=9, attackers=("internet-anon",))
    assert "also assessed" not in svg


# ---- out-of-scope strip -----------------------------------------------------
def _excl(*ids):
    return {"component_selection": {"excluded": [{"id": i} for i in ids], "analyzed": 0, "total": 0}}


def test_out_of_scope_strip_absent_without_selection():
    # No component_selection → no strip (legacy / passthrough runs unchanged).
    svg = _build(app=2)
    assert "Out of scope — enumerated" not in svg


# The dashed-box meaning is explained ONCE in the Diagram Legend, not repeated
# as a caption in every tier band.
_OOS_LEGEND = "out of scope (not analyzed)"


def test_out_of_scope_strip_inline_for_few():
    # ≤ _OOS_INLINE_MAX excluded → individual dimmed boxes, no collapsed count.
    svg = _build(app=3, meta=_excl("app2"))
    assert _OOS_LEGEND in svg  # explained once in the legend
    assert "Service 2" in svg  # the excluded component is named in its tier band
    assert "components out of scope (not analyzed)" not in svg  # not collapsed
    assert "Out of scope — enumerated" not in svg  # no per-band caption
    ET.fromstring(svg)  # still well-formed


def test_out_of_scope_strip_collapses_for_many():
    # > _OOS_INLINE_MAX excluded → one collapsed count box, names not drawn.
    svg = _build(app=6, meta=_excl("app0", "app1", "app2", "app3", "app4"))
    assert "5 components out of scope (not analyzed) — see §11 Out of Scope" in svg
    # an excluded component is pulled out of the tier grid entirely (not drawn)
    assert "Service 0" not in svg
    # the one analyzed app component is still drawn (C-07 = app5, the non-excluded)
    assert "C-07" in svg
    ET.fromstring(svg)


def test_out_of_scope_excluded_not_in_also_assessed_note():
    # Excluded components must not be folded into "+N also assessed" (that note
    # means "assessed, lower priority" — the opposite of out-of-scope).
    svg = _build(app=3, meta=_excl("app0", "app1"))
    assert "also assessed" not in svg  # only 1 app component left → no overflow note


def test_out_of_scope_rendered_inside_each_tier():
    # db (data) + app0 (application) excluded → the excluded comps render inside
    # their respective tier bands (dashed boxes), with a SINGLE shared legend
    # explanation rather than a caption repeated in every band.
    svg = _build(app=2, meta=_excl("db", "app0"))
    assert "Data Layer" in svg  # excluded data comp named in the data band
    assert "Service 0" in svg  # excluded app comp named in the application band
    assert svg.count(_OOS_LEGEND) == 1  # one legend entry, not one caption per band
    assert "Out of scope — enumerated" not in svg
    ET.fromstring(svg)


def test_out_of_scope_legend_absent_without_exclusions():
    # No exclusions → no legend entry (an honest legend explains only what's drawn).
    svg = _build(app=2)
    assert _OOS_LEGEND not in svg


def test_out_of_scope_empty_tier_renders_title_and_box():
    # The only data component is excluded → the Data Tier band must still draw
    # its title AND show the excluded comp inside it (the old layout left an
    # empty Data Tier band with the comp stranded in a strip below).
    svg = _build(app=2, meta=_excl("db"))
    assert "Data Tier" in svg
    assert "Data Layer" in svg
    assert _OOS_LEGEND in svg  # explained in the legend
    ET.fromstring(svg)


def _rects(svg):
    """Return [(x, y, w, h, fill, dash)] for every <rect> (namespace-agnostic)."""
    out = []
    for el in ET.fromstring(svg).iter():
        if el.tag.rsplit("}", 1)[-1] != "rect":
            continue
        a = el.attrib
        out.append(
            (
                float(a["x"]),
                float(a["y"]),
                float(a["width"]),
                float(a["height"]),
                a.get("fill", ""),
                a.get("stroke-dasharray", ""),
            )
        )
    return out


def test_out_of_scope_box_geometrically_inside_its_tier_band():
    # The crux of the fix: the dashed OOS box must sit WITHIN the purple data
    # band rectangle, not below it.
    svg = _build(app=2, meta=_excl("db"))
    rects = _rects(svg)
    band = next(r for r in rects if r[4] == "#f2ecf9")  # data tier band fill
    oos = next(r for r in rects if r[4] == "#ffffff" and r[5] == "4 3")  # dashed OOS box
    band_y, band_h = band[1], band[3]
    oos_y, oos_h = oos[1], oos[3]
    assert band_y <= oos_y, "OOS box starts below the data band top"
    assert oos_y + oos_h <= band_y + band_h, "OOS box overflows the data band bottom"


def _viewbox_w(svg):
    return float(ET.fromstring(svg).attrib["viewBox"].split()[2])


def test_width_bounded_by_max_columns():
    # many components must NOT make the figure unboundedly wide (height grows).
    # The on-page width is capped; assert on the true viewBox coordinate width.
    narrow = _viewbox_w(_build(app=2, exposed=("app0",)))
    wide = _viewbox_w(_build(app=6, exposed=("app0",)))
    assert wide <= narrow + 4 * (F._BW + F._GX)


def test_display_width_capped_but_viewbox_full():
    svg = _build(app=8, attackers=("internet-anon", "supply-chain"), exposed=("app0",))
    root = ET.fromstring(svg)
    disp_w = float(root.attrib["width"])
    view_w = _viewbox_w(svg)
    assert disp_w <= F._MAX_DISPLAY_W  # compact overview, not "riesig"
    assert view_w >= disp_w  # full detail preserved in the viewBox (zoomable)


def _actor_card_rects(svg):
    # attacker cards fill #fff7f7; the legitimate Shop User card fill #f4faf6.
    return sorted((r for r in _rects(svg) if r[4] in ("#fff7f7", "#f4faf6")), key=lambda r: r[0])


def test_actor_cards_legible_on_narrow_model():
    # Regression: a NARROW model (few components → small content width) with
    # several distinct, non-collapsed actors must NOT squeeze the one-row actor
    # band until the cards overlap into an unreadable strip. Each card keeps at
    # least _MIN_ACTOR_CARD_W and adjacent cards never horizontally overlap.
    svg = _build(app=1, attackers=("internet-anon", "internet-user", "internet-priv-user", "supply-chain"))
    cards = _actor_card_rects(svg)
    assert len(cards) == 5  # 4 attackers + the legitimate Shop User
    for x, y, w, h, *_ in cards:
        assert w >= F._MIN_ACTOR_CARD_W - 0.5, f"actor card too narrow to be legible: {w}"
    for a, b in zip(cards, cards[1:]):
        assert a[0] + a[2] <= b[0] + 0.5, "actor cards overlap horizontally"


def test_actor_floor_is_noop_for_wide_models():
    # The floor must only WIDEN a too-narrow band, never touch a model whose
    # component grid is already wide enough for its (few) actors — else it would
    # change the width of typical/large reports. Width tracks the grid, not the
    # actor count, when the actors fit.
    two = _viewbox_w(_build(app=6, attackers=("internet-anon", "internet-user")))
    one = _viewbox_w(_build(app=6, attackers=("internet-anon",)))
    assert two == one


# ---- multi-actor ------------------------------------------------------------
def test_multiple_attacker_cards():
    svg = _build(
        attackers=("internet-anon", "supply-chain"),
        actor_labels={"internet-anon": {"label": "Anon Attacker"}, "supply-chain": {"label": "Supply-Chain Attacker"}},
    )
    assert "Anon Attacker" in svg
    assert "Supply-Chain Attacker" in svg


def test_actor_description_shown_for_few_actors():
    svg = _build(
        attackers=("internet-anon",),
        actor_labels={"internet-anon": {"label": "Anon", "default_subtitle": "no privilege needed"}},
    )
    assert "no privilege needed" in svg  # subtitle shown with ≤2 attackers


def test_actor_description_hidden_for_many_actors():
    labels = {a: {"label": a, "default_subtitle": f"sub-{a}"} for a in ("a1", "a2", "a3")}
    svg = _build(attackers=("a1", "a2", "a3"), app=3, actor_labels=labels)
    assert "sub-a1" not in svg  # >2 attackers → descriptions dropped (compact)


# ---- adaptive band title ----------------------------------------------------
def test_title_internet_only():
    # the band title is word-wrapped into the gutter, so assert a single-line
    # token rather than the full (split-across-<text>) string.
    svg = _build(attackers=("internet-anon",))
    assert "External Actors" in svg and "Internal" not in svg


def test_title_mixed_when_internal_actor_present():
    svg = _build(
        attackers=("internet-anon", "malicious-insider"),
        actor_labels={"internet-anon": {"label": "Anon"}, "malicious-insider": {"label": "Insider"}},
    )
    assert "Threat Actors" in svg and "Internal" in svg


# ---- exposed marker + direct-attack arrow -----------------------------------
def test_internet_exposed_marker_and_direct_attack_arrow():
    svg = _build(app=2, exposed=("app0",))
    assert "direct attack" in svg  # the red arrow label
    assert "arrowred" in svg  # the red arrowhead marker is used
    assert "internet-exposed entry point" in svg  # legend entry


@pytest.mark.parametrize(
    "boundary",
    [
        {"id": "tb-1", "from": "", "to": "app0", "confidence": "confirmed", "resolution_status": "unresolved"},
        {"id": "tb-1", "to": "app0", "confidence": "confirmed", "resolution_status": "unresolved"},
        {"id": "tb-1", "from": "external", "to": "app0", "confidence": "inferred", "resolution_status": "resolved"},
        {
            "id": "tb-1",
            "from": "Public Internet",
            "to": "Application (port 3000)",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        },
    ],
)
def test_incomplete_or_unconfirmed_boundary_does_not_imply_exposure(boundary):
    y, apd, tax = _model(app=2, exposed=())
    y["trust_boundaries"] = [boundary]
    svg = F.build_figure1_svg(y, apd, tax)
    assert "internet-exposed entry point" not in svg


def test_direct_attack_arrow_present_for_direct_path():
    # Arrows are derived from attack_paths, NOT from trust-boundary exposure: a
    # path whose actor reaches the tier itself (internet-anon → application)
    # draws a solid direct-attack arrow with the large red arrowhead and a
    # "direct attack" legend row — even when nothing is marked internet-exposed.
    svg = _build(app=2, exposed=())
    assert "arrowred-lg" in svg
    assert ">direct attack<" in svg  # legend row (exact text node)


def test_victim_required_only_draws_indirect_not_direct():
    # When the ONLY attack path is victim-required (DOM XSS → client), the figure
    # draws an INDIRECT (dashed) arrow into the client tier and a matching legend
    # row — and NO solid direct-attack arrow / "direct attack" row.
    # ("indirect attack (via victim)" contains the substring "direct attack", so
    #  the direct check matches the exact text node `>direct attack<`.)
    svg = _build(app=0, attackers=(), xss=True)
    assert "indirect attack (via victim)" in svg
    assert ">direct attack<" not in svg


def test_data_targeted_injection_draws_no_direct_data_arrow():
    # `target: data` names the compromised ASSET, not a directly-attacked tier.
    # A SQL/NoSQL injection ENTERS at the application endpoint and the data tier
    # (not internet-exposed) is reached THROUGH the app — so it gets a direct
    # arrow on application ONLY, never on the data tier.
    y, apd, tax = _model(app=2, attackers=("internet-anon",), exposed=("app0",))
    app_fid = next(t["id"] for t in y["threats"] if t["component"] == "app0")
    tax["classes"].append(
        {"id": "sqli", "short_label": "SQLi", "default_actor": "internet-anon", "default_target_tier": "data"}
    )
    apd["attack_paths"].append({"class": "sqli", "actor": "internet-anon", "target": "data", "findings": [app_fid]})
    svg = F.build_figure1_svg(y, apd, tax)
    # Exactly ONE direct branch (application); the data tier gets no 4.0 line.
    assert svg.count('stroke-width="4.0"') == 1


def test_data_arrow_only_when_data_component_exposed_and_hit():
    # A data-tier arrow appears ONLY when a DATA component is internet-exposed
    # AND hosts the attack's findings (a genuinely directly-reachable data tier).
    y, apd, tax = _model(app=1, attackers=("internet-anon",), exposed=("app0", "db"))
    db_fid = next(t["id"] for t in y["threats"] if t["component"] == "db")
    tax["classes"].append(
        {"id": "dbx", "short_label": "DBX", "default_actor": "internet-anon", "default_target_tier": "data"}
    )
    apd["attack_paths"].append({"class": "dbx", "actor": "internet-anon", "target": "data", "findings": [db_fid]})
    svg = F.build_figure1_svg(y, apd, tax)
    # Two direct branches (application + the exposed data component).
    assert svg.count('stroke-width="4.0"') >= 2


# ---- victim -----------------------------------------------------------------
def test_xss_marks_shop_user_as_victim():
    svg = _build(app=1, xss=True)
    assert "Shop User" in svg
    assert "victim" in svg


def test_attack_id_circles_are_red_with_white_text():
    svg = _build(app=2, exposed=("app0",))
    assert 'fill="#c0392b" stroke="#c0392b"' in svg  # solid-red attack-scenario circle
    assert 'fill="#ffffff"' in svg  # white digit inside it


# ---- single-component tier bars ---------------------------------------------
def test_single_component_tier_renders_as_bar():
    svg = _build(app=2, exposed=("app0",))
    # client + data tiers have one component each → bar with section labels
    assert "Findings" in svg and "Attack scenarios" in svg


# ---- determinism ------------------------------------------------------------
def test_deterministic_output():
    a = _build(app=4, attackers=("internet-anon", "supply-chain"), exposed=("app0", "app1"), xss=True)
    b = _build(app=4, attackers=("internet-anon", "supply-chain"), exposed=("app0", "app1"), xss=True)
    assert a == b


# ---- application-tier stack label (derived, not hardcoded) ------------------
def test_stack_label_detects_java_spring():
    comps = [
        {"name": "Auth Subsystem", "paths": ["src/main/java/**/config/SecurityConfig.java"]},
        {"name": "Backend", "paths": ["src/main/java/**", "pom.xml"], "description": "Spring Boot app"},
    ]
    assert F._stack_label(comps) == "Java / Spring"


def test_stack_label_framework_matrix():
    cases = {
        "Node / Express": [{"name": "api", "paths": ["package.json"], "description": "express server"}],
        "Node.js": [{"name": "api", "paths": ["package.json", "tsconfig.json"]}],
        "Python / Django": [{"name": "web", "description": "django app", "paths": ["manage.py"]}],
        "Python": [{"name": "svc", "paths": ["requirements.txt"]}],
        "Go": [{"name": "svc", "paths": ["go.mod", "main.go"]}],
        "Java": [{"name": "svc", "paths": ["build.gradle"]}],
    }
    for expected, comps in cases.items():
        assert F._stack_label(comps) == expected, expected


def test_stack_label_none_without_signal():
    # Language-agnostic paths (Dockerfile only) → no stack guess.
    assert F._stack_label([{"name": "Container Build", "paths": ["Dockerfile", "Makefile"]}]) is None
    assert F._stack_label([]) is None


def test_application_band_uses_derived_stack_label():
    # A Java/Spring model must render the derived label and NEVER the old
    # hardcoded "Node / Express" default.
    y, apd, tax = _model(app=2)
    for c in y["components"]:
        if c["tier"] == "application":
            c["paths"] = ["src/main/java/**", "pom.xml"]
            c["description"] = "Spring Boot service"
    svg = F.build_figure1_svg(y, apd, tax)
    assert "Java / Spring" in svg
    assert "Node / Express" not in svg


def test_application_band_bare_title_without_stack_signal():
    # No stack signal (synthetic model has no paths) → bare "Application Tier".
    svg = _build(app=2, exposed=("app0",))
    assert "Application Tier" in svg
    assert "Node / Express" not in svg


# ---- ghost bands: empty canonical tiers ------------------------------------
def _app_only(*, stores=True, server_rendered=True):
    """A single-tier monolith: only application components. Client and Data are
    empty canonical tiers → candidates for ghost rendering."""
    desc = "Spring Boot backend" + ("; Thymeleaf server-rendered views" if server_rendered else "")
    comps = [
        {
            "id": "svc",
            "name": "Backend",
            "tier": "application",
            "paths": ["src/main/java/**", "pom.xml"],
            "description": desc,
        }
    ]
    threats = [
        {"id": "T-001", "component": "svc", "risk": "Critical"},
        {"id": "T-002", "component": "svc", "risk": "High"},
    ]
    tb = [
        {
            "id": "tb-1",
            "from": "external",
            "to": "svc",
            "name": "Public to app",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    ]
    if stores:
        tb += [
            {
                "id": "tb-2",
                "from": "svc",
                "to": "h2-database",
                "name": "App to H2",
                "confidence": "confirmed",
                "resolution_status": "resolved",
            },
            {
                "id": "tb-3",
                "from": "svc",
                "to": "sqlite-legacy-auth",
                "name": "App to SQLite",
                "confidence": "confirmed",
                "resolution_status": "resolved",
            },
        ]
    yaml_data = {"components": comps, "threats": threats, "trust_boundaries": tb, "meta": {}}
    apd = {
        "attack_paths": [{"class": "sqli", "actor": "internet-anon", "target": "application", "findings": ["T-001"]}]
    }
    tax = {
        "glyph_sequence": ["①"],
        "classes": [
            {
                "id": "sqli",
                "short_label": "SQLi",
                "default_actor": "internet-anon",
                "default_target_tier": "application",
            }
        ],
    }
    return yaml_data, apd, tax


def test_empty_client_and_data_render_as_ghost():
    svg = F.build_figure1_svg(*_app_only())
    # reading order preserved — the tier titles are still present …
    assert "Client Tier" in svg and "Data Tier" in svg
    # … but as dimmed ghost bands that NAME why the tier is absent.
    assert "no distinct client tier — server-rendered" in svg
    assert "data embedded in-process (H2, SQLite) — no separate tier" in svg
    assert F._GHOST_STROKE in svg  # dimmed styling actually emitted
    assert "Node / Express" not in svg


def test_ghost_flow_hops_are_unlabelled():
    # Every legitimate-flow gap touches a ghost tier here → no "uses"/"API calls"
    # label may imply a boundary crossing that does not exist.
    svg = F.build_figure1_svg(*_app_only())
    assert "API calls" not in svg


def test_client_ghost_plain_when_not_server_rendered():
    svg = F.build_figure1_svg(*_app_only(server_rendered=False))
    assert "no distinct client tier" in svg
    assert "server-rendered" not in svg


def test_data_ghost_generic_without_known_store():
    reason = F._ghost_reason("data", [], [{"from": "svc", "to": "external-urls"}])
    assert reason == "no separate data tier"
    reason_db = F._ghost_reason(
        "data",
        [],
        [
            {
                "from": "svc",
                "to": "orders-database",
                "confidence": "confirmed",
                "resolution_status": "resolved",
            }
        ],
    )
    assert reason_db == "data embedded in-process — no separate tier"


def test_populated_tiers_are_not_ghosted():
    # The normal 4-tier model (client + data components present) must keep solid
    # bands and normal flow labels — ghosting is strictly for empty tiers.
    svg = _build(app=2, exposed=("app0",))
    assert "no distinct client tier" not in svg
    assert "no separate data tier" not in svg
    assert "embedded in-process" not in svg


# ---- WeasyPrint smoke (PDF path) — skipped if not installed -----------------
def test_weasyprint_renders_without_error(tmp_path):
    wp = pytest.importorskip("weasyprint")
    svg = _build(app=6, attackers=("internet-anon", "supply-chain"), exposed=("app0",), xss=True)
    svg_path = tmp_path / "figure1.svg"
    svg_path.write_text(svg)
    html = tmp_path / "t.html"
    html.write_text(f'<!doctype html><html><body><img src="{svg_path.name}"></body></html>')
    # must not raise — verifies WeasyPrint accepts our flat SVG (incl. markers)
    wp.HTML(str(html)).write_pdf(str(tmp_path / "t.pdf"))
    assert (tmp_path / "t.pdf").stat().st_size > 2000


# ---------------------------------------------------------------------------
# Trust boundaries — architecture dividers at the tier transitions
# ---------------------------------------------------------------------------

_TRUST_STROKE = 'stroke="#475569"'


def _divider_captions(svg: str) -> list[str]:
    """The caption text of every trust-boundary divider drawn into the figure."""
    import re

    return [t for t in re.findall(r">([^<]*)</text>", svg) if t.startswith("trust boundary · ")]


def test_trust_boundary_is_drawn_as_a_divider_at_the_tier_transition():
    """A trust boundary belongs to the architecture, so it is a divider between
    trust zones — not an annotation on the attack vectors, which would make it
    read as a property of the attack."""
    svg = _build(exposed=("app0", "app1"))
    assert "trust boundary · external → app0 (tb-1) · external → app1 (tb-2)" in svg
    assert _TRUST_STROKE in svg


def test_divider_names_the_crossing_not_just_the_id():
    """A bare `tb-1` is a lookup key, not information — the reader cannot tell
    what the divider separates without leaving the figure. The caption names the
    crossing and keeps the id as the secondary locator into §1."""
    assert _divider_captions(_build(exposed=("app0",))) == ["trust boundary · external → app0 (tb-1)"]


def test_two_boundaries_on_the_same_crossing_share_one_caption_entry():
    """Two enforcement points between the same pair of components are ONE
    crossing; printing the pair twice spends the caption's width budget without
    adding information."""
    y, apd, tax = _model(exposed=("app0",))
    y["trust_boundaries"].append(
        {
            "id": "tb-5",
            "from": "external",
            "to": "app0",
            "name": "Second enforcement point on the same crossing",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    )

    assert _divider_captions(F.build_figure1_svg(y, apd, tax)) == ["trust boundary · external → app0 (tb-1, tb-5)"]


def test_every_placed_boundary_is_named_in_the_legend_panel():
    """A `+N more` caption is only honest when the hidden crossings are
    enumerated somewhere in the figure — the Trust Boundaries panel is that
    place, so every placed boundary appears there with its id."""
    y, apd, tax = _model(exposed=("app0", "app1"))
    y["trust_boundaries"].append(
        {
            "id": "tb-7",
            "from": "app0",
            "to": "external",
            "name": "Outbound to a third party",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    )

    svg = F.build_figure1_svg(y, apd, tax)

    # Panel presence, not its wording — the "(see §1)" pointer was dropped once
    # the caption below the figure carried a clickable link to the catalogue.
    assert "Trust Boundaries" in svg
    assert "external → app0 · tb-1" in svg
    assert "external → app1 · tb-2" in svg
    assert "app0 → external · tb-7" in svg  # the band-header note is named too


def test_legend_states_an_exposure_the_figure_does_not_assert():
    """The rail ORDERS by exposure but rendered none of it, so a confirmed
    internet edge and an unconfirmed one read identically while §1 grades them
    apart. Only the two exposures the reader must not skim past are named; a
    confirmed crossing keeps its row clean, because where it sits in the stack
    already says what it separates."""
    y, apd, tax = _model(exposed=("app0",))
    y["trust_boundaries"] += [
        {
            "id": "tb-2",
            "from": "external",
            "to": "app1",
            "name": "Unconfirmed edge",
            "confidence": "inferred",
            "resolution_status": "resolved",
        },
    ]

    svg = F.build_figure1_svg(y, apd, tax)

    assert "external → app1 · tb-2 · Unverified" in svg
    assert "external → app0 · tb-1" in svg
    assert "tb-1 · internet-facing" not in svg


def test_legend_badge_names_the_worst_exposure_on_the_row():
    """One row can carry several boundaries over the same crossing. An
    unresolvable one outranks an unconfirmed one — the row is a warning, and the
    worse of the two is what it must carry."""
    meta = {
        "tb-1": {"from": "external", "to": "app0", "confidence": "inferred", "resolution_status": "resolved"},
        "tb-2": {"from": "external", "to": "app0", "confidence": "confirmed", "resolution_status": "unresolved"},
    }
    assert F._legend_badge(["tb-1"], meta, {"app0"}) == "Unverified"
    assert F._legend_badge(["tb-1", "tb-2"], meta, {"app0"}) == "Review"
    assert F._legend_badge(["tb-2"], meta, set()) == "Review"


def test_legend_row_keeps_the_badge_when_the_crossing_is_truncated():
    # The badge shares the ids' priority: the crossing text pays for the width.
    assert F._legend_boundary_text("external → a-very-long-name", ["tb-1"], 30, "Unverified") == (
        "external … · tb-1 · Unverified"
    )


def test_band_note_stays_inside_the_tier_gutter():
    """The note is a marker, not a description: the gutter left of the first
    component box is ~19 characters at size 9, and `outbound: app0 → external`
    is 25. Naming it there would run the text under the boxes."""
    assert F._note_text("outbound", ["tb-3"]) == "outbound: tb-3"
    assert F._note_text("internal", ["tb-1", "tb-2", "tb-3"]) == "internal: tb-1 · tb-2 +1"


def test_no_boundary_legend_panel_without_a_boundary():
    """Honest legend — a model with zero resolved boundaries renders exactly as
    it did before the panel existed."""
    svg = _build(exposed=())
    assert "Trust Boundaries (see §1)" not in svg
    assert "trust boundary (" not in svg


def test_crossing_that_spans_more_than_one_tier_gap_still_draws():
    """`external → <data store>` skips the application zone, so it matched no
    band gap and vanished from the figure. It belongs on the first gap its span
    contains — the point where it leaves the untrusted zone."""
    y, apd, tax = _model(exposed=())
    y["trust_boundaries"] = [
        {
            "id": "tb-3",
            "from": "external",
            "to": "db",
            "name": "Internet to the data layer",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    ]

    svg = F.build_figure1_svg(y, apd, tax)

    assert _divider_captions(svg) == ["trust boundary · external → db (tb-3)"]


def test_divider_sits_below_the_client_tier_not_above_it():
    """The client tier runs on the user's device, so it is on the untrusted side
    with the actors. The trust change happens at the client/application gap."""
    svg = _build(exposed=("app0",))
    root = ET.fromstring(svg)
    ns = "{http://www.w3.org/2000/svg}"
    divider_y = [float(el.get("y1")) for el in root.iter(f"{ns}line") if el.get("stroke") == "#475569"]
    assert divider_y, "no trust-boundary divider drawn"

    def band_y(label_start: str) -> float:
        for el in root.iter(f"{ns}text"):
            if (el.text or "").startswith(label_start):
                return float(el.get("y"))
        raise AssertionError(f"band label {label_start!r} not found")

    # Between the client band's label and the application band's label.
    assert band_y("Client Tier") < min(divider_y) < band_y("Application Tier")


def test_no_divider_without_a_boundary_crossing_a_tier_gap():
    svg = _build(exposed=())
    assert "trust boundary ·" not in svg
    assert _TRUST_STROKE not in svg


def test_divider_label_names_internet_facing_crossings_first():
    """Internet-facing crossings are what a reader looks for, so they must
    survive the truncation that keeps the caption on one line."""
    meta = {f"tb-{i}": {"id": f"tb-{i}", "from": "external", "to": f"svc{i}"} for i in (1, 2, 3, 4, 9)}
    label = F._divider_label(list(meta), meta, priority_ids={"tb-9"}, max_chars=70)
    assert label == "trust boundary · external → svc9 (tb-9) · +4 more (see legend)"
    assert F._divider_label([]) == ""


# ---- caption legibility: criticality decides what is named on the divider ----


def _tb(bid: str, src: str, dst: str, **kw) -> dict:
    row = {
        "id": bid,
        "from": src,
        "to": dst,
        "name": f"{src} to {dst}",
        "confidence": "confirmed",
        "resolution_status": "resolved",
    }
    row.update(kw)
    return row


def _meta(*rows: dict) -> dict[str, dict]:
    return {r["id"]: r for r in rows}


def test_divider_caption_names_only_the_lead_tier_crossings():
    """A divider that carries the internet edge AND an internal hop must lead
    with the internet edge — the internal one needs a foothold first, so it
    recedes into the legend instead of spending the band's width."""
    meta = _meta(
        _tb("tb-1", "external", "api"),
        _tb("tb-2", "spa", "api"),
        _tb("tb-3", "api", "external"),
    )
    label = F._divider_label(list(meta), meta, component_ids={"api", "spa"}, max_chars=200)

    assert label == "trust boundary · external → api (tb-1) · +2 more (see legend)"


def test_divider_caption_caps_the_names_even_when_all_are_internet_facing():
    """Nine boundaries at the same exposure are still nine — the caption names
    the first two and lets the panel carry the rest, because a caption that
    enumerates a register is a caption nobody reads."""
    meta = _meta(*[_tb(f"tb-{i}", "external", f"svc{i}") for i in range(1, 6)])
    label = F._divider_label(list(meta), meta, component_ids={f"svc{i}" for i in range(1, 6)}, max_chars=400)

    assert label == "trust boundary · external → svc1 (tb-1) · external → svc2 (tb-2) · +3 more (see legend)"
    assert label.count("→") == F._DIVIDER_MAX_CROSSINGS


def test_divider_caption_with_only_quiet_crossings_names_just_one():
    """Nothing internet-facing on this gap: the crossings are still named — the
    divider would otherwise be unexplained — but one is enough."""
    meta = _meta(_tb("tb-4", "spa", "api"), _tb("tb-5", "api", "db"))
    label = F._divider_label(list(meta), meta, component_ids={"spa", "api", "db"}, max_chars=200)

    assert label == "trust boundary · spa → api (tb-4) · +1 more (see legend)"


def test_divider_caption_stays_inside_its_width_budget():
    """The `+N more` note is part of the caption, so it is budgeted. Appending
    it past the budget is how the caption grew wider than the band it annotates
    and collided with the boxes beneath."""
    meta = _meta(*[_tb(f"tb-{i}", "external", f"service-{i}") for i in range(1, 5)])
    ids = {f"service-{i}" for i in range(1, 5)}
    for budget in (70, 90, 120, 200):
        assert len(F._divider_label(list(meta), meta, component_ids=ids, max_chars=budget)) <= budget
    # Floor: a budget too small for even one crossing still names one. An
    # unlabelled divider is worse than a caption that runs a little long, and
    # the band width never gets that small in practice.
    assert F._divider_label(list(meta), meta, component_ids=ids, max_chars=10).count("→") == 1


def test_divider_caption_declares_exactly_what_it_holds_back():
    """Truncation is only honest when the count is right: `+N` counts
    BOUNDARIES, not crossings, so two enforcement points on one crossing are
    two."""
    meta = _meta(
        _tb("tb-1", "external", "api"),
        _tb("tb-2", "external", "ci"),
        _tb("tb-3", "external", "auth"),
        _tb("tb-4", "external", "auth"),
    )
    label = F._divider_label(list(meta), meta, component_ids={"api", "auth", "ci"}, max_chars=400)

    # Held back: the auth crossing — ONE crossing, but TWO enforcement points.
    assert label == "trust boundary · external → api (tb-1) · external → ci (tb-2) · +2 more (see legend)"


def test_quiet_crossings_are_still_drawn_and_still_named_in_the_legend():
    """Receding is not dropping: the divider a held-back crossing annotates is
    still drawn, and the panel still names it with its id."""
    y, apd, tax = _model(exposed=("app0", "app1"))
    y["trust_boundaries"].append(_tb("tb-3", "spa", "app1"))
    y["trust_boundaries"].append(_tb("tb-4", "external", "db"))

    svg = F.build_figure1_svg(y, apd, tax)

    caption = _divider_captions(svg)[0]
    assert caption.startswith("trust boundary · external → app0 (tb-1)")
    assert "spa → app1" not in caption  # the internal hop recedes…
    assert "spa → app1 · tb-3" in svg  # …into the panel, named, with its id
    assert _TRUST_STROKE in svg  # …and the divider it annotates is still drawn
    for bid in ("tb-1", "tb-2", "tb-3", "tb-4"):
        assert bid in svg


def test_divider_caption_does_not_run_the_width_of_the_band():
    """The reported defect, measured: with many boundaries the caption filled
    the rule edge to edge and smeared over the band beneath it. It must stay
    well inside the divider it annotates."""
    y, apd, tax = _model(exposed=("app0", "app1", "db"))
    y["trust_boundaries"].append(_tb("tb-4", "spa", "app1"))

    svg = F.build_figure1_svg(y, apd, tax)
    root = ET.fromstring(svg)
    ns = "{http://www.w3.org/2000/svg}"
    # Select the divider by what makes it one — slate, and spanning the band —
    # not by its stroke weight. Pinning the weight here made a legibility change
    # to the rule look like a caption regression (2026-08-01).
    rules = [
        (float(el.get("x1")), float(el.get("x2")))
        for el in root.iter(f"{ns}line")
        if el.get("stroke") == "#475569" and float(el.get("x2")) - float(el.get("x1")) > 100
    ]
    assert rules, "no trust-boundary divider drawn"
    band_w = max(x2 - x1 for x1, x2 in rules)

    for caption in _divider_captions(svg):
        assert len(caption) * 0.55 * 9.5 <= band_w * F._DIVIDER_CAPTION_BAND_SHARE


def test_caption_rule_is_tolerant_of_any_boundary_id():
    """Ids are renumbered into criticality order upstream, so the caption must
    not depend on a specific number or count — only on the tier."""
    meta = _meta(_tb("tb-41", "external", "api"), _tb("tb-7", "spa", "api"))
    label = F._divider_label(list(meta), meta, component_ids={"api", "spa"}, max_chars=200)

    assert label == "trust boundary · external → api (tb-41) · +1 more (see legend)"


def test_legend_row_gives_up_the_crossing_before_the_ids():
    """The id is the locator into §1 — a row that truncates it is useless. The
    crossing text pays for the width, and a too-long id list is DECLARED."""
    assert F._legend_boundary_text("external → a-very-long-component-name", ["tb-1"], 24) == "external → a-ver… · tb-1"
    assert F._legend_boundary_text("external → api", ["tb-1", "tb-2", "tb-3", "tb-4", "tb-5"], 20).endswith(
        "tb-1 +4"
    )  # an id is never cut in half — the remainder is declared


def test_divider_label_falls_back_to_ids_when_the_crossing_is_unknown():
    """No endpoints in the model → the id alone, never an invented description."""
    assert F._divider_label(["tb-2", "tb-1"], {"tb-1": {"id": "tb-1"}}) == "trust boundary · tb-1 · tb-2"


def test_boundary_inside_a_tier_is_named_in_the_band_instead_of_dropped():
    """An application tier holding an untrusted component (or a privilege split
    within one service) has a boundary that cannot be a band divider. It is
    reported in the band header rather than silently omitted."""
    y, apd, tax = _model(exposed=("app0",))
    y["trust_boundaries"].append(
        {
            "id": "tb-9",
            "from": "app0",
            "to": "app1",
            "name": "Untrusted component in the application tier",
            "kind": "privilege",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    )

    svg = F.build_figure1_svg(y, apd, tax)

    assert "internal: tb-9" in svg
    # It is NOT promoted onto the tier divider, which separates zones.
    assert _divider_captions(svg) == ["trust boundary · external → app0 (tb-1)"]
    assert "app0 → app1 · tb-9" in svg  # …but it IS named in the legend panel


def test_classification_separates_gap_crossings_from_intra_tier_boundaries():
    y, _apd, _tax = _model(exposed=("app0",))
    y["trust_boundaries"].append(
        {
            "id": "tb-9",
            "from": "app0",
            "to": "app1",
            "name": "Intra-tier split",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    )
    tier_of = {row["id"]: row["tier"] for row in y["components"]}

    crossings, notes = F._classify_boundaries(y, tier_of)

    assert crossings == {(0, 2): ["tb-1"]}
    assert notes == {"application": {"internal": ["tb-9"]}}


def test_outbound_boundary_is_not_placed_on_the_client_server_divider():
    """Regression: `external` denotes two different things — the untrusted
    client side as a SOURCE, a third party as a TARGET. Ordering the endpoints
    by zone discarded the direction, so `backend -> LLM provider` landed on the
    same divider as `internet -> backend`."""
    y, apd, tax = _model(exposed=("app0",))
    y["trust_boundaries"].append(
        {
            "id": "tb-9",
            "from": "app0",
            "to": "external",
            "name": "API to external LLM provider",
            "kind": "third-party",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    )
    tier_of = {row["id"]: row["tier"] for row in y["components"]}

    crossings, notes = F._classify_boundaries(y, tier_of)

    assert crossings == {(0, 2): ["tb-1"]}, "egress must not join the ingress divider"
    assert notes == {"application": {"outbound": ["tb-9"]}}

    svg = F.build_figure1_svg(y, apd, tax)
    assert "outbound: tb-9" in svg
    assert _divider_captions(svg) == ["trust boundary · external → app0 (tb-1)"]


def test_ingress_and_egress_between_the_same_pair_stay_apart():
    """The two directions are different boundaries and must not collapse into
    one divider entry just because they share endpoints."""
    tier_of = {"api": "application"}
    model = {
        "trust_boundaries": [
            {"id": "tb-1", "from": "external", "to": "api", "resolution_status": "resolved"},
            {"id": "tb-2", "from": "api", "to": "external", "resolution_status": "resolved"},
        ]
    }

    crossings, notes = F._classify_boundaries(model, tier_of)

    assert crossings == {(0, 2): ["tb-1"]}
    assert notes == {"application": {"outbound": ["tb-2"]}}


# ---- legend legibility ------------------------------------------------------
def _lines_with_stroke(svg: str, stroke: str) -> list[dict]:
    import re

    out = []
    for tag in re.findall(r"<line [^>]*>", svg):
        if f'stroke="{stroke}"' not in tag:
            continue
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', tag))
        attrs["_width"] = abs(float(attrs["x2"]) - float(attrs["x1"]))
        out.append(attrs)
    return out


def _boundary_model():
    y, apd, tax = _model()
    y["trust_boundaries"] = [
        {
            "id": "tb-1",
            "name": "Perimeter",
            "from": "external",
            "to": "app0",
            "kind": "network",
            "confidence": "confirmed",
            "resolution_status": "resolved",
        }
    ]
    return y, apd, tax


def test_boundary_legend_swatch_is_not_the_faintest_row():
    """juice-shop 2026-07-30 — the legend swatch inherited the divider's
    ``sw=1.4, dash="7 5"``. That reads across a ~700-unit band but not across a
    22-unit swatch: at the delivered scale (viewBox 1080 → width 760) it lands
    under one device pixel with fewer than two dashes, so the row was reported as
    missing even though it renders.
    """
    y, apd, tax = _boundary_model()
    svg = F.build_figure1_svg(y, apd, tax)
    assert "trust boundary (listed below)" in svg, "fixture must draw a divider + legend row"

    swatches = [ln for ln in _lines_with_stroke(svg, F._TRUST) if ln["_width"] < 40]
    assert swatches, "no legend swatch found"
    boundary_swatch = swatches[0]

    # Select siblings by shared left edge, NOT by width: `_EXPOSED` also strokes
    # thin globe markers inside the tier bands, and including those dropped the
    # comparison floor to 0.9 — which let the pre-fix 1.4 sail through.
    lx = boundary_swatch["x1"]
    others = [
        float(a["stroke-width"])
        for a in (
            _lines_with_stroke(svg, F._EXPOSED) + _lines_with_stroke(svg, F._BACKBONE)
        )
        if a["x1"] == lx and a["_width"] < 40
    ]
    assert others, "expected sibling legend swatches to compare against"
    assert float(boundary_swatch["stroke-width"]) >= min(others), (
        "boundary swatch must not be thinner than its neighbours in the legend"
    )


def test_boundary_divider_in_the_figure_keeps_its_own_dash():
    """The in-figure divider spans the band width and carries its OWN dash —
    never the legend swatch's short one, which dissolves over that distance.

    The figure ships at 0.72× its viewBox, so both the dash and the weight are
    chosen against the display scale (user 2026-08-01): "10 6" at sw 2.2 stays a
    readable rule where the previous "7 5" at 1.4 rendered as a ~1px dotted
    hairline, thinner than this boundary's own legend key.
    """
    y, apd, tax = _boundary_model()
    svg = F.build_figure1_svg(y, apd, tax)

    dividers = [ln for ln in _lines_with_stroke(svg, F._TRUST) if ln["_width"] > 100]
    assert dividers, "expected a full-width divider"
    assert all(d["stroke-dasharray"] == "10 6" for d in dividers)
    # The rule must not render fainter than the legend key that explains it.
    assert all(float(d["stroke-width"]) >= 1.8 for d in dividers)
