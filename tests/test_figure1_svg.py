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
        "trust_boundaries": [{"from": "external", "to": t, "name": f"Public to {t}"} for t in exposed],
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
    comps = [{"id": "svc", "name": "Backend", "tier": "application", "paths": ["src/main/java/**", "pom.xml"], "description": desc}]
    threats = [{"id": "T-001", "component": "svc", "risk": "Critical"}, {"id": "T-002", "component": "svc", "risk": "High"}]
    tb = [{"from": "external", "to": "svc", "name": "Public to app"}]
    if stores:
        tb += [
            {"from": "svc", "to": "h2-database", "name": "App to H2"},
            {"from": "svc", "to": "sqlite-legacy-auth", "name": "App to SQLite"},
        ]
    yaml_data = {"components": comps, "threats": threats, "trust_boundaries": tb, "meta": {}}
    apd = {"attack_paths": [{"class": "sqli", "actor": "internet-anon", "target": "application", "findings": ["T-001"]}]}
    tax = {
        "glyph_sequence": ["①"],
        "classes": [{"id": "sqli", "short_label": "SQLi", "default_actor": "internet-anon", "default_target_tier": "application"}],
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
    reason_db = F._ghost_reason("data", [], [{"from": "svc", "to": "orders-database"}])
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
