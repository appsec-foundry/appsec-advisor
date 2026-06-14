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
        classes.append({"id": cid, "short_label": f"Attack{i}", "default_actor": actor, "default_target_tier": "application"})
        hosts = [f"app{j}" for j in range(min(app, i + 1))] or (["app0"] if app else [])
        paths.append({"class": cid, "actor": actor, "target": "application", "findings": [cf[h][0] for h in hosts]})
    if xss:
        classes.append({"id": "xss", "short_label": "XSS", "default_actor": "victim-required", "default_target_tier": "client"})
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


# ---- multi-actor ------------------------------------------------------------
def test_multiple_attacker_cards():
    svg = _build(attackers=("internet-anon", "supply-chain"),
                 actor_labels={"internet-anon": {"label": "Anon Attacker"},
                               "supply-chain": {"label": "Supply-Chain Attacker"}})
    assert "Anon Attacker" in svg
    assert "Supply-Chain Attacker" in svg


def test_actor_description_shown_for_few_actors():
    svg = _build(attackers=("internet-anon",),
                 actor_labels={"internet-anon": {"label": "Anon", "default_subtitle": "no privilege needed"}})
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
    svg = _build(attackers=("internet-anon", "malicious-insider"),
                 actor_labels={"internet-anon": {"label": "Anon"}, "malicious-insider": {"label": "Insider"}})
    assert "Threat Actors" in svg and "Internal" in svg


# ---- exposed marker + direct-attack arrow -----------------------------------
def test_internet_exposed_marker_and_direct_attack_arrow():
    svg = _build(app=2, exposed=("app0",))
    assert "direct attack" in svg            # the red arrow label
    assert "arrowred" in svg                 # the red arrowhead marker is used
    assert "internet-exposed entry point" in svg  # legend entry


def test_no_exposed_no_direct_attack_arrow():
    svg = _build(app=2, exposed=())
    assert "direct attack" not in svg


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
