#!/usr/bin/env python3
"""Figure-1 layout measurement harness (dev tool — not part of the pipeline).

Renders ``compose_threat_model._render_top_threats_architecture`` for a matrix
of synthetic threat models, converts each Mermaid block to SVG via ``mmdc``,
and measures layout legibility from the rendered geometry:

  * ``crossings``       — number of edge PAIRS whose drawn polylines intersect.
  * ``box_overlaps``    — number of (edge, node-box) pairs where an edge that
                          does NOT start/end at that box runs through its
                          interior (a line crossing an unrelated component box).

Both are model-size-independent legibility proxies: a clean tiered diagram has
few of each regardless of how many components/actors it has. The harness is the
objective gate for the Figure-1 rewrite — "clean for any model" becomes a
measured property, not a single screenshot.

Usage:
    python3 scripts/figure1_harness.py [--png OUTDIR] [--only NAME]

Writes a JSON report to stdout and, with --png, one PNG + one .mmd per fixture.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compose_threat_model as compose  # noqa: E402

# --------------------------------------------------------------------------- #
# Synthetic model matrix                                                       #
# --------------------------------------------------------------------------- #
# A taxonomy entry per class id used across fixtures.
_CLASS = {
    "injection": ("Injection", "internet-anon", "data"),
    "auth-bypass": ("Auth Bypass", "internet-anon", "application"),
    "privilege-escalation": ("Priv-Esc", "internet-anon", "application"),
    "remote-code-execution": ("RCE", "internet-anon", "application"),
    "cross-site-scripting": ("XSS", "victim-required", "victim"),
    "csrf": ("CSRF", "victim-required", "victim"),
    "sensitive-data-exposure": ("Secret Exposure", "repo-read", "data"),
    "dos": ("DoS", "internet-anon", "application"),
}


def _taxonomy(class_ids: list[str]) -> dict:
    glyphs = ["①", "②", "③", "④", "⑤", "⑥", "⑦"]
    classes = []
    for cid in class_ids:
        label, actor, tier = _CLASS[cid]
        classes.append(
            {
                "id": cid,
                "label": label,
                "short_label": label,
                "threat_label": label,
                "default_actor": actor,
                "default_target_tier": tier,
            }
        )
    return {"glyph_sequence": glyphs[: len(class_ids)], "classes": classes}


def _ctx(tmp: Path, components: list[dict], threats: list[dict], meta: dict | None = None) -> "compose.RenderContext":
    return compose.RenderContext(
        output_dir=tmp,
        contract={},
        yaml_data={"components": components, "threats": threats, "meta": meta or {}},
        triage={},
        fragments_dir=tmp / ".fragments",
    )


def _comp(cid: str, name: str, tier: str) -> dict:
    return {"id": cid, "name": name, "tier": tier}


def _thr(fid: str, comp: str, risk: str = "High") -> dict:
    return {"id": fid, "title": f"weakness {fid}", "component": comp, "risk": risk}


def fixtures(tmp: Path) -> dict:
    """Return {name: (ctx, attack_paths_data, taxonomy)}."""
    F: dict = {}

    # 1. single dominant attacker, many components across all tiers (the
    #    juice-shop worst case: public-repo collapse → one actor fans out).
    comps = [
        _comp("spa", "Angular SPA", "client"),
        _comp("api", "Express API Server", "application"),
        _comp("upload", "File Upload Service", "application"),
        _comp("b2b", "B2B API", "application"),
        _comp("auth", "Auth & Session", "application"),
        _comp("ci", "CI/CD Pipeline", "application"),
        _comp("ws", "Real-time WebSocket", "application"),
        _comp("db", "Data Layer", "data"),
    ]
    threats = (
        [_thr(f"F-00{i}", "api", "Critical") for i in range(1, 5)]
        + [_thr(f"F-01{i}", "api") for i in range(0, 6)]
        + [_thr("F-020", "spa", "Critical"), _thr("F-021", "spa")]
        + [_thr("F-030", "upload", "Critical"), _thr("F-031", "upload")]
        + [_thr("F-040", "b2b", "Critical"), _thr("F-041", "b2b")]
        + [_thr("F-050", "auth", "Critical"), _thr("F-051", "auth")]
        + [_thr("F-060", "ci"), _thr("F-061", "ws"), _thr("F-070", "db")]
    )
    ap = {
        "attack_paths": [
            {"class": "injection", "actor": "internet-anon", "target": "data", "findings": ["F-001", "F-010"]},
            {"class": "auth-bypass", "actor": "repo-read", "target": "application", "findings": ["F-050", "F-051"]},
            {"class": "privilege-escalation", "actor": "internet-anon", "target": "application", "findings": ["F-002"]},
            {"class": "remote-code-execution", "actor": "internet-anon", "target": "application", "findings": ["F-030", "F-040"]},
            {"class": "cross-site-scripting", "actor": "victim-required", "target": "victim", "findings": ["F-020"]},
            {"class": "sensitive-data-exposure", "actor": "repo-read", "target": "data", "findings": ["F-003", "F-070"]},
        ]
    }
    F["single-actor-wide"] = (_ctx(tmp, comps, threats, {"public_source_repo": True, "open_user_registration": True}), ap, _taxonomy([a["class"] for a in ap["attack_paths"]]))

    # 1b. same model WITHOUT public-repo collapse → 3 distinct actors.
    F["multi-actor-wide"] = (_ctx(tmp, comps, threats, {"open_user_registration": True}), ap, _taxonomy([a["class"] for a in ap["attack_paths"]]))

    # 2. victim present, small model (XSS + CSRF both).
    comps2 = [_comp("spa", "SPA", "client"), _comp("api", "API", "application"), _comp("db", "DB", "data")]
    threats2 = [_thr("F-001", "spa", "Critical"), _thr("F-002", "api", "Critical"), _thr("F-003", "db")]
    ap2 = {"attack_paths": [
        {"class": "cross-site-scripting", "actor": "victim-required", "target": "victim", "findings": ["F-001"]},
        {"class": "csrf", "actor": "victim-required", "target": "victim", "findings": ["F-001"]},
        {"class": "injection", "actor": "internet-anon", "target": "data", "findings": ["F-002"]},
    ]}
    F["victim-xss-csrf"] = (_ctx(tmp, comps2, threats2), ap2, _taxonomy(["cross-site-scripting", "csrf", "injection"]))

    # 3. victim absent (data-only targets).
    ap3 = {"attack_paths": [
        {"class": "injection", "actor": "internet-anon", "target": "data", "findings": ["F-002"]},
        {"class": "sensitive-data-exposure", "actor": "internet-anon", "target": "data", "findings": ["F-003"]},
    ]}
    F["data-only"] = (_ctx(tmp, comps2, threats2), ap3, _taxonomy(["injection", "sensitive-data-exposure"]))

    # 4. single component, single class.
    comps4 = [_comp("api", "Monolith", "application")]
    threats4 = [_thr("F-001", "api", "Critical")]
    ap4 = {"attack_paths": [{"class": "injection", "actor": "internet-anon", "target": "application", "findings": ["F-001"]}]}
    F["single-component"] = (_ctx(tmp, comps4, threats4), ap4, _taxonomy(["injection"]))

    # 5. API-only, victim-targeting (no client tier) — thin model edge case.
    comps5 = [_comp("api", "REST API", "application"), _comp("db", "DB", "data")]
    threats5 = [_thr("F-001", "api", "High")]
    ap5 = {"attack_paths": [{"class": "cross-site-scripting", "actor": "victim-required", "target": "victim", "findings": ["F-001"]}]}
    F["api-only-victim"] = (_ctx(tmp, comps5, threats5), ap5, _taxonomy(["cross-site-scripting"]))

    # 6. large stress: 14 components, 7 classes, mixed actors.
    big_comps = [_comp("spa", "SPA", "client"), _comp("spa2", "Admin SPA", "client")]
    for i in range(1, 11):
        big_comps.append(_comp(f"svc{i}", f"Service {i}", "application"))
    big_comps += [_comp("db", "DB", "data"), _comp("cache", "Cache", "data")]
    big_threats = []
    for i in range(1, 11):
        big_threats.append(_thr(f"F-1{i:02d}", f"svc{i}", "Critical" if i % 3 == 0 else "High"))
    big_threats += [_thr("F-201", "spa", "Critical"), _thr("F-202", "spa2"), _thr("F-203", "db"), _thr("F-204", "cache")]
    big_ap = {"attack_paths": [
        {"class": "injection", "actor": "internet-anon", "target": "data", "findings": ["F-101"]},
        {"class": "auth-bypass", "actor": "internet-anon", "target": "application", "findings": ["F-102"]},
        {"class": "privilege-escalation", "actor": "internet-anon", "target": "application", "findings": ["F-103"]},
        {"class": "remote-code-execution", "actor": "internet-anon", "target": "application", "findings": ["F-104", "F-105"]},
        {"class": "cross-site-scripting", "actor": "victim-required", "target": "victim", "findings": ["F-201"]},
        {"class": "sensitive-data-exposure", "actor": "repo-read", "target": "data", "findings": ["F-203"]},
        {"class": "dos", "actor": "internet-anon", "target": "application", "findings": ["F-106", "F-107"]},
    ]}
    F["large-stress"] = (_ctx(tmp, big_comps, big_threats, {"public_source_repo": True}), big_ap, _taxonomy([a["class"] for a in big_ap["attack_paths"]]))

    # 7. complex app: MANY app components that are ALL genuine top-threat hosts,
    #    so the complexity budget canNOT collapse them — this is the worst case
    #    for horizontal width scaling. 11 attacked app services + 2 client + 2 data.
    cax = [_comp("spa", "Web SPA", "client"), _comp("admin", "Admin Console", "client")]
    for i in range(1, 12):
        cax.append(_comp(f"a{i}", f"Service {i}", "application"))
    cax += [_comp("db", "Primary DB", "data"), _comp("warehouse", "Data Warehouse", "data")]
    cthreats = [_thr("F-301", "spa", "Critical"), _thr("F-302", "admin", "Critical")]
    for i in range(1, 12):
        cthreats.append(_thr(f"F-3{i:02d}".replace("F-3", "F-4"), f"a{i}", "Critical" if i % 2 else "High"))
    cthreats += [_thr("F-501", "db", "High"), _thr("F-502", "warehouse")]
    # 7 classes, findings spread so all 11 app services + spa are hosts.
    cap = {"attack_paths": [
        {"class": "injection", "actor": "internet-anon", "target": "data", "findings": ["F-401", "F-402"]},
        {"class": "auth-bypass", "actor": "internet-anon", "target": "application", "findings": ["F-403", "F-404"]},
        {"class": "privilege-escalation", "actor": "internet-anon", "target": "application", "findings": ["F-405", "F-406"]},
        {"class": "remote-code-execution", "actor": "internet-anon", "target": "application", "findings": ["F-407", "F-408"]},
        {"class": "cross-site-scripting", "actor": "victim-required", "target": "victim", "findings": ["F-301"]},
        {"class": "sensitive-data-exposure", "actor": "repo-read", "target": "data", "findings": ["F-409", "F-501"]},
        {"class": "dos", "actor": "internet-anon", "target": "application", "findings": ["F-410", "F-411"]},
    ]}
    F["complex-app"] = (_ctx(tmp, cax, cthreats, {"open_user_registration": True}), cap, _taxonomy([a["class"] for a in cap["attack_paths"]]))

    return F


# --------------------------------------------------------------------------- #
# SVG geometry extraction + metric                                             #
# --------------------------------------------------------------------------- #
def _flatten_path(d: str) -> list[tuple[float, float]]:
    """Flatten an SVG path 'd' (M/L/C, absolute) into a polyline of points.

    Mermaid/ELK edge paths are mostly M + L (polylines) with occasional C
    curves; C is sampled at t=0.25/0.5/0.75/1 from the current point."""
    toks = re.findall(r"[MLC]|-?\d*\.?\d+(?:e-?\d+)?", d)
    pts: list[tuple[float, float]] = []
    i = 0
    cur = (0.0, 0.0)
    cmd = None
    nums: list[float] = []

    def _num(j: int) -> tuple[float, int]:
        return float(toks[j]), j + 1

    while i < len(toks):
        t = toks[i]
        if t in ("M", "L", "C"):
            cmd = t
            i += 1
            continue
        if cmd in ("M", "L"):
            x, i = _num(i)
            y, i = _num(i)
            cur = (x, y)
            pts.append(cur)
        elif cmd == "C":
            x1, i = _num(i)
            y1, i = _num(i)
            x2, i = _num(i)
            y2, i = _num(i)
            x, i = _num(i)
            y, i = _num(i)
            p0 = cur
            for tt in (0.25, 0.5, 0.75, 1.0):
                mt = 1 - tt
                bx = mt**3 * p0[0] + 3 * mt**2 * tt * x1 + 3 * mt * tt**2 * x2 + tt**3 * x
                by = mt**3 * p0[1] + 3 * mt**2 * tt * y1 + 3 * mt * tt**2 * y2 + tt**3 * y
                pts.append((bx, by))
            cur = (x, y)
        else:
            i += 1
    return pts


def _seg_intersect(p1, p2, p3, p4) -> bool:
    def ccw(a, b, c):
        return (c[1] - a[1]) * (b[0] - a[0]) - (b[1] - a[1]) * (c[0] - a[0])
    d1 = ccw(p3, p4, p1)
    d2 = ccw(p3, p4, p2)
    d3 = ccw(p1, p2, p3)
    d4 = ccw(p1, p2, p4)
    if ((d1 > 0) != (d2 > 0)) and ((d3 > 0) != (d4 > 0)):
        return True
    return False


def _polylines_cross(a: list, b: list) -> bool:
    for i in range(len(a) - 1):
        for j in range(len(b) - 1):
            if _seg_intersect(a[i], a[i + 1], b[j], b[j + 1]):
                # ignore intersections at shared/near-shared endpoints
                if _close(a[i], b[j]) or _close(a[i], b[j + 1]) or _close(a[i + 1], b[j]) or _close(a[i + 1], b[j + 1]):
                    continue
                return True
    return False


def _close(p, q, tol: float = 3.0) -> bool:
    return abs(p[0] - q[0]) < tol and abs(p[1] - q[1]) < tol


def _seg_through_box(p1, p2, box) -> bool:
    x, y, w, h = box
    # quick reject
    if max(p1[0], p2[0]) < x or min(p1[0], p2[0]) > x + w:
        return False
    if max(p1[1], p2[1]) < y or min(p1[1], p2[1]) > y + h:
        return False
    # midpoint-inside test (cheap interior hit) + edge-of-box crossing
    mid = ((p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2)
    if x < mid[0] < x + w and y < mid[1] < y + h:
        return True
    corners = [(x, y), (x + w, y), (x + w, y + h), (x, y + h)]
    for i in range(4):
        if _seg_intersect(p1, p2, corners[i], corners[(i + 1) % 4]):
            return True
    return False


def _pt_in_box(p, box, pad: float = 4.0) -> bool:
    x, y, w, h = box
    return (x - pad) <= p[0] <= (x + w + pad) and (y - pad) <= p[1] <= (y + h + pad)


def _decode_points(b64: str) -> list[tuple[float, float]]:
    import base64
    try:
        arr = json.loads(base64.b64decode(b64))
        return [(float(p["x"]), float(p["y"])) for p in arr]
    except Exception:
        return []


def _split_endpoints(data_id: str, node_ids: set[str]) -> tuple[str | None, str | None]:
    """data-id is ``L_<SRC>_<DST>_<i>_<j>``; SRC/DST themselves contain '_'.
    Resolve against the known node-id set by greedy prefix match."""
    s = data_id
    if s.startswith("L_"):
        s = s[2:]
    s = re.sub(r"_\d+_\d+$", "", s)
    for a in node_ids:
        if s == a:  # degenerate
            return a, None
        if s.startswith(a + "_"):
            b = s[len(a) + 1:]
            if b in node_ids:
                return a, b
    return None, None


def _extract_geometry(svg: str):
    """Return (edges, node_boxes) using mermaid's own geometry metadata.

    edges: list of {points: polyline, src, dst}.
    node_boxes: dict node_id -> (x,y,w,h)  (component + actor boxes only; the
    dashed tier/cluster containers are excluded — they are meant to contain
    edges)."""
    node_boxes: dict[str, tuple] = {}
    # Node groups: <g class="node ..." id="flowchart-<NID>-<n>" transform="translate(x,y)"> <rect class="basic label-container" x y width height>
    for m in re.finditer(
        r'<g[^>]*class="node[^"]*"[^>]*id="[^"]*flowchart-([^"]+?)-\d+"[^>]*transform="translate\(([-\d.]+),\s*([-\d.]+)\)"',
        svg,
    ):
        nid = m.group(1)
        tx, ty = float(m.group(2)), float(m.group(3))
        tail = svg[m.end(): m.end() + 1500]
        rm = re.search(r'<rect[^>]*class="basic label-container"[^>]*>', tail) or re.search(r"<rect[^>]*>", tail)
        if not rm:
            continue
        rect = rm.group(0)
        wv = re.search(r'\bwidth="([-\d.]+)"', rect)
        hv = re.search(r'\bheight="([-\d.]+)"', rect)
        if not (wv and hv):
            continue
        w, h = float(wv.group(1)), float(hv.group(1))
        xv = re.search(r'\bx="([-\d.]+)"', rect)
        yv = re.search(r'\by="([-\d.]+)"', rect)
        ox = float(xv.group(1)) if xv else -w / 2
        oy = float(yv.group(1)) if yv else -h / 2
        node_boxes[nid] = (tx + ox, ty + oy, w, h)

    node_ids = set(node_boxes)
    edges = []
    for pm in re.finditer(r'<path\b[^>]*class="[^"]*flowchart-link[^"]*"[^>]*>', svg):
        tag = pm.group(0)
        dpm = re.search(r'data-points="([^"]+)"', tag)
        pts = _decode_points(dpm.group(1)) if dpm else []
        if len(pts) < 2:
            dm = re.search(r'\bd="([^"]+)"', tag)
            pts = _flatten_path(dm.group(1)) if dm else []
        if len(pts) < 2:
            continue
        did = re.search(r'data-id="([^"]+)"', tag)
        src, dst = _split_endpoints(did.group(1), node_ids) if did else (None, None)
        edges.append({"points": pts, "src": src, "dst": dst})
    return edges, node_boxes


def _viewbox(svg: str) -> tuple[float, float]:
    m = re.search(r'viewBox="([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)"', svg)
    if not m:
        return (0.0, 0.0)
    return float(m.group(3)), float(m.group(4))


def _node_tier(nid: str, comp_tier: dict) -> str:
    if nid.startswith("EXT_") or nid.startswith("ACT_"):
        return "actors"
    if nid.startswith("CMP_"):
        return comp_tier.get(nid, "?")
    return "?"


def _metric(svg: str, comp_tier: dict | None = None) -> dict:
    comp_tier = comp_tier or {}
    edges, boxes = _extract_geometry(svg)
    crossings = 0
    for i in range(len(edges)):
        for j in range(i + 1, len(edges)):
            a, b = edges[i], edges[j]
            shared = {a["src"], a["dst"]} & {b["src"], b["dst"]}
            shared.discard(None)
            if shared:
                continue
            if _polylines_cross(a["points"], b["points"]):
                crossings += 1
    overlaps = 0
    for e in edges:
        pts = e["points"]
        endpoints = {e["src"], e["dst"]}
        for nid, box in boxes.items():
            if nid in endpoints:
                continue
            if any(_seg_through_box(pts[k], pts[k + 1], box) for k in range(len(pts) - 1)):
                overlaps += 1
    # --- tier vertical ordering + width ---
    w, h = _viewbox(svg)
    aspect = round(w / h, 2) if h else 0.0
    # per-tier centre-y and box counts
    tier_cy: dict[str, list[float]] = {}
    tier_n: dict[str, int] = {}
    for nid, (x, y, bw, bh) in boxes.items():
        t = _node_tier(nid, comp_tier)
        tier_cy.setdefault(t, []).append(y + bh / 2)
        tier_n[t] = tier_n.get(t, 0) + 1
    cy = {t: (sum(v) / len(v)) for t, v in tier_cy.items() if v}
    order = ["actors", "client", "application", "data"]
    present = [t for t in order if t in cy]
    tier_order_ok = all(cy[present[k]] < cy[present[k + 1]] for k in range(len(present) - 1))
    app_boxes = tier_n.get("application", 0)
    return {
        "edges": len(edges),
        "nodes": len(boxes),
        "crossings": crossings,
        "box_overlaps": overlaps,
        "aspect_w_h": aspect,
        "svg_w": round(w),
        "app_boxes": app_boxes,
        "max_tier_boxes": max([tier_n.get(t, 0) for t in ("client", "application", "data")] or [0]),
        "tier_order_ok": tier_order_ok,
    }


def _mermaid_of(md: str) -> str | None:
    m = re.search(r"```mermaid\n(.*?)```", md, re.S)
    return m.group(1) if m else None


_CHROME_CANDIDATES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome")
_PPTR_CFG: list[str] = []


def _find_chrome() -> str | None:
    env = os.environ.get("PUPPETEER_EXECUTABLE_PATH")
    if env and Path(env).exists():
        return env
    for n in _CHROME_CANDIDATES:
        p = shutil.which(n)
        if p:
            return p
    return None


def _pptr_args() -> list[str]:
    """Write a one-shot puppeteer config (system Chrome + --no-sandbox) so mmdc
    launches headless Chrome on WSL/CI — mirrors export_pdf.mmdc_render_args."""
    if _PPTR_CFG:
        return _PPTR_CFG
    cfg = {
        "args": ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--disable-crash-reporter", "--no-first-run", "--disable-extensions"],
    }
    chrome = _find_chrome()
    if chrome:
        cfg["executablePath"] = chrome
    fd, path = tempfile.mkstemp(prefix="fig1-pptr-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh)
    _PPTR_CFG.extend(["-p", path])
    return _PPTR_CFG


def _mmdc_env() -> dict:
    env = os.environ.copy()
    if not env.get("PUPPETEER_EXECUTABLE_PATH"):
        chrome = _find_chrome()
        if chrome:
            env["PUPPETEER_EXECUTABLE_PATH"] = chrome
    return env


def _render_svg(mmd: str, tmp: Path, name: str) -> str | None:
    src = tmp / f"{name}.mmd"
    src.write_text(mmd, encoding="utf-8")
    out = tmp / f"{name}.svg"
    cmd = ["mmdc", "-i", str(src), "-o", str(out), "-b", "transparent"] + _pptr_args()
    try:
        subprocess.run(cmd, capture_output=True, timeout=180, check=False, env=_mmdc_env())
    except Exception:
        return None
    return out.read_text(encoding="utf-8") if out.is_file() else None


def _real_fixture(real_dir: Path, tmp: Path):
    """Load an actual OUTPUT_DIR (threat-model.yaml + attack-paths fragment) as
    the authoritative regression model — the real juice-shop layout to beat."""
    import yaml as _yaml
    yml = _yaml.safe_load((real_dir / "threat-model.yaml").read_text(encoding="utf-8"))
    ctx = compose.RenderContext(
        output_dir=real_dir,
        contract={},
        yaml_data=yml,
        triage={},
        fragments_dir=real_dir / ".fragments",
    )
    tax = compose._load_attack_class_taxonomy()
    threats = yml.get("threats") or []
    apd = compose._load_attack_paths_fragment(ctx, tax, threats)
    if (yml.get("meta") or {}).get("public_source_repo"):
        compose._collapse_public_repo_actors(apd)
    return ctx, apd, tax


def mmdc_available() -> bool:
    """True when mmdc + a launchable Chrome are present (else the harness/test
    that needs SVG geometry must skip — most CI has no browser)."""
    if not shutil.which("mmdc"):
        return False
    with tempfile.TemporaryDirectory() as td:
        svg = _render_svg("flowchart TB\n A-->B\n", Path(td), "probe")
    return bool(svg)


def run(real: str | None = None, png: str | None = None, only: str | None = None) -> dict:
    """Render + measure every fixture. Returns {name: metric-dict}. Importable
    from the regression test; ``main`` is the CLI wrapper around it."""
    import copy

    report: dict = {}
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        (tmp / ".fragments").mkdir(exist_ok=True)
        fx = fixtures(tmp)
        if real:
            try:
                fx["real"] = _real_fixture(Path(real), tmp)
            except Exception as e:  # noqa: BLE001
                report["real"] = {"error": f"load failed: {e}"}
        for name, (ctx, apd, tax) in fx.items():
            if only and only != name:
                continue
            apd = copy.deepcopy(apd)  # fixtures may share the attack_paths object
            # Faithfully replicate the wrapper: the public-repo actor collapse
            # runs in render() BEFORE the figure, not inside the figure fn.
            if name != "real" and (ctx.yaml_data.get("meta") or {}).get("public_source_repo"):
                compose._collapse_public_repo_actors(apd)
            md = compose._render_top_threats_architecture(ctx, apd, tax)
            mmd = _mermaid_of(md) if md else None
            if not mmd:
                report[name] = {"error": "no figure produced"}
                continue
            svg = _render_svg(mmd, tmp, name)
            if not svg:
                report[name] = {"error": "mmdc render failed", "mmd_lines": mmd.count(chr(10))}
                continue
            comp_tier_by_node = {
                compose._fig1_node_id("CMP", c.get("id", "")): (c.get("tier") or "application").strip().lower()
                for c in (ctx.yaml_data.get("components") or [])
                if c.get("id")
            }
            report[name] = _metric(svg, comp_tier_by_node)
            if png:
                outdir = Path(png)
                outdir.mkdir(parents=True, exist_ok=True)
                (outdir / f"{name}.mmd").write_text(mmd, encoding="utf-8")
                cmd = ["mmdc", "-i", str(tmp / f"{name}.mmd"), "-o", str(outdir / f"{name}.png"), "-b", "white", "-s", "2"] + _pptr_args()
                subprocess.run(cmd, capture_output=True, timeout=180, check=False, env=_mmdc_env())
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--png", type=str, default="")
    ap.add_argument("--only", type=str, default="")
    ap.add_argument("--real", type=str, default="", help="OUTPUT_DIR of a real run to add as the 'real' fixture")
    args = ap.parse_args()
    report = run(real=args.real or None, png=args.png or None, only=args.only or None)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
