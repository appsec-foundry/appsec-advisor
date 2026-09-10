#!/usr/bin/env python3
"""Deterministic Figure 1 renderer: a threat-model data-flow diagram.

Draws external entities, processes, data stores, labelled data flows, trust
boundaries as zones with crossing chips that carry the assumption verdict, a
STRIDE-per-element strip and severity counts on every node, and the numbered
attack scenarios of the Security Posture section as badges on the components
they touch. Attackers enter the diagram as red edges into the entry point.

The layout is computed, never hand-placed: three columns (untrusted, application,
data), zones stacked per column, nodes ordered by the barycenter of their
incoming flows, orthogonal edges with one lane per edge, ports spread along the
node sides. The same input yields byte-identical SVG.

Public entry point: ``build_figure1_dfd_svg(yaml_data, attack_paths_data,
attack_taxonomy, meta=None, actor_labels=None) -> str``. Returns "" when there
is nothing to draw.

``check_diagram`` (used by the tests and the ``--check`` CLI flag) verifies the
result geometrically and semantically: no edge crosses a foreign node, no label
overlaps another, every arrow starts on its source and ends on its target with
the head pointing inward, every chip sits on the crossing of its own flow, and
every flow and boundary is either drawn or explained in the legend.

Dev CLI: ``figure1_dfd.py <threat-model.yaml> [<threat-model.md>] <out.svg> [--check]``
— the markdown is only a stand-in for ``attack_paths_data`` when replaying a
published example.
"""

from __future__ import annotations

import collections
import html
import re
import sys

from prepare_trust_boundary_context import boundary_endpoints_valid

# ---- style --------------------------------------------------------------------
FONT = "Helvetica, Arial, sans-serif"
INK, MUTED, LINE = "#1f2937", "#6b7280", "#94a3b8"
RED, ORANGE, YELLOW, GREEN, AMBER, NAVY = "#dc2626", "#f59e0b", "#eab308", "#16a34a", "#d97706", "#1e3a5f"
CLS_COL = {"Restricted": "#b91c1c", "Confidential": "#c2410c", "Internal": "#64748b", "Public": "#94a3b8"}
CLS_RANK = {"Restricted": 0, "Confidential": 1, "Internal": 2, "Public": 3}
VERDICT = {"refuted": ("✕", RED), "clean": ("✓", GREEN), "held": ("✓", GREEN), "unconfirmed": ("?", AMBER)}
ZONE_STYLE = {  # zone key -> (title, stroke, fill)
    "internet": ("INTERNET — untrusted", "#b91c1c", "#fff5f5"),
    "client": ("Client device", "#9a3412", "#fff7ed"),
    "application": ("Application", "#1d4ed8", "#eff6ff"),
    "build": ("Build pipeline", "#0369a1", "#f0f9ff"),
    "data": ("Data", "#6d28d9", "#f5f3ff"),
    "third-party": ("Third-party", "#0f766e", "#f0fdfa"),
}
SEV_COL = {"Critical": RED, "High": ORANGE, "Medium": YELLOW}
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_FALLBACK_ACTOR = {
    "internet-anon": "Anonymous Internet Attacker",
    "internet-user": "Authenticated Internet Attacker",
    "internet-priv-user": "Privileged User",
    "repo-read": "Source-Code Reader",
    "supply-chain": "Supply-Chain Attacker",
    "build-time": "Supply-Chain / Build Attacker",
    "malicious-insider": "Malicious Insider",
    "insider": "Malicious Insider",
    "developer": "Developer",
    "b2b-partner": "B2B Partner",
}
USER_ID = "actor:user"

# ---- geometry -------------------------------------------------------------------
NODE_W, PROC_H, EXT_W, EXT_H = 190, 96, 172, 52
ZONE_PAD, ZONE_HEAD, NODE_GAP, ZONE_GAP = 14, 36, 26, 26
COL_W = NODE_W + 2 * ZONE_PAD
GAP, MARGIN, TOP = 150, 20, 66
B_OFF = 100  # boundary line offset inside a gap (from gap left)
LANE0, LANE_STEP = 40, 10  # first lane offset right of the boundary (clear of the chips)
LEGEND_W = 300
FS = 8.5  # small label font
ZONE_CAP = 8  # drawn nodes per zone; the rest collapse into one bar
ACTOR_CAP = 4
PORT_STEP = 22  # minimum spacing between ports on one node side
BAR_H = 24
COLUMN = {"client": 0, "application": 1, "build": 1, "data": 2, "third-party": 2}
ZONE_ORDER = {"client": 0, "application": 0, "build": 1, "data": 0, "third-party": 1}


def _esc(s):
    return html.escape(str(s), quote=True)


def _tw(s, size):
    """Approximate Helvetica text width in px."""
    return len(s) * size * 0.54


def _wrap(s, maxw, size):
    words, lines, cur = str(s).split(), [], ""
    for w in words:
        t = (cur + " " + w).strip()
        if _tw(t, size) <= maxw or not cur:
            cur = t
        else:
            lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines


def _cut(s, n):
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def _tb_num(tbid):
    m = re.search(r"(\d+)$", str(tbid))
    return int(m.group(1)) if m else 0


class _Canvas:
    def __init__(self):
        self.o = []
        self.labels = []  # bboxes for the overlap check: (x0, y0, x1, y1, name)
        self.badges = []
        self.maxy = 0

    def add(self, s):
        self.o.append(s)

    def rect(self, x, y, w, h, fill="none", stroke="none", sw=1, rx=0, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.add(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{rx}" fill="{fill}" '
            f'stroke="{stroke}" stroke-width="{sw}"{d}/>'
        )
        self.maxy = max(self.maxy, y + h)

    def text(self, x, y, s, size=11, fill=INK, anchor="middle", weight="normal", italic=False, track=None):
        st = ' font-style="italic"' if italic else ""
        self.add(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}"{st}>{_esc(s)}</text>'
        )
        self.maxy = max(self.maxy, y + 3)
        if track:
            w = _tw(s, size)
            x0 = {"start": x, "middle": x - w / 2, "end": x - w}[anchor]
            self.labels.append((x0, y - size, x0 + w, y + 2, track))

    def path(self, d, stroke, sw=1.5, dash=None, marker=None, marker_start=None):
        ds = f' stroke-dasharray="{dash}"' if dash else ""
        mk = f' marker-end="url(#{marker})"' if marker else ""
        mk += f' marker-start="url(#{marker_start})"' if marker_start else ""
        self.add(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{sw}" stroke-linejoin="round"{ds}{mk}/>')

    def circle(self, cx, cy, r, fill="none", stroke="none", sw=1):
        self.add(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')


# ---- glyphs -----------------------------------------------------------------------
def _badge(c, cx, cy, n, col=RED, r=8):
    c.circle(cx, cy, r, fill=col, stroke="#ffffff", sw=1.5)
    c.text(cx, cy + 3.5, n, size=9.5, fill="#ffffff", weight="bold")


def _sev_chips(c, x, y, counts):
    for s in ("Critical", "High", "Medium"):
        n = counts.get(s, 0)
        if not n:
            continue
        c.circle(x, y, 4.5, fill=SEV_COL[s])
        c.text(x + 8, y + 3.5, str(n), size=9.5, anchor="start", weight="bold")
        x += 8 + _tw(str(n), 9.5) + 10


def _stride_strip(c, x, y, counts):
    for i, letter in enumerate("STRIDE"):
        n = counts.get(letter, 0)
        bx = x + i * 15
        c.rect(bx, y, 13, 13, fill=(NAVY if n else "#f1f5f9"), stroke=("#ffffff" if n else "#cbd5e1"), sw=0.8, rx=2)
        c.text(bx + 6.5, y + 10, letter, size=8.5, fill=("#ffffff" if n else "#94a3b8"), weight="bold")
    c.text(x + 93, y + 10, "STRIDE", size=7.5, fill=MUTED, anchor="start")


def _globe(c, cx, cy, r=6.5):
    c.circle(cx, cy, r, fill="#ffffff", stroke=RED, sw=1.3)
    c.path(f"M {cx - r} {cy} H {cx + r} M {cx} {cy - r} V {cy + r}", RED, sw=1)
    c.path(f"M {cx} {cy - r} A {r * 0.5} {r} 0 0 0 {cx} {cy + r} A {r * 0.5} {r} 0 0 0 {cx} {cy - r}", RED, sw=1)


def _lock(c, cx, cy, col="#7c3aed"):
    c.rect(cx - 5, cy - 1, 10, 8, fill=col, rx=1.5)
    c.path(f"M {cx - 3} {cy - 1} V {cy - 4} A 3 3 0 0 1 {cx + 3} {cy - 4} V {cy - 1}", col, sw=1.6)


def _person(c, x, y, col):
    c.circle(x, y, 5, fill="none", stroke=col, sw=1.5)
    c.path(f"M {x - 8} {y + 16} A 8 8 0 0 1 {x + 8} {y + 16}", col, sw=1.5)


def _chip_width(tbid, n):
    return 8 + _tw(tbid, 8.5) + 4 + 10 + (6 + _tw(str(n), 8) if n else 0) + 6


# ---- inputs ---------------------------------------------------------------------------
def _zone_key(comp):
    tier = (comp.get("tier") or "application").lower()
    zones = [str(z).lower() for z in (comp.get("deployment_zones") or [])]
    if any(("ci" in z or "build" in z or "pipeline" in z) for z in zones):
        return "build"
    if tier == "client":
        return "client"
    if tier == "data":
        return "data"
    return "application"


def _finding_component_map(threats):
    """F-NNN / T-NNN → component id, from every id field a threat may carry."""
    fid_comp = {}
    for t in threats:
        cid = (t.get("component") or "").strip()
        if not cid:
            continue
        for kn in ("id", "t_id", "original_id"):
            m = re.match(r"^[FT]-(\d+)$", str(t.get(kn) or "").strip().upper())
            if m:
                for pre in ("F-", "T-"):
                    fid_comp.setdefault(f"{pre}{m.group(1)}", cid)
    return fid_comp


def scenarios_from_attack_paths(yaml_data, attack_paths_data, attack_taxonomy, actor_labels=None):
    """Numbered scenarios and actor cards, derived exactly like Figure 2 and the
    Top Threats table: one scenario per attack path, in fragment order."""
    threats = yaml_data.get("threats") or []
    fid_comp = _finding_component_map(threats)
    sev_by_fid = {}
    for t in threats:
        m = re.match(r"^[FT]-(\d+)$", str(t.get("id") or "").upper())
        if m:
            sev_by_fid[int(m.group(1))] = t.get("effective_severity") or t.get("risk") or t.get("severity")
    cls_by_id = {c.get("id"): c for c in (attack_taxonomy.get("classes") or []) if isinstance(c, dict)}
    labels = actor_labels or {}

    def actor_name(slug):
        return (labels.get(slug) or {}).get("label") or _FALLBACK_ACTOR.get(slug) or slug

    def actor_sub(slug):
        return (labels.get(slug) or {}).get("default_subtitle") or ""

    scenarios, order = [], []
    for idx, ap in enumerate(attack_paths_data.get("attack_paths") or []):
        if not isinstance(ap, dict):
            continue
        slug = (ap.get("class") or "").strip()
        cl = cls_by_id.get(slug) or {}
        raw_actor = (ap.get("actor") or cl.get("default_actor") or "internet-anon").strip()
        tgt = str(ap.get("_llm_target") or ap.get("target") or cl.get("default_target_tier") or "application").lower()
        victim = raw_actor == "victim-required" or tgt in ("client", "victim")
        actor = "internet-anon" if raw_actor in ("victim-required", "") else raw_actor
        if actor not in order:
            order.append(actor)
        cids, fids = [], []
        for f in ap.get("findings") or []:
            m = re.match(r"^[FT]-(\d+)$", str(f or "").upper())
            if m:
                fids.append(int(m.group(1)))
            cid = fid_comp.get(str(f or "").upper())
            if cid and cid not in cids:
                cids.append(cid)
        sevs = [sev_by_fid[f] for f in fids if sev_by_fid.get(f)]
        risk = min(sevs, key=lambda s: SEV_RANK.get(s, 9)) if sevs else ""
        scenarios.append(
            {
                "n": str(idx + 1),
                "title": cl.get("short_label") or cl.get("label") or slug or "attack",
                "actor": actor_name(actor),
                "victim": victim,
                "cids": cids,
                "fids": fids,
                "risk": risk,
            }
        )
    actors = [{"name": actor_name(s), "sub": actor_sub(s), "attacker": True} for s in order]
    return scenarios, actors


def _parse_markdown(md_text):
    """Dev-only stand-in for attack_paths_data: the ①–⑤ rows and actor bullets
    of a published report."""
    circ = "①②③④⑤⑥⑦⑧⑨"
    scenarios = []
    row_re = r'^\| <a id="path-[^"]+"></a>(.)\s*\| \*\*(.+?)\*\*.*?\|(.*?)\|\s*(?:🔴|🟠|🟡|🟢)\s*\*\*(\w+)\*\*'
    for m in re.finditer(row_re, md_text, re.M):
        glyph, title, findings, risk = m.groups()
        cnums = []
        for cm in re.finditer(r"\[(C-\d+)\]", findings):
            if cm.group(1) not in cnums:
                cnums.append(cm.group(1))
        fids = sorted({int(x) for x in re.findall(r"\[F-(\d+)\]", findings)})
        scenarios.append(
            {
                "n": str(circ.index(glyph) + 1),
                "title": title.replace("`", ""),
                "risk": risk,
                "cnums": cnums,
                "fids": fids,
            }
        )
    actors = []
    sect = md_text.split("**Threat actors.**", 1)[-1] if "**Threat actors.**" in md_text else ""
    sect = sect.split("\n\n**", 1)[0]
    for m in re.finditer(r"^- \*\*(.+?)\*\* — (.+)$", sect, re.M):
        name, rest = m.groups()
        drives = [circ.index(g) + 1 for g in (re.findall(r"drives.*", rest) or [""])[0] if g in circ]
        victim_of = [circ.index(g) + 1 for g in (re.findall(r"target of.*", rest) or [""])[0] if g in circ]
        actors.append({"name": name, "sub": rest.split(";")[0].strip(), "drives": drives, "victim_of": victim_of})
    attackers = [a for a in actors if a["drives"]]
    for s in scenarios:
        s["actor"] = next((a["name"] for a in attackers if int(s["n"]) in a["drives"]), None)
        s["victim"] = any(int(s["n"]) in a["victim_of"] for a in actors)
        if s["actor"] is None and attackers:
            s["actor"] = attackers[0]["name"]
    return scenarios, [{"name": a["name"], "sub": a["sub"], "attacker": True} for a in attackers]


# ---- model preparation ------------------------------------------------------------------
def _build_model(d, scenarios, actors):
    comps = [c for c in (d.get("components") or []) if isinstance(c, dict) and c.get("id")]
    cnum = {c["id"]: f"C-{i:02d}" for i, c in enumerate(comps, 1)}
    by_cnum = {v: k for k, v in cnum.items()}
    sev = collections.defaultdict(collections.Counter)
    stride = collections.defaultdict(collections.Counter)
    tb_threats = collections.Counter()
    for t in d.get("threats") or []:
        sev[t.get("component")][t.get("effective_severity") or t.get("risk") or t.get("severity")] += 1
        stride[t.get("component")][(t.get("stride") or "?")[0].upper()] += 1
        for b in t.get("boundary_refs") or []:
            if isinstance(b, dict):
                tb_threats[b.get("boundary_id")] += 1
    tbs = [t for t in (d.get("trust_boundaries") or []) if isinstance(t, dict) and t.get("id")]
    component_ids = {c["id"] for c in comps}
    exposed = {
        t["to"]
        for t in tbs
        if t.get("from") == "external"
        and t.get("confidence") == "confirmed"
        and boundary_endpoints_valid(t, component_ids)
    }

    nodes = {}
    for comp in comps:
        cid = comp["id"]
        zk = _zone_key(comp)
        nodes[cid] = {
            "id": cid,
            "kind": "store" if zk == "data" else "process",
            "name": f"{cnum[cid]} · {comp.get('name') or cid}",
            "zone": zk,
            "col": COLUMN[zk],
            "w": NODE_W,
            "h": PROC_H,
            "sev": sev[cid],
            "stride": stride[cid],
            "exposed": cid in exposed or "internet" in [str(z).lower() for z in comp.get("deployment_zones") or []],
            "sensitive": bool(comp.get("handles_sensitive_data")),
            "complex": comp.get("complexity") == "complex",
            "badges": [],
            "assets": [],
            "order": len(nodes),
        }
    for s in scenarios:
        cids = s.get("cids") or [by_cnum.get(cn) for cn in s.get("cnums") or []]
        for cid in cids:
            if cid in nodes:
                nodes[cid]["badges"].append(s["n"])
    # a single data store lists the crown jewels; a scenario marks the asset it reaches
    stores = [n for n in nodes.values() if n["kind"] == "store"]
    for st in stores:
        st["badges"] = []
    if len(stores) == 1:
        assets = sorted(
            [a for a in (d.get("assets") or []) if isinstance(a, dict)],
            key=lambda a: (CLS_RANK.get(str(a.get("classification")).title(), 9), str(a.get("id"))),
        )[:4]
        for a in assets:
            linked = {int(m) for t in (a.get("linked_threats") or []) for m in re.findall(r"(\d+)$", str(t))}
            a["_hits"] = [s["n"] for s in scenarios if linked & set(s.get("fids") or [])]
        stores[0]["assets"] = assets
        stores[0]["h"] = 100 + 15 * len(assets) + (6 if assets else 0)
    # actors: one legitimate user, then the attackers
    victim_of = [s["n"] for s in scenarios if s.get("victim")]
    nodes[USER_ID] = {
        "id": USER_ID,
        "kind": "ext",
        "name": "User",
        "sub": "legitimate client"
        + (" · victim of " + " ".join("①②③④⑤⑥⑦⑧⑨"[int(n) - 1] for n in victim_of[:4]) if victim_of else ""),
        "zone": "internet",
        "col": 0,
        "w": EXT_W,
        "h": EXT_H,
        "col_rank": 0,
        "color": GREEN,
        "order": 0,
        "badges": [],
    }
    for i, a in enumerate(actors[: ACTOR_CAP - 1]):
        nodes[f"actor:a{i}"] = {
            "id": f"actor:a{i}",
            "kind": "ext",
            "name": a["name"],
            "sub": _cut(a.get("sub") or "", 34),
            "zone": "internet",
            "col": 0,
            "w": EXT_W,
            "h": EXT_H,
            "col_rank": 2,
            "color": RED,
            "order": i + 1,
            "attacker": True,
            "badges": [],
        }

    # edges from data flows; `external` is the user's client on the way in, a third-party entity on the way out
    bundles = collections.OrderedDict()
    undrawn = []  # (flow id, reason)
    for f in d.get("data_flows") or []:
        if not isinstance(f, dict):
            continue
        src, dst = f.get("from"), f.get("to")
        fid = f.get("id") or "?"
        if src == dst:
            undrawn.append((fid, "self-loop"))
            continue
        if src == "external":
            src = USER_ID
        if dst == "external":
            key = f"ext:{f.get('from')}"
            if key not in nodes:
                nodes[key] = {
                    "id": key,
                    "kind": "ext",
                    "name": "External service",
                    "sub": _cut(f.get("label") or "", 36),
                    "zone": "third-party",
                    "col": 2,
                    "w": EXT_W,
                    "h": EXT_H,
                    "color": INK,
                    "order": len(nodes),
                    "badges": [],
                }
            dst = key
        if src not in nodes or dst not in nodes:
            undrawn.append((fid, f"unknown component {src if src not in nodes else dst}"))
            continue
        b = bundles.setdefault(
            (src, dst), {"src": src, "dst": dst, "ids": [], "cls": "Public", "tb": [], "bidi": False}
        )
        b["ids"].append(fid)
        cls = str(f.get("data_classification") or "Public").title()
        if CLS_RANK.get(cls, 9) < CLS_RANK.get(b["cls"], 9):
            b["cls"] = cls
        if str(f.get("direction") or "").lower() == "bidirectional":
            b["bidi"] = True
    edges = list(bundles.values())
    d["_undrawn_flows"] = undrawn
    # attack edges: every attacker targets the entry point with the most boundary-crossing threats
    ext_tb = collections.Counter()
    for t in tbs:
        if t.get("from") == "external" and t.get("to") in nodes:
            ext_tb[t["to"]] += tb_threats.get(t["id"], 0) + 1
    entry = [n for n in nodes.values() if n["col"] == 1 and n["kind"] == "process"]
    entry.sort(key=lambda n: (-ext_tb[n["id"]], -n["sev"].get("Critical", 0), -n["sev"].get("High", 0), n["order"]))
    if entry:
        for n in nodes.values():
            if n.get("attacker"):
                edges.append({"src": n["id"], "dst": entry[0]["id"], "ids": [], "cls": None, "tb": [], "attack": True})
    # trust boundaries: chip on the flow that crosses them, else a tag on the guarded node
    unplaced = []
    for t in tbs:
        src = USER_ID if t.get("from") == "external" else t.get("from")
        dst = t.get("to")
        if dst == "external":
            dst = f"ext:{t.get('from')}"
        hit = next((e for e in edges if e["src"] == src and e["dst"] == dst), None)
        if hit and nodes[hit["src"]]["col"] != nodes[hit["dst"]]["col"]:
            hit["tb"].append(t["id"])
        elif dst in nodes and dst != USER_ID:
            nodes[dst].setdefault("tags", []).append(t["id"])  # guards the entry into dst
        elif src in nodes and src != USER_ID:
            nodes[src].setdefault("tags", []).append(t["id"])  # guards the exit from src
        else:
            unplaced.append((t["id"], f"neither {t.get('from')} nor {t.get('to')} is drawn"))
    d["_unplaced_tbs"] = unplaced
    return nodes, edges, tbs, tb_threats


def _select_drawn(nodes, edges, d):
    """Cap nodes per zone. Nodes that carry flows or boundaries win, then severity.
    Dropped nodes are recorded per zone; their flows and boundaries are explained."""
    linked = collections.Counter()
    for e in edges:
        linked[e["src"]] += 1
        linked[e["dst"]] += 1
    for n in nodes.values():
        linked[n["id"]] += len(n.get("tags", []))
    dropped = collections.defaultdict(list)
    by_zone = collections.defaultdict(list)
    for n in nodes.values():
        by_zone[(n["col"], n["zone"])].append(n)
    for (col, zk), members in by_zone.items():
        cap = ACTOR_CAP if zk == "internet" else ZONE_CAP
        members.sort(
            key=lambda n: (
                -linked[n["id"]],
                -n.get("sev", {}).get("Critical", 0),
                -n.get("sev", {}).get("High", 0),
                n["order"],
            )
        )
        for n in members[cap:]:
            dropped[(col, zk)].append(n)
            n["dropped"] = True
    drawn = {k: n for k, n in nodes.items() if not n.get("dropped")}
    for e in edges:
        if e["src"] not in drawn or e["dst"] not in drawn:
            gone = e["src"] if e["src"] not in drawn else e["dst"]
            cn = nodes[gone]["name"].split(" · ")[0]
            for fid in e["ids"]:
                d["_undrawn_flows"].append((fid, f"{cn} collapsed"))
            for tid in e["tb"]:
                d["_unplaced_tbs"].append((tid, f"{cn} collapsed"))
    for n in nodes.values():
        if n.get("dropped"):
            for tid in n.get("tags", []):
                d["_unplaced_tbs"].append((tid, f"{n['name'].split(' · ')[0]} collapsed"))
    edges = [e for e in edges if e["src"] in drawn and e["dst"] in drawn]
    return drawn, edges, dropped


# ---- layout ----------------------------------------------------------------------------------
def _layout(nodes, edges, dropped, tb_threats, ncols=3):
    # 1. sides: L = entering from the left, R = leaving right / intra-column channel
    for e in edges:
        s, t = nodes[e["src"]], nodes[e["dst"]]
        dc = t["col"] - s["col"]
        e["kind"] = "intra" if dc == 0 else ("forward" if dc > 0 else "backward")
        e["skip"] = abs(dc) > 1
    sides = collections.defaultdict(lambda: {"L": [], "R": []})
    for e in edges:
        if e["kind"] == "forward":
            sides[e["src"]]["R"].append(("out", e))
            sides[e["dst"]]["L"].append(("in", e))
        elif e["kind"] == "backward":
            sides[e["src"]]["L"].append(("out", e))
            sides[e["dst"]]["R"].append(("in", e))
        else:
            sides[e["src"]]["R"].append(("out", e))
            sides[e["dst"]]["R"].append(("in", e))
    # 2. node heights grow with port count and boundary tags
    for n in nodes.values():
        k = max(len(sides[n["id"]]["L"]), len(sides[n["id"]]["R"]))
        n["tagspace"] = 20 * len(n.get("tags", []))
        n["h"] = max(n["h"], n["tagspace"] + PORT_STEP * (k + 1))
    # 3. column widths (right-side channel for intra edges), gap widths (one lane per edge)
    intra_per_col = collections.Counter(nodes[e["src"]]["col"] for e in edges if e["kind"] == "intra")
    col_w = [COL_W + (14 * intra_per_col[c] + 4 if intra_per_col[c] else 0) for c in range(ncols)]
    n_lanes = collections.Counter()
    for e in edges:
        if e["kind"] == "intra":
            continue
        g1, g2 = sorted((nodes[e["src"]]["col"], nodes[e["dst"]]["col"]))
        for g in range(g1, g2):
            n_lanes[g] += 1
    gap_w = [max(GAP, B_OFF + LANE0 + n_lanes[g] * LANE_STEP + 24) for g in range(ncols - 1)]
    col_x = [MARGIN]
    for c in range(1, ncols):
        col_x.append(col_x[-1] + col_w[c - 1] + gap_w[c - 1])
    incoming = collections.defaultdict(list)
    for e in edges:
        if e["kind"] == "forward":
            incoming[e["dst"]].append(e["src"])

    # 4. place columns: zones stacked, nodes ordered by the barycenter of placed sources
    def place_column(col):
        members = [n for n in nodes.values() if n["col"] == col]

        def key(n):
            srcs = [nodes[s]["cy"] for s in incoming[n["id"]] if "cy" in nodes[s]]
            bary = sum(srcs) / len(srcs) if srcs else 1e9
            return (n.get("col_rank", 1), ZONE_ORDER.get(n["zone"], 9), bary, n["order"])

        members.sort(key=key)
        x, y, boxes = col_x[col], TOP, []
        outer_top = y
        if col == 0:
            y += ZONE_HEAD
        cur, zy = None, None

        def close(zk):
            nonlocal y
            bar = dropped.get((col, zk))
            if bar:
                boxes.append({"bar": True, "x": x + ZONE_PAD, "y": y, "w": NODE_W, "h": BAR_H, "nodes": bar})
                y += BAR_H + NODE_GAP
            if zk != "internet":
                boxes.append({"zone": zk, "x": x, "y": zy, "w": col_w[col], "h": y - NODE_GAP + ZONE_PAD - zy})
                y = y - NODE_GAP + ZONE_PAD + ZONE_GAP

        for n in members:
            if n["zone"] != cur:
                if cur is not None:
                    close(cur)
                cur = n["zone"]
                if cur != "internet":
                    zy = y
                    y += ZONE_HEAD
            n["x"], n["y"] = x + ZONE_PAD + (NODE_W - n["w"]) / 2, y
            n["cy"] = y + n["h"] / 2
            y += n["h"] + NODE_GAP
        if cur is not None:
            close(cur)
        if col == 0:
            boxes.insert(
                0,
                {
                    "zone": "internet",
                    "x": x - 6,
                    "y": outer_top,
                    "w": col_w[0] + 12,
                    "h": y - ZONE_GAP + ZONE_PAD - outer_top,
                    "outer": True,
                },
            )
        return boxes

    zone_boxes = []
    for col in range(ncols):
        zone_boxes += place_column(col)
    bottom = max([b["y"] + b["h"] for b in zone_boxes if not b.get("bar")] + [TOP])

    # 5. ports: spread along each side, ordered by the other end's cy
    def other(item):
        role, e = item
        oid = e["dst"] if role == "out" else e["src"]
        return nodes[oid]["cy"]

    for nid, sd in sides.items():
        n = nodes[nid]
        for side in ("L", "R"):
            items = sorted(sd[side], key=lambda it: (other(it), it[1].get("ids", [])))
            k = len(items)
            for i, (role, e) in enumerate(items):
                yv = n["y"] + n["tagspace"] + (n["h"] - n["tagspace"]) * (i + 1) / (k + 1)
                if role == "out":
                    e["ys"] = yv
                else:
                    e["yd"] = yv

    # 6. routes
    boundaries = [col_x[g] + col_w[g] + B_OFF for g in range(ncols - 1)]
    gap_edges = collections.defaultdict(list)
    detour_y = bottom + 16
    for e in edges:
        if e["kind"] != "intra":
            gap_edges[min(nodes[e["src"]]["col"], nodes[e["dst"]]["col"])].append(e)
    lanes = {}
    for g, ge in gap_edges.items():
        ge.sort(key=lambda e: (abs(e["yd"] - e["ys"]), e["ys"], e["ids"]))
        for i, e in enumerate(ge):
            lanes[id(e)] = boundaries[g] + LANE0 + i * LANE_STEP
    chan_used = collections.Counter()
    for e in edges:
        s, t = nodes[e["src"]], nodes[e["dst"]]
        if e["kind"] == "intra":
            j = chan_used[s["col"]]
            chan_used[s["col"]] += 1
            cx = col_x[s["col"]] + ZONE_PAD + NODE_W + 10 + j * 14
            e["pts"] = [(s["x"] + s["w"], e["ys"]), (cx, e["ys"]), (cx, e["yd"]), (t["x"] + t["w"], e["yd"])]
            e["bx"] = None
        elif e["kind"] == "forward" and not e["skip"]:
            lane = lanes[id(e)]
            e["pts"] = [(s["x"] + s["w"], e["ys"]), (lane, e["ys"]), (lane, e["yd"]), (t["x"], e["yd"])]
            e["bx"] = boundaries[s["col"]]
        elif e["kind"] == "backward" and not e["skip"]:
            lane = lanes[id(e)]
            e["pts"] = [(s["x"], e["ys"]), (lane, e["ys"]), (lane, e["yd"]), (t["x"] + t["w"], e["yd"])]
            e["bx"] = boundaries[t["col"]]
        else:  # skips a column: detour below the diagram
            g1, g2 = sorted((s["col"], t["col"]))
            l1 = boundaries[g1] + LANE0 + len(gap_edges[g1]) * LANE_STEP
            l2 = boundaries[g2 - 1] + LANE0 + len(gap_edges[g2 - 1]) * LANE_STEP
            gap_edges[g1].append(e)
            gap_edges[g2 - 1].append(e)
            if e["kind"] == "forward":
                e["pts"] = [
                    (s["x"] + s["w"], e["ys"]),
                    (l1, e["ys"]),
                    (l1, detour_y),
                    (l2, detour_y),
                    (l2, e["yd"]),
                    (t["x"], e["yd"]),
                ]
            else:
                e["pts"] = [
                    (s["x"], e["ys"]),
                    (l2, e["ys"]),
                    (l2, detour_y),
                    (l1, detour_y),
                    (l1, e["yd"]),
                    (t["x"] + t["w"], e["yd"]),
                ]
            e["bx"] = boundaries[g1]
            detour_y += LANE_STEP
    # 7. chips: on the crossing of their own flow; same-flow chips stack, others slide along their line
    chips = []
    for e in edges:
        if e.get("bx") is not None:
            y0 = e["pts"][0][1] if e["kind"] == "forward" else e["pts"][-1][1]
            for j, tbid in enumerate(sorted(e["tb"], key=_tb_num)):
                chips.append({"bx": e["bx"], "y": y0 + j * 17, "tb": tbid, "group": id(e)})
    for ch in chips:
        ch["w"] = _chip_width(ch["tb"], tb_threats.get(ch["tb"], 0))
        ch["x"] = ch["bx"]
        ch["own"] = ch["y"]
    for bx in boundaries:
        placed = []
        for ch in sorted([ch for ch in chips if ch["bx"] == bx], key=lambda ch: (ch["y"], ch["tb"])):
            while any(
                p["group"] != ch["group"]
                and abs(ch["y"] - p["y"]) < 20
                and abs(ch["x"] - p["x"]) < (ch["w"] + p["w"]) / 2 + 6
                for p in placed
            ):
                ch["x"] -= 2
            placed.append(ch)
    height = max(bottom, detour_y) + MARGIN
    return col_x, col_w, zone_boxes, boundaries, chips, height


# ---- rendering ----------------------------------------------------------------------------------
def _orth(pts, r=8.0):
    """Orthogonal polyline with uniformly rounded corners."""
    if len(pts) < 3:
        return "M " + " L ".join(f"{px:.1f} {py:.1f}" for px, py in pts)
    d = f"M {pts[0][0]:.1f} {pts[0][1]:.1f}"
    for i in range(1, len(pts) - 1):
        (ax, ay), (bx, by), (cx, cy) = pts[i - 1], pts[i], pts[i + 1]
        l1 = abs(bx - ax) + abs(by - ay)
        l2 = abs(cx - bx) + abs(cy - by)
        rr = min(r, l1 / 2, l2 / 2)
        if rr < 1:
            d += f" L {bx:.1f} {by:.1f}"
            continue
        ux, uy = (bx - ax) / l1, (by - ay) / l1
        vx, vy = (cx - bx) / l2, (cy - by) / l2
        d += f" L {bx - ux * rr:.1f} {by - uy * rr:.1f} Q {bx:.1f} {by:.1f} {bx + vx * rr:.1f} {by + vy * rr:.1f}"
    d += f" L {pts[-1][0]:.1f} {pts[-1][1]:.1f}"
    return d


def _render(
    d,
    nodes,
    edges,
    tbs,
    tb_threats,
    scenarios,
    col_x,
    col_w,
    zone_boxes,
    boundaries,
    chips,
    height,
    dropped,
    unattached_assets,
):
    W = col_x[-1] + col_w[-1] + 30 + LEGEND_W + MARGIN
    c = _Canvas()
    c.add("")  # header, filled in once the height is known
    c.add("")
    defs = "<defs>"
    for key, col in list(CLS_COL.items()) + [("red", RED), ("grey", LINE)]:
        defs += (
            f'<marker id="arw-{key}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
            f'orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{col}"/></marker>'
        )
    c.add(defs + "</defs>")
    meta = d.get("meta") or {}
    project = (
        meta.get("project")
        if isinstance(meta.get("project"), str)
        else (meta.get("project") or {}).get("name")
        if isinstance(meta.get("project"), dict)
        else None
    )
    c.text(
        MARGIN,
        26,
        "Figure 1 — Data-flow diagram: trust boundaries, STRIDE-per-element, top attack paths",
        size=14,
        anchor="start",
        weight="bold",
        fill=NAVY,
    )
    n_comp = sum(1 for n in nodes.values() if n["kind"] != "ext") + sum(len(v) for v in dropped.values())
    c.text(
        MARGIN,
        42,
        f"{project or 'Project'} · {n_comp} components · {len(d.get('data_flows') or [])} data flows · {len(tbs)} trust boundaries · {len(d.get('threats') or [])} threats",
        size=10,
        anchor="start",
        fill=MUTED,
    )

    # zones
    zone_sub, zone_fw = collections.defaultdict(set), collections.defaultdict(set)
    for comp in d.get("components") or []:
        if not isinstance(comp, dict):
            continue
        for z in comp.get("deployment_zones") or []:
            zone_sub[_zone_key(comp)].add(str(z))
        if comp.get("framework"):
            zone_fw[_zone_key(comp)].add(str(comp["framework"]))
    for zb in [z for z in zone_boxes if not z.get("bar")]:
        title, stroke, fill = ZONE_STYLE[zb["zone"]]
        c.rect(zb["x"], zb["y"], zb["w"], zb["h"], fill=fill, stroke=stroke, sw=1.6, rx=10, dash="7 4")
        c.text(zb["x"] + 10, zb["y"] + 16, title, size=10.5, anchor="start", weight="bold", fill=stroke)
        zk = zb["zone"]
        sub = {"internet": "actors and their browsers", "third-party": "outbound dependencies"}.get(zk) or (
            ", ".join(sorted(zone_sub[zk])) + (" · " + ", ".join(sorted(zone_fw[zk])) if zone_fw[zk] else "")
            if zone_sub[zk]
            else ""
        )
        if sub:
            c.text(zb["x"] + 10, zb["y"] + 29, _cut(sub, 38), size=8.5, anchor="start", fill=MUTED, italic=True)
    for zb in [z for z in zone_boxes if z.get("bar")]:
        ids = ", ".join(n["name"].split(" · ")[0] for n in zb["nodes"])
        nthr = sum(sum(n["sev"].values()) for n in zb["nodes"])
        c.rect(zb["x"], zb["y"], zb["w"], zb["h"], fill="#ffffff", stroke=LINE, sw=1, rx=6, dash="3 3")
        c.text(
            zb["x"] + zb["w"] / 2,
            zb["y"] + 15,
            _cut(f"+{len(zb['nodes'])} more: {ids} · {nthr} threats", 40),
            size=8.5,
            fill=MUTED,
        )

    # boundary lines
    for i, bx in enumerate(boundaries):
        c.path(f"M {bx} {TOP - 4} V {height - MARGIN}", RED, sw=2.4, dash="6 5")
        ids = {ch["tb"] for ch in chips if ch["bx"] == bx}
        for n in nodes.values():
            if n["col"] == i + 1:
                ids |= set(n.get("tags", []))
        c.text(
            bx,
            TOP - 9,
            "TRUST BOUNDARY · " + " · ".join(sorted(ids, key=_tb_num)),
            size=8,
            fill=RED,
            weight="bold",
            track="bline",
        )

    # nodes
    for n in sorted(nodes.values(), key=lambda n: n["order"]):
        x, y, w, h = n["x"], n["y"], n["w"], n["h"]
        if n["kind"] == "ext":
            col = n["color"]
            c.rect(x, y, w, h, fill="#ffffff", stroke=col, sw=1.8)
            if n["zone"] == "internet":
                _person(c, x + 16, y + 20, col)
                tx = x + 32
            else:
                tx = x + 12
            for i, line in enumerate(_wrap(n["name"], w - (tx - x) - 8, 10)[:2]):
                c.text(tx, y + 19 + i * 12, line, size=10, anchor="start", weight="bold", fill=col)
            c.text(tx, y + h - 8, _cut(n["sub"], 36), size=7.5, anchor="start", fill=MUTED, italic=True)
            continue
        crit = n["sev"].get("Critical", 0)
        border = RED if crit else (ORANGE if n["sev"].get("High") else LINE)
        if n["kind"] == "process":
            c.rect(x, y, w, h, fill="#ffffff", stroke=border, sw=2 if crit else 1.4, rx=22)
            if n["complex"]:
                c.rect(x + 3, y + 3, w - 6, h - 6, fill="none", stroke=border, sw=0.8, rx=19)
            ox = 20
        else:  # Gane–Sarson data store
            c.rect(x, y, w, h, fill="#ffffff")
            c.path(
                f"M {x} {y} H {x + w} M {x} {y + h} H {x + w} M {x} {y} V {y + h} M {x + 8} {y} V {y + h}",
                border,
                sw=1.8,
            )
            ox = 24
        lines = _wrap(n["name"], w - 52, 11)[:2]
        for i, line in enumerate(lines):
            c.text(x + w / 2 - 6, y + 22 + i * 13, line, size=11, weight="bold")
        ty = y + 22 + len(lines) * 13 + 2
        _sev_chips(c, x + ox + 2, ty, n["sev"])
        _stride_strip(c, x + ox, ty + 10, n["stride"])
        if n["exposed"]:
            _globe(c, x + w - 16, y + 15)
        if n["sensitive"]:
            _lock(c, x + w - 16, y + 34)
        if n["assets"]:
            ay = ty + 36
            c.text(x + ox, ay, "Crown jewels stored here", size=8.5, anchor="start", fill=MUTED, italic=True)
            for i, a in enumerate(n["assets"]):
                col = CLS_COL.get(str(a.get("classification")).title(), MUTED)
                yy = ay + 10 + i * 15
                c.rect(x + ox, yy, 6, 6, fill=col)
                hits = a.get("_hits", [])
                badge_x0 = x + w - 30 - (len(hits) - 1) * 15 if hits else x + w - 26
                avail = badge_x0 - 10 - (x + ox + 10)
                name = _cut(f"{a.get('id')} {a.get('name')}", max(8, int(avail / (8.5 * 0.54))))
                c.text(x + ox + 10, yy + 6, name, size=8.5, anchor="start")
                for j, s in enumerate(hits):
                    _badge(c, badge_x0 + j * 15, yy + 3, s, r=6.5)
                c.text(
                    x + w - 4, yy + 6, str(a.get("classification"))[:4], size=7.5, anchor="end", fill=col, weight="bold"
                )
        for i, b in enumerate(n["badges"]):
            _badge(c, x + w - 18 - i * 19, y + h - 1, b)
            c.badges.append((x + w - 26 - i * 19, y + h - 9, x + w - 10 - i * 19, y + h + 7, f"badge {b} on {n['id']}"))

    # edges
    def chip(x, y, tbid, track=True):
        v = next((t.get("assumption_verdict") for t in tbs if t["id"] == tbid), "unconfirmed")
        g, col = VERDICT.get(v, VERDICT["unconfirmed"])
        n = tb_threats.get(tbid, 0)
        w = _chip_width(tbid, n)
        x0 = x - w / 2
        c.rect(x0, y - 8, w, 16, fill="#ffffff", stroke=col, sw=1.5, rx=8)
        c.text(x0 + 8, y + 3.5, tbid, size=8.5, anchor="start", weight="bold", fill=col)
        gx = x0 + 8 + _tw(tbid, 8.5) + 4
        c.text(gx + 5, y + 4, g, size=10, weight="bold", fill=col)
        if n:
            c.rect(gx + 14, y - 6, 6 + _tw(str(n), 8), 12, fill=col, rx=6)
            c.text(gx + 17 + _tw(str(n), 8) / 2, y + 3, str(n), size=8, fill="#ffffff", weight="bold")
        if track:
            c.labels.append((x0, y - 8, x0 + w, y + 8, f"chip {tbid}"))
        return w

    for e in edges:
        if e.get("attack"):
            c.path(_orth(e["pts"]), RED, sw=2.4, marker="arw-red")
            continue
        col = CLS_COL.get(e["cls"], LINE)
        mk = f"arw-{e['cls'] if e['cls'] in CLS_COL else 'grey'}"
        c.path(
            _orth(e["pts"]),
            col,
            sw=(2.2 if e["cls"] == "Restricted" else 1.6),
            marker=mk,
            marker_start=(mk if e.get("bidi") else None),
        )
        ids = "/".join(i.replace("df-", "") for i in e["ids"])
        lbl = "df-" + ids if len(e["ids"]) <= 3 else f"df-{e['ids'][0][3:]} +{len(e['ids']) - 1}"
        x0, y0 = e["pts"][0]
        if e["kind"] == "forward":
            c.text(x0 + 6, y0 - 4, lbl, size=FS, fill=col, anchor="start", weight="bold", track=f"label {lbl}")
        elif e["kind"] == "backward":
            xe, ye = e["pts"][-1]
            c.text(xe + 6, ye - 4, lbl, size=FS, fill=col, anchor="start", weight="bold", track=f"label {lbl}")
        else:  # intra: rotated along the channel segment
            (cx, ya), (_, yb) = e["pts"][1], e["pts"][2]
            ym = (ya + yb) / 2
            c.add(
                f'<text x="{cx + 9:.1f}" y="{ym:.1f}" font-family="{FONT}" font-size="{FS}" fill="{col}" text-anchor="middle" '
                f'font-weight="bold" transform="rotate(-90 {cx + 9:.1f} {ym:.1f})">{_esc(lbl)}</text>'
            )
            w = _tw(lbl, FS)
            c.labels.append((cx + 3, ym - w / 2, cx + 13, ym + w / 2, f"label {lbl}"))
    for ch in chips:
        chip(ch["x"], ch["y"], ch["tb"])
    for n in nodes.values():  # boundary tags on the corner of the node they guard
        for i, tbid in enumerate(n.get("tags", [])):
            w = _chip_width(tbid, tb_threats.get(tbid, 0))
            cx, cy = n["x"] + 2, n["y"] + 10 + i * 20
            chip(cx, cy, tbid, track=False)
            c.badges.append((cx - w / 2, cy - 8, cx + w / 2, cy + 8, f"tag {tbid} on {n['id']}"))

    # legend
    lx, ly, lw = col_x[-1] + col_w[-1] + 30, TOP - 6, LEGEND_W

    def head(y, t):
        c.rect(lx, y, lw, 20, fill=NAVY, rx=4)
        c.text(lx + lw / 2, y + 14, t, size=10.5, fill="#ffffff", weight="bold")
        return y + 30

    y = head(ly, "Notation (DFD)")
    c.rect(lx + 10, y - 8, 22, 14, fill="#ffffff", stroke=INK, sw=1.4)
    c.text(lx + 40, y + 3, "external entity (actor, third party)", size=9, anchor="start")
    y += 20
    c.rect(lx + 10, y - 8, 22, 14, fill="#ffffff", stroke=INK, sw=1.4, rx=7)
    c.text(lx + 40, y + 3, "process (component); double line = complex", size=9, anchor="start")
    y += 20
    c.path(
        f"M {lx + 10} {y - 8} H {lx + 32} M {lx + 10} {y + 6} H {lx + 32} M {lx + 10} {y - 8} V {y + 6} M {lx + 13} {y - 8} V {y + 6}",
        INK,
        sw=1.4,
    )
    c.text(lx + 40, y + 3, "data store (with crown-jewel assets)", size=9, anchor="start")
    y += 20
    c.path(f"M {lx + 10} {y - 1} H {lx + 32}", CLS_COL["Confidential"], sw=1.6, marker="arw-Confidential")
    c.text(lx + 40, y + 3, "data flow · colour = classification · two heads = bidirectional", size=9, anchor="start")
    y += 16
    xx = lx + 40
    for k, col in CLS_COL.items():
        c.rect(xx, y - 6, 8, 8, fill=col)
        c.text(xx + 11, y + 1, k, size=8, anchor="start", fill=col)
        xx += _tw(k, 8) + 22
    y += 18
    c.path(f"M {lx + 10} {y - 1} H {lx + 32}", RED, sw=2, dash="6 4")
    c.text(lx + 40, y + 3, "trust boundary (dashed) = zone edge", size=9, anchor="start")
    y += 20
    c.rect(lx + 8, y - 9, 44, 16, fill="#ffffff", stroke=RED, sw=1.4, rx=8)
    c.text(lx + 14, y + 3, "tb ✕", size=8, anchor="start", fill=RED, weight="bold")
    c.rect(lx + 38, y - 7, 11, 12, fill=RED, rx=6)
    c.text(lx + 43.5, y + 3, "9", size=8, fill="#ffffff", weight="bold")
    c.text(lx + 60, y + 3, "boundary crossing: ✕ assumption refuted · ✓ held · ? unverified", size=8.5, anchor="start")
    y += 13
    c.text(
        lx + 60,
        y + 3,
        "count = threats crossing it · on a node corner = guards that entry",
        size=8.5,
        anchor="start",
        fill=MUTED,
    )
    y += 20
    c.path(f"M {lx + 10} {y - 1} H {lx + 32}", RED, sw=2.4, marker="arw-red")
    c.text(lx + 40, y + 3, "attacker → entry point (⊕ = every exposed process)", size=9, anchor="start")
    y += 20
    _globe(c, lx + 21, y - 2)
    c.text(lx + 40, y + 3, "⊕ internet-exposed entry point", size=9, anchor="start")
    y += 18
    _lock(c, lx + 21, y - 3)
    c.text(lx + 40, y + 3, "handles sensitive data", size=9, anchor="start")
    y += 20
    _stride_strip(c, lx + 10, y - 9, {"S": 1, "T": 1, "I": 1})
    c.text(lx + 10, y + 20, "STRIDE-per-element: filled = threats found in that class", size=8.5, anchor="start")
    y += 30
    xx = lx + 10
    for s, col in SEV_COL.items():
        c.circle(xx, y - 2, 4.5, fill=col)
        c.text(xx + 8, y + 1, s, size=9, anchor="start")
        xx += 70
    c.text(
        lx + 10,
        y + 16,
        "counts on a node = threats per severity · ①–⑨ = attack scenario",
        size=8.5,
        anchor="start",
        fill=MUTED,
    )
    y += 13
    c.text(
        lx + 10,
        y + 16,
        "a data store shows a scenario only at the asset it reaches",
        size=8.5,
        anchor="start",
        fill=MUTED,
    )
    y += 32

    if scenarios:
        y = head(y, "Attack scenarios — by actor")
        cur = None
        for s in scenarios:
            who = (s.get("actor") or "Attacker") + (" → User (victim)" if s.get("victim") else "")
            if who != cur:
                cur = who
                c.text(lx + 10, y + 3, _cut(who, 52), size=9, anchor="start", weight="bold", fill=RED)
                y += 16
            _badge(c, lx + 20, y - 2, s["n"])
            c.text(lx + 34, y + 2, _cut(s["title"], 40), size=9, anchor="start")
            if s.get("risk"):
                c.text(
                    lx + lw - 6,
                    y + 2,
                    s["risk"],
                    size=8,
                    anchor="end",
                    fill=SEV_COL.get(s["risk"], MUTED),
                    weight="bold",
                )
            y += 17
        y += 8

    if tbs:
        y = head(y, "Trust boundaries — assumption verdicts")
        for t in sorted(tbs, key=lambda t: _tb_num(t["id"])):
            g, col = VERDICT.get(t.get("assumption_verdict"), VERDICT["unconfirmed"])
            c.text(lx + 10, y + 3, f"{t['id']} {g}", size=9, anchor="start", weight="bold", fill=col)
            ep = t.get("enforcement_point") or "no enforcement point"
            c.text(lx + 52, y + 3, _cut(f"{t.get('from')} → {t.get('to')} · {ep}", 44), size=8.5, anchor="start")
            if tb_threats.get(t["id"]):
                c.text(
                    lx + lw - 6, y + 3, f"{tb_threats[t['id']]} threats", size=8, anchor="end", fill=col, weight="bold"
                )
            y += 15
        y += 12
    flows = {f.get("id"): f for f in d.get("data_flows") or [] if isinstance(f, dict)}
    if edges:
        y = head(y, "Data flows")
        for e in edges:
            for fid in e["ids"]:
                f = flows.get(fid, {})
                col = CLS_COL.get(str(f.get("data_classification")).title(), LINE)
                c.text(lx + 10, y + 3, fid, size=8.5, anchor="start", weight="bold", fill=col)
                c.text(
                    lx + 52,
                    y + 3,
                    _cut(
                        f"{f.get('from')} → {f.get('to')} · {f.get('protocol')} · {_cut(f.get('label') or '', 28)}", 50
                    ),
                    size=8,
                    anchor="start",
                )
                y += 14
    if unattached_assets:
        y += 12
        y = head(y, "Crown jewels (assets)")
        for a in unattached_assets[:6]:
            col = CLS_COL.get(str(a.get("classification")).title(), MUTED)
            c.rect(lx + 10, y - 6, 6, 6, fill=col)
            c.text(lx + 22, y + 1, _cut(f"{a.get('id')} {a.get('name')}", 44), size=8.5, anchor="start")
            c.text(lx + lw - 6, y + 1, str(a.get("classification")), size=7.5, anchor="end", fill=col, weight="bold")
            y += 14
    notes = []
    if dropped:
        n = sum(len(v) for v in dropped.values())
        notes.append(f"{n} lower-priority component(s) collapsed into '+N more' bars; their flows are not drawn.")
    for fid, why in d.get("_undrawn_flows", []):
        notes.append(f"{fid} not drawn: {why}")
    for tid, why in d.get("_unplaced_tbs", []):
        notes.append(f"{tid} not placed: {why}")
    if notes:
        y += 12
        for s in notes[:8]:
            c.text(lx + 10, y + 3, _cut(s, 70), size=8, anchor="start", fill=MUTED, italic=True)
            y += 12
    H = max(height, c.maxy + MARGIN)
    c.o[0] = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">'
    )
    c.o[1] = f'<rect width="{W}" height="{H}" fill="#ffffff"/>'
    c.add("</svg>")
    return "\n".join(c.o), c


# ---- verification -------------------------------------------------------------------------------
def _check_geometry(nodes, edges, canvas, chips):
    problems = []
    rects = {n["id"]: (n["x"] + 1, n["y"] + 1, n["x"] + n["w"] - 1, n["y"] + n["h"] - 1) for n in nodes.values()}
    segs = []
    for e in edges:
        for p, q in zip(e["pts"], e["pts"][1:]):
            segs.append((p, q, (e.get("ids") or ["attack"]) + list(e.get("tb") or [])))

    def hits(p, q, r):
        x0, y0, x1, y1 = r
        if p[1] == q[1]:
            return y0 < p[1] < y1 and min(p[0], q[0]) < x1 and max(p[0], q[0]) > x0
        return x0 < p[0] < x1 and min(p[1], q[1]) < y1 and max(p[1], q[1]) > y0

    for e in edges:
        own = {e["src"], e["dst"]}
        for p, q in zip(e["pts"], e["pts"][1:]):
            for nid, r in rects.items():
                if nid not in own and hits(p, q, r):
                    problems.append(f"edge {e.get('ids') or 'attack'} crosses node {nid}")
    for i in range(len(segs)):
        for j in range(i + 1, len(segs)):
            (a, b, na), (c2, d2, nb) = segs[i], segs[j]
            if (
                a[1] == b[1] == c2[1] == d2[1]
                and min(a[0], b[0]) < max(c2[0], d2[0]) - 1
                and min(c2[0], d2[0]) < max(a[0], b[0]) - 1
            ):
                problems.append(f"collinear horizontal overlap: {na} × {nb} at y={a[1]:.0f}")
            if (
                a[0] == b[0] == c2[0] == d2[0]
                and min(a[1], b[1]) < max(c2[1], d2[1]) - 1
                and min(c2[1], d2[1]) < max(a[1], b[1]) - 1
            ):
                problems.append(f"collinear vertical overlap: {na} × {nb} at x={a[0]:.0f}")
    for ch in chips:
        r = (ch["x"] - ch["w"] / 2, ch["y"] - 8, ch["x"] + ch["w"] / 2, ch["y"] + 8)
        for p, q, name in segs:
            if p[1] == q[1] and abs(p[1] - ch["own"]) <= 17 * 3 and ch["tb"] in name:
                continue
            if hits(p, q, r):
                problems.append(f"segment {name} runs through chip {ch['tb']}")
    for bx0, by0, bx1, by1, name in canvas.badges:
        for p, q, ename in segs:
            if hits(p, q, (bx0, by0, bx1, by1)):
                problems.append(f"segment {ename} touches {name}")
    labs = canvas.labels
    for i in range(len(labs)):
        for j in range(i + 1, len(labs)):
            a, b = labs[i], labs[j]
            if a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]:
                problems.append(f"label overlap: {a[4]} × {b[4]}")
        for nid, r in rects.items():
            a = labs[i]
            if a[0] < r[2] and r[0] < a[2] and a[1] < r[3] and r[1] < a[3]:
                problems.append(f"label on node: {a[4]} × {nid}")
    return problems


def _audit(d, nodes, edges, chips, boundaries):
    """Every drawn arrow matches its YAML flow; every flow and boundary is drawn or explained."""
    problems = []
    flows = {f.get("id"): f for f in d.get("data_flows") or [] if isinstance(f, dict)}
    tbs = {t["id"]: t for t in d.get("trust_boundaries") or [] if isinstance(t, dict) and t.get("id")}

    def on_edge(pt, n):
        x, y = pt
        return (abs(x - n["x"]) < 0.6 or abs(x - n["x"] - n["w"]) < 0.6) and n["y"] <= y <= n["y"] + n["h"]

    def want(rec):
        src = USER_ID if rec.get("from") == "external" else rec.get("from")
        dst = f"ext:{rec.get('from')}" if rec.get("to") == "external" else rec.get("to")
        return src, dst

    for e in edges:
        s, t = nodes[e["src"]], nodes[e["dst"]]
        name = "/".join(e["ids"]) or f"attack {s['name']}"
        p1 = e["pts"][-1]
        if not on_edge(e["pts"][0], s):
            problems.append(f"{name}: does not start on its source {s['id']}")
        if not on_edge(p1, t):
            problems.append(f"{name}: does not end on its target {t['id']}")
        (qx, qy), (px, py) = e["pts"][-2], p1
        if qy != py:
            problems.append(f"{name}: last segment is not horizontal")
        elif (abs(p1[0] - t["x"]) < 0.6) != (px > qx):
            problems.append(f"{name}: arrowhead points away from {t['id']}")
        for fid in e["ids"]:
            f = flows.get(fid)
            if not f:
                problems.append(f"{fid}: drawn but not in YAML")
                continue
            if (e["src"], e["dst"]) != want(f):
                problems.append(f"{fid}: drawn {e['src']}→{e['dst']}, YAML says {f.get('from')}→{f.get('to')}")
            cls = str(f.get("data_classification") or "Public").title()
            if CLS_RANK.get(cls, 9) < CLS_RANK.get(e["cls"], 9):
                problems.append(f"{fid}: bundle colour {e['cls']} weaker than flow classification {cls}")
            if str(f.get("direction") or "").lower() == "bidirectional" and not e.get("bidi"):
                problems.append(f"{fid}: bidirectional flow drawn with one head")
        for ch in [c for c in chips if c.get("group") == id(e)]:
            seg = (e["pts"][0], e["pts"][1]) if e["kind"] == "forward" else (e["pts"][-2], e["pts"][-1])
            xs = sorted((seg[0][0], seg[1][0]))
            if not (xs[0] <= ch["x"] <= xs[1]) or not (0 <= ch["y"] - seg[0][1] <= 17 * 3):
                problems.append(f"{ch['tb']}: chip not on the crossing segment of {name}")
            if e["bx"] not in boundaries or not (xs[0] <= e["bx"] <= xs[1]):
                problems.append(f"{ch['tb']}: {name} does not cross boundary at x={e['bx']}")
            tb = tbs.get(ch["tb"])
            if tb and (e["src"], e["dst"]) != want(tb):
                problems.append(f"{ch['tb']}: chip on {name} but boundary is {tb.get('from')}→{tb.get('to')}")
    for n in nodes.values():
        for tid in n.get("tags", []):
            tb = tbs.get(tid)
            if tb and n["id"] not in (tb.get("from"), tb.get("to")):
                problems.append(f"{tid}: tag on {n['id']} but boundary is {tb.get('from')}→{tb.get('to')}")
    drawn = {fid for e in edges for fid in e["ids"]}
    explained = {u[0] for u in d.get("_undrawn_flows", [])}
    for fid in flows:
        if fid not in drawn and fid not in explained:
            problems.append(f"{fid}: neither drawn nor explained")
    placed = (
        {c["tb"] for c in chips}
        | {t for n in nodes.values() for t in n.get("tags", [])}
        | {u[0] for u in d.get("_unplaced_tbs", [])}
    )
    for tid in tbs:
        if tid not in placed:
            problems.append(f"{tid}: neither chip, tag nor explained")
    return problems


# ---- entry points ---------------------------------------------------------------------------------
def _build(yaml_data, scenarios, actors):
    d = dict(yaml_data)  # the builder annotates a shallow copy, never the caller's model
    nodes, edges, tbs, tb_threats = _build_model(d, scenarios, actors)
    nodes, edges, dropped = _select_drawn(nodes, edges, d)
    col_x, col_w, zone_boxes, boundaries, chips, height = _layout(nodes, edges, dropped, tb_threats)
    stores = [n for n in nodes.values() if n["kind"] == "store"]
    unattached = (
        []
        if len(stores) == 1
        else sorted(
            [a for a in (d.get("assets") or []) if isinstance(a, dict)],
            key=lambda a: (CLS_RANK.get(str(a.get("classification")).title(), 9), str(a.get("id"))),
        )
    )
    svg, canvas = _render(
        d,
        nodes,
        edges,
        tbs,
        tb_threats,
        scenarios,
        col_x,
        col_w,
        zone_boxes,
        boundaries,
        chips,
        height,
        dropped,
        unattached,
    )
    return svg, {"d": d, "nodes": nodes, "edges": edges, "chips": chips, "boundaries": boundaries, "canvas": canvas}


def build_figure1_dfd_svg(yaml_data, attack_paths_data, attack_taxonomy, meta=None, actor_labels=None):
    """Figure 1 for a threat model. Returns "" when there is nothing to draw."""
    if not (yaml_data.get("components") or []):
        return ""
    scenarios, actors = scenarios_from_attack_paths(
        yaml_data, attack_paths_data or {}, attack_taxonomy or {}, actor_labels
    )
    svg, _state = _build(yaml_data, scenarios, actors)
    return svg


def check_diagram(yaml_data, attack_paths_data, attack_taxonomy, actor_labels=None, scenarios=None, actors=None):
    """Render and verify; returns (svg, problems). Used by the tests and the CLI."""
    if scenarios is None:
        scenarios, actors = scenarios_from_attack_paths(
            yaml_data, attack_paths_data or {}, attack_taxonomy or {}, actor_labels
        )
    svg, st = _build(yaml_data, scenarios, actors or [])
    problems = _check_geometry(st["nodes"], st["edges"], st["canvas"], st["chips"]) + _audit(
        st["d"], st["nodes"], st["edges"], st["chips"], st["boundaries"]
    )
    return svg, problems


def main(argv):
    import yaml

    do_check = "--check" in argv
    args = [a for a in argv if a != "--check"]
    if len(args) < 2:
        print(__doc__)
        return 2
    yaml_path, out = args[0], args[-1]
    with open(yaml_path, encoding="utf-8") as fh:
        d = yaml.safe_load(fh)
    scenarios, actors = ([], [])
    if len(args) == 3:
        with open(args[1], encoding="utf-8") as fh:
            scenarios, actors = _parse_markdown(fh.read())
    svg, problems = check_diagram(d, {}, {}, scenarios=scenarios, actors=actors)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(f"wrote {out}")
    if do_check:
        for p in problems:
            print("CHECK:", p)
        print("check:", "OK" if not problems else f"{len(problems)} problem(s)")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
