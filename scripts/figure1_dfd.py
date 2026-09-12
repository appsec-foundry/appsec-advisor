#!/usr/bin/env python3
"""Deterministic Figure 1 renderer: a threat-model data-flow diagram.

Draws external entities, processes, data stores, labelled data flows, trust
boundaries as zones with crossing chips that carry the assumption verdict, a
STRIDE-per-element strip, severity counts and evidenced weaknesses or causes on
every node, and the numbered attack scenarios of the Security Posture section as
badges on the components they touch. Each attacker enters over a labelled, coloured bus that
fans out into every exposed process its scenarios reach; a victim scenario adds
a dashed edge back to the user.

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

from detect_open_registration import overview_actor_notes, overview_actor_slug
from prepare_trust_boundary_context import boundary_endpoints_valid
from weakness_classifier import load_weakness_classes

# ---- style --------------------------------------------------------------------
FONT = "Helvetica, Arial, sans-serif"
INK, MUTED, LINE = "#1f2937", "#6b7280", "#94a3b8"
RED, ORANGE, YELLOW, GREEN, AMBER, NAVY = "#b3453f", "#cf8a3e", "#c4a441", "#3f8a5e", "#b3842c", "#334d6e"
CLS_COL = {"Restricted": "#9c3d3d", "Confidential": "#b46a38", "Internal": "#6f7d8f", "Public": "#a3aab4"}
CLS_RANK = {"Restricted": 0, "Confidential": 1, "Internal": 2, "Public": 3}
VERDICT = {"refuted": ("✕", RED), "clean": ("✓", GREEN), "held": ("✓", GREEN), "unconfirmed": ("?", AMBER)}
ZONE_STYLE = {  # zone key -> (title, stroke, fill)
    "internet": ("INTERNET — untrusted", "#a04d4a", "#fbf6f6"),
    "client": ("Client device", "#a0673f", "#fcf8f3"),
    "application": ("Application", "#4f6d9c", "#f3f6fa"),
    "build": ("Build pipeline", "#4b7a94", "#f3f8fa"),
    "data": ("Data", "#7b62a6", "#f7f5fa"),
    "third-party": ("Third-party", "#3f857c", "#f3f9f8"),
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
ACTOR_COLORS = ("#b3453f", "#79439b", "#8c2545", "#b85283", "#552660", "#d05c61", "#9b4890", "#732e38")

# ---- geometry -------------------------------------------------------------------
NODE_W, PROC_H, EXT_W, EXT_H = 190, 110, 172, 52
WEAK_SEV_COL = {0: "#c05656", 1: "#d39a4a"}  # weakness/finding severity: Critical, High
WEAK_COL = "#a08a5a"

ZONE_PAD, ZONE_HEAD, NODE_GAP, ZONE_GAP = 14, 36, 26, 26
COL_W = NODE_W + 2 * ZONE_PAD
GAP, MARGIN, TOP = 150, 20, 66
B_OFF = 100  # boundary line offset inside a gap (from gap left)
LANE0, LANE_STEP = 40, 10  # first lane offset right of the boundary (clear of the chips)
LEGEND_W = 350
FS = 8.5  # small label font
ZONE_CAP = 8  # drawn nodes per zone; the rest collapse into one bar
PORT_STEP = 22  # minimum spacing between ports on one node side
BAR_H = 24
COLUMN = {"client": 0, "application": 1, "build": 1, "data": 2, "third-party": 0}
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

    def text(self, x, y, s, size=11, fill=INK, anchor="middle", weight="normal", italic=False, track=None, halo=False):
        st = ' font-style="italic"' if italic else ""
        hl = ' paint-order="stroke" stroke="#ffffff" stroke-width="3" stroke-linejoin="round"' if halo else ""
        self.add(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}"{st}{hl}>{_esc(s)}</text>'
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


def _person(c, x, y, col):
    c.circle(x, y, 5, fill="none", stroke=col, sw=1.5)
    c.path(f"M {x - 8} {y + 16} A 8 8 0 0 1 {x + 8} {y + 16}", col, sw=1.5)


def _chip_width(tbid, n):
    return 8 + _tw(tbid, 8.5) + 4 + 10 + (6 + _tw(str(n), 8) if n else 0) + 6


# ---- inputs ---------------------------------------------------------------------------
MAX_CAUSE_ANNOTATIONS = 3


def _annotation_vocabulary():
    """Index the central presentation vocabulary without guessing unknown causes.

    Catalog shape and supported-CWE coverage are guarded at build time by
    test_weakness_class_config_consistency. Reject ambiguous assignments here
    rather than letting catalog order silently choose a label.
    """
    catalog = load_weakness_classes()["diagram_annotations"]
    by_cwe, by_mechanism, priority_groups, tie_break_order, families = {}, {}, {}, {}, {}
    qualifiers = {}
    family_variants = set()
    for label, entry in catalog["labels"].items():
        for field, index in (("cwes", by_cwe), ("mechanisms", by_mechanism)):
            for key in entry.get(field, []):
                if key in index:
                    raise ValueError(f"Duplicate Figure 1 annotation for {key}")
                index[key] = label
        priority_groups[label] = entry.get("priority_group", "standard")
        tie_break_order[label] = entry["tie_break_order"]
        families[label] = (entry.get("control_family", label), entry.get("variant_order", 0))
        if families[label] in family_variants:
            raise ValueError("Duplicate Figure 1 control-family variant")
        family_variants.add(families[label])
        qualifiers[label] = entry.get("cwe_qualifiers", {})
        if not qualifiers[label].keys() <= set(entry["cwes"]):
            raise ValueError("Figure 1 qualifier requires a CWE assigned to its label")
    if by_cwe.keys() & catalog["exceptions"].keys():
        raise ValueError("Figure 1 annotation also declared as an exception")
    return by_cwe, by_mechanism, priority_groups, tie_break_order, families, qualifiers


def _component_weaknesses(model):
    """At most three short High/Critical causes; the report retains the full register."""
    by_cwe, by_mechanism, priority_groups, tie_break_order, families, qualifiers = _annotation_vocabulary()
    threats = {t.get("id"): t for t in model.get("threats") or [] if isinstance(t, dict)}
    ranks = {
        tid: SEV_RANK.get(t.get("effective_severity") or t.get("risk") or t.get("severity"), 9)
        for tid, t in threats.items()
    }
    rows, covered = collections.defaultdict(dict), collections.defaultdict(set)

    def add(cid, label, rank, ids, structural):
        if rank > 1:
            return
        # One control family gets one badge. Wording follows its most specific
        # evidenced defect; severity remains the maximum supported family risk.
        for old_label, previous in list(rows[cid].items()):
            if families[old_label][0] != families[label][0]:
                continue
            label = max((label, old_label), key=lambda candidate: families[candidate][1])
            rank, ids, structural = min(rank, previous[0]), ids | previous[1], structural or previous[2]
            del rows[cid][old_label]
        rows[cid][label] = (rank, ids, structural)

    for weakness in model.get("weaknesses") or []:
        label = by_mechanism.get(weakness.get("mechanism_id"))
        rank = SEV_RANK.get(weakness.get("severity"), 9)
        if not label or rank > 1:
            continue
        backing = weakness.get("observable_backing") or {}
        # Confirmed instances establish this mechanism's scope. A supporting
        # practice site alone must not extend it to an unrelated component.
        references = weakness.get("instances") or backing.get("practice_evidence") or []
        linked = {i.get("id") for i in references if isinstance(i, dict)} & threats.keys()
        owners = {cid for tid in linked if ranks[tid] <= 1 for cid in _affected_components(threats[tid])}
        if not linked and backing:
            owners.update(weakness.get("affected_components") or [])
        for cid in owners:
            hits = {tid for tid in linked if ranks[tid] <= 1 and cid in _affected_components(threats[tid])}
            # A general architectural risk does not prove a broken control.
            # Actual linked defects can refine its badge, within the same family.
            variants = [label]
            for tid in hits:
                specific = by_cwe.get(threats[tid].get("cwe"))
                if specific and families[specific][0] == families[label][0]:
                    variants.append(specific)
            evidenced_label = max(variants, key=lambda candidate: families[candidate][1])
            add(cid, evidenced_label, rank, hits, True)
            covered[cid].update(hits)
    for tid, threat in threats.items():
        label = by_cwe.get(threat.get("cwe"))
        if not label or ranks[tid] > 1:
            continue
        for cid in _affected_components(threat):
            if tid not in covered[cid]:
                add(cid, label, ranks[tid], {tid}, False)
    result = {}
    for cid, causes in rows.items():
        ordered = sorted(
            causes.items(),
            key=lambda item: (
                item[1][0],
                priority_groups[item[0]] != "interpreter",
                not item[1][2],
                priority_groups[item[0]] == "fallback",
                -len(item[1][1]),
                tie_break_order[item[0]],
            ),
        )
        result[cid] = []
        for label, (rank, ids, _structural) in ordered[:MAX_CAUSE_ANNOTATIONS]:
            # Qualify after ranking; a mixed or design-only cause stays generic.
            suffixes = {qualifiers[label].get(threats[tid].get("cwe")) for tid in ids}
            if len(suffixes) == 1 and None not in suffixes:
                label = f"{label} ({suffixes.pop()})"
            result[cid].append((label, len(ids), rank))
    return result


def _weak_lines(items, maxw):
    return [
        (line, rank, index == 0)
        for label, _count, rank in items
        for index, line in enumerate(_wrap(label, maxw - 9, 9))
    ]


def _asset_lines(asset):
    return _wrap(f"{asset.get('id')} {asset.get('name')}", NODE_W - 46, 8.5)


def _weak_line(c, x, y, items, maxw):
    for i, (line, rank, first) in enumerate(_weak_lines(items, maxw)):
        yy = y + 12 * i
        if first:
            c.rect(x, yy - 7, 6, 6, fill=WEAK_SEV_COL.get(rank, WEAK_COL), rx=1)
        c.text(x + 9, yy, line, size=9, anchor="start", fill=INK)


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


def _affected_components(threat):
    return list(
        dict.fromkeys(
            c
            for c in [
                threat.get("component"),
                *(threat.get("merged_from") or []),
                *(i.get("component_id") for i in threat.get("instances") or [] if isinstance(i, dict)),
            ]
            if isinstance(c, str) and c
        )
    )


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
                    fid_comp.setdefault(f"{pre}{m.group(1)}", _affected_components(t))
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
    meta = yaml_data.get("meta") or {}

    def actor_name(slug):
        if slug == "internet-anon" and meta.get("open_user_registration") is True:
            return "Internet Attacker"
        return (labels.get(slug) or {}).get("label") or _FALLBACK_ACTOR.get(slug) or slug

    def actor_sub(slug):
        if slug == "internet-anon" and meta.get("open_user_registration") is True:
            return "can self-register a regular account"
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
        actor = overview_actor_slug(actor, meta)
        if actor not in order:
            order.append(actor)
        cids, fids = [], []
        for f in ap.get("findings") or []:
            m = re.match(r"^[FT]-(\d+)$", str(f or "").upper())
            if m:
                fids.append(int(m.group(1)))
            for cid in fid_comp.get(str(f or "").upper(), []):
                if cid not in cids:
                    cids.append(cid)
        sevs = [sev_by_fid[f] for f in fids if sev_by_fid.get(f)]
        risk = min(sevs, key=lambda s: SEV_RANK.get(s, 9)) if sevs else ""
        scenarios.append(
            {
                "n": str(idx + 1),
                "title": cl.get("short_label") or cl.get("label") or slug or "attack",
                "actor": actor_name(actor),
                "actor_slug": actor,
                "victim": victim,
                "cids": cids,
                "fids": fids,
                "risk": risk,
            }
        )
    actors = [{"name": actor_name(s), "slug": s, "sub": actor_sub(s), "attacker": True} for s in order]
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
def _flow_endpoints(flow):
    src, dst = flow.get("from"), flow.get("to")
    return (
        flow.get("from_entity") or USER_ID if src == "external" else src,
        flow.get("to_entity") or f"ext:{src}" if dst == "external" else dst,
    )


def _build_model(d, scenarios, actors):
    comps = [c for c in (d.get("components") or []) if isinstance(c, dict) and c.get("id")]
    cnum = {c["id"]: f"C-{i:02d}" for i, c in enumerate(comps, 1)}
    by_cnum = {v: k for k, v in cnum.items()}
    sev = collections.defaultdict(collections.Counter)
    stride = collections.defaultdict(collections.Counter)
    tb_threats = collections.Counter()
    weak = _component_weaknesses(d)
    for t in d.get("threats") or []:
        for cid in _affected_components(t):
            sev[cid][t.get("effective_severity") or t.get("risk") or t.get("severity")] += 1
            stride[cid][(t.get("stride") or "?")[0].upper()] += 1
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
            "complex": comp.get("complexity") == "complex",
            "badges": [],
            "assets": [],
            "weak": weak.get(cid, []),
            "order": len(nodes),
        }
    for s in scenarios:
        cids = s.get("cids") or [by_cnum.get(cn) for cn in s.get("cnums") or []]
        for cid in cids:
            if cid in nodes:
                nodes[cid]["badges"].append(s["n"])
    # Storage claims require an explicit, evidenced relation; classification alone is insufficient.
    for asset in d.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        linked = {int(m) for t in asset.get("linked_threats") or [] for m in re.findall(r"(\d+)$", str(t))}
        for ref in asset.get("component_refs") or []:
            node = nodes.get(ref.get("component_id"))
            if node and node["kind"] == "store" and ref.get("relation") == "stored" and ref.get("evidence"):
                node["assets"].append(
                    dict(asset, _hits=[s["n"] for s in scenarios if linked & set(s.get("fids") or [])])
                )
    for node in nodes.values():
        node["h"] = max(
            PROC_H,
            108
            + 12 * len(_weak_lines(node["weak"], NODE_W - 32))
            + (24 + sum(11 * len(_asset_lines(a)) + 17 for a in node["assets"]) if node["assets"] else 0),
        )
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
    for i, a in enumerate(actors):
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
            "color": ACTOR_COLORS[i % len(ACTOR_COLORS)],
            "marker": f"attacker-{i}",
            "actor_code": f"A{i + 1}",
            "order": i + 1,
            "attacker": True,
            "badges": [],
        }

    for entity in d.get("external_entities") or []:
        key = entity["id"]
        role = entity.get("kind") == "legitimate-role"
        nodes[key] = {
            "id": key,
            "kind": "ext",
            "name": entity["name"],
            "sub": _cut(entity.get("description") or "", 34),
            "zone": "internet" if role else "third-party",
            "col": 0,
            "w": EXT_W,
            "h": EXT_H,
            "color": GREEN if role else INK,
            "order": len(nodes),
            "badges": [],
        }
    needs_generic_user = victim_of or any(
        f.get("from") == "external" and not f.get("from_entity") for f in d.get("data_flows") or []
    )
    if not needs_generic_user and any(e.get("kind") == "legitimate-role" for e in d.get("external_entities") or []):
        nodes.pop(USER_ID)

    # edges from data flows; `external` is the user's client on the way in, a third-party entity on the way out
    bundles = collections.OrderedDict()
    undrawn = []  # (flow id, reason)
    for f in d.get("data_flows") or []:
        if not isinstance(f, dict):
            continue
        src, dst = f.get("from"), f.get("to")
        fid = f.get("id") or "?"
        if (src, f.get("from_entity")) == (dst, f.get("to_entity")):
            undrawn.append((fid, "self-loop"))
            continue
        if src == "external":
            src = f.get("from_entity") or USER_ID
        if dst == "external":
            key = f.get("to_entity") or f"ext:{f.get('from')}"
            if key not in nodes and f.get("to_entity"):
                undrawn.append((fid, f"unknown external entity {key}"))
                continue
            if key not in nodes:
                nodes[key] = {
                    "id": key,
                    "kind": "ext",
                    "name": "External service",
                    "sub": _cut(f.get("label") or "", 36),
                    "zone": "third-party",
                    "col": 0,
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
    # attack edges: every exposed process a scenario reaches; a victim scenario also points at the user
    attacker_by_name = {n["name"]: n["id"] for n in nodes.values() if n.get("attacker")}
    default_attacker = next(iter(attacker_by_name.values()), None)
    atk = collections.OrderedDict()
    for s in scenarios:
        src = attacker_by_name.get(s.get("actor")) or default_attacker
        if not src:
            continue
        cids = s.get("cids") or [by_cnum.get(cn) for cn in s.get("cnums") or []]
        app = [c for c in cids if c in nodes and nodes[c]["col"] == 1 and nodes[c]["kind"] == "process"]
        hit = [c for c in app if nodes[c].get("exposed")]
        if not hit and not s.get("victim"):  # a victim scenario reaches the user, not an unexposed process
            hit = app[:1]
        for dst in hit:
            atk.setdefault((src, dst), []).append(s["n"])
        if s.get("victim"):
            atk.setdefault((src, USER_ID), []).append(s["n"])
    for (src, dst), ns in atk.items():
        edges.append(
            {
                "src": src,
                "dst": dst,
                "ids": [],
                "cls": None,
                "tb": [],
                "attack": True,
                "scen": ns,
                "victim": dst == USER_ID,
            }
        )
    # trust boundaries: chip on the flow that crosses them, else a tag on the guarded node
    unplaced = []
    for t in tbs:
        src = USER_ID if t.get("from") == "external" else t.get("from")
        dst = t.get("to")
        if dst == "external":
            dst = f"ext:{t.get('from')}"
        matching_ids = {
            f.get("id")
            for f in d.get("data_flows") or []
            if (f.get("from"), f.get("to")) == (t.get("from"), t.get("to"))
        }
        matching_edges = [e for e in edges if matching_ids.intersection(e["ids"])]
        # Canonical boundaries cannot select one role from several named flows.
        hit = matching_edges[0] if len(matching_edges) == 1 else None
        if hit and nodes[hit["src"]]["col"] != nodes[hit["dst"]]["col"]:
            hit["tb"].append(t["id"])
        elif t.get("to") != "external" and dst in nodes and dst != USER_ID:
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
        cap = len(members) if zk in {"internet", "third-party"} else ZONE_CAP
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
    def _nports(items):  # all attack edges of one attacker share a port on either end
        keys = set()
        for role, e in items:
            keys.add(("atk", e["src"]) if e.get("attack") and not e.get("victim") else id(e))
        return len(keys)

    for n in nodes.values():
        k = max(_nports(sides[n["id"]]["L"]), _nports(sides[n["id"]]["R"]))
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
        flows = [e for e in ge if not e.get("attack")]
        for i, e in enumerate(flows):
            lanes[id(e)] = boundaries[g] + LANE0 + i * LANE_STEP
        buses = list(dict.fromkeys(e["src"] for e in ge if e.get("attack")))  # one bus per attacker, right of the flows
        for e in ge:
            if e.get("attack"):
                lanes[id(e)] = boundaries[g] + LANE0 + (len(flows) + buses.index(e["src"])) * LANE_STEP
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
    # attack buses: the trunk leaves the attacker once; every further target is a stub off the bus
    groups = collections.defaultdict(list)
    for e in edges:
        if e.get("attack") and e["kind"] == "forward" and not e["skip"]:
            groups[e["src"]].append(e)
    for src, ge in groups.items():
        s = nodes[src]
        bus, ys = ge[0]["pts"][1][0], s["cy"]
        ge.sort(key=lambda e: e["yd"])
        down = [e for e in ge if e["yd"] >= ys]
        up = [e for e in ge if e["yd"] < ys]
        for e in ge:
            e["pts"] = [(bus, e["yd"]), (nodes[e["dst"]]["x"], e["yd"])]
        if down:
            e = down[-1]
            e["pts"] = [(s["x"] + s["w"], ys), (bus, ys), (bus, e["yd"]), (nodes[e["dst"]]["x"], e["yd"])]
        if up:
            e = up[0]
            head = [(s["x"] + s["w"], ys)] if not down else []
            e["pts"] = head + [(bus, ys), (bus, e["yd"]), (nodes[e["dst"]]["x"], e["yd"])]
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
def _trim(pts, a=1.2, b=1.8):
    """Drawn copy of a polyline: starts just outside the source border, ends where the arrowhead touches the target."""

    def sg(v):
        return (v > 0) - (v < 0)

    p = [tuple(q) for q in pts]
    (x0, y0), (x1, y1) = p[0], p[1]
    p[0] = (x0 + sg(x1 - x0) * a, y0 + sg(y1 - y0) * a)
    (xa, ya), (xb, yb) = p[-2], p[-1]
    p[-1] = (xb - sg(xb - xa) * b, yb - sg(yb - ya) * b)
    return p


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
    actor_notes=(),
):
    actor_colors = {n["name"]: n["color"] for n in nodes.values() if n.get("attacker")}
    scenario_colors = {s["n"]: actor_colors.get(s.get("actor"), RED) for s in scenarios}
    W = col_x[-1] + col_w[-1] + 30 + LEGEND_W + MARGIN
    c = _Canvas()
    c.add("")  # header, filled in once the height is known
    c.add("")
    defs = "<defs>"
    markers = [(n["marker"], n["color"]) for n in nodes.values() if n.get("attacker")]
    for key, col in list(CLS_COL.items()) + [("red", RED), ("grey", LINE)] + markers:
        defs += (
            f'<marker id="arw-{key}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="9" markerHeight="9" '
            f'markerUnits="userSpaceOnUse" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{col}"/></marker>'
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
        sub = {"internet": "actors and their browsers", "third-party": "external integrations"}.get(zk) or (
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
        c.text(
            bx,
            TOP - 9,
            "TRUST BOUNDARY",
            size=8,
            fill=RED,
            weight="bold",
            track="bline",
        )

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

    intra_n = collections.Counter(nodes[e["src"]]["col"] for e in edges if e["kind"] == "intra")

    def _chan(col):  # width of the intra-column channel that sits right of the nodes in `col`
        return 14 * intra_n[col] + 4 if intra_n[col] else 0

    for e in edges:
        if e.get("attack"):
            c.path(
                _orth(_trim(e["pts"])),
                nodes[e["src"]]["color"],
                sw=(1.6 if e.get("victim") else 2.2),
                marker=f"arw-{nodes[e['src']]['marker']}",
                dash=("5 4" if e.get("victim") else None),
            )
            source = nodes[e["src"]]
            if not e.get("victim") and abs(e["pts"][0][0] - source["x"] - source["w"]) < 0.6:
                x0, y0 = e["pts"][0]
                c.text(
                    x0 + 6,
                    y0 - 4,
                    source["actor_code"],
                    size=FS,
                    fill=source["color"],
                    anchor="start",
                    weight="bold",
                    halo=True,
                    track=f"actor {source['actor_code']}",
                )
            continue
        col = CLS_COL.get(e["cls"], LINE)
        mk = f"arw-{e['cls'] if e['cls'] in CLS_COL else 'grey'}"
        c.path(
            _orth(_trim(e["pts"])),
            col,
            sw=(2.2 if e["cls"] == "Restricted" else 1.6),
            marker=mk,
            marker_start=(mk if e.get("bidi") else None),
        )
        ids = "/".join(i.replace("df-", "") for i in e["ids"])
        lbl = "df-" + ids if len(e["ids"]) <= 3 else f"df-{e['ids'][0][3:]} +{len(e['ids']) - 1}"
        x0, y0 = e["pts"][0]
        if e["kind"] == "forward":  # past the intra channel of its column; the halo keeps it legible on the border
            c.text(
                x0 + 6 + _chan(nodes[e["src"]]["col"]),
                y0 - 4,
                lbl,
                size=FS,
                fill=col,
                anchor="start",
                weight="bold",
                track=f"label {lbl}",
                halo=True,
            )
        elif e["kind"] == "backward":
            xe, ye = e["pts"][-1]
            c.text(
                xe + 6 + _chan(nodes[e["dst"]]["col"]),
                ye - 4,
                lbl,
                size=FS,
                fill=col,
                anchor="start",
                weight="bold",
                track=f"label {lbl}",
                halo=True,
            )
        else:  # intra: rotated along the channel segment
            (cx, ya), (_, yb) = e["pts"][1], e["pts"][2]
            ym = (ya + yb) / 2
            c.add(
                f'<text x="{cx + 9:.1f}" y="{ym:.1f}" font-family="{FONT}" font-size="{FS}" fill="{col}" text-anchor="middle" '
                f'font-weight="bold" transform="rotate(-90 {cx + 9:.1f} {ym:.1f})">{_esc(lbl)}</text>'
            )
            w = _tw(lbl, FS)
            c.labels.append((cx + 3, ym - w / 2, cx + 13, ym + w / 2, f"label {lbl}"))
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
            label = (n["actor_code"] + " · " if n.get("actor_code") else "") + n["name"]
            for i, line in enumerate(_wrap(label, w - (tx - x) - 8, 10)[:2]):
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
        _weak_line(c, x + ox, ty + 36, n.get("weak") or [], w - ox - 8)
        if n["exposed"]:
            _globe(c, x + w - 16, y + 15)
        if n["assets"]:
            ay = ty + 50 + 12 * max(0, len(_weak_lines(n["weak"], w - ox - 8)) - 1)
            c.text(x + ox, ay, "Stored assets", size=8.5, anchor="start", fill=MUTED, italic=True)
            yy = ay + 10
            for a in n["assets"]:
                col = CLS_COL.get(str(a.get("classification")).title(), MUTED)
                c.rect(x + ox, yy, 6, 6, fill=col)
                lines = _asset_lines(a)
                for index, line in enumerate(lines):
                    c.text(x + ox + 10, yy + 6 + index * 11, line, size=8.5, anchor="start")
                yy += len(lines) * 11
                hits = a.get("_hits", [])
                badge_x0 = x + w - 30 - (len(hits) - 1) * 15 if hits else x + w - 26
                for j, s in enumerate(hits):
                    _badge(c, badge_x0 + j * 15, yy + 3, s, col=scenario_colors.get(s, RED), r=6.5)
                c.text(x + ox + 10, yy + 6, str(a.get("classification")), size=7.5, anchor="start", fill=col)
                yy += 17
        for i, b in enumerate(n["badges"]):
            _badge(c, x + w - 18 - i * 19, y + h - 1, b, col=scenario_colors.get(b, RED))
            c.badges.append((x + w - 26 - i * 19, y + h - 9, x + w - 10 - i * 19, y + h + 7, f"badge {b} on {n['id']}"))

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
    c.text(lx + 40, y + 3, "data store (evidenced asset locations)", size=9, anchor="start")
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
    c.text(
        lx + 40,
        y + 3,
        "A1… = attacker; colour follows actor · dashed = victim",
        size=9,
        anchor="start",
    )
    y += 20
    _globe(c, lx + 21, y - 2)
    c.text(lx + 40, y + 3, "⊕ internet-exposed entry point", size=9, anchor="start")
    y += 20
    _stride_strip(c, lx + 10, y - 9, {"S": 1, "T": 1, "I": 1})
    c.text(lx + 10, y + 20, "STRIDE-per-element: filled = threats found in that class", size=8.5, anchor="start")
    y += 30
    _weak_line(c, lx + 10, y + 1, [("Unsafe Query Construction (SQLi)", 3, 0)], 200)
    c.text(
        lx + 10,
        y + 28,
        "Up to 3 key causes · High/Critical only",
        size=8.5,
        anchor="start",
        fill=MUTED,
    )
    y += 38
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
        "asset badges require linked findings and evidenced storage",
        size=8.5,
        anchor="start",
        fill=MUTED,
    )
    y += 32

    if actor_notes:
        y = head(y, "Actor grouping")
        for note in actor_notes:
            for line in _wrap(note, lw - 20, 9):
                c.text(lx + 10, y + 3, line, size=9, anchor="start", track="actor grouping")
                y += 13
            y += 5
        y += 8

    if scenarios:
        y = head(y, "Attack scenarios — by actor")
        cur = None
        for s in scenarios:
            who = (s.get("actor") or "Attacker") + (" → User (victim)" if s.get("victim") else "")
            if who != cur:
                cur = who
                c.text(
                    lx + 10,
                    y + 3,
                    _cut(who, 52),
                    size=9,
                    anchor="start",
                    weight="bold",
                    fill=actor_colors.get(s.get("actor"), RED),
                )
                y += 16
            _badge(c, lx + 20, y - 2, s["n"], col=actor_colors.get(s.get("actor"), RED))
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
    if any(e["ids"] for e in edges):
        y = head(y, "Data flows")
        for e in edges:
            for fid in e["ids"]:
                f = flows.get(fid, {})
                col = CLS_COL.get(str(f.get("data_classification")).title(), LINE)
                c.text(lx + 10, y + 3, fid, size=8.5, anchor="start", weight="bold", fill=col)
                src, dst = _flow_endpoints(f)
                detail = f"{nodes.get(src, {}).get('name', src)} → {nodes.get(dst, {}).get('name', dst)} · {f.get('protocol') or ''} · {f.get('label') or ''}"
                lines = _wrap(detail, lw - 62, 8)
                for index, line in enumerate(lines):
                    c.text(lx + 52, y + 3 + index * 11, line, size=8, anchor="start")
                y += max(14, 11 * len(lines) + 5)
    if unattached_assets:
        y += 12
        y = head(y, "Assets — location and handling")
        for a in unattached_assets:
            col = CLS_COL.get(str(a.get("classification")).title(), MUTED)
            c.rect(lx + 10, y - 6, 6, 6, fill=col)
            c.text(lx + 22, y + 1, _cut(f"{a.get('id')} {a.get('name')}", 44), size=8.5, anchor="start")
            c.text(lx + lw - 6, y + 1, str(a.get("classification")), size=7.5, anchor="end", fill=col, weight="bold")
            relations = []
            for ref in a.get("component_refs") or []:
                if not ref.get("evidence"):
                    continue
                owner = nodes.get(ref.get("component_id"), {}).get("name") or ref.get("component_id")
                verb = {"stored": "stored in", "processed": "processed by", "transmitted": "transmitted by"}.get(
                    ref.get("relation")
                )
                if owner and verb:
                    relations.append(f"{verb} {owner}")
            for detail in _wrap("; ".join(relations) or "location not established", lw - 32, 8):
                y += 11
                c.text(lx + 22, y + 1, detail, size=8, anchor="start", fill=MUTED)
            y += 18
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
        for s in notes:
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
        return _flow_endpoints(rec)

    for e in edges:
        s, t = nodes[e["src"]], nodes[e["dst"]]
        name = "/".join(e["ids"]) or f"attack {s['name']}"
        p1 = e["pts"][-1]
        if e.get("attack") and not on_edge(e["pts"][0], s):
            bus_ok = any(
                o is not e and o.get("attack") and o["src"] == e["src"] and o["pts"][1][0] == e["pts"][0][0]
                for o in edges
            )
            if not bus_ok:
                problems.append(f"{name}: stub does not start on its attacker's bus")
        elif not on_edge(e["pts"][0], s):
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
            if tb and not any(
                (flows[fid].get("from"), flows[fid].get("to")) == (tb.get("from"), tb.get("to")) for fid in e["ids"]
            ):
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
def _build(yaml_data, scenarios, actors, actor_notes=()):
    d = dict(yaml_data)  # the builder annotates a shallow copy, never the caller's model
    nodes, edges, tbs, tb_threats = _build_model(d, scenarios, actors)
    nodes, edges, dropped = _select_drawn(nodes, edges, d)
    col_x, col_w, zone_boxes, boundaries, chips, height = _layout(nodes, edges, dropped, tb_threats)
    attached = {a.get("id") for n in nodes.values() for a in n.get("assets", [])}
    unattached = sorted(
        [a for a in d.get("assets") or [] if isinstance(a, dict) and a.get("id") not in attached],
        key=lambda a: (CLS_RANK.get(str(a.get("classification")).title(), 9), str(a.get("id"))),
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
        actor_notes,
    )
    return svg, {"d": d, "nodes": nodes, "edges": edges, "chips": chips, "boundaries": boundaries, "canvas": canvas}


def build_figure1_dfd_svg(yaml_data, attack_paths_data, attack_taxonomy, meta=None, actor_labels=None):
    """Figure 1 for a threat model. Returns "" when there is nothing to draw."""
    if not (yaml_data.get("components") or []):
        return ""
    scenarios, actors = scenarios_from_attack_paths(
        yaml_data, attack_paths_data or {}, attack_taxonomy or {}, actor_labels
    )
    svg, _state = _build(
        yaml_data, scenarios, actors, overview_actor_notes(yaml_data, attack_paths_data, attack_taxonomy)
    )
    return svg


def check_diagram(yaml_data, attack_paths_data, attack_taxonomy, actor_labels=None, scenarios=None, actors=None):
    """Render and verify; returns (svg, problems). Used by the tests and the CLI."""
    if scenarios is None:
        scenarios, actors = scenarios_from_attack_paths(
            yaml_data, attack_paths_data or {}, attack_taxonomy or {}, actor_labels
        )
    svg, st = _build(
        yaml_data, scenarios, actors or [], overview_actor_notes(yaml_data, attack_paths_data, attack_taxonomy)
    )
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
