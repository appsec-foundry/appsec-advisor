#!/usr/bin/env python3
"""Deterministic Figure 1 renderer: a threat-model data-flow diagram.

Draws external entities, processes, data stores, labelled data flows, trust
zones and evidenced authentication tabs, evidenced capability and service-role
labels, a STRIDE-per-element strip, severity counts and evidenced weaknesses or
causes on every node, and the numbered attack scenarios of the Security Posture
section as badges on the components they touch. Each attacker enters over a
labelled bus that fans out into every exposed process its scenarios reach; a
victim scenario adds a dashed edge back to the user.

Trust-boundary lines mark a column gap only when a resolved boundary that is not
an internal interface connects endpoints on both sides of it. Finding tallies
(header total, node severity counts, STRIDE strip) follow ``_severity_rollup``
(decision RA-7); per-cause colours keep the per-finding severity the report's
finding dots use.

The layout is computed, never hand-placed: three columns (untrusted, application,
data), zones stacked per column, nodes ordered by the barycenter of their
incoming flows, orthogonal edges with one lane per edge, ports spread along the
node sides. Measured legend blocks fill up to three columns below the diagram.
The same input yields byte-identical SVG.

Public entry point: ``build_figure1_dfd_svg(yaml_data, attack_paths_data,
attack_taxonomy, meta=None, actor_labels=None, detail=True) -> str``. The report
requests the compact overview with ``detail=False``; the compatibility API
default retains boundary verdicts and the complete flow legend. Returns ""
when there is nothing to draw.

``check_diagram`` (used by the tests and the ``--check`` CLI flag) verifies the
result geometrically and semantically: no edge crosses a foreign node, no label
overlaps another, every arrow starts on its source and ends on its target with
the head pointing inward, every chip sits on the crossing of its own flow, and
every flow and boundary is either drawn or explained in the legend.

Dev CLI: ``figure1_dfd.py <threat-model.yaml> [<threat-model.md>] <out.svg> [--check] [--detail]``
— the markdown is only a stand-in for ``attack_paths_data`` when replaying a
published example.
"""

from __future__ import annotations

import collections
import copy
import html
import re
import sys
import xml.etree.ElementTree as ET
from functools import cache
from itertools import product
from pathlib import Path

import yaml
from _severity_rollup import register_severity, register_threats, risk_distribution_counts
from detect_open_registration import overview_actor_groups, overview_actor_slug
from figure1_security import (
    authentication_profile,
    bundle_access_groups,
    flow_bundle_key,
    profile_catalog,
    select_references,
)
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
    "client": ("Client Layer", "#a0673f", "#fcf8f3"),
    "application": ("Application Layer", "#4f6d9c", "#f3f6fa"),
    "build": ("Build pipeline", "#4b7a94", "#f3f8fa"),
    "data": ("Data Layer", "#7b62a6", "#f7f5fa"),
    "third-party": ("Third-party", "#3f857c", "#f3f9f8"),
    "attackers": ("Attackers", "#a04d4a", "#fbf6f6"),
    "users": ("Users", "#6d927c", "#f5f8f6"),
}
ZONE_SUBTITLE = {
    "internet": "actors and their browsers",
    "third-party": "external integrations",
    "build": "CI/CD and release tooling",
}
SEV_COL = {"Critical": RED, "High": ORANGE, "Medium": YELLOW}
SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_PILL_FINDING_BORDER = {SEV_RANK[sev]: col for sev, col in SEV_COL.items()}
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
INTERACTION_LABEL = "User input"
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
LEGEND_GAP = 20
LEGEND_HEAD = 26
LEGEND_INSET = 14
LEGEND_CONTENT_GAP = 10
ASSET_INLINE_HEIGHT = 300
ASSET_SYMBOL_ROW = 22
ATTACK_WIDTH = 1.8
FS = 8.5  # small label font
ZONE_CAP = 8  # drawn nodes per zone; the rest collapse into one bar
OVERVIEW_FLOW_CAP = 24  # Keep dense graphs navigable through the linked detail views.
PORT_STEP = 22  # minimum spacing between ports on one node side
INTRA_STUB, INTRA_STEP = 48, 14  # reserve authentication tabs and a straight arrow approach
BAR_H = 24
CAPABILITY_CAP = 3  # Selected labels only; the legend says that absence is not implied.
PILL_H, PILL_ROW, PILL_GAP, PILL_SIZE = 13, 17, 5, 7.5
TECH_H, TECH_CHARS = 16, 28  # technology line under a component title, before the labels
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


def _figure_boundaries(d):
    """Only resolved catalogue rows with canonical endpoints may affect the figure."""
    component_ids = {c["id"] for c in d.get("components") or [] if isinstance(c, dict) and c.get("id")}
    return [
        row
        for row in d.get("trust_boundaries") or []
        if isinstance(row, dict) and row.get("id") and boundary_endpoints_valid(row, component_ids)
    ]


def _internal_interface(row):
    """An in-process call without a trust change is not a trust boundary.

    Legacy rows may carry only kind; explicit surface/transition axes take
    precedence, as in the report's boundary catalogue.
    """
    if row.get("surface") in {"network", "in-process", "build-pipeline"} and isinstance(row.get("transition"), list):
        return row["surface"] == "in-process" and not row["transition"]
    return row.get("kind") == "process"


def _boundary_count_label(tbs, *, interfaces=True):
    boundaries = [t for t in tbs if not _internal_interface(t)]
    inferred = sum(t.get("confidence") != "confirmed" for t in boundaries)
    label = f"{len(boundaries)} trust {'boundary' if len(boundaries) == 1 else 'boundaries'}"
    if inferred:
        label += f" ({inferred} inferred)"
    count = len(tbs) - len(boundaries)
    if count and interfaces:
        label += f" · {count} internal {'interface' if count == 1 else 'interfaces'}"
    return label


def _boundary_gaps(d, nodes, tbs):
    """Column gaps crossed by a resolved trust boundary, with its boundary IDs.

    Internal interfaces never mark a gap. An ``external`` endpoint takes the
    column of the drawn participant on a flow with the same canonical endpoints;
    ingress without such a flow comes from the untrusted column, while egress
    without one cannot be placed and stays in the catalogue only.
    """
    columns = {
        row["id"]: COLUMN[_zone_key(row)]
        for row in d.get("components") or []
        if isinstance(row, dict) and row.get("id")
    }
    flows = [f for f in d.get("data_flows") or [] if isinstance(f, dict)]

    def drawn_columns(source, target, index):
        return {
            nodes[_flow_endpoints(f)[index]]["col"]
            for f in flows
            if (f.get("from"), f.get("to")) == (source, target) and _flow_endpoints(f)[index] in nodes
        }

    gaps = collections.defaultdict(list)
    for t in tbs:
        source, target = t.get("from"), t.get("to")
        if _internal_interface(t) or source == target == "external":
            continue
        if source == "external":
            starts = drawn_columns(source, target, 0) or {0}
        else:
            starts = {columns.get(source)}
        ends = drawn_columns(source, target, 1) if target == "external" else {columns.get(target)}
        for start, end in product(starts, ends):
            if start is None or end is None:
                continue
            for gap in range(min(start, end), max(start, end)):
                if t["id"] not in gaps[gap]:
                    gaps[gap].append(t["id"])
    return {gap: sorted(ids, key=_tb_num) for gap, ids in sorted(gaps.items())}


@cache
def _capability_vocabulary():
    """Display labels for evidenced component capabilities and service roles."""
    data = yaml.safe_load((Path(__file__).resolve().parents[1] / "data/security-capabilities.yaml").read_text())
    return data["component_capabilities"], data["service_roles"]


def _words(text):
    return set(re.findall(r"[a-z0-9]+", str(text).lower()))


def _capability_rows(items, vocabulary, key, name="", severity=None, label_key="label"):
    """Known, evidenced labels, most critical first; unknown values never render.

    Order is the vocabulary `tier` (criticality of the function type), then the
    most severe linked finding (`severity`: value → SEV_RANK), then vocabulary
    order. Each row carries its `tier` and linked `severity`. A label is left
    out when a more specific evidenced value implies it, or when the node's own
    name already says everything the label would. The first item per value
    wins. `label_key` selects an alternative wording, such as the
    identity-provider term, where the vocabulary defines one.
    """
    evidenced = [
        item for item in items or [] if isinstance(item, dict) and item.get("evidence") and item.get(key) in vocabulary
    ]
    implied = {value for item in evidenced for value in vocabulary[item[key]].get("implies") or []}
    severity = severity or {}
    rank = {
        value: (entry.get("tier", 9), severity.get(value, len(SEV_RANK)), index)
        for index, (value, entry) in enumerate(vocabulary.items())
    }
    rows = []
    for item in evidenced:
        entry = vocabulary[item[key]]
        label = entry.get(label_key) or entry["label"]
        if item[key] in implied or _words(label) <= _words(name):
            continue
        if all(row["id"] != item[key] for row in rows):
            rows.append(
                {
                    "id": item[key],
                    "label": label,
                    "evidence": item["evidence"],
                    "derived": bool(item.get("derived")),
                    "tier": entry.get("tier", 9),
                    "severity": severity.get(item[key]),
                }
            )
    return sorted(rows, key=lambda row: rank[row["id"]])


def _technology(comp):
    """Framework (a store's engine) and implementation language, each left out when the name or framework says it."""
    name = _words(comp.get("name") or comp.get("id"))
    framework = " ".join(str(comp.get("framework") or "").split())
    language = " ".join(str(comp.get("language") or "").split())
    shown = {
        "framework": "" if _words(framework) <= name else framework,
        "language": "" if _words(language) <= name | _words(framework) else language,
    }
    return {key: value for key, value in shown.items() if value}


def _technology_label(tech):
    """One bracketed line; a long framework is shortened before the language is."""
    framework, language = tech.get("framework", ""), _cut(tech.get("language", ""), TECH_CHARS)
    framework = _cut(framework, max(8, TECH_CHARS - len(language) - 3) if language else TECH_CHARS)
    return "[" + " · ".join(part for part in (framework, language) if part) + "]"


def _capability_display(rows):
    """Every tier-1 label, filled up to CAPABILITY_CAP, then one `+N` label carrying the rest."""
    shown = max(CAPABILITY_CAP, sum(1 for row in rows if row.get("tier") == 1))
    if len(rows) <= shown:
        return rows
    more = rows[shown:]
    return [*rows[:shown], {"id": "+", "label": f"+{len(more)}", "evidence": [], "more": more}]


# Only deterministic source rules may add a label from a finding: a model-assigned
# CWE can name the wrong class (a prompt-injection finding once carried CWE-1336).
# Ranking may use any reported finding: a wrong CWE can reorder labels, never add one.
_CAPABILITY_FINDING_SOURCES = frozenset({"source-scan"})


def _finding_sites(threat, component_ids=None, sources=None):
    """(component, location) pairs of a finding, limited to `sources` provenance when given.

    An instance carries the provenance of the finding it was merged from and
    otherwise inherits the finding's own. An instance outside `component_ids`
    belongs to the finding's component: current runs resolve every owner (FE-12),
    but a rerender composes an existing model without that pass.
    """
    own = threat.get("source")
    sites = []
    if sources is None or own in sources:
        sites = [(threat.get("component"), row) for row in threat.get("evidence") or []]
    for row in threat.get("instances") or []:
        if not isinstance(row, dict) or (sources is not None and (row.get("source") or own) not in sources):
            continue
        component = row.get("component_id")
        if component_ids is not None and component not in component_ids:
            component = threat.get("component")
        sites.append((component, row))
    return sites


def _capability_severity(threats, vocabulary, component_ids=None):
    """Component id → {value: SEV_RANK of its most severe reported finding with a CWE the value links}.

    A value links its own `cwes` and those of the values it implies.
    """
    by_cwe = collections.defaultdict(set)
    for value, entry in vocabulary.items():
        for linked in [value, *(entry.get("implies") or [])]:
            for cwe in vocabulary[linked].get("cwes") or []:
                by_cwe[cwe].add(value)
    worst = collections.defaultdict(dict)
    for threat in threats:
        values = by_cwe.get(str(threat.get("cwe") or "").strip().upper())
        rank = SEV_RANK.get(register_severity(threat))
        if not values or rank is None:
            continue
        components = {threat.get("component")} | {component for component, _ in _finding_sites(threat, component_ids)}
        for component in components:
            if isinstance(component, str):
                for value in values:
                    worst[component][value] = min(rank, worst[component].get(value, rank))
    return dict(worst)


def _finding_capabilities(threats, vocabulary, component_ids=None):
    """Component id → capability items proven by deterministic-rule findings whose CWE the vocabulary lists."""
    by_cwe = {cwe: value for value, entry in vocabulary.items() for cwe in entry.get("cwes") or []}
    derived = collections.defaultdict(dict)
    for threat in threats:
        value = by_cwe.get(str(threat.get("cwe") or "").strip().upper())
        if not value:
            continue
        for component, row in _finding_sites(threat, component_ids, _CAPABILITY_FINDING_SOURCES):
            if not isinstance(component, str) or not isinstance(row, dict):
                continue
            if not isinstance(row.get("file"), str) or not isinstance(row.get("line"), int):
                continue
            item = derived[component].setdefault(value, {"capability": value, "evidence": [], "derived": True})
            location = {"file": row["file"], "line": row["line"]}
            if location not in item["evidence"]:
                item["evidence"].append(location)
    return {component: list(items.values()) for component, items in derived.items()}


def _pill_rows(capabilities, width):
    rows, used = [], width
    for cap in capabilities:
        w = _tw(cap["label"], PILL_SIZE) + 12
        if not rows or used + PILL_GAP + w > width:
            rows.append([])
            used = -PILL_GAP
        rows[-1].append((cap, w))
        used += PILL_GAP + w
    return rows


def _pill_height(capabilities, width):
    rows = _pill_rows(capabilities, width)
    return len(rows) * PILL_ROW + 2 if rows else 0


def _capability_title(cap):
    sources = ", ".join(f"{ev.get('file')}:{ev.get('line')}" for ev in cap["evidence"] if isinstance(ev, dict))
    return f"{cap['label']} — evidence: {sources}" + (" (reported finding)" if cap.get("derived") else "")


def _capability_pills(c, x, y, node, width):
    """Draw labels; a linked finding colours only the border, evidence stays available on hover."""
    for r, row in enumerate(_pill_rows(node.get("capabilities") or [], width)):
        px = x
        for cap, w in row:
            py = y + r * PILL_ROW
            track = f"capability {node['id']} {cap['id']}"
            c.label_owners[track] = node["id"]
            if cap.get("more"):
                c.add(f'<g data-capability-more="{len(cap["more"])}" data-capability-owner="{_esc(node["id"])}">')
                c.add(
                    f"<title>{_esc('Further capabilities: ' + '; '.join(map(_capability_title, cap['more'])))}</title>"
                )
                c.rect(px, py, w, PILL_H, fill="#ffffff", stroke="#b6c6d8", sw=0.7, rx=3, dash="2 2")
                c.text(px + w / 2, py + 9.5, cap["label"], size=PILL_SIZE, fill=MUTED, track=track)
            else:
                linked = _PILL_FINDING_BORDER.get(cap.get("severity"))
                c.add(f'<g data-capability="{_esc(cap["id"])}" data-capability-owner="{_esc(node["id"])}">')
                c.add(f"<title>{_esc(_capability_title(cap))}</title>")
                c.rect(px, py, w, PILL_H, fill="#eef3f8", stroke=linked or "#b6c6d8", sw=1.2 if linked else 0.7, rx=3)
                c.text(px + w / 2, py + 9.5, cap["label"], size=PILL_SIZE, fill=NAVY, track=track)
            c.add("</g>")
            px += w + PILL_GAP
    return _pill_height(node.get("capabilities") or [], width)


def _legend_wrap(text, width, size):
    """Wrap complete legend text, including long identifiers, within its column."""
    limit = max(1, int(width / (size * 0.54)))
    lines = []
    for line in _wrap(text, width, size):
        while len(line) > limit:
            lines.append(line[:limit])
            line = line[limit:]
        if line:
            lines.append(line)
    return lines


def flow_payload(flow):
    """(payload, protocol) shown for a flow; a human interaction states use, never an authored payload."""
    if flow.get("interaction"):
        return INTERACTION_LABEL, ""
    return flow.get("label") or "", flow.get("protocol") or ""


def flow_hover_text(flow):
    """One flow's hover line; an interaction adds its evidence instead of a payload description."""
    payload, protocol = flow_payload(flow)
    if flow.get("interaction"):
        sources = ", ".join(f"{ev.get('file')}:{ev.get('line')}" for ev in flow.get("evidence") or [])
        return f"{flow['id']}: {payload}" + (f"; evidence: {sources}" if sources else "")
    return f"{flow['id']}: {payload} {_protocol_part(protocol)}"


def _flow_ids_label(ids):
    return ids[0] + "".join("/" + fid.removeprefix("df-") for fid in ids[1:])


def _flow_legend_detail(entries, nodes, edge):
    """Keep endpoints compact and protocol/payload associations intact per edge."""

    def endpoint(key):
        node = nodes.get(key, {})
        name = node.get("name", key)
        return name.split(" · ", 1)[0] if node.get("kind") != "ext" else name

    by_protocol = collections.OrderedDict()
    for flow in entries:
        protocol = "" if edge.get("interaction") else flow.get("protocol") or ""
        label = INTERACTION_LABEL if edge.get("interaction") else flow.get("diagram_label") or flow.get("label") or ""
        labels = by_protocol.setdefault(protocol, [])
        if label and label not in labels:
            labels.append(label)
    payloads = [" · ".join(p for p in (protocol, " / ".join(labels)) if p) for protocol, labels in by_protocol.items()]
    direction = "↔" if edge.get("bidi") else "→"
    route = f"{endpoint(edge['src'])} {direction} {endpoint(edge['dst'])}"
    return " · ".join(part for part in (route, "; ".join(payloads)) if part)


def _tb_num(tbid):
    m = re.search(r"(\d+)$", str(tbid))
    return int(m.group(1)) if m else 0


class _Canvas:
    def __init__(self):
        self.o = []
        self.labels = []  # bboxes for the overlap check: (x0, y0, x1, y1, name)
        self.badges = []
        self.legend_boxes = []
        self.legend_content = None
        self.legend_clearances = []
        self.label_owners = {}  # Tracked in-node labels must remain inside their owner.
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
        if self.legend_content is not None:
            self.legend_content.append((x, y, x + w, y + h))

    def text(self, x, y, s, size=11, fill=INK, anchor="middle", weight="normal", italic=False, track=None, halo=False):
        st = ' font-style="italic"' if italic else ""
        hl = ' paint-order="stroke" stroke="#ffffff" stroke-width="3" stroke-linejoin="round"' if halo else ""
        self.add(
            f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}"{st}{hl}>{_esc(s)}</text>'
        )
        self.maxy = max(self.maxy, y + 3)
        if track or self.legend_content is not None:
            w = _tw(s, size)
            x0 = {"start": x, "middle": x - w / 2, "end": x - w}[anchor]
            bounds = (x0, y - size, x0 + w, y + 2)
            if self.legend_content is not None:
                self.legend_content.append(bounds)
            if track:
                self.labels.append((*bounds, track))

    def path(self, d, stroke, sw=1.5, dash=None, marker=None, marker_start=None):
        ds = f' stroke-dasharray="{dash}"' if dash else ""
        mk = f' marker-end="url(#{marker})"' if marker else ""
        mk += f' marker-start="url(#{marker_start})"' if marker_start else ""
        self.add(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{sw}" stroke-linejoin="round"{ds}{mk}/>')

    def circle(self, cx, cy, r, fill="none", stroke="none", sw=1):
        self.add(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')
        if self.legend_content is not None:
            self.legend_content.append((cx - r, cy - r, cx + r, cy + r))
            self.maxy = max(self.maxy, cy + r)


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
CAUSE_ANNOTATION_TARGET = 5


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
    return _component_weakness_summary(model)[0]


def _component_weakness_summary(model):
    """Keep all Critical causes; fill to five with High causes from the full register."""
    by_cwe, by_mechanism, priority_groups, tie_break_order, families, qualifiers = _annotation_vocabulary()
    threats = {t.get("id"): t for t in model.get("threats") or [] if isinstance(t, dict)}
    ranks = {tid: SEV_RANK.get(register_severity(t), 9) for tid, t in threats.items()}
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
    result, omitted_high = {}, {}
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
        for index, (label, (rank, ids, _structural)) in enumerate(ordered):
            if index >= CAUSE_ANNOTATION_TARGET and rank != 0:
                break
            # Qualify after ranking; a mixed or design-only cause stays generic.
            suffixes = {qualifiers[label].get(threats[tid].get("cwe")) for tid in ids}
            if len(suffixes) == 1 and None not in suffixes:
                label = f"{label} ({suffixes.pop()})"
            result[cid].append((label, len(ids), rank))
        omitted_high[cid] = len(ordered) - len(result[cid])
    return result, omitted_high


def _weak_lines(items, maxw):
    return [
        (line, rank, index == 0)
        for label, _count, rank in items
        for index, line in enumerate(_wrap(label, maxw - 9, 9))
    ]


def _asset_lines(asset):
    relation = asset.get("_relation", "stored").title()
    return _legend_wrap(f"{relation}: {asset.get('id')} {asset.get('name')}", NODE_W - 46, 8.5)


def _asset_inline_height(assets):
    return sum(11 * len(_asset_lines(a)) + 17 + (18 if a.get("_hits") else 0) for a in assets)


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
    """Owners of a finding; an unregistered owner (older models, FE-12) matches no node and adds nothing."""
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
    Top Threats table: one number per path, with attributed access groups."""
    from actor_presentation import projected_paths, represented_role_counts

    threats = yaml_data.get("threats") or []
    fid_comp = _finding_component_map(threats)
    sev_by_fid = {}
    for t in threats:
        m = re.match(r"^[FT]-(\d+)$", str(t.get("id") or "").upper())
        if m:
            sev_by_fid[int(m.group(1))] = register_severity(t)
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
    for number, ap in projected_paths(yaml_data, attack_paths_data, attack_taxonomy):
        if not isinstance(ap, dict):
            continue
        slug = (ap.get("class") or "").strip()
        cl = cls_by_id.get(slug) or {}
        raw_actor = (ap.get("actor") or cl.get("default_actor") or "internet-anon").strip()
        tgt = str(ap.get("_llm_target") or ap.get("target") or cl.get("default_target_tier") or "application").lower()
        victim = bool(ap.get("_victim_required")) or raw_actor == "victim-required" or tgt in ("client", "victim")
        actor = "internet-anon" if raw_actor in ("victim-required", "") else raw_actor
        actor = overview_actor_slug(actor, meta)
        if actor not in order:
            order.append(actor)
        cids, fids, targets = [], [], []
        for f in ap.get("findings") or []:
            m = re.match(r"^[FT]-(\d+)$", str(f or "").upper())
            if m:
                fids.append(int(m.group(1)))
            affected = fid_comp.get(str(f or "").upper(), [])
            if affected and affected not in targets:
                targets.append(affected)
            for cid in affected:
                if cid not in cids:
                    cids.append(cid)
        sevs = [sev_by_fid[f] for f in fids if sev_by_fid.get(f)]
        risk = min(sevs, key=lambda s: SEV_RANK.get(s, 9)) if sevs else ""
        scenarios.append(
            {
                "n": str(number),
                "title": ap.get("scenario_title")
                or cl.get("diagram_label")
                or cl.get("label")
                or cl.get("short_label")
                or slug
                or "attack",
                "actor": actor_name(actor),
                "actor_slug": actor,
                "victim": victim,
                "cids": cids,
                "fids": fids,
                "targets": targets,
                "risk": risk,
            }
        )
    # Equivalent overview origins share one numbered scenario, retaining the
    # union of explicitly attributed findings rather than duplicate edges.
    combined = {}
    for scenario in scenarios:
        key = (scenario["n"], scenario["actor_slug"], scenario["victim"])
        if key not in combined:
            combined[key] = scenario
            continue
        existing = combined[key]
        for field in ("cids", "fids"):
            existing[field] = list(dict.fromkeys(existing[field] + scenario[field]))
        existing["targets"] += [row for row in scenario["targets"] if row not in existing["targets"]]
        existing["risk"] = min((existing["risk"], scenario["risk"]), key=lambda risk: SEV_RANK.get(risk, 9))
    scenarios = list(combined.values())
    actors = [{"name": actor_name(s), "slug": s, "sub": actor_sub(s), "attacker": True} for s in order]
    counts = represented_role_counts(yaml_data, attack_paths_data, attack_taxonomy)
    for actor in actors:
        if count := counts.get(actor["slug"]):
            actor["sub"] = f"{count} role" + ("s" if count != 1 else "") + "; access details in Identified Actors"
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


@cache
def _role_labels():
    """Load legitimate-role labels from the same vocabulary as attacker labels."""
    return yaml.safe_load((Path(__file__).resolve().parents[1] / "data/posture-actor-labels.yaml").read_text())[
        "actors"
    ]


def _project_name(d):
    meta = d.get("meta") or {}
    project = d.get("project") if isinstance(d.get("project"), dict) else {}
    legacy = (
        meta.get("project")
        if isinstance(meta.get("project"), str)
        else (meta.get("project") or {}).get("name")
        if isinstance(meta.get("project"), dict)
        else None
    )
    return project.get("name") or d.get("project_name") or meta.get("project_name") or legacy


def _role_name(d, access):
    """`<project> <noun>` for a classified legitimate role; the noun alone without a project name."""
    entry = _role_labels().get(access) or {}
    noun = entry.get("legitimate_role_noun")
    if access == "internet-anon" and (d.get("meta") or {}).get("open_user_registration") is True:
        noun = entry.get("open_registration_role_noun") or noun
    return " ".join(part for part in (str(_project_name(d) or "").strip(), noun) if part) if noun else None


def _project_legitimate_roles(yaml_data):
    """Name classified roles after the project and their access, then fold equal regular access.

    A name that two unmerged roles would share keeps the authored names apart.
    """
    d, victim, notes = _fold_legitimate_roles(yaml_data)
    roles = [e for e in d.get("external_entities") or [] if e.get("kind") == "legitimate-role"]
    names = {e["id"]: _role_name(d, e.get("access")) for e in roles}
    counts = collections.Counter(names.values())
    for entity in roles:
        if names[entity["id"]] and counts[names[entity["id"]]] == 1:
            entity["name"] = names[entity["id"]]
    return d, victim, notes


def _fold_legitimate_roles(yaml_data):
    """Fold only explicit regular access, retaining canonical identities in the input.

    One merged or single classified regular role may also represent the
    generic victim. A second regular or unclassified role makes that assignment
    ambiguous. Privileged roles never merge and never become this default
    victim target.
    """
    d = copy.deepcopy(yaml_data)
    meta = d.get("meta") or {}
    groups = collections.defaultdict(list)
    for entity in d.get("external_entities") or []:
        if entity.get("kind") == "legitimate-role" and entity.get("access") in ("internet-anon", "internet-user"):
            groups[overview_actor_slug(entity["access"], meta)].append(entity)
    groups = {slug: rows for slug, rows in groups.items() if len(rows) > 1}
    if not groups:
        regular = [
            row
            for row in d.get("external_entities") or []
            if row.get("kind") == "legitimate-role" and row.get("access") != "internet-priv-user"
        ]
        if len(regular) == 1 and regular[0].get("access") in ("internet-anon", "internet-user"):
            return d, regular[0]["id"], []
        return d, USER_ID, []
    aliases, merged = {}, {}
    labels = _role_labels()
    for slug, rows in groups.items():
        key = min(row["id"] for row in rows)
        label = labels[slug]
        prefix = (
            "open_registration_role"
            if slug == "internet-anon" and meta.get("open_user_registration") is True
            else "legitimate_role"
        )
        merged[key] = {
            **next(row for row in rows if row["id"] == key),
            "name": label[prefix + "_label"],
            "description": label[prefix + "_subtitle"],
            "access": slug,
        }
        aliases.update({row["id"]: key for row in rows})
    entities = []
    seen = set()
    for entity in d["external_entities"]:
        key = aliases.get(entity["id"], entity["id"])
        if key not in seen:
            entities.append(merged.get(key, entity))
            seen.add(key)
    d["external_entities"] = entities
    for flow in d.get("data_flows") or []:
        for endpoint in ("from_entity", "to_entity"):
            if flow.get(endpoint) in aliases:
                flow[endpoint] = aliases[flow[endpoint]]
    regular = [
        row for row in entities if row.get("kind") == "legitimate-role" and row.get("access") != "internet-priv-user"
    ]
    victim = regular[0]["id"] if len(regular) == 1 and regular[0]["id"] in merged else USER_ID
    mixed = any({row["access"] for row in rows} == {"internet-anon", "internet-user"} for rows in groups.values())
    notes = [
        "Anonymous and authenticated regular users share one card because self-registration is open."
        if mixed
        else "Regular roles with equivalent access share one card."
    ]
    notes.append("Individual flows may still require login.")
    return d, victim, notes


def legitimate_role_notes(yaml_data):
    """Describe actual role grouping for the report caption, not the SVG legend."""
    return _project_legitimate_roles(yaml_data)[2]


def overview_facts(yaml_data, attack_paths_data, attack_taxonomy, actor_labels=None):
    """Counts of what the overview draws, for the report sentence that introduces it."""
    comps = [c for c in yaml_data.get("components") or [] if isinstance(c, dict) and c.get("id")]
    flows = [f for f in yaml_data.get("data_flows") or [] if isinstance(f, dict)]
    services = {
        e["id"]
        for e in yaml_data.get("external_entities") or []
        if isinstance(e, dict) and e.get("id") and e.get("kind") != "legitimate-role"
    } | {f"ext:{f.get('from')}" for f in flows if f.get("to") == "external" and not f.get("to_entity")}
    scenarios, _actors = scenarios_from_attack_paths(
        yaml_data, attack_paths_data or {}, attack_taxonomy or {}, actor_labels
    )
    return {
        "components": len(comps),
        "layers": len({_zone_key(c) for c in comps}),
        "external_services": len(services),
        "scenarios": len({s["n"] for s in scenarios}),
    }


def _build_model(d, scenarios, actors, victim_target=USER_ID):
    comps = [c for c in (d.get("components") or []) if isinstance(c, dict) and c.get("id")]
    cnum = d.get("_component_numbers") or {c["id"]: f"C-{i:02d}" for i, c in enumerate(comps, 1)}
    by_cnum = {v: k for k, v in cnum.items()}
    sev = collections.defaultdict(collections.Counter)
    stride = collections.defaultdict(collections.Counter)
    tb_threats = collections.Counter()
    weak, omitted_high = _component_weakness_summary(d)
    for t in register_threats(d):
        for cid in _affected_components(t):
            sev[cid][register_severity(t)] += 1
            stride[cid][(t.get("stride") or "?")[0].upper()] += 1
        for b in t.get("boundary_refs") or []:
            if isinstance(b, dict):
                tb_threats[b.get("boundary_id")] += 1
    tbs = _figure_boundaries(d)
    component_ids = {c["id"] for c in comps}
    exposed = {
        t["to"]
        for t in tbs
        if t.get("from") == "external"
        and t.get("confidence") == "confirmed"
        and not _internal_interface(t)
        and boundary_endpoints_valid(t, component_ids)
    }

    component_capabilities, service_roles = _capability_vocabulary()
    reported = register_threats(d)
    derived_capabilities = _finding_capabilities(reported, component_capabilities, component_ids)
    capability_severity = _capability_severity(reported, component_capabilities, component_ids)
    nodes = {}
    for comp in comps:
        cid = comp["id"]
        zk = _zone_key(comp)
        name = f"{cnum[cid]} · {comp.get('name') or cid}"
        nodes[cid] = {
            "id": cid,
            "kind": "store" if zk == "data" else "process",
            "name": name,
            "title_lines": min(3, len(_legend_wrap(name, NODE_W - 52, 11))),
            "zone": zk,
            "col": COLUMN[zk],
            "w": NODE_W,
            "h": PROC_H,
            "sev": sev[cid],
            "stride": stride[cid],
            "exposed": cid in exposed or "internet" in [str(z).lower() for z in comp.get("deployment_zones") or []],
            "complex": comp.get("complexity") == "complex",
            "technology": _technology(comp),
            "capabilities": _capability_display(
                _capability_rows(
                    [*(comp.get("capabilities") or []), *derived_capabilities.get(cid, [])],
                    component_capabilities,
                    "capability",
                    comp.get("name") or cid,
                    capability_severity.get(cid),
                )
            ),
            "badges": [],
            "assets": [],
            "weak": weak.get(cid, []),
            "weak_more_high": omitted_high.get(cid, 0),
            "order": len(nodes),
        }
    for s in scenarios:
        cids = s.get("cids") or [by_cnum.get(cn) for cn in s.get("cnums") or []]
        for cid in cids:
            # Several attributed access groups can share one scenario number.
            if cid in nodes and s["n"] not in nodes[cid]["badges"]:
                nodes[cid]["badges"].append(s["n"])
    # Prefer evidenced storage locations. Without storage evidence, show known
    # processing or transmission instead, labelled as such rather than as storage.
    asset_risk = {t.get("id"): SEV_RANK.get(register_severity(t), 3) for t in d.get("threats") or []}
    for asset in d.get("assets") or []:
        if not isinstance(asset, dict):
            continue
        linked = {int(m) for t in asset.get("linked_threats") or [] for m in re.findall(r"(\d+)$", str(t))}
        refs = [
            ref for ref in asset.get("component_refs") or [] if ref.get("component_id") in nodes and ref.get("evidence")
        ]
        for relation in ("stored", "processed", "transmitted"):
            owners = dict.fromkeys(ref["component_id"] for ref in refs if ref.get("relation") == relation)
            if not owners:
                continue
            for owner in owners:
                nodes[owner]["assets"].append(
                    dict(
                        asset,
                        _relation=relation,
                        _priority=(
                            min((asset_risk.get(tid, 3) for tid in asset.get("linked_threats") or []), default=3),
                            CLS_RANK.get(str(asset.get("classification")).title(), 9),
                            asset["id"],
                        ),
                        _hits=list(dict.fromkeys(s["n"] for s in scenarios if linked & set(s.get("fids") or [])))
                        if relation == "stored"
                        else [],
                    )
                )
            break
    for node in nodes.values():
        asset_height = _asset_inline_height(node["assets"])
        node["compact_assets"] = asset_height > ASSET_INLINE_HEIGHT
        if node["compact_assets"]:
            inline = []
            inline_height = 0
            for asset in sorted(node["assets"], key=lambda a: a["_priority"])[:2]:
                row_height = _asset_inline_height([asset])
                if inline_height + row_height <= ASSET_INLINE_HEIGHT / 2:
                    inline.append(asset["id"])
                    inline_height += row_height
            node["inline_asset_ids"] = inline
            cell_width = max(_tw(a["id"], 8.5) + 20 for a in node["assets"])
            columns = max(1, min(3, int((NODE_W - 46) / cell_width)))
            node["asset_columns"] = columns
            symbol_count = len(node["assets"]) - len(inline)
            asset_height = inline_height + (16 if inline else 0)
            asset_height += ((symbol_count + columns - 1) // columns) * ASSET_SYMBOL_ROW
        node["h"] = max(
            PROC_H,
            108
            + 13 * (node["title_lines"] - 2)
            + (TECH_H if node["technology"] else 0)
            + _pill_height(node["capabilities"], NODE_W - 44)
            + 12 * len(_weak_lines(node["weak"], NODE_W - 32))
            + (12 if node["weak_more_high"] else 0)
            + (24 + asset_height if node["assets"] else 24 if node["kind"] == "store" else 0),
        )
    # actors: one legitimate user, then the attackers
    victim_of = list(dict.fromkeys(s["n"] for s in scenarios if s.get("victim")))
    nodes[USER_ID] = {
        "id": USER_ID,
        "kind": "ext",
        "name": " ".join(part for part in (str(_project_name(d) or "").strip(), "User") if part),
        "sub": "legitimate client"
        + (
            " · victim of " + " ".join("①②③④⑤⑥⑦⑧⑨"[int(n) - 1] for n in victim_of[:4])
            if victim_of and victim_target == USER_ID
            else ""
        ),
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
            "sub": a.get("sub") or "",
            "zone": "internet",
            "col": 0,
            "w": EXT_W,
            "h": EXT_H,
            "col_rank": 2,
            "color": ACTOR_COLORS[i % len(ACTOR_COLORS)],
            "marker": f"attacker-{i}",
            "actor_code": f"A{i + 1}",
            "actor_slug": a.get("slug"),
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
            "sub": entity.get("description") or "",
            "access": entity.get("access") if role else None,
            "zone": "internet" if role else "third-party",
            "col": 0,
            "w": EXT_W,
            "h": EXT_H,
            "color": GREEN if role else INK,
            "capabilities": []
            if role
            else _capability_display(
                _capability_rows(
                    entity.get("service_roles"),
                    service_roles,
                    "role",
                    entity["name"],
                    label_key="identity_provider_label" if entity.get("kind") == "identity-provider" else "label",
                )
            ),
            "order": len(nodes),
            "badges": [],
        }
    if victim_of and victim_target != USER_ID:
        nodes[victim_target]["col_rank"] = 0
        nodes[victim_target]["victim_label"] = "victim of " + " ".join("①②③④⑤⑥⑦⑧⑨"[int(n) - 1] for n in victim_of[:4])
        nodes[victim_target]["h"] += 12
    needs_generic_user = (victim_of and victim_target == USER_ID) or any(
        f.get("from") == "external" and not f.get("from_entity") for f in d.get("data_flows") or []
    )
    if not needs_generic_user:
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
                    "sub": f.get("label") or "",
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
        key = (
            flow_bundle_key(f)
            if d.get("_overview") or f.get("authentication")
            else (src, dst, str(f.get("direction") or "").lower())
        )
        b = bundles.setdefault(
            key,
            {
                "src": src,
                "dst": dst,
                "ids": [],
                "cls": "Public",
                "tb": [],
                "bidi": False,
                "authentication": authentication_profile(f),
                "interaction": bool(f.get("interaction")),
            },
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
    also = collections.defaultdict(dict)
    for s in scenarios:
        src = attacker_by_name.get(s.get("actor")) or default_attacker
        if not src:
            continue
        cids = s.get("cids") or [by_cnum.get(cn) for cn in s.get("cnums") or []]
        app = [c for c in cids if c in nodes and nodes[c]["col"] == 1 and nodes[c]["kind"] == "process"]
        # One edge per finding, to its own component when exposed, else to the
        # first exposed affected one; the other affected components go into
        # the edge's tooltip instead of fanning the attack out.
        hit = []
        for affected in s.get("targets") or [cids]:
            exposed = [c for c in affected if c in app and nodes[c].get("exposed")]
            if exposed:
                hit += [exposed[0]] if exposed[0] not in hit else []
                also[(src, exposed[0])].update(dict.fromkeys(c for c in affected if c in nodes and c != exposed[0]))
        if not hit and not s.get("victim"):  # a victim scenario reaches the user, not an unexposed process
            hit = app[:1]
        for dst in hit:
            atk.setdefault((src, dst), []).append(s["n"])
        if s.get("victim"):
            atk.setdefault((src, victim_target), []).append(s["n"])
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
                "victim": dst == victim_target,
                "also": [nodes[c]["name"] for c in also[(src, dst)] if c != dst],
            }
        )
    # trust boundaries: chip on the flow that crosses them, else a tag on the guarded node
    unplaced = []
    for t in tbs:
        if _internal_interface(t):
            continue
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
        cap = len(members) if zk == "internet" or (zk == "third-party" and not d.get("_overview")) else ZONE_CAP
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
    if d.get("_overview"):
        # Calls that a canonical internal interface places inside one process
        # carry no crossing; the detail views keep them. Stores stay visible.
        internal = {frozenset((t.get("from"), t.get("to"))) for t in _figure_boundaries(d) if _internal_interface(t)}
        in_process = {
            id(e)
            for e in edges
            if not e.get("attack")
            and frozenset((e["src"], e["dst"])) in internal
            and drawn[e["src"]]["kind"] == drawn[e["dst"]]["kind"] == "process"
            and drawn[e["src"]]["col"] == drawn[e["dst"]]["col"]
        }
        for edge in edges:
            if id(edge) in in_process:
                d["_undrawn_flows"].extend((fid, "in-process call in detail views") for fid in edge["ids"])
        edges = [e for e in edges if id(e) not in in_process]
        flows = sorted((e for e in edges if not e.get("attack")), key=lambda e: not bool(e["tb"]))
        hidden = {id(e) for e in flows[OVERVIEW_FLOW_CAP:]}
        for edge in edges:
            if id(edge) in hidden:
                d["_undrawn_flows"].extend((fid, "connection in detail views") for fid in edge["ids"])
                d["_unplaced_tbs"].extend((tid, "connection in detail views") for tid in edge["tb"])
        edges = [e for e in edges if id(e) not in hidden]
    return drawn, edges, dropped


# ---- layout ----------------------------------------------------------------------------------
def _flow_lane_order(flows):
    """Keep opposing horizontal stubs apart when their ports share a height.

    A left stub must turn before a right stub on the same row. Preserve the
    existing lane order wherever those constraints allow it. Cyclic constraints
    cannot be resolved by lane ordering; the geometric gate still rejects them.
    """

    def ports(edge):
        return (edge["ys"], edge["yd"]) if edge["kind"] == "forward" else (edge["yd"], edge["ys"])

    prerequisites = {id(edge): set() for edge in flows}
    for left in flows:
        for right in flows:
            if left is not right and not left["skip"] and not right["skip"] and ports(left)[0] == ports(right)[1]:
                prerequisites[id(right)].add(id(left))
    pending, ordered = list(flows), []
    while pending:
        edge = next((edge for edge in pending if not prerequisites[id(edge)]), None)
        if edge is None:
            return flows
        pending.remove(edge)
        ordered.append(edge)
        for required in prerequisites.values():
            required.discard(id(edge))
    return ordered


def _intra_channel(count):
    return INTRA_STUB + INTRA_STEP * (count - 1) + 8 if count else 0


def _port_range(node):
    return node["y"] + node["tagspace"] + PORT_STEP / 2, node["y"] + node["h"] - PORT_STEP / 2


def _bus_stub(role, edge):
    return role == "in" and edge.get("attack") and edge["kind"] == "forward" and not edge["skip"]


def _place_ports(ports, pinned, low, high):
    """Heights for every port, or None when the pinned heights leave no valid slot."""
    placed = dict(pinned)
    free = [i for i in range(len(ports)) if i not in pinned]
    # Attack stubs cannot move later; data flows are refined by the route optimizer.
    free.sort(key=lambda i: (not ports[i]["attack"], ports[i]["want"], i))
    for i in free:
        want = ports[i]["want"]
        candidates = {want, low, high, *(y + d for y in placed.values() for d in (-PORT_STEP, PORT_STEP))}
        fits = [
            y
            for y in candidates
            if low - 1e-6 <= y <= high + 1e-6 and all(abs(y - other) >= PORT_STEP - 1e-6 for other in placed.values())
        ]
        if not fits:
            return None
        placed[i] = min(fits, key=lambda y: (abs(y - want), y))
    return placed


def _align_attack_ports(nodes, sides):
    """Let an attacker's stub continue straight from its bus when the target spans that height.

    Only sides with such a stub change. Other attack stubs take the free height
    nearest their bus and data-flow ports the free height nearest their even
    slot; every port keeps ``PORT_STEP`` clearance. A side whose pins leave no
    valid slot drops pins until it fits, and keeps the even spread without any.
    """
    for nid, sd in sides.items():
        node = nodes[nid]
        low, high = _port_range(node)
        for side in ("L", "R"):
            groups = collections.OrderedDict()
            for role, edge in sd[side]:
                shared_bus = role == "out" and edge.get("attack") and edge["kind"] == "forward" and not edge["skip"]
                key = ("bus", edge["src"]) if shared_bus else id(edge)
                groups.setdefault(key, []).append((role, edge))
            ports = []
            for items in groups.values():
                role, edge = items[0]
                current = edge["ys"] if role == "out" else edge["yd"]
                stub = len(items) == 1 and _bus_stub(role, edge)
                ports.append(
                    {
                        "items": items,
                        "attack": stub,
                        "want": min(high, max(low, edge["ys"])) if stub else current,
                        "pin": edge["ys"] if stub and low <= edge["ys"] <= high else None,
                    }
                )
            pins = {}
            for i, port in enumerate(ports):
                if port["pin"] is not None and all(abs(port["pin"] - y) >= PORT_STEP for y in pins.values()):
                    pins[i] = port["pin"]
            if not pins:
                continue
            placed = None
            while pins:
                placed = _place_ports(ports, pins, low, high)
                if placed is not None:
                    break
                pins.pop(max(pins))
                placed = None
            if placed is None:
                continue
            for i, port in enumerate(ports):
                for role, edge in port["items"]:
                    edge["ys" if role == "out" else "yd"] = placed[i]


def _align_flow_ports(nodes, edges, sides):
    """Remove sub-corner-sized jogs only where the destination port has clearance."""
    for edge in edges:
        if edge.get("attack") or edge["kind"] == "intra" or edge["skip"]:
            continue
        if not 0 < abs(edge["yd"] - edge["ys"]) <= 8:
            continue
        node = nodes[edge["dst"]]
        side = "L" if edge["kind"] == "forward" else "R"
        height = edge["ys"]
        if not node["y"] + node["tagspace"] + PORT_STEP / 2 <= height <= node["y"] + node["h"] - PORT_STEP / 2:
            continue
        if any(
            other is not edge and abs(height - other["ys" if role == "out" else "yd"]) < PORT_STEP
            for role, other in sides[edge["dst"]][side]
        ):
            continue
        edge["yd"] = height


def _route_intersections(first, second):
    """Count shared line intervals and proper crossings, excluding endpoint touches."""
    overlaps = crossings = 0
    for a, b in zip(first, first[1:]):
        if a == b:
            continue
        for c, d in zip(second, second[1:]):
            if c == d:
                continue
            horizontal = a[1] == b[1]
            other_horizontal = c[1] == d[1]
            if horizontal == other_horizontal:
                axis, fixed = (0, 1) if horizontal else (1, 0)
                overlaps += (
                    abs(a[fixed] - c[fixed]) < 0.01
                    and min(max(a[axis], b[axis]), max(c[axis], d[axis]))
                    - max(min(a[axis], b[axis]), min(c[axis], d[axis]))
                    > 1
                )
            else:
                h1, h2, v1, v2 = (a, b, c, d) if horizontal else (c, d, a, b)
                crossings += min(h1[0], h2[0]) < v1[0] < max(h1[0], h2[0]) and min(v1[1], v2[1]) < h1[1] < max(
                    v1[1], v2[1]
                )
    return overlaps, crossings


def _improve_routes(nodes, edges, boundaries, zones, *, straight_only=False):
    """Improve data routes without moving nodes, changing topology or splitting buses.

    Compare only affected paths, with invalid geometry taking precedence over
    overlaps, crossings, short jogs, bends and length. One deterministic sweep
    exchanges existing ports, uses free port positions, then exchanges lanes;
    a final sweep tries free corridors for routes that skip a column. Ports
    retain their minimum clearance. Layout failures still reach the independent
    geometry and semantic gates.
    """
    movable = [i for i, e in enumerate(edges) if not e.get("attack") and not e.get("ui_top_entry")]
    regular = [] if straight_only else movable
    headings = [(z["x"], z["y"], z["x"] + z["w"], z["y"] + ZONE_HEAD - 3) for z in zones if not z.get("bar")]
    badges = [
        (n["x"] + n["w"] - 26 - i * 19, n["y"] + n["h"] - 9, n["x"] + n["w"] - 10 - i * 19, n["y"] + n["h"] + 7)
        for n in nodes.values()
        for i, _ in enumerate(n.get("badges", []))
    ]

    def shape_cost(index, points):
        edge = edges[index]
        segments = [(a, b) for a, b in zip(points, points[1:]) if a != b]
        invalid = 0
        for a, b in segments:
            invalid += a[0] != b[0] and a[1] != b[1]
            invalid += a[0] == b[0] and any(abs(a[0] - bx) < 14 for bx in boundaries)
            for node in nodes.values():
                rect = (node["x"] + 1, node["y"] + 1, node["x"] + node["w"] - 1, node["y"] + node["h"] - 1)
                invalid += _segment_hits_rect(a, b, rect)
            invalid += sum(_segment_hits_rect(a, b, rect) for rect in headings)
            invalid += sum(_segment_hits_rect(a, b, rect) for rect in badges)
        # Keep the existing source/receiver side and room for the authentication tab.
        for nid, end, approach in ((edge["src"], points[0], points[1]), (edge["dst"], points[-1], points[-2])):
            node = nodes[nid]
            invalid += end[1] != approach[1] or (
                approach[0] >= end[0] if end[0] == node["x"] else approach[0] <= end[0]
            )
        invalid += abs(points[-1][0] - points[-2][0]) < 38 + 32 * (max(1, len(edge.get("auth_keys", []))) - 1)
        if edge.get("tb") and edge.get("bx") is not None:
            a, b = points[:2] if edge["kind"] == "forward" else points[-2:]
            invalid += not min(a[0], b[0]) <= edge["bx"] <= max(a[0], b[0])
        lengths = [abs(a[0] - b[0]) + abs(a[1] - b[1]) for a, b in segments]
        bends = sum((a[0] == b[0]) != (c[0] == d[0]) for (a, b), (c, d) in zip(segments, segments[1:]))
        return invalid, sum(length < 8 for length in lengths), bends, sum(lengths)

    def cost(changes):
        invalid = overlaps = crossings = jogs = bends = 0
        length = 0
        for i, points in changes.items():
            bad, short, turns, distance = shape_cost(i, points)
            invalid += bad
            jogs += short
            bends += turns
            length += distance
            for j, edge in enumerate(edges):
                if j == i or j in changes and j < i:
                    continue
                shared, crossed = _route_intersections(points, changes.get(j, edge["pts"]))
                overlaps += shared
                crossings += crossed
        return invalid, overlaps, crossings, jogs, bends, round(length, 6)

    def consider(changes, *, straight=False):
        before = {i: edges[i]["pts"] for i in changes}
        candidate = cost(changes)
        previous = cost(before)
        if straight:
            # A valid straight connection takes precedence over avoiding a proper
            # crossing. Shared line intervals still reject ambiguous junctions.
            order = lambda c: (c[0], c[1], c[3], c[4], c[2], c[5])
            candidate, previous = order(candidate), order(previous)
        if candidate[0] or candidate >= previous:
            return
        for i, points in changes.items():
            edges[i]["pts"] = points
            edges[i]["ys"], edges[i]["yd"] = points[0][1], points[-1][1]

    ports = collections.defaultdict(list)
    for i in regular:
        for role, position in (("src", 0), ("dst", -1)):
            ports[(edges[i][role], edges[i]["pts"][position][0])].append((i, position))
    for entries in ports.values():
        for offset, (i, end) in enumerate(entries):
            for j, other_end in entries[offset + 1 :]:
                if i == j:
                    continue
                first, second = list(edges[i]["pts"]), list(edges[j]["pts"])
                y1, y2 = first[end][1], second[other_end][1]
                for points, pos, y in ((first, end, y2), (second, other_end, y1)):
                    for p in (0, 1) if pos == 0 else (-2, -1):
                        points[p] = (points[p][0], y)
                consider({i: first, j: second})
    # Break cyclic lane constraints using free space on the existing node side.
    # Also align ports when a straight connection fits without crowding a peer.
    for i in regular:
        edge = edges[i]
        for role, end, opposite in (("src", 0, -1), ("dst", -1, 0)):
            node = nodes[edge[role]]
            x, y = edge["pts"][end]
            candidates = (edge["pts"][opposite][1], y - PORT_STEP / 2, y + PORT_STEP / 2)
            for height in candidates:
                if not node["y"] + node["tagspace"] + PORT_STEP / 2 <= height <= node["y"] + node["h"] - PORT_STEP / 2:
                    continue
                if any(
                    j != i
                    and other[r] == edge[role]
                    and other["pts"][p][0] == x
                    and abs(other["pts"][p][1] - height) < PORT_STEP
                    for j, other in enumerate(edges)
                    for r, p in (("src", 0), ("dst", -1))
                ):
                    continue
                points = list(edge["pts"])
                for p in (0, 1) if end == 0 else (-2, -1):
                    points[p] = (points[p][0], height)
                consider({i: points})
    for offset, i in enumerate(regular):
        edge = edges[i]
        if len(edge["pts"]) != 4 or edge["skip"]:
            continue
        for j in regular[offset + 1 :]:
            other = edges[j]
            if len(other["pts"]) != 4 or other["skip"]:
                continue
            corridor = lambda e: (e["kind"] == "intra", min(nodes[e["src"]]["col"], nodes[e["dst"]]["col"]))
            if corridor(edge) != corridor(other):
                continue
            first, second = list(edge["pts"]), list(other["pts"])
            x1, x2 = first[1][0], second[1][0]
            for points, x in ((first, x2), (second, x1)):
                points[1:3] = [(x, points[1][1]), (x, points[2][1])]
            consider({i: first, j: second})
    for i in regular:
        edge = edges[i]
        if not edge["skip"]:
            continue
        points = edge["pts"]
        for x in dict.fromkeys((points[1][0], points[-2][0])):
            consider({i: [points[0], (x, points[0][1]), (x, points[-1][1]), points[-1]]})
    # Straighten parallel routes between one node pair together: one flow alone
    # can be boxed in by its neighbours' clearance while the pair still fits.
    pairs = collections.defaultdict(list)
    for i in movable:
        edge = edges[i]
        if edge["kind"] != "intra" and not edge["skip"] and len(edge["pts"]) == 4:
            pairs[(edge["src"], edge["dst"], edge["pts"][0][0], edge["pts"][-1][0])].append(i)
    for (src, dst, x_src, x_dst), group in pairs.items():
        group.sort(key=lambda i: (edges[i]["pts"][0][1] + edges[i]["pts"][-1][1], i))
        if len(group) < 2 or all(edges[i]["pts"][0][1] == edges[i]["pts"][-1][1] for i in group):
            continue
        lower = max(_port_range(nodes[n])[0] for n in (src, dst))
        upper = min(_port_range(nodes[n])[1] for n in (src, dst))
        members = set(group)
        blocked = [
            other["pts"][p][1]
            for j, other in enumerate(edges)
            if j not in members
            for r, p in (("src", 0), ("dst", -1))
            if (other[r], other["pts"][p][0]) in ((src, x_src), (dst, x_dst))
        ]
        current = [(edges[i]["pts"][0][1] + edges[i]["pts"][-1][1]) / 2 for i in group]

        def stack(floor):
            heights = []
            for _ in group:
                options = [floor] + [y + PORT_STEP for y in blocked if y + PORT_STEP >= floor]
                fits = [y for y in options if y <= upper and all(abs(y - b) >= PORT_STEP for b in blocked)]
                if not fits:
                    return None
                heights.append(min(fits))
                floor = heights[-1] + PORT_STEP
            return heights

        starts = {
            lower,
            *(y + PORT_STEP for y in blocked),
            *(max(lower, y) for i in group for y in (edges[i]["pts"][0][1], edges[i]["pts"][-1][1])),
        }
        stacks = [h for h in map(stack, sorted(y for y in starts if y >= lower)) if h]
        if not stacks:
            continue
        heights = min(stacks, key=lambda h: (sum(abs(a - b) for a, b in zip(h, current)), h))
        consider(
            {
                i: [(edges[i]["pts"][0][0], y), (edges[i]["pts"][1][0], y), (edges[i]["pts"][2][0], y), (x_dst, y)]
                for i, y in zip(group, heights)
            },
            straight=True,
        )
    for i in movable:
        edge = edges[i]
        if edge["kind"] == "intra":
            continue
        source, target = nodes[edge["src"]], nodes[edge["dst"]]
        lower = max(n["y"] + n["tagspace"] + PORT_STEP / 2 for n in (source, target))
        upper = min(n["y"] + n["h"] - PORT_STEP / 2 for n in (source, target))
        if lower > upper:
            continue
        peers = []
        for role, end in (("src", 0), ("dst", -1)):
            peers.extend(
                other["pts"][p][1]
                for j, other in enumerate(edges)
                if j != i
                for r, p in (("src", 0), ("dst", -1))
                if other[r] == edge[role] and other["pts"][p][0] == edge["pts"][end][0]
            )
        candidates = [edge["pts"][0][1], edge["pts"][-1][1], (lower + upper) / 2, lower, upper]
        candidates.extend(y + delta for y in peers for delta in (-PORT_STEP, PORT_STEP))
        for height in dict.fromkeys(max(lower, min(upper, y)) for y in candidates):
            if any(abs(height - y) < PORT_STEP for y in peers):
                continue
            points = edge["pts"]
            lane = points[1][0]
            consider(
                {i: [(points[0][0], height), (lane, height), (lane, height), (points[-1][0], height)]}, straight=True
            )


def _layout(nodes, edges, dropped, tb_threats, ncols=3, *, optimize=True):
    # 1. sides: L = entering from the left, R = leaving right / intra-column channel
    for e in edges:
        s, t = nodes[e["src"]], nodes[e["dst"]]
        dc = t["col"] - s["col"]
        e["kind"] = "intra" if dc == 0 else ("forward" if dc > 0 else "backward")
        e["skip"] = abs(dc) > 1
    sides = collections.defaultdict(lambda: {"L": [], "R": []})
    ui_entries = collections.defaultdict(list)
    for e in edges:
        if e.get("interaction") and e["kind"] == "intra" and nodes[e["dst"]]["zone"] == "client":
            ui_entries[e["dst"]].append(e)
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
        n["h"] = n["tagspace"] + max(n["h"], PORT_STEP * (k + 1))
    # 3. column widths (right-side channel for intra edges), gap widths (one lane per edge)
    intra_per_col = collections.Counter(nodes[e["src"]]["col"] for e in edges if e["kind"] == "intra")
    port_extra = 32 if any(len(e.get("auth_keys", [])) > 1 for e in edges) else 0
    col_w = [COL_W + _intra_channel(intra_per_col[c]) + (port_extra if intra_per_col[c] else 0) for c in range(ncols)]
    n_lanes = collections.Counter()
    for e in edges:
        if e["kind"] == "intra":
            continue
        g1, g2 = sorted((nodes[e["src"]]["col"], nodes[e["dst"]]["col"]))
        for g in range(g1, g2):
            n_lanes[g] += 1
    gap_w = [max(GAP, B_OFF + LANE0 + n_lanes[g] * LANE_STEP + 52 + port_extra) for g in range(ncols - 1)]
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
            if n.get("stable_order"):
                bary = n["order"]
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
                    if cur == "client":
                        y += max(
                            (12 * len(ui_entries[m["id"]]) + 16 for m in members if ui_entries[m["id"]]), default=0
                        )
            n["x"], n["y"] = x + ZONE_PAD + (NODE_W - n["w"]) / 2, y
            n["cy"] = y + n["h"] / 2
            y += n["h"] + NODE_GAP
        if cur is not None:
            close(cur)
        if col == 0 and members:
            boxes.insert(
                0,
                {
                    "zone": "internet",
                    "x": x - 10,
                    "y": outer_top,
                    "w": col_w[0] + 20,
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
            ports = {}
            for role, e in items:
                shared_bus = role == "out" and e.get("attack") and e["kind"] == "forward" and not e["skip"]
                key = ("bus", e["src"]) if shared_bus else id(e)
                ports.setdefault(key, []).append((role, e))
            k = len(ports)
            for i, port in enumerate(ports.values()):
                yv = n["y"] + n["tagspace"] + (n["h"] - n["tagspace"]) * (i + 1) / (k + 1)
                for role, e in port:
                    if role == "out":
                        e["ys"] = yv
                    else:
                        e["yd"] = yv

    _align_attack_ports(nodes, sides)
    _align_flow_ports(nodes, edges, sides)

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
        flows = _flow_lane_order([e for e in ge if not e.get("attack")])
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
            cx = col_x[s["col"]] + ZONE_PAD + NODE_W + INTRA_STUB + port_extra + j * INTRA_STEP
            e["pts"] = [(s["x"] + s["w"], e["ys"]), (cx, e["ys"]), (cx, e["yd"]), (t["x"] + t["w"], e["yd"])]
            if e in ui_entries[e["dst"]]:
                entries = ui_entries[e["dst"]]
                slot = entries.index(e)
                px = t["x"] + t["w"] * (slot + 1) / (len(entries) + 1)
                py = t["y"] - 16 - 12 * (len(entries) - slot - 1)
                e["pts"] = [(s["x"] + s["w"], e["ys"]), (cx, e["ys"]), (cx, py), (px, py), (px, t["y"])]
                e["ui_top_entry"] = True
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
        # Use an allocated attack port so the shared trunk cannot overlap a separate victim edge.
        bus, ys = ge[0]["pts"][1][0], ge[0]["ys"]
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
    # 7. Single-boundary chips stay on their flow. Shared crossings retain all
    # boundary IDs in the legend; vertical stacks would leave the actual flow.
    _improve_routes(nodes, edges, boundaries, zone_boxes, straight_only=not optimize)
    chips = []
    for e in edges:
        if e.get("bx") is not None and len(e["tb"]) == 1:
            y0 = e["pts"][0][1] if e["kind"] == "forward" else e["pts"][-1][1]
            chips.append({"bx": e["bx"], "y": y0, "tb": e["tb"][0], "group": id(e)})
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
    route_bottom = max((p[1] for e in edges for p in e["pts"]), default=bottom)
    height = max(bottom + 16, route_bottom + LANE_STEP) + MARGIN
    return col_x, col_w, zone_boxes, boundaries, chips, height


# ---- rendering ----------------------------------------------------------------------------------
def _overview_groups(nodes, edges):
    """Keep semantic sidebar groups contiguous; backend-only egress sits by data."""
    for node in nodes.values():
        node["stable_order"] = True
        if node.get("attacker"):
            node.update(zone="attackers", col_rank=0, color=RED)
        elif node["zone"] == "internet":
            node.update(zone="users", col_rank=1)
        elif node["zone"] == "client":
            node["col_rank"] = 2
        elif node["zone"] == "third-party":
            node["col_rank"] = 3
            peers = [
                nodes[e["src"] if e["dst"] == node["id"] else e["dst"]]
                for e in edges
                if node["id"] in (e["src"], e["dst"])
            ]
            if peers and all(p["col"] in {1, 2} for p in peers):
                node.update(col=2, col_rank=2)


def _authentication_endpoint(edge, model):
    """Shorten only the displayed receiving end; retain semantic node endpoints."""
    pts = _trim(edge["pts"])
    if not model.get("_auth_catalog") or edge.get("interaction"):
        return pts
    x, y = edge["pts"][-1]
    side = "left" if x > edge["pts"][-2][0] else "right"
    edge["auth_port"] = (x, y, side)
    clearance = 24 + 32 * (max(1, len(edge.get("auth_keys", []))) - 1)
    pts[-1] = (x - clearance if side == "left" else x + clearance, y)
    return pts


def _auth_tab(canvas, x, y, side, profile, flow_ids=""):
    """A numbered 20-unit hexagonal access port, distinct from attack circles."""
    palette = {
        "red": (RED, "#fff0ee"),
        "yellow": ("#926200", "#fff5d6"),
        "green": ("#28704b", "#e4f3e9"),
        "grey": ("#64748b", "#edf2f7"),
    }
    color, fill = palette[profile["color"]]
    dx = -1 if side == "left" else 1
    number = profile["number"]
    canvas.add(
        f'<g data-authentication="{_esc(number)}" data-authentication-shape="hexagon" data-auth-flows="{_esc(flow_ids)}" transform="translate({x:.1f} {y:.1f}) scale({dx} 1)">'
    )
    canvas.add(f"<title>{_esc(profile['title'])}</title>")
    canvas.add(
        f'<polygon points="0,0 5,-9 15,-9 20,0 15,9 5,9" fill="{fill}" stroke="{color}" stroke-width="1.2" stroke-linejoin="round"/>'
    )
    size = min(10, 12 / max(1, len(str(number)) * 0.56))
    canvas.add(
        f'<text x="{10 * dx}" y="3.5" transform="scale({dx} 1)" text-anchor="middle" font-size="{size:g}" font-weight="bold" fill="{color}">{_esc(number)}</text></g>'
    )
    if flow_ids:
        canvas.badges.append((min(x, x + dx * 20), y - 9, max(x, x + dx * 20), y + 9, f"auth {flow_ids}"))
    if canvas.legend_content is not None:
        canvas.legend_content.append((min(x, x + dx * 20), y - 9, max(x, x + dx * 20), y + 9))


def _prepare_reference_rows(nodes):
    """Reserve measured footers before layout; names never select connectivity."""
    for node in nodes.values():
        rows = []
        for ref in node.get("references", []):
            profiles = ref["profiles"]
            for offset in range(0, max(1, len(profiles)), 2):
                chunk = profiles[offset : offset + 2]
                label = f"{ref['direction']} {ref['id']} · {nodes[ref['peer']]['name']}"
                lines = _legend_wrap(label, node["w"] - 36 - 26 * len(chunk), 9)
                rows.append({**ref, "profiles": chunk, "lines": lines, "height": max(24, len(lines) * 12 + 8)})
        if rows:
            node["reference_rows"] = rows
            node["reference_height"] = sum(r["height"] + 4 for r in rows) + 16
            node["h"] += node["reference_height"]


def _prepare_external_text(nodes):
    for node in nodes.values():
        if node["kind"] != "ext" or node.get("group_lines"):
            continue
        inset = 32 if node["zone"] in {"internet", "users", "attackers"} else 12
        width = node["w"] - inset - 8
        text = str(node.get("sub") or "").strip()
        lines = _legend_wrap(text, width, 7.5) if text else []
        if len(lines) > 3:
            text = re.split(r"(?<=[.!?])\s+", text, maxsplit=1)[0]
            lines = _legend_wrap(text, width, 7.5)
        if len(lines) > 3:
            words = []
            for word in text.split():
                candidate = _legend_wrap(" ".join([*words, word]) + "…", width, 7.5)
                if len(candidate) > 3:
                    break
                words.append(word)
            lines = _legend_wrap(" ".join(words) + "…", width, 7.5) if words else ["See full description on hover"]
        node["sub_lines"] = lines
        title_lines = min(2, len(_wrap(node["name"], width, 10)))
        node["h"] = max(
            node["h"],
            20
            + title_lines * 12
            + _pill_height(node.get("capabilities") or [], width)
            + 8
            + len(lines) * 10
            + (12 if node.get("victim_label") else 0),
        )


def _segment_hits_rect(a, b, rect):
    x0, y0, x1, y1 = rect[:4]
    if a[1] == b[1]:
        return y0 < a[1] < y1 and min(a[0], b[0]) < x1 and max(a[0], b[0]) > x0
    return x0 < a[0] < x1 and min(a[1], b[1]) < y1 and max(a[1], b[1]) > y0


def _protocol_part(protocol, *, own_line=False):
    """The protocol in parentheses; one with its own parentheses follows a separator or its own line."""
    if "(" not in protocol and ")" not in protocol:
        return f"({protocol})"
    return protocol if own_line else f"· {protocol}"


def _flow_label_candidates(entries, interaction):
    """Prefer authored payloads; shorten legacy prose without inventing a summary."""
    labels = list(dict.fromkeys(f.get("diagram_label") or f.get("label") or "Data exchange" for f in entries))
    protocol = " / ".join(dict.fromkeys(f["protocol"] for f in entries if f.get("protocol")))
    if interaction:
        # A person operates the client; an authored payload here describes delivery, not use.
        labels, protocol = [INTERACTION_LABEL], ""
    part = _protocol_part(protocol) if protocol else ""
    line = _protocol_part(protocol, own_line=True) if protocol else ""
    choices = [" / ".join(labels) + (f" {part}" if part else "")]
    if part:
        choices.append(" / ".join(labels) + f"\n{line}")
    for width in (48, 30, 18):
        label = labels[0]
        if len(label) > width:
            label = label[:width].rsplit(" ", 1)[0] + "…"
        if len(labels) > 1:
            label += f" +{len(labels) - 1}"
        if part:
            choices.extend([f"{label} {part}", f"{label}\n{line}"])
        else:
            choices.append(label)
    return list(dict.fromkeys(choices))


def _label_gaps(a, b, width, offset, occupied, segments, *, lines=1):
    """Find actual free label intervals instead of sampling a few fractions."""
    horizontal = a[1] == b[1]
    along, cross = (0, 1) if horizontal else (1, 0)
    fixed = a[cross] + offset
    extra = (lines - 1) * 12
    low, high = fixed - FS, fixed + 2 + extra
    intervals = [(min(a[along], b[along]) + width / 2 + 10, max(a[along], b[along]) - width / 2 - 10)]
    blocked = [(r[along], r[along + 2]) for r in occupied if r[cross] < high and r[cross + 2] > low]
    blocked += [
        (min(p[along], q[along]), max(p[along], q[along]))
        for p, q in segments
        if min(p[cross], q[cross]) < high and max(p[cross], q[cross]) > low
    ]
    for left, right in blocked:
        left, right = left - width / 2 - 0.5, right + width / 2 + 0.5
        intervals = [
            part
            for start, end in intervals
            for part in ((start, min(end, left)), (max(start, right), end))
            if part[0] <= part[1]
        ]
        if not intervals:
            break
    middle = (a[along] + b[along]) / 2
    for start, end in intervals:
        center = min(end, max(start, middle))
        x, y = (center, fixed) if horizontal else (fixed, center)
        rect = (
            (x - width / 2, y - FS, x + width / 2, y + 2 + extra)
            if horizontal
            else (x - FS, y - width / 2, x + 2 + extra, y + width / 2)
        )
        yield x, y, rect, abs(center - middle)


def _flow_labels(canvas, model, nodes, edges, boundaries, zones):
    """Place actual payload labels on clear runs; retain overflow in compact notes."""
    segments = [(a, b, e) for e in edges for a, b in zip(e.get("draw_pts", e["pts"]), e.get("draw_pts", e["pts"])[1:])]
    walls = [((bx, TOP), (bx, max(n["y"] + n["h"] for n in nodes.values()))) for bx in boundaries]
    for z in zones:
        x, y, w, h = z["x"], z["y"], z["w"], z["h"]
        walls.extend(
            [((x, y), (x + w, y)), ((x, y + h), (x + w, y + h)), ((x, y), (x, y + h)), ((x + w, y), (x + w, y + h))]
        )
    occupied = [(n["x"] - 3, n["y"] - 3, n["x"] + n["w"] + 3, n["y"] + n["h"] + 3) for n in nodes.values()]
    occupied += [(z["x"], z["y"], z["x"] + z["w"], z["y"] + ZONE_HEAD) for z in zones]
    occupied += canvas.labels + canvas.badges
    # A small white break at proper crossings prevents false junction readings.
    seen = set()
    for i, (a, b, edge) in enumerate(segments):
        for p, q, other in segments[i + 1 :]:
            if edge is other or edge.get("attack") and other.get("attack"):
                continue
            h, v = ((a, b, edge), (p, q, other)) if a[1] == b[1] else ((p, q, other), (a, b, edge))
            if h[0][1] != h[1][1] or v[0][0] != v[1][0]:
                continue
            x, y = v[0][0], h[0][1]
            if not (
                min(h[0][0], h[1][0]) + 7 < x < max(h[0][0], h[1][0]) - 7
                and min(v[0][1], v[1][1]) + 7 < y < max(v[0][1], v[1][1]) - 7
            ):
                continue
            if (x, y) in seen:
                continue
            seen.add((x, y))
            over = v if v[2].get("attack") else h
            path = f"M {x} {y - 3} V {y + 3}" if over is v else f"M {x - 3} {y} H {x + 3}"
            canvas.path(path, "#ffffff", sw=4)
            canvas.path(
                path,
                RED if over[2].get("attack") else CLS_COL.get(over[2]["cls"], LINE),
                sw=ATTACK_WIDTH if over[2].get("attack") else 1.1,
            )
    flows = {f["id"]: f for f in model.get("data_flows") or []}
    for edge in edges:
        if edge.get("attack"):
            continue
        entries = [flows[fid] for fid in edge["ids"]]
        points = edge.get("draw_pts", edge["pts"])
        candidates = []
        texts = _flow_label_candidates(entries, edge.get("interaction"))
        if edge.get("access_group"):
            # Access labels can express conditions or a sequence. Keep those
            # words intact rather than abbreviating away an optional step.
            label = edge["access_group"]["label"]
            protocol = " / ".join(dict.fromkeys(f["protocol"] for f in entries if f.get("protocol")))
            part = _protocol_part(protocol) if protocol else ""
            line = _protocol_part(protocol, own_line=True) if protocol else ""
            texts = [label + (f" {part}" if part else "")]
            if part:
                texts.append(label + f"\n{line}")
            wrapped = _legend_wrap(label, 110, FS)
            if len(wrapped) <= 3:
                texts.append("\n".join([*wrapped, *([line] if line else [])]))
        for index, text in enumerate(texts):
            for a, b in zip(points, points[1:]):
                length = abs(a[0] - b[0]) + abs(a[1] - b[1])
                lines = text.split("\n")
                tw = max(_tw(line, FS) for line in lines)
                if length < tw + 20:
                    continue
                horizontal = a[1] == b[1]
                for offset in (-6, 14, -18, 26):
                    for x, y, rect, distance in _label_gaps(
                        a, b, tw, offset, occupied, [(p, q) for p, q, _ in segments] + walls, lines=len(lines)
                    ):
                        candidates.append((index, not horizontal, abs(offset), distance, x, y, rect))
            if candidates:
                break
        if not candidates:
            model.setdefault("_label_notes", []).append((edge["ids"], texts[0]))
            continue
        index, rotated, _, _, x, y, rect = min(candidates)
        text = texts[index]
        if rotated:
            canvas.add(f'<g transform="rotate(-90 {x:.1f} {y:.1f})">')
        for line_index, line in enumerate(text.split("\n")):
            canvas.text(x, y + line_index * 12, line, size=FS, fill=MUTED)
        if rotated:
            canvas.add("</g>")
        canvas.labels.append((*rect, "payload " + "/".join(edge["ids"])))
        occupied.append(rect)


def _trim(pts, a=1.2, b=1.8):
    """Drawn copy of a polyline: starts just outside the source border, ends where the arrowhead touches the target."""

    def sg(v):
        return (v > 0) - (v < 0)

    p = []
    for point in map(tuple, pts):
        if p and p[-1] == point:
            continue
        while len(p) >= 2 and (
            p[-2][0] == p[-1][0] == point[0]
            and min(p[-2][1], point[1]) <= p[-1][1] <= max(p[-2][1], point[1])
            or p[-2][1] == p[-1][1] == point[1]
            and min(p[-2][0], point[0]) <= p[-1][0] <= max(p[-2][0], point[0])
        ):
            p.pop()
        p.append(point)
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


def _legend_columns(sections, ncols):
    """Balance the fixed set of at most seven sections without splitting a block.

    Preserve source order within each column and use first-appearance order to
    remove equivalent column permutations. Within one panel gap of the shortest
    layout, prefer related sections together; then minimize height, imbalance,
    and finally the column tuple for deterministic ties. Input rows change block
    heights, never the number of sections searched here.
    """
    candidates = []
    for columns in product(range(ncols), repeat=len(sections)):
        if list(dict.fromkeys(columns)) != list(range(ncols)):
            continue
        heights = [0] * ncols
        location = {}
        for (key, height), col in zip(sections, columns):
            heights[col] += height + LEGEND_GAP
            location[key] = col
        related = (("scenarios", "boundaries"), ("flows", "assets"))
        separation = sum(location[a] != location[b] for a, b in related if a in location and b in location)
        candidates.append((max(heights), separation, sum(h * h for h in heights), columns))
    shortest = min(c[0] for c in candidates)
    eligible = (c for c in candidates if c[0] <= shortest + LEGEND_GAP)
    return min(eligible, key=lambda c: (c[1], c[0], c[2], c[3]))[3]


def _place_legend(canvas, blocks, width, top):
    """Place measured blocks below the graph without enlarging its width."""
    ncols = min(3, len(blocks), max(1, int((width + LEGEND_GAP) // (LEGEND_W + LEGEND_GAP))))
    columns = _legend_columns([(key, block.maxy) for key, block in blocks], ncols)
    gap = (width - ncols * LEGEND_W) / (ncols - 1) if ncols > 1 else 0
    bottoms = [top] * ncols
    for (key, block), col in zip(blocks, columns):
        x, y = MARGIN + col * (LEGEND_W + gap), bottoms[col]
        canvas.add(
            f'<g data-legend-section="{key}" data-legend-column="{col + 1}" transform="translate({x:.1f} {y:.1f})">'
        )
        canvas.o.extend(block.o)
        canvas.add("</g>")
        canvas.legend_boxes.append((x, y, x + LEGEND_W, y + block.maxy, key))
        if block.legend_content:
            canvas.legend_clearances.append(
                (
                    key,
                    min(b[1] for b in block.legend_content) - LEGEND_HEAD,
                    min(min(b[0], LEGEND_W - b[2]) for b in block.legend_content),
                    block.maxy - max(b[3] for b in block.legend_content),
                )
            )
        for source, dest in ((block.labels, canvas.labels), (block.badges, canvas.badges)):
            dest.extend((x0 + x, y0 + y, x1 + x, y1 + y, name) for x0, y0, x1, y1, name in source)
        bottoms[col] = y + block.maxy + LEGEND_GAP
        canvas.maxy = max(canvas.maxy, y + block.maxy)


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
    actor_groups=(),
):
    actor_colors = {n["name"]: n["color"] for n in nodes.values() if n.get("attacker")}
    scenario_colors = {}
    for s in scenarios:  # A shared number keeps the colour of its first attributed group.
        scenario_colors.setdefault(s["n"], actor_colors.get(s.get("actor"), RED))
    W = col_x[-1] + col_w[-1] + MARGIN
    c = _Canvas()
    c.add("")  # header, filled in once the height is known
    c.add("")
    defs = "<defs>"
    markers = [(n["marker"], n["color"]) for n in nodes.values() if n.get("attacker")]
    for key, col in list(CLS_COL.items()) + [("red", RED), ("grey", LINE)] + markers:
        defs += (
            f'<marker id="arw-{key}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="9" markerHeight="9" '
            f'markerUnits="userSpaceOnUse" orient="auto-start-reverse" overflow="visible"><path d="M0 0 L10 5 L0 10 z" fill="{col}"/></marker>'
        )
    c.add(defs + "</defs>")
    meta = d.get("meta") or {}
    project_data = d.get("project") if isinstance(d.get("project"), dict) else {}
    project = _project_name(d)
    version = project_data.get("version") or meta.get("project_version")
    identity = str(project or "Project")
    if isinstance(version, (str, int, float)) and not isinstance(version, bool) and str(version).strip():
        identity += " · " + str(version).strip()
    c.text(
        MARGIN,
        26,
        "Figure 1 — Architecture and Threat Overview",
        size=14,
        anchor="start",
        weight="bold",
        fill=NAVY,
    )
    n_comp = sum(n["kind"] != "ext" for n in nodes.values()) + sum(
        n["kind"] != "ext" for group in dropped.values() for n in group
    )
    boundary_label = _boundary_count_label(tbs, interfaces=not d.get("_overview"))
    threat_total = sum(risk_distribution_counts(d).values())
    c.text(
        MARGIN,
        42,
        f"{identity} · {n_comp} components · {len(d.get('data_flows') or [])} data flows · {boundary_label} · {threat_total} threats",
        size=10,
        anchor="start",
        fill=MUTED,
    )

    # zones
    for zb in [z for z in zone_boxes if not z.get("bar")]:
        title, stroke, fill = ZONE_STYLE[zb["zone"]]
        c.rect(
            zb["x"],
            zb["y"],
            zb["w"],
            zb["h"],
            fill=fill,
            stroke=stroke,
            sw=1.2,
            rx=7,
            dash=None if zb["zone"] in {"attackers", "users"} else "7 4",
        )
        c.text(zb["x"] + 10, zb["y"] + 16, title, size=10.5, anchor="start", weight="bold", fill=stroke)
        zk = zb["zone"]
        # Fixed reader wording only: deployment-zone IDs are analysis vocabulary.
        sub = ZONE_SUBTITLE.get(zk, "")
        if d.get("_overview"):
            privileged = any(
                n.get("access") == "internet-priv-user" for n in nodes.values() if n.get("zone") == "users"
            )
            sub = {
                "attackers": "Untrusted threat actors",
                "users": "Application users and administrators" if privileged else "Application users",
                "client": "User-facing applications",
            }.get(zk, sub)
        if zk in {"client", "application", "data"}:
            sub = ""
        if sub:
            c.text(zb["x"] + 10, zb["y"] + 29, _cut(sub, 38), size=8.5, anchor="start", fill=MUTED, italic=True)
    for zb in [z for z in zone_boxes if z.get("bar")]:
        ids = ", ".join(n["name"].split(" · ")[0] for n in zb["nodes"])
        nthr = sum(sum(n.get("sev", {}).values()) for n in zb["nodes"])
        c.rect(zb["x"], zb["y"], zb["w"], zb["h"], fill="#ffffff", stroke=LINE, sw=1, rx=6, dash="3 3")
        c.text(
            zb["x"] + zb["w"] / 2,
            zb["y"] + 15,
            _cut(f"+{len(zb['nodes'])} more: {ids} · {nthr} threats", 40),
            size=8.5,
            fill=MUTED,
        )

    # A column gap is only a routing coordinate unless a resolved boundary crosses it.
    cnums = d.get("_component_numbers") or {}
    by_id = {t["id"]: t for t in tbs}
    for gap, ids in (d.get("_boundary_gaps") or {}).items():
        bx = boundaries[gap]
        crossings = "; ".join(
            f"{tid} " + " → ".join(cnums.get(by_id[tid].get(key), "External") for key in ("from", "to")) for tid in ids
        )
        c.add(f'<g data-boundary-line="{gap}" data-boundary-ids="{_esc(" ".join(ids))}">')
        c.add(f"<title>{_esc('Trust boundary crossing: ' + crossings)}</title>")
        c.path(f"M {bx} {TOP - 4} V {height - MARGIN}", RED, sw=2.4, dash="6 5")
        c.text(bx, TOP - 9, "TRUST BOUNDARY", size=8, fill=RED, weight="bold", track=f"boundary line {gap}")
        c.add("</g>")

    # edges
    def chip(x, y, tbid, track=True):
        v = next((t.get("assumption_verdict") for t in tbs if t["id"] == tbid), "unconfirmed")
        g, col = VERDICT.get(v, VERDICT["unconfirmed"])
        n = tb_threats.get(tbid, 0)
        w = _chip_width(tbid, n)
        x0 = x - w / 2
        c.add(f'<g data-boundary-marker="{_esc(tbid)}">')
        if d.get("_overview"):
            c.rect(x0, y - 8, w, 16, fill="#ffffff", stroke=NAVY, sw=1.2, rx=8)
            c.text(x, y + 3.5, tbid, size=8.5, weight="bold", fill=NAVY)
            c.add("</g>")
            if track:
                c.labels.append((x0, y - 8, x0 + w, y + 8, f"chip {tbid}"))
            return w
        c.rect(x0, y - 8, w, 16, fill="#ffffff", stroke=col, sw=1.5, rx=8)
        c.text(x0 + 8, y + 3.5, tbid, size=8.5, anchor="start", weight="bold", fill=col)
        gx = x0 + 8 + _tw(tbid, 8.5) + 4
        c.text(gx + 5, y + 4, g, size=10, weight="bold", fill=col)
        if n:
            c.rect(gx + 14, y - 6, 6 + _tw(str(n), 8), 12, fill=col, rx=6)
            c.text(gx + 17 + _tw(str(n), 8) / 2, y + 3, str(n), size=8, fill="#ffffff", weight="bold")
        c.add("</g>")
        if track:
            c.labels.append((x0, y - 8, x0 + w, y + 8, f"chip {tbid}"))
        return w

    for e in edges:
        if e.get("attack"):
            tip = f"{nodes[e['src']]['name']} → {nodes[e['dst']]['name']}: scenario " + ", ".join(e["scen"])
            if e.get("also"):
                tip += "; its findings also affect " + ", ".join(e["also"])
            c.add(f'<g data-attack-edge="{_esc(e["src"])} {_esc(e["dst"])}"><title>{_esc(tip)}</title>')
            c.path(
                _orth(_trim(e["pts"]), r=0 if d.get("_overview") else 8),
                nodes[e["src"]]["color"],
                sw=ATTACK_WIDTH,
                marker=f"arw-{nodes[e['src']]['marker']}",
                dash=("5 4" if e.get("victim") else None),
            )
            source = nodes[e["src"]]
            if abs(e["pts"][0][0] - source["x"] - source["w"]) < 0.6:
                x0, y0 = e["pts"][0]
                c.text(
                    x0 + 6,
                    y0 - 4,
                    "Via user" if e.get("victim") else "Direct attack",
                    size=FS,
                    fill=source["color"],
                    anchor="start",
                    weight="bold",
                    halo=True,
                    track=f"attack label {source['actor_code']} {bool(e.get('victim'))}",
                )
            c.add("</g>")
            continue
        col = CLS_COL.get(e["cls"], LINE)
        mk = f"arw-{e['cls'] if e['cls'] in CLS_COL else 'grey'}"
        draw_pts = _authentication_endpoint(e, d)
        e["draw_pts"] = draw_pts
        mode = e.get("access_group", {}).get("mode", "")
        c.add(f'<g data-flow-ids="{_esc(" ".join(e["ids"]))}" data-access-mode="{_esc(mode)}">')
        inventory = [f for f in d.get("data_flows", []) if f.get("id") in e["ids"]]
        full_labels = [flow_hover_text(f) for f in inventory]
        for flow in inventory:
            auth = flow.get("authentication") or {}
            if auth:
                sources = ", ".join(f"{ev.get('file')}:{ev.get('line')}" for ev in auth.get("evidence") or [])
                full_labels.append(f"{flow['id']} authentication: {auth.get('scope', '')}; evidence: {sources}")
            group = flow.get("access_group")
            if group:
                full_labels.append(
                    f"{flow['id']} access group: {group['label']}; {group['mode']}; step {group.get('step', 'n/a')}"
                )
        c.add(f"<title>{_esc(chr(10).join(full_labels))}</title>")
        c.path(
            _orth(draw_pts, r=0 if d.get("_overview") else 8),
            col,
            sw=1.1,
            marker=mk,
            marker_start=(mk if e.get("bidi") else None),
        )
        c.add("</g>")
    # nodes
    for n in sorted(nodes.values(), key=lambda n: n["order"]):
        x, y, w, h = n["x"], n["y"], n["w"], n["h"]
        if n["kind"] == "ext":
            if not n.get("attacker"):
                c.add(f'<g data-external-id="{_esc(n["id"])}"><title>{_esc(n.get("sub", ""))}</title>')
            col = n["color"]
            if n.get("group_lines"):
                c.label_owners[f"actor grouping {n['actor_code']}"] = n["id"]
                c.add(f'<g data-actor-grouping="{n["actor_code"]}">')
            c.rect(x, y, w, h, fill="#ffffff", stroke=col, sw=1.8)
            if n["zone"] in {"internet", "users", "attackers"}:
                _person(c, x + 16, y + 20, col)
                tx = x + 32
            else:
                tx = x + 12
            label = (n["actor_code"] + " · " if n.get("actor_code") else "") + n["name"]
            label_lines = _wrap(label, w - (tx - x) - 8, 10)[:2]
            for i, line in enumerate(label_lines):
                c.text(tx, y + 19 + i * 12, line, size=10, anchor="start", weight="bold", fill=col)
            if n.get("capabilities"):
                _capability_pills(c, tx, y + 12 + len(label_lines) * 12, n, w - (tx - x) - 8)
            sub_y = y + h - n.get("reference_height", 0) - (20 if n.get("victim_label") else 8)
            if n.get("group_lines"):
                for i, line in enumerate(n["group_lines"]):
                    c.text(
                        tx,
                        sub_y - 10 * (len(n["group_lines"]) - 1 - i),
                        line,
                        size=7.5,
                        anchor="start",
                        fill=MUTED,
                        track=f"actor grouping {n['actor_code']}",
                    )
                c.add("</g>")
            else:
                lines = n.get("sub_lines") or []
                for i, line in enumerate(lines):
                    c.text(
                        tx, sub_y - 10 * (len(lines) - 1 - i), line, size=7.5, anchor="start", fill=MUTED, italic=True
                    )
            if n.get("victim_label"):
                c.text(tx, y + h - 8, n["victim_label"], size=7.5, anchor="start", fill=MUTED, italic=True)
            if not n.get("attacker"):
                c.add("</g>")
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
        title_lines = _legend_wrap(n["name"], w - 52, 11)
        lines = title_lines[:3]
        if len(title_lines) > 3:
            lines[-1] = lines[-1][:-1] + "…"
        c.add(f'<g data-component-id="{_esc(n["id"])}"><title>{_esc(n["name"])}</title>')
        title_key = f"node title {n['id']}"
        c.label_owners[title_key] = n["id"]
        title_y = y + n["tagspace"] + 22
        for i, line in enumerate(lines):
            c.text(x + w / 2 - 6, title_y + i * 13, line, size=11, weight="bold", track=title_key)
        c.add("</g>")
        ty = title_y + len(lines) * 13 + 2
        if n.get("technology"):
            tech = n["technology"]
            tech_key = f"node technology {n['id']}"
            c.label_owners[tech_key] = n["id"]
            attrs = "".join(f' data-{key}="{_esc(value)}"' for key, value in tech.items())
            c.add(f'<g data-technology-owner="{_esc(n["id"])}"{attrs}>')
            names = {"framework": "Storage engine" if n["kind"] == "store" else "Framework", "language": "Language"}
            c.add(f"<title>{_esc(' · '.join(f'{names[key]}: {value}' for key, value in tech.items()))}</title>")
            c.text(x + w / 2 - 6, ty + 2, _technology_label(tech), size=FS, fill=MUTED, italic=True, track=tech_key)
            c.add("</g>")
            ty += TECH_H
        if n.get("capabilities"):
            ty += _capability_pills(c, x + 20, ty - 6, n, NODE_W - 44)
        _sev_chips(c, x + ox + 2, ty, n["sev"])
        _stride_strip(c, x + ox, ty + 10, n["stride"])
        _weak_line(c, x + ox, ty + 36, n.get("weak") or [], w - ox - 8)
        weak_lines = len(_weak_lines(n["weak"], w - ox - 8))
        if n["weak_more_high"]:
            c.text(
                x + ox + 9,
                ty + 36 + 12 * weak_lines,
                f"+{n['weak_more_high']} more High",
                size=8.5,
                anchor="start",
                fill=MUTED,
            )
            weak_lines += 1
        if n["exposed"]:
            _globe(c, x + w - 16, y + 15)
        if n["assets"]:
            ay = ty + 50 + 12 * max(0, weak_lines - 1)
            compact = n.get("compact_assets")
            c.text(
                x + ox,
                ay,
                "Assets — see legend" if compact and not n.get("inline_asset_ids") else "Assets",
                size=8.5,
                anchor="start",
                fill=MUTED,
                italic=True,
            )
            yy = ay + 10
            inline_ids = n.get("inline_asset_ids", [a["id"] for a in n["assets"]])
            assets = (
                sorted(n["assets"], key=lambda a: (a["id"] not in inline_ids, a["_priority"]))
                if compact
                else n["assets"]
            )
            symbol_index = 0
            for a in assets:
                symbol = compact and a["id"] not in inline_ids
                if symbol and symbol_index == 0 and inline_ids:
                    c.text(x + ox, yy + 5, "More assets — see legend", size=8, anchor="start", fill=MUTED)
                    yy += 16
                c.add(
                    f'<g data-asset-id="{_esc(a["id"])}" data-asset-component="{_esc(n["id"])}" '
                    f'data-asset-relation="{a["_relation"]}" '
                    f'data-asset-display="{"symbol" if symbol else "inline"}">'
                )
                c.add(f"<title>{_esc(n['name'] + ': ' + str(a.get('name')))}</title>")
                col = CLS_COL.get(str(a.get("classification")).title(), MUTED)
                if symbol:
                    columns = n["asset_columns"]
                    ax = x + ox + (symbol_index % columns) * (NODE_W - 46) / columns
                    sy = yy + (symbol_index // columns) * ASSET_SYMBOL_ROW
                    c.rect(ax, sy, 6, 6, fill=col)
                    c.text(ax + 10, sy + 6, a["id"], size=8.5, anchor="start", fill=col)
                    symbol_index += 1
                    c.add("</g>")
                    continue
                c.rect(x + ox, yy, 6, 6, fill=col)
                lines = _asset_lines(a)
                for index, line in enumerate(lines):
                    c.text(x + ox + 10, yy + 6 + index * 11, line, size=8.5, anchor="start")
                yy += len(lines) * 11
                hits = a.get("_hits", [])
                badge_x0 = x + w - 30 - (len(hits) - 1) * 15 if hits else x + w - 26
                for j, s in enumerate(hits):
                    _badge(c, badge_x0 + j * 15, yy + 20, s, col=scenario_colors.get(s, RED), r=6.5)
                c.text(x + ox + 10, yy + 6, str(a.get("classification")), size=7.5, anchor="start", fill=col)
                yy += 17 + (18 if hits else 0)
                c.add("</g>")
        elif n["kind"] == "store":
            for i, line in enumerate(_wrap("Asset mapping not established", w - ox - 12, 8.5)):
                c.text(
                    x + ox,
                    ty + 50 + 12 * max(0, weak_lines - 1) + i * 11,
                    line,
                    size=8.5,
                    anchor="start",
                    fill=MUTED,
                    italic=True,
                )
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

    flow_inventory = {f["id"]: f for f in d.get("data_flows", [])}
    for node in nodes.values():
        x, y = node["x"] + 8, node["y"] + node["h"] - node.get("reference_height", 0)
        for i, ref in enumerate(node.get("reference_rows", [])):
            w, h = node["w"] - 16, ref["height"]
            track = f"reference {node['id']} {i}"
            c.label_owners[track] = node["id"]
            c.add(
                f'<g data-integration-reference="{_esc(ref["id"])}" data-reference-owner="{_esc(node["id"])}" data-reference-peer="{_esc(ref["peer"])}" data-reference-direction="{ref["direction"]}">'
            )
            operations = [nodes[ref["peer"]]["name"]]
            for fid in ref["ids"]:
                flow = flow_inventory[fid]
                auth = flow.get("authentication") or {}
                operations.append(
                    f"{fid}: {flow.get('label', '')} {_protocol_part(flow.get('protocol', ''))}; "
                    f"{auth.get('scope', 'authentication unknown')}"
                )
            c.add(f"<title>{_esc(chr(10).join(operations))}</title>")
            c.rect(x, y, w, h, fill="#edf3f9", stroke="#b6c6d8", sw=0.7, rx=3)
            for j, line in enumerate(ref["lines"]):
                c.text(x + 6, y + 14 + j * 12, line, size=9, fill=NAVY, anchor="start", weight="bold", track=track)
            for j, key in enumerate(ref["profiles"]):
                _auth_tab(c, x + w - 4 - j * 26, y + h / 2, "left", d["_auth_catalog"][key])
            c.badges.append((x, y, x + w, y + h, track))
            c.add("</g>")
            y += h + 4
    for e in edges:
        if e.get("auth_port"):
            x, y, side = e["auth_port"]
            keys = e.get("auth_keys", [e["authentication"]["key"]])
            flow_ids = " ".join(e["ids"])
            if e.get("access_group"):
                c.add(f'<g data-auth-flows="{_esc(flow_ids)}" data-access-mode="{e["access_group"]["mode"]}">')
            dx = -1 if side == "left" else 1
            for i, key in enumerate(keys):
                px = x + dx * 32 * (len(keys) - i - 1)
                _auth_tab(c, px, y, side, d["_auth_catalog"][key], flow_ids)
                if i:
                    separator = "/" if e["access_group"]["mode"] == "alternatives" else ("→" if side == "left" else "←")
                    c.text(px + dx * 26, y + 3, separator, size=9, fill=MUTED)
            if e.get("access_group"):
                c.add("</g>")
    _flow_labels(c, d, nodes, edges, boundaries, zone_boxes)

    blocks = _legend_blocks(
        d, nodes, edges, tbs, tb_threats, scenarios, actor_colors, dropped, unattached_assets, actor_groups
    )
    _place_legend(c, blocks, W - 2 * MARGIN, max(height, c.maxy + MARGIN) + 10)
    H = max(height, c.maxy + MARGIN)
    c.o[0] = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">'
    )
    c.o[1] = f'<rect width="{W}" height="{H}" fill="#ffffff"/>'
    c.add("</svg>")
    return "\n".join(c.o), c


def _legend_blocks(d, nodes, edges, tbs, tb_threats, scenarios, actor_colors, dropped, unattached_assets, actor_groups):
    """Render independent sections at the origin before measuring their heights."""
    blocks = []
    lx = LEGEND_INSET - 10
    lw = LEGEND_W - 2 * lx
    c = None

    def head(key, title):
        nonlocal c
        c = _Canvas()
        blocks.append((key, c))
        c.rect(0, 0, LEGEND_W, LEGEND_HEAD, fill=NAVY, rx=4)
        c.text(lx + lw / 2, 17, title, size=10.5, fill="#ffffff", weight="bold")
        c.legend_content = []
        return LEGEND_HEAD + LEGEND_CONTENT_GAP + 9

    y = head("notation", "Notation")
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
    if any(n.get("technology") for n in nodes.values()):
        c.text(lx + 21, y + 3, "[ ]", size=FS, fill=MUTED, italic=True)
        c.text(lx + 40, y + 3, "framework · language; data store: engine", size=9, anchor="start")
        y += 20
    c.path(f"M {lx + 10} {y - 1} H {lx + 32}", CLS_COL["Confidential"], sw=1.6, marker="arw-Confidential")
    c.text(lx + 40, y + 3, "data flow · classification colour · two heads = bidirectional", size=9, anchor="start")
    y += 16
    xx = lx + 40
    for k, col in CLS_COL.items():
        c.rect(xx, y - 6, 8, 8, fill=col)
        c.text(xx + 11, y + 1, k, size=8, anchor="start", fill=col)
        xx += _tw(k, 8) + 22
    y += 18
    if d.get("_boundary_gaps"):
        c.path(f"M {lx + 10} {y - 1} H {lx + 32}", RED, sw=2, dash="6 4")
        c.text(lx + 40, y + 3, "trust boundary crossed between these columns", size=9, anchor="start")
        y += 20
    c.path(f"M {lx + 10} {y - 1} H {lx + 32}", LINE, sw=1.2, dash="6 4")
    c.text(lx + 40, y + 3, "dashed outline = zone, not itself a boundary", size=9, anchor="start")
    if not d.get("_overview"):
        y += 20
        c.rect(lx + 8, y - 9, 44, 16, fill="#ffffff", stroke=RED, sw=1.4, rx=8)
        c.text(lx + 14, y + 3, "tb ✕", size=8, anchor="start", fill=RED, weight="bold")
        c.rect(lx + 38, y - 7, 11, 12, fill=RED, rx=6)
        c.text(lx + 43.5, y + 3, "9", size=8, fill="#ffffff", weight="bold")
        c.text(lx + 60, y + 3, "boundary: ✕ refuted · ✓ held · ? unverified", size=8.5, anchor="start")
        y += 13
        c.text(
            lx + 60,
            y + 3,
            "count = crossing threats · corner tag = guarded entry",
            size=8.5,
            anchor="start",
            fill=MUTED,
        )
    y += 20
    c.path(f"M {lx + 10} {y - 1} H {lx + 32}", RED, sw=ATTACK_WIDTH, marker="arw-red")
    c.text(
        lx + 40,
        y + 3,
        "solid = direct attack · dashed = via user",
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
        "All Critical · High fills to 5 · +N = omitted High categories",
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

    overflow = [(n, cap["more"]) for n in nodes.values() for cap in n.get("capabilities") or [] if cap.get("more")]
    capabilities = list(
        {
            cap["id"]: cap
            for n in nodes.values()
            for shown in n.get("capabilities") or []
            for cap in shown.get("more") or [shown]
        }.values()
    )
    if capabilities:
        c.text(lx + 10, y + 3, "Security-relevant capabilities / service roles", size=9, anchor="start", weight="bold")
        y += 16
        sample = capabilities[0]
        width = _tw(sample["label"], PILL_SIZE) + 12
        c.rect(lx + 10, y - 7, width, PILL_H, fill="#eef3f8", stroke="#b6c6d8", sw=0.7, rx=3)
        c.text(lx + 10 + width / 2, y + 2.5, sample["label"], size=PILL_SIZE, fill=NAVY)
        c.text(lx + 18 + width, y + 3, "function or service role", size=8.5, anchor="start")
        y += 18
        if any(cap.get("severity") in _PILL_FINDING_BORDER for cap in capabilities):
            c.rect(lx + 10, y - 7, width, PILL_H, fill="#eef3f8", stroke=RED, sw=1.2, rx=3)
            c.text(lx + 10 + width / 2, y + 2.5, sample["label"], size=PILL_SIZE, fill=NAVY)
            c.text(lx + 18 + width, y + 3, "border: most severe linked finding", size=8.5, anchor="start")
            y += 18
        vocabulary = {**_capability_vocabulary()[0], **_capability_vocabulary()[1]}
        notes = [
            f"{cap['label']} = {vocabulary[cap['id']]['note']}"
            for cap in capabilities
            if vocabulary[cap["id"]].get("note")
        ]
        ranking = (
            f"Most security-critical functions always shown, others up to {CAPABILITY_CAP} labels per element: "
            "most critical first, then most severe linked finding"
        )
        if overflow:
            ranking += "; +N = further labels, listed under Further capabilities"
        for note in [*notes, ranking + ".", "Functions may go undetected: a missing label does not mean absence."]:
            for line in _legend_wrap(note, lw - 20, 8.5):
                c.text(lx + 10, y + 3, line, size=8.5, anchor="start", fill=MUTED)
                y += 12
        y += 14

    if d.get("_references"):
        c.text(lx + 10, y + 3, "↔ E1", size=9, fill=NAVY, weight="bold", anchor="start")
        for i, line in enumerate(_legend_wrap("Matching E-labels indicate a connection; lines omitted.", lw - 58, 9)):
            c.text(lx + 48, y + 3 + 12 * i, line, size=9, anchor="start")

    if scenarios:
        y = head("scenarios", "Attack scenarios — by actor")
        by_actor = {}
        for s in scenarios:
            who = (s.get("actor") or "Attacker") + (" → User (victim)" if s.get("victim") else "")
            by_actor.setdefault(who, []).append(s)
        for who, members in by_actor.items():
            col = actor_colors.get(members[0].get("actor"), RED)
            c.add(f'<g data-scenario-actor="{_esc(who)}">')
            c.text(lx + 10, y + 3, _cut(who, 52), size=9, anchor="start", weight="bold", fill=col)
            y += 16
            for s in members:
                _badge(c, lx + 20, y - 2, s["n"], col=col)
                title_lines = _legend_wrap(s["title"], lw - 94, 9)
                for i, line in enumerate(title_lines):
                    c.text(lx + 34, y + 2 + i * 12, line, size=9, anchor="start", track=f"scenario {who} {s['n']}")
                if s.get("risk"):
                    c.text(
                        lx + lw - 10,
                        y + 2,
                        s["risk"],
                        size=8,
                        anchor="end",
                        fill=SEV_COL.get(s["risk"], MUTED),
                        weight="bold",
                        track=f"scenario severity {who} {s['n']}",
                    )
                y += max(17, 12 * len(title_lines) + 5)
            c.add("</g>")
        y += 8

    if tbs and not d.get("_overview"):
        y = head("boundaries", "Trust boundaries and internal interfaces")
        cnums = d.get("_component_numbers") or {
            row["id"]: f"C-{i:02d}" for i, row in enumerate(d.get("components") or [], 1)
        }
        flows = {f.get("id"): f for f in d.get("data_flows") or [] if isinstance(f, dict)}
        for t in sorted(tbs, key=lambda t: _tb_num(t["id"])):
            c.add(f'<g data-boundary-id="{_esc(t["id"])}">')
            endpoints = " → ".join(cnums.get(t.get(key), "External") for key in ("from", "to"))
            c.text(lx + 10, y + 3, f"{t['id']} · {endpoints}", size=9, anchor="start", weight="bold", fill=NAVY)
            y += 14
            if _internal_interface(t):
                description = "internal interface · no trust transition"
            else:
                description = str(t.get("surface") or t.get("kind") or "type not recorded")
                if t.get("transition"):
                    description += " · " + " + ".join(t["transition"])
            description += " · " + ("confirmed" if t.get("confidence") == "confirmed" else "inferred")
            for line in _legend_wrap(description, lw - 20, 8.5):
                c.text(lx + 10, y + 3, line, size=8.5, anchor="start", fill=MUTED)
                y += 12
            if not _internal_interface(t):
                matched = [
                    e
                    for e in edges
                    if any(
                        (flows[fid].get("from"), flows[fid].get("to")) == (t.get("from"), t.get("to"))
                        for fid in e["ids"]
                    )
                ]
                location = "flow " + _flow_ids_label(matched[0]["ids"]) if len(matched) == 1 else "no unique drawn flow"
                if len(matched) == 1 and len(matched[0]["tb"]) > 1:
                    location += " · shared crossing"
                for line in _legend_wrap(location, lw - 20, 8):
                    c.text(lx + 10, y + 3, line, size=8, anchor="start", fill=MUTED)
                    y += 12
            if not d.get("_overview"):
                g, col = VERDICT.get(t.get("assumption_verdict"), VERDICT["unconfirmed"])
                verdict = f"{g} {t.get('assumption_verdict') or 'unconfirmed'} · {t.get('enforcement_point') or 'no enforcement point'}"
                if tb_threats.get(t["id"]):
                    verdict += f" · {tb_threats[t['id']]} threats"
                for line in _legend_wrap(verdict, lw - 20, 8):
                    c.text(lx + 10, y + 3, line, size=8, anchor="start", fill=col)
                    y += 12
            c.add("</g>")
            y += 8
        for line in _legend_wrap(
            "External means outside modelled components, not necessarily the Internet.", lw - 20, 8
        ):
            c.text(lx + 10, y + 3, line, size=8, anchor="start", fill=MUTED)
            y += 12
    flows = {f.get("id"): f for f in d.get("data_flows") or [] if isinstance(f, dict)}
    if any(e["ids"] for e in edges) and not d.get("_overview"):
        y = head("flows", "Data flows")
        for e in edges:
            if not e["ids"]:
                continue
            entries = [flows.get(fid, {}) for fid in e["ids"]]
            fid_label = _flow_ids_label(e["ids"])
            # The SVG title keeps the full inventory available on hover, while
            # the visible legend uses authored summaries and existing C-NN IDs.
            c.add(f'<g data-flow-ids="{_esc(" ".join(e["ids"]))}">')
            details = []
            for fid, f in zip(e["ids"], entries):
                src, dst = _flow_endpoints(f)
                payload, protocol = flow_payload(f)
                details.append(
                    f"{fid}: {nodes.get(src, {}).get('name', src)} → {nodes.get(dst, {}).get('name', dst)} · {protocol} · {payload} · {f.get('data_classification') or ''} · {f.get('direction') or ''}"
                )
            c.add(f"<title>{_esc(chr(10).join(details))}</title>")
            id_lines = _legend_wrap(fid_label.replace("/", "/ "), 66, 8)
            if _tw(fid_label, 8) <= 66:
                id_lines = [fid_label]
            for i, line in enumerate(id_lines):
                c.text(
                    lx + 10,
                    y + 3 + i * 11,
                    line,
                    size=8,
                    anchor="start",
                    weight="bold",
                    fill=CLS_COL.get(e.get("cls"), LINE),
                    track=f"flow ids {fid_label}",
                )
            detail = _flow_legend_detail(entries, nodes, e)
            lines = _legend_wrap(detail, lw - 88, 8)
            for i, line in enumerate(lines):
                c.text(lx + 82, y + 3 + i * 11, line, size=8, anchor="start", track=f"flow detail {fid_label}")
            y += max(14, 11 * max(len(lines), len(id_lines)) + 5)
            c.add("</g>")
    if d.get("_auth_catalog"):
        y = head("authentication", "Authentication")
        for profile in sorted(
            d["_auth_catalog"].values(),
            key=lambda p: (p["number"] == "?", int(p["number"]) if p["number"].isdigit() else 999),
        ):
            _auth_tab(c, lx + 30, y, "left", profile)
            for line in _legend_wrap(profile["title"], lw - 50, 9):
                c.text(lx + 40, y + 2, line, size=9, anchor="start", weight="bold")
                y += 12
            y += 4
            for line in _legend_wrap(profile["description"], lw - 50, 8):
                c.text(lx + 40, y, line, size=8, anchor="start", fill=MUTED)
                y += 11
            y += 8
        for line in [
            "Numbered hexagon: authentication · circle: attack scenario",
            "0: no authentication · ?: unknown",
            "Red: absent / unsafe · yellow: standard / limited · green: stronger",
            "Method properties, not proof of a secure implementation.",
        ]:
            c.text(lx + 10, y + 3, line, size=8, anchor="start", fill=MUTED)
            y += 12
        if any(e.get("access_group") for e in edges):
            c.text(
                10,
                y + 3,
                "/: alternatives · →: successive checks (see access label)",
                size=8,
                anchor="start",
                fill=MUTED,
            )
            y += 12
    symbol_assets = collections.defaultdict(list)
    for node in nodes.values():
        if node.get("compact_assets"):
            for asset in node["assets"]:
                if asset["id"] not in node["inline_asset_ids"]:
                    symbol_assets[asset["id"]].append((node, asset))
    if symbol_assets:
        y = head("assets", "Asset symbols")
        for aid, occurrences in sorted(symbol_assets.items()):
            asset = occurrences[0][1]
            col = CLS_COL.get(str(asset.get("classification")).title(), MUTED)
            c.add(f'<g data-asset-legend-id="{_esc(aid)}">')
            c.rect(lx + 10, y - 6, 6, 6, fill=col)
            for line in _legend_wrap(f"{aid} {asset.get('name')}", lw - 32, 8.5):
                c.text(lx + 22, y + 1, line, size=8.5, anchor="start")
                y += 11
            relations = []
            for node, placed_asset in occurrences:
                verb = {"stored": "stored in", "processed": "processed by", "transmitted": "transmitted by"}[
                    placed_asset["_relation"]
                ]
                relations.append(f"{verb} {node['name'].split(' · ')[0]}")
            info = f"{asset.get('classification')} · " + "; ".join(relations)
            for line in _legend_wrap(info, lw - 32, 8):
                c.text(lx + 22, y + 1, line, size=8, anchor="start", fill=MUTED)
                y += 11
            hits = list(dict.fromkeys(hit for _, placed_asset in occurrences for hit in placed_asset.get("_hits", [])))
            if hits:
                for line in _legend_wrap("Attack scenarios: " + ", ".join(hits), lw - 32, 8):
                    c.text(lx + 22, y + 1, line, size=8, anchor="start", fill=RED)
                    y += 11
            y += 12
            c.add("</g>")
    if overflow:
        y = head("capability-notes", "Further capabilities")
        c.text(lx + 10, y + 3, "Labels behind +N on their element:", size=8, anchor="start", fill=MUTED)
        y += 18
        for node, more in overflow:
            owner = node["name"].split(" · ")[0]
            for line in _legend_wrap(f"{owner}: {', '.join(cap['label'] for cap in more)}", lw - 20, 8):
                c.text(lx + 10, y + 3, line, size=8, anchor="start", fill=MUTED)
                y += 12
            y += 6
    if d.get("_label_notes"):
        y = head("flow-notes", "Additional flow labels")
        c.text(lx + 10, y + 3, "Labels without room on their connection:", size=8, anchor="start", fill=MUTED)
        y += 18
        edge_by_ids = {tuple(edge["ids"]): edge for edge in edges if not edge.get("attack")}
        for ids, label in d["_label_notes"]:
            edge = edge_by_ids[tuple(ids)]
            source, target = (nodes[edge[key]]["name"].split(" · ")[0] for key in ("src", "dst"))
            for line in _legend_wrap(f"{source} → {target}: {label}", lw - 20, 8):
                c.text(lx + 10, y + 3, line, size=8, anchor="start", fill=MUTED)
                y += 12
            y += 6
    notes = []
    if unattached_assets:
        count = len(unattached_assets)
        subject = "1 asset has" if count == 1 else f"{count} assets have"
        notes.append(f"{subject} no displayed component mapping; see the report asset register.")
    if dropped:
        n = sum(len(v) for v in dropped.values())
        notes.append(f"{n} participants collapsed into '+N more' bars; open the detail views for their connections.")
    if d.get("_overview"):
        omitted = {fid for fid, _ in d.get("_undrawn_flows", [])}
        groups = collections.defaultdict(collections.Counter)
        component_zones = {row["id"]: _zone_key(row) for row in d.get("components", [])}

        def endpoint(key):
            if key in nodes:
                return nodes[key]["name"].split(" · ")[0]
            zone = component_zones.get(key, "third-party")
            return f"Grouped {ZONE_STYLE[zone][0]} participants"

        for flow in d.get("data_flows", []):
            if flow.get("id") in omitted:
                source, target = _flow_endpoints(flow)
                direction = "↔" if flow.get("direction") == "bidirectional" else "→"
                groups[(endpoint(source), direction)][endpoint(target)] += 1
        for (source, direction), targets in groups.items():
            count = sum(targets.values())
            target = ", ".join(targets)
            notes.append(f"{source} {direction} {target}: {count} {'flow' if count == 1 else 'flows'} in detail views.")
    else:
        for fid, why in d.get("_undrawn_flows", []):
            notes.append(f"{fid} not drawn: {why}")
        for tid, why in d.get("_unplaced_tbs", []):
            notes.append(f"{tid} not placed: {why}")
    if notes:
        y = head("notes", "Diagram notes")
        for s in notes:
            for line in _legend_wrap(s, lw - 20, 8):
                c.text(lx + 10, y + 3, line, size=8, anchor="start", fill=MUTED)
                y += 12
    for _, block in blocks:
        block.maxy += LEGEND_CONTENT_GAP
    return blocks


# ---- verification -------------------------------------------------------------------------------
def _check_geometry(nodes, edges, canvas, chips, *, boundaries=()):
    problems = []
    for name, top, side, bottom in canvas.legend_clearances:
        if top < LEGEND_CONTENT_GAP or side < 8 or bottom < LEGEND_CONTENT_GAP:
            problems.append(f"legend padding: {name} (top={top:g}, side={side:g}, bottom={bottom:g})")
    rects = {n["id"]: (n["x"] + 1, n["y"] + 1, n["x"] + n["w"] - 1, n["y"] + n["h"] - 1) for n in nodes.values()}
    segs = []
    for e in edges:
        points = e.get("draw_pts", e["pts"])
        for p, q in zip(points, points[1:]):
            segs.append((p, q, (e.get("ids") or ["attack"]) + list(e.get("tb") or [])))
            if p[0] == q[0] and p != q and any(abs(p[0] - bx) < 14 for bx in boundaries):
                problems.append(f"edge {e.get('ids') or 'attack'} runs along a reserved crossing lane")
        if e.get("auth_port"):
            p, q = points[-2:]
            if p[1] != q[1] or abs(q[0] - p[0]) < 12:
                problems.append(f"edge {e['ids']}: authentication arrow approach is too short")

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
        if labs[i][4].startswith("node title "):
            a = labs[i]
            for b in canvas.badges:
                if a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]:
                    problems.append(f"title overlaps badge: {a[4]} × {b[4]}")
        if labs[i][4].startswith("payload ") and any(hits(p, q, labs[i][:4]) for p, q, _ in segs):
            problems.append(f"payload label crosses a connection: {labs[i][4]}")
        for j in range(i + 1, len(labs)):
            a, b = labs[i], labs[j]
            if a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]:
                problems.append(f"label overlap: {a[4]} × {b[4]}")
        for nid, r in rects.items():
            a = labs[i]
            if canvas.label_owners.get(a[4]) == nid:
                if not (r[0] <= a[0] <= a[2] <= r[2] and r[1] <= a[1] <= a[3] <= r[3]):
                    problems.append(f"label outside owner: {a[4]} × {nid}")
                continue
            if a[0] < r[2] and r[0] < a[2] and a[1] < r[3] and r[1] < a[3]:
                problems.append(f"label on node: {a[4]} × {nid}")
    for i, box in enumerate(canvas.legend_boxes):
        for other in [*canvas.legend_boxes[i + 1 :], *[(*r, nid) for nid, r in rects.items()]]:
            if box[0] < other[2] and other[0] < box[2] and box[1] < other[3] and other[1] < box[3]:
                problems.append(f"legend overlap: {box[4]} × {other[4]}")
        for p, q, name in segs:
            if hits(p, q, box[:4]):
                problems.append(f"segment {name} crosses legend {box[4]}")
    return problems


def _audit(d, nodes, edges, chips, boundaries, canvas=None):
    """Every drawn arrow matches its YAML flow; every flow and boundary is drawn or explained."""
    problems = []
    flows = {f.get("id"): f for f in d.get("data_flows") or [] if isinstance(f, dict)}
    tbs = {t["id"]: t for t in _figure_boundaries(d)}

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
        top_entry = e.get("ui_top_entry") and e.get("interaction") and t["zone"] == "client"
        on_top = t["x"] < p1[0] < t["x"] + t["w"] and abs(p1[1] - t["y"]) < 0.6
        if not on_edge(p1, t) and not (top_entry and on_top):
            problems.append(f"{name}: does not end on its target {t['id']}")
        (qx, qy), (px, py) = e["pts"][-2], p1
        if top_entry:
            if qx != px or not on_top or py - qy < 12:
                problems.append(f"{name}: human interaction needs a straight approach into the client top")
        elif qy != py:
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
            elif str(f.get("direction") or "").lower() != "bidirectional" and e.get("bidi"):
                problems.append(f"{fid}: one-way flow drawn with two heads")
        for ch in [c for c in chips if c.get("group") == id(e)]:
            seg = (e["pts"][0], e["pts"][1]) if e["kind"] == "forward" else (e["pts"][-2], e["pts"][-1])
            xs = sorted((seg[0][0], seg[1][0]))
            if not (xs[0] <= ch["x"] <= xs[1]) or abs(ch["y"] - seg[0][1]) > 0.6:
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
    explained = {u[0] for u in d.get("_undrawn_flows", [])} | {
        fid for ref in d.get("_references", []) for fid in ref["ids"]
    }
    for fid in flows:
        if fid not in drawn and fid not in explained:
            problems.append(f"{fid}: neither drawn nor explained")
    explained_boundaries = set()
    if canvas is not None:
        root = ET.fromstring("\n".join(canvas.o))
        if d.get("_overview"):
            # The overview defers every entry to the report's boundary catalogue.
            explained_boundaries = set(d.get("_overview_tbs", []))
        else:
            for entry in root.findall("{*}g[@data-legend-section='boundaries']/{*}g[@data-boundary-id]"):
                tid = entry.get("data-boundary-id")
                if any(text.text and text.text.startswith(tid + " · ") for text in entry.findall("{*}text")):
                    explained_boundaries.add(tid)
        for tid in sorted(tbs.keys() - explained_boundaries, key=_tb_num):
            problems.append(f"{tid}: boundary legend missing")
        lines = {
            int(g.get("data-boundary-line")): g.get("data-boundary-ids", "").split()
            for g in root.iter("{http://www.w3.org/2000/svg}g")
            if g.get("data-boundary-line") is not None
        }
        if lines != _boundary_gaps(d, nodes, list(tbs.values())):
            problems.append(f"trust-boundary lines {lines} do not match resolved crossings")
        for tid in {tid for ids in lines.values() for tid in ids}:
            if tid not in tbs or _internal_interface(tbs[tid]):
                problems.append(f"{tid}: trust-boundary line without a resolved trust boundary")
    placed = (
        {c["tb"] for c in chips}
        | explained_boundaries
        | {t for n in nodes.values() for t in n.get("tags", [])}
        | {u[0] for u in d.get("_unplaced_tbs", [])}
    )
    for tid in tbs:
        if tid not in placed:
            problems.append(f"{tid}: neither chip, tag nor explained")
    return problems


# ---- entry points ---------------------------------------------------------------------------------
def _build(
    yaml_data,
    scenarios,
    actors,
    actor_groups=(),
    *,
    detail=True,
    _optimize=True,
    component_numbers=None,
    authentication_catalog=None,
    projected_victim=None,
):
    if projected_victim is None:
        d, victim_target, _role_notes = _project_legitimate_roles(yaml_data)
    else:
        d, victim_target = copy.deepcopy(yaml_data), projected_victim
    d["_component_numbers"] = component_numbers or {
        row["id"]: f"C-{i:02d}" for i, row in enumerate(d.get("components") or [], 1)
    }
    d["_overview"] = not detail
    d["_auth_catalog"] = (
        authentication_catalog
        if authentication_catalog is not None
        else (
            profile_catalog(d.get("data_flows") or [])
            if not detail or any(f.get("authentication") for f in d.get("data_flows") or [])
            else {}
        )
    )
    nodes, edges, tbs, tb_threats = _build_model(d, scenarios, actors, victim_target)
    if not detail:
        _overview_groups(nodes, edges)
    group_labels = {"internet-user": "Self-registered users", "repo-read": "Public-source readers"}
    for node in nodes.values():
        if not node.get("attacker"):
            continue
        sources = dict.fromkeys(source for source, target in actor_groups if target == node.get("actor_slug"))
        labels = [group_labels[source] for source in sources if source in group_labels]
        if labels:
            notes = ["Includes:", *labels, "Login / privileges: per finding"]
            node["group_lines"] = [line for note in notes for line in _legend_wrap(note, node["w"] - 40, 7.5)]
            title = f"{node['actor_code']} · {node['name']}"
            title_height = 12 * min(2, len(_wrap(title, node["w"] - 40, 10)))
            node["h"] = max(node["h"], 24 + title_height + 10 * len(node["group_lines"]))
    nodes, edges, dropped = _select_drawn(nodes, edges, d)
    _prepare_external_text(nodes)
    if not detail:
        edges, d["_references"] = select_references(d, nodes, edges, tb_threats)
        edges = bundle_access_groups(d, edges)
        _prepare_reference_rows(nodes)
        # The overview names no boundary IDs; the report catalogue lists them all.
        for node in nodes.values():
            node.pop("tags", None)
        for edge in edges:
            edge["tb"] = []
        d["_overview_tbs"] = [t["id"] for t in tbs]
    d["_boundary_gaps"] = _boundary_gaps(d, nodes, tbs)
    col_x, col_w, zone_boxes, boundaries, chips, height = _layout(nodes, edges, dropped, tb_threats, optimize=_optimize)
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
        actor_groups,
    )
    state = {"d": d, "nodes": nodes, "edges": edges, "chips": chips, "boundaries": boundaries, "canvas": canvas}
    if _optimize and d.get("_label_notes"):
        # Fewer bends must not displace readable payloads. Compare complete layouts
        # once, since endpoint markers and earlier labels also consume label space.
        alternative_svg, alternative = _build(
            yaml_data,
            scenarios,
            actors,
            actor_groups,
            detail=detail,
            _optimize=False,
            component_numbers=component_numbers,
            authentication_catalog=authentication_catalog,
            projected_victim=projected_victim,
        )
        missing = {fid for ids, _ in d["_label_notes"] for fid in ids}
        alternative_missing = {fid for ids, _ in alternative["d"].get("_label_notes", []) for fid in ids}
        if alternative_missing < missing and not (
            _check_geometry(
                alternative["nodes"],
                alternative["edges"],
                alternative["canvas"],
                alternative["chips"],
                boundaries=alternative["boundaries"],
            )
            + _audit(
                alternative["d"],
                alternative["nodes"],
                alternative["edges"],
                alternative["chips"],
                alternative["boundaries"],
                alternative["canvas"],
            )
        ):
            return alternative_svg, alternative
    return svg, state


def build_figure1_dfd_svg(yaml_data, attack_paths_data, attack_taxonomy, meta=None, actor_labels=None, *, detail=True):
    """Figure 1 for a threat model. Returns "" when there is nothing to draw."""
    if not (yaml_data.get("components") or []):
        return ""
    if detail:
        from figure1_detail import needs_views

        if needs_views(yaml_data):
            return check_diagram(yaml_data, attack_paths_data, attack_taxonomy, actor_labels, detail=True)[0]
    scenarios, actors = scenarios_from_attack_paths(
        yaml_data, attack_paths_data or {}, attack_taxonomy or {}, actor_labels
    )
    svg, _state = _build(
        yaml_data,
        scenarios,
        actors,
        overview_actor_groups(yaml_data, attack_paths_data, attack_taxonomy),
        detail=detail,
    )
    return svg


def check_diagram(
    yaml_data, attack_paths_data, attack_taxonomy, actor_labels=None, scenarios=None, actors=None, *, detail=True
):
    """Render and verify; returns (svg, problems). Used by the tests and the CLI."""
    if scenarios is None:
        scenarios, actors = scenarios_from_attack_paths(
            yaml_data, attack_paths_data or {}, attack_taxonomy or {}, actor_labels
        )
    if detail:
        from figure1_detail import build_views, needs_views

        if needs_views(yaml_data):
            return build_views(
                yaml_data, scenarios, actors or [], overview_actor_groups(yaml_data, attack_paths_data, attack_taxonomy)
            )
    svg, st = _build(
        yaml_data,
        scenarios,
        actors or [],
        overview_actor_groups(yaml_data, attack_paths_data, attack_taxonomy),
        detail=detail,
    )
    problems = _check_geometry(
        st["nodes"], st["edges"], st["canvas"], st["chips"], boundaries=st["boundaries"]
    ) + _audit(st["d"], st["nodes"], st["edges"], st["chips"], st["boundaries"], st["canvas"])
    return svg, problems


def main(argv):
    import yaml

    do_check = "--check" in argv
    detail = "--detail" in argv
    args = [a for a in argv if a not in {"--check", "--detail"}]
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
    svg, problems = check_diagram(d, {}, {}, scenarios=scenarios, actors=actors, detail=detail)
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
