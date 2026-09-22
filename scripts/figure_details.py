"""§2 detail figures: deterministic SVG views that each detail one aspect of Figure 1.

Figure 1 stays the overview. These views add what it leaves out, each for one
question, in Figure 1's visual language (palette, ``C-NN``, severity colours,
the authentication hexagon):

* deployment and technology (§2.2) — where each component runs and what it is
  built on, drawn by ``figure_deployment`` from ``.deployment-inventory.json``;
* controls (§2.3) — per component: exposure, threat tally and the effectiveness
  of the security controls evidenced on it.

Both read the threat model and the deployment inventory the scan wrote; neither
reads the repository, so a re-render shows the state of the scan. Each builder
returns ``None`` when its inputs are missing; the §2 generator then keeps that
subsection's Mermaid diagram. Every string drawn comes from the model or the
inventory and is XML-escaped; no figure contains scripts, links or environment
values.
"""

from __future__ import annotations

import html
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from _severity_rollup import register_severity, register_threats, risk_distribution_counts
from compose_services import Port, Service, service_at
from figure1_dfd import GREEN as F1_GREEN
from figure1_dfd import INK, MUTED, NAVY, ORANGE, RED, YELLOW, _affected_components
from pregenerate_fragments import component_coverage

# ---------------------------------------------------------------- style (Figure 1 family)
FONT = "Helvetica, Arial, sans-serif"
W = 1286
FAINT, RULE = "#94a3b8", "#d6dbe1"
NAVY_BG = "#eef2f7"
RED_BG = "#fff0ee"
AMBER, AMBER_BG = "#a8671f", "#fdf0e0"
YEL, YEL_BG = "#926200", "#fff5d6"
GREEN, GREEN_BG = "#28704b", "#e4f3e9"
BLUE, BLUE_BG = "#3f5f8a", "#eef3f9"
GREY, GREY_BG = "#64748b", "#edf2f7"
SEV = {"Critical": RED, "High": ORANGE, "Medium": YELLOW, "Low": F1_GREEN}
EFF = {  # schemas/fragments/security-controls.schema.json effectiveness enum
    "Unsafe": (RED_BG, RED, 4),
    "Missing": (RED_BG, RED, 4),
    "Weak": (AMBER_BG, AMBER, 3),
    "Partial": (YEL_BG, YEL, 2),
    "Adequate": (GREEN_BG, GREEN, 1),
}
EFF_TEXT = {  # same definitions as the schema
    "Unsafe": "relied upon but defeated or trivially bypassable — fix it",
    "Missing": "never built — add it",
    "Weak": "present, with exploitable gaps",
    "Partial": "covers some surfaces, meaningful gaps remain",
    "Adequate": "present and sound",
}
AUTH = {"none": ("0", RED, RED_BG), "unknown": ("?", GREY, GREY_BG)}  # Figure 1 access-port hexagon
DOMAINS = [  # classified by control name and domain text; model domain strings vary in wording
    ("AuthN", r"authentication gate|login|\bmfa\b|identity"),
    ("Session", r"jwt|session|token"),
    ("AuthZ", r"authori[sz]ation|idor|management endpoint|console access|access control"),
    ("Input /\nquery", r"parameteri[sz]ed|input|allowlist|query construction|injection"),
    ("Output\nencoding", r"output encoding|xss|rendering"),
    ("Secrets /\ncrypto", r"password hashing|secret|cryptograph|key management"),
    ("Transport", r"transport|\btls\b|encryption in transit"),
    ("Logging", r"logging|audit|monitoring"),
    ("Supply\nchain", r"pinning|ci/cd|\bsca\b|dependenc|lockfile|supply|signing|sbom"),
    ("LLM", r"\bllm\b|prompt|model output"),
]
SYSTEM_WIDE = "__system__"


@dataclass
class DetailFigure:
    key: str  # §2 subsection: "2.1".."2.4"
    number: int
    title: str
    takeaway: str
    svg: str


# ================================================================ drawing primitives
def esc(s) -> str:
    return html.escape(str(s), quote=True)


def tw(s, size, bold=False) -> float:
    return len(str(s)) * size * (0.61 if bold else 0.53)


def bw(label, size=9) -> float:
    return len(label) * size * 0.72 + 10


def wrap(s, size, width, bold=False) -> list[str]:
    lines, cur = [], ""
    for word in str(s).split():
        cand = (cur + " " + word).strip()
        if tw(cand, size, bold) > width and cur:
            lines.append(cur)
            cur = word
        else:
            cur = cand
    if cur:
        lines.append(cur)
    return lines


def clip(s, size, width, bold=False) -> str:
    s = str(s)
    if tw(s, size, bold) <= width:
        return s
    while s and tw(s + "…", size, bold) > width:
        s = s[:-1]
    return s + "…"


class Svg:
    def __init__(self, w=W):
        self.w, self.parts, self.h = w, [], 0.0

    def add(self, s):
        self.parts.append(s)

    def rect(self, x, y, w, h, fill="#fff", stroke=INK, sw=1, rx=6, dash=None, title=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        t = f"<title>{esc(title)}</title>" if title else ""
        self.add(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{max(w, 0):.1f}" height="{max(h, 0):.1f}" rx="{rx}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}>{t}</rect>'
        )
        self.h = max(self.h, y + h)

    def text(self, x, y, s, size=11, fill=INK, weight="normal", anchor="start", italic=False, title=None, rotate=False):
        st = ' font-style="italic"' if italic else ""
        rot = f' transform="rotate(-90 {x:.1f} {y:.1f})"' if rotate else ""
        t = f"<title>{esc(title)}</title>" if title else ""
        self.add(
            f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" fill="{fill}" font-weight="{weight}" '
            f'text-anchor="{anchor}"{st}{rot}>{t}{esc(s)}</text>'
        )
        if not rotate:
            self.h = max(self.h, y + 4)

    def lines(self, x, y, lines, size=11, lh=None, **kw):
        lh = lh or size * 1.35
        for i, ln in enumerate(lines):
            self.text(x, y + i * lh, ln, size=size, **kw)
        return y + len(lines) * lh

    def path(self, d, stroke=INK, sw=1.4, dash=None, marker=None):
        ds = f' stroke-dasharray="{dash}"' if dash else ""
        m = f' marker-end="url(#arw-{marker})"' if marker else ""
        self.add(f'<path d="{d}" fill="none" stroke="{stroke}" stroke-width="{sw}"{ds}{m}/>')

    def dot(self, x, y, color, r=4, title=None):
        t = f"<title>{esc(title)}</title>" if title else ""
        self.add(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}">{t}</circle>')

    def hexagon(self, x, y, scheme, count=None, title=None):
        num, col, bg = AUTH.get(scheme, ("✓", GREEN, GREEN_BG))
        self.add(
            f'<g data-authentication="{esc(num)}" transform="translate({x:.1f} {y:.1f})"><title>{esc(title or scheme)}</title>'
            f'<polygon points="0,0 5,-9 15,-9 20,0 15,9 5,9" fill="{bg}" stroke="{col}" stroke-width="1.2" '
            f'stroke-linejoin="round"/><text x="10" y="3.5" text-anchor="middle" font-size="10" '
            f'font-weight="bold" fill="{col}">{esc(num)}</text></g>'
        )
        if count is None:
            return x + 24
        self.text(x + 24, y + 4, f"×{count}", size=10, weight="bold", fill=col)
        return x + 24 + tw(f"×{count}", 10, True) + 8

    def badge(self, x, y, label, color, bg=None, size=9):
        w = bw(label, size)
        self.rect(x, y - size - 2, w, size + 6, fill=bg or "#fff", stroke=color, sw=1, rx=3)
        self.text(x + 5, y + 1, label, size=size, fill=color, weight="bold")
        return x + w + 4

    def label_bg(self, x, y, s, size=10, fill=MUTED, anchor="middle", weight="normal"):
        w = tw(s, size, weight == "bold") + 10
        x0 = x - w / 2 if anchor == "middle" else x - 5
        self.add(f'<rect x="{x0:.1f}" y="{y - size - 1:.1f}" width="{w:.1f}" height="{size + 6}" rx="2" fill="#fff"/>')
        self.text(x, y, s, size=size, fill=fill, anchor=anchor, weight=weight)

    def frame(self, number, title, aspect, subtitle, takeaway):
        self.text(20, 30, f"Figure {number} — {title}", size=17, fill=NAVY, weight="bold")
        lab = f"DETAIL OF FIGURE 1 · {aspect.upper()}"
        self.rect(20, 39, bw(lab, 9), 15, fill=NAVY_BG, stroke=NAVY, sw=1, rx=3)
        self.text(25, 50, lab, size=9, fill=NAVY, weight="bold")
        self.text(20 + bw(lab, 9) + 10, 50, subtitle, size=11, fill=MUTED)
        lines = wrap(takeaway, 12, self.w - 190, bold=True)
        h = 16 + 17 * len(lines)
        self.rect(20, 64, self.w - 40, h, fill=NAVY_BG, stroke=NAVY_BG, rx=4)
        self.rect(20, 64, 5, h, fill=NAVY, stroke=NAVY, rx=0)
        self.text(38, 86, "KEY TAKEAWAY", size=10, fill=NAVY, weight="bold")
        self.lines(150, 86, lines, size=12, lh=17, fill=INK, weight="bold")
        return 64 + h + 26

    def legend(self, y, items, note=None):
        """items: (kind, colour, background, label, text); kind in line|dash|box|badge|dot|cell|hex."""
        self.rect(20, y, self.w - 40, 24, fill=NAVY, stroke=NAVY, rx=4)
        self.text(self.w / 2, y + 16, "How to read this figure", size=12, fill="#fff", weight="bold", anchor="middle")
        y += 44
        colw = (self.w - 60) / 2
        for i, (kind, col, bg, label, txt) in enumerate(items):
            x = 30 + (i % 2) * colw
            yy = y + (i // 2) * 20
            tx = x + 44
            if kind in ("line", "dash"):
                self.path(
                    f"M{x} {yy - 4} L{x + 34} {yy - 4}", stroke=col, sw=2.2, dash="5 3" if kind == "dash" else None
                )
            elif kind == "box":
                self.rect(x + 8, yy - 11, 18, 13, fill=bg or "#fff", stroke=col, sw=2, rx=3)
            elif kind == "dot":
                self.dot(x + 17, yy - 4, col, r=5)
            elif kind == "hex":
                self.hexagon(x + 7, yy - 4, label)
            elif kind == "cell":
                self.rect(x, yy - 12, 60, 16, fill=bg, stroke=col, sw=1, rx=3)
                self.text(x + 30, yy, label, size=9, fill=col, weight="bold", anchor="middle")
                tx = x + 70
            else:
                self.badge(x, yy, label, col, bg)
                tx = x + 84
            self.text(tx, yy, txt, size=10, fill=INK)
        y += ((len(items) + 1) // 2) * 20
        for ln in wrap(note or "", 10, self.w - 60):
            self.text(30, y + 12, ln, size=10, fill=MUTED, italic=True)
            y += 14

    def render(self, number, title, pad=20) -> str:
        h = self.h + pad
        markers = "".join(
            f'<marker id="arw-{n}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="8" markerHeight="8" '
            f'markerUnits="userSpaceOnUse" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{c}"/></marker>'
            for n, c in {"grey": GREY, "red": RED, "amber": AMBER, "green": GREEN, "navy": NAVY}.items()
        )
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{h:.0f}" viewBox="0 0 {self.w} {h:.0f}" '
            f'font-family="{FONT}" role="img" aria-label="{esc(f"Figure {number} - {title}")}" data-figure="{number}">\n'
            f"<title>{esc(f'Figure {number} - {title}')}</title>\n"
            f'<rect width="{self.w}" height="{h:.0f}" fill="#ffffff"/><defs>{markers}</defs>\n'
            + "\n".join(self.parts)
            + "\n</svg>\n"
        )


# ================================================================ model
def _compact(s) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def _glob_re(g: str) -> re.Pattern:
    r = re.escape(g).replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.compile("^" + r + "$")


def _short_title(title: str) -> str:
    return re.split(r"\s+—\s+", str(title or ""))[0].strip()


class Model:
    """Everything the figures read, computed once from the model and the deployment inventory."""

    def __init__(self, yaml_data: dict, inventory: dict | None):
        self.d = yaml_data
        self.inventory = inventory if isinstance(inventory, dict) else {}
        self.comps = [c for c in yaml_data.get("components") or [] if isinstance(c, dict) and c.get("id")]
        # Same C-NN rule as the §2 component table (`_inject_components_table`).
        self.cnum = {
            c["id"]: c["id"] if re.match(r"^C-\d+$", str(c["id"])) else f"C-{i:02d}"
            for i, c in enumerate(self.comps, 1)
        }
        self.name = {c["id"]: str(c.get("name") or c["id"]) for c in self.comps}
        coverage = component_coverage(yaml_data.get("meta") or {}) or {}
        excluded = {str(e.get("id") or "") for e in coverage.get("excluded") or [] if isinstance(e, dict)}
        screened = {str(e.get("id") or "") for e in coverage.get("screened") or [] if isinstance(e, dict)}
        self.scope = {
            c["id"]: ("Out of scope" if c["id"] in excluded else "Screened" if c["id"] in screened else "Analyzed")
            if excluded or screened
            else ""
            for c in self.comps
        }
        self.flows = [f for f in yaml_data.get("data_flows") or [] if isinstance(f, dict)]
        self.controls = [
            c for c in yaml_data.get("security_controls") or [] if isinstance(c, dict) and c.get("control")
        ]
        self.surface = [a for a in yaml_data.get("attack_surface") or [] if isinstance(a, dict)]
        self.threat_total = sum(risk_distribution_counts(yaml_data).values())
        self.affected: dict[str, Counter] = defaultdict(Counter)
        self.owned: Counter = Counter()
        self.findings: list[dict] = []
        for t in register_threats(yaml_data):
            sev = register_severity(t)
            for cid in _affected_components(t):
                self.affected[cid][sev] += 1
            self.owned[t.get("component")] += 1
            m = re.match(r"^[FT]-(\d+)$", str(t.get("id") or ""))
            ev = t.get("evidence") if isinstance(t.get("evidence"), list) else []
            files = {str(e.get("file")) for e in ev if isinstance(e, dict) and e.get("file")}
            lines = {(str(e.get("file")), e.get("line")) for e in ev if isinstance(e, dict) and e.get("file")}
            self.findings.append(
                {
                    "fid": f"F-{m.group(1)}" if m else str(t.get("id") or "?"),
                    "sev": sev,
                    "title": _short_title(t.get("title")),
                    "cwe": str(t.get("cwe") or "").upper(),
                    "comp": t.get("component"),
                    "files": files,
                    "lines": lines,
                }
            )
        self.findings.sort(key=lambda f: (list(SEV).index(f["sev"]) if f["sev"] in SEV else 9, f["fid"]))
        # compose services of the scan (not of the current checkout)
        compose = self.inventory.get("compose") or {}
        self.compose_file = str(compose.get("file") or "")
        self.services: list[Service] = [
            Service(
                name=str(s.get("name")),
                file=self.compose_file,
                line=int(s.get("line") or 0),
                end_line=int(s.get("end_line") or 0),
                image=str(s.get("image") or ""),
                builds=bool(s.get("builds")),
                ports=[
                    Port(str(p.get("host") or ""), str(p.get("container") or ""), str(p.get("host_ip") or ""))
                    for p in s.get("ports") or []
                    if isinstance(p, dict)
                ],
            )
            for s in compose.get("services") or []
            if isinstance(s, dict) and s.get("name")
        ]
        self.svc_comp, self.in_process = self._map_services()

    def _map_services(self) -> tuple[dict[str, str], dict[str, list[str]]]:
        """Service → component by name similarity, then by model evidence inside the service block."""
        svc_comp: dict[str, str] = {}
        taken: set[str] = set()
        scored = []
        for svc in self.services:
            s = _compact(svc.name)
            for c in self.comps:
                for cand in (_compact(c["id"]), _compact(c.get("name"))):
                    if len(s) >= 4 and len(cand) >= 4 and (s in cand or cand in s):
                        scored.append((min(len(s), len(cand)) / max(len(s), len(cand)), svc.name, c["id"]))
        for _score, svc, cid in sorted(scored, reverse=True):
            if svc not in svc_comp and cid not in taken:
                svc_comp[svc] = cid
                taken.add(cid)
        votes: Counter = Counter()
        for f in self.flows:
            for ev in f.get("evidence") or []:
                if isinstance(ev, dict):
                    svc = service_at(self.services, str(ev.get("file")), ev.get("line"))
                    if svc and f.get("to") in self.cnum:
                        votes[(svc.name, f["to"])] += 1
        for (svc, cid), _n in votes.most_common():
            if svc not in svc_comp and cid not in taken:
                svc_comp[svc] = cid
                taken.add(cid)
        # A component without its own container whose source paths fall under a
        # mapped component's paths runs inside that container.
        in_process: dict[str, list[str]] = defaultdict(list)
        for c in self.comps:
            if c["id"] in taken:
                continue
            for host in [h for h in self.comps if h["id"] in taken]:
                if self._paths_inside(c, host):
                    in_process[host["id"]].append(c["id"])
                    break
        return svc_comp, dict(in_process)

    @staticmethod
    def _paths_inside(inner: dict, host: dict) -> bool:
        ip = [str(p) for p in inner.get("paths") or []]
        hp = [str(p) for p in host.get("paths") or []]
        if not ip or not hp:
            return False
        # Most of the inner component's sources sit in the host's build: companion
        # assets (static files, templates) may live elsewhere in the tree.
        inside = sum(1 for p in ip if p in hp or any(_glob_re(g).match(p) for g in hp))
        return inside * 2 > len(ip)

    def findings_where(self, pred) -> list[dict]:
        return [f for f in self.findings if pred(f)]


def _is_ci_file(p: str) -> bool:
    return p.startswith((".github/", ".gitlab-ci", ".circleci/")) or p.endswith("Jenkinsfile")


def _auth_counts(flows) -> Counter:
    return Counter(str((f.get("authentication") or {}).get("scheme") or "unknown") for f in flows)


# ================================================================ Figure: controls (§2.3)
# Specific domains first: "LLM Prompt Injection Guard" is an LLM control, not input validation.
_DOMAIN_PRIORITY = ["LLM", "Supply\nchain", "Transport"] + [
    d for d, _ in DOMAINS if d not in ("LLM", "Supply\nchain", "Transport")
]


def _domain_of(control: dict) -> str | None:
    rx = dict(DOMAINS)
    for text in (str(control.get("control", "")), f"{control.get('control', '')} {control.get('domain', '')}"):
        hit = next((d for d in _DOMAIN_PRIORITY if re.search(rx[d], text, re.I)), None)
        if hit:
            return hit
    return None


def _control_targets(m: Model, control: dict) -> set[str]:
    targets: set[str] = set()
    for part in filter(None, (p.strip() for p in str(control.get("implementation") or "").split(";"))):
        mt = re.match(r"([^:]+)(?::([\d,\-\s]+))?", part)
        path, lines = mt.group(1).strip(), mt.group(2)
        nums = [
            int(x.split("-")[0]) for x in re.split(r"[,\s]+", lines or "") if x.strip() and x.split("-")[0].isdigit()
        ]
        if m.compose_file and path == m.compose_file:
            hit = {m.svc_comp.get(svc.name) for n in nums if (svc := service_at(m.services, path, n))}
            hit.discard(None)
            targets |= hit or {SYSTEM_WIDE}
            continue
        scored = [
            (len(g.split("*")[0]), c["id"])
            for c in m.comps
            for g in c.get("paths") or []
            if _glob_re(str(g)).match(path)
        ]
        if scored:
            best = max(sc for sc, _ in scored)
            targets |= {cid for sc, cid in scored if sc == best}
        else:
            targets.add(SYSTEM_WIDE)
    if not targets:
        dom = _domain_of(control) or ""
        ci = [c["id"] for c in m.comps if any(_is_ci_file(str(p)) for p in c.get("paths") or [])]
        targets = set(ci) if dom.startswith("Supply") and ci else {SYSTEM_WIDE}
    return targets


def figure_controls(m: Model, number: int) -> DetailFigure | None:
    if not m.comps or not m.controls:
        return None
    cmap: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for c in m.controls:
        dom = _domain_of(c)
        if dom:
            for t in _control_targets(m, c):
                cmap[t][dom].append(c)
    worst = {
        cid: {
            d: max(cs, key=lambda k: EFF.get(k.get("effectiveness"), ("", "", 0))[2]).get("effectiveness")
            for d, cs in doms.items()
        }
        for cid, doms in cmap.items()
    }
    unsafe = [c for c in m.comps if any(e in ("Unsafe", "Missing") for e in worst.get(c["id"], {}).values())]
    cred = [
        c
        for c in m.comps
        if any(isinstance(x, dict) and x.get("category") == "credentials" for x in c.get("sensitive_data") or [])
    ]
    scope = m.scope
    bare = [c for c in m.comps if not cmap.get(c["id"]) and scope[c["id"]] != "Out of scope"]
    if cred and {c["id"] for c in cred} <= {c["id"] for c in unsafe}:
        take = f"Every component that handles credentials ({', '.join(m.cnum[c['id']] for c in cred)}) has at least one control rated Unsafe or Missing"
    elif unsafe:
        take = f"{len(unsafe)} component{'s have' if len(unsafe) != 1 else ' has'} at least one control rated Unsafe or Missing ({', '.join(m.cnum[c['id']] for c in unsafe)})"
    else:
        take = "No component has a control rated Unsafe or Missing"
    inbound = defaultdict(list)
    for f in m.flows:
        inbound[f.get("to")].append(f)
    if bare:
        open_ = all(_auth_counts(inbound.get(c["id"], [])).get("none") for c in bare)
        take += (
            f"; {len(bare)} component{'s have' if len(bare) != 1 else ' has'} no control evidenced at all "
            f"({', '.join(m.cnum[c['id']] for c in bare)})"
            + (", although each accepts unauthenticated traffic" if open_ else "")
        )
    take += "."
    s = Svg()
    title = "Component Exposure and Control Coverage"
    top = s.frame(
        number,
        title,
        "control coverage",
        "per component: how it is reached, what it handles, how effective its controls are",
        take,
    )

    pub = {m.svc_comp.get(svc.name) for svc in m.services if any(not p.loopback_only for p in svc.ports)}
    rank = ["Public", "Internal", "Confidential", "Restricted"]
    X0 = 20
    cols = [("Component", 262), ("Inbound flows", 100), ("Host\nport", 46), ("Data handled", 104), ("Threats", 122)]
    ctrl_w = (W - 40 - sum(w for _, w in cols)) / len(DOMAINS)
    ex_w = sum(w for _, w in cols[1:4])
    cx0 = X0 + sum(w for _, w in cols)
    y = top
    s.rect(X0 + cols[0][1], y, ex_w - 4, 18, fill=NAVY, stroke=NAVY, rx=3)
    s.text(X0 + cols[0][1] + ex_w / 2, y + 13, "EXPOSURE", size=10, fill="#fff", weight="bold", anchor="middle")
    s.rect(cx0 - cols[4][1], y, cols[4][1] - 4, 18, fill=NAVY, stroke=NAVY, rx=3)
    s.text(cx0 - cols[4][1] / 2, y + 13, "RISK", size=10, fill="#fff", weight="bold", anchor="middle")
    s.rect(cx0, y, ctrl_w * len(DOMAINS), 18, fill=NAVY, stroke=NAVY, rx=3)
    s.text(
        cx0 + ctrl_w * len(DOMAINS) / 2,
        y + 13,
        "CONTROLS — worst effectiveness evidenced on the component",
        size=10,
        fill="#fff",
        weight="bold",
        anchor="middle",
    )
    y += 26
    x = X0
    for label, w in cols:
        s.lines(
            x + (6 if label == "Component" else w / 2),
            y + 12,
            label.split("\n"),
            size=10,
            lh=12,
            weight="bold",
            fill=NAVY,
            anchor="start" if label == "Component" else "middle",
        )
        x += w
    for label, _ in DOMAINS:
        s.lines(x + ctrl_w / 2, y + 12, label.split("\n"), size=10, lh=12, weight="bold", fill=NAVY, anchor="middle")
        x += ctrl_w
    y += 34
    s.path(f"M{X0} {y} L{W - 20} {y}", stroke=NAVY, sw=1.2)
    y += 2
    RH = 48
    max_find = max((sum(m.affected[c["id"]].values()) for c in m.comps), default=0) or 1

    def cells(x, y, cid):
        for dom, _ in DOMAINS:
            cs = cmap.get(cid, {}).get(dom, [])
            if cs:
                eff = worst[cid][dom]
                fill, col, _r = EFF.get(eff, (GREY_BG, MUTED, 0))
                tip = "\n".join(f"{k.get('control')}: {k.get('effectiveness')}" for k in cs)
                s.rect(x + 3, y + 6, ctrl_w - 6, RH - 12, fill=fill, stroke=col, sw=1, rx=4, title=tip)
                s.text(
                    x + ctrl_w / 2,
                    y + (22 if len(cs) > 1 else 28),
                    eff or "?",
                    size=10,
                    weight="bold",
                    fill=col,
                    anchor="middle",
                    title=tip,
                )
                if len(cs) > 1:
                    s.text(x + ctrl_w / 2, y + 35, f"{len(cs)} controls", size=8, fill=MUTED, anchor="middle")
            else:
                s.text(x + ctrl_w / 2, y + 29, "–", size=11, fill="#c5cad1", anchor="middle")
            x += ctrl_w

    for i, c in enumerate(m.comps):
        cid = c["id"]
        oos = scope[cid] == "Out of scope"
        if i % 2 == 0:
            s.rect(X0, y, W - 40, RH, fill="#f8f9fb", stroke="none", rx=0)
        x = X0
        s.text(
            x + 6,
            y + 20,
            clip(f"{m.cnum[cid]} · {m.name[cid]}", 12, cols[0][1] - 14, True),
            size=12,
            weight="bold",
            fill=FAINT if oos else INK,
            title=m.name[cid],
        )
        s.text(
            x + 6,
            y + 36,
            " · ".join(v for v in (str(c.get("tier") or ""), scope[cid]) if v),
            size=10,
            fill=MUTED,
            italic=oos,
        )
        x += cols[0][1]
        fl = inbound.get(cid, [])
        if fl:
            auth = _auth_counts(fl)
            widths = sum(24 + tw(f"×{v}", 10, True) + 8 for v in auth.values()) - 8
            hx = x + (cols[1][1] - widths) / 2
            for k, v in auth.most_common():
                hx = s.hexagon(hx, y + 24, k, v, title=f"{v} inbound flow(s): authentication {k}")
        else:
            s.text(x + cols[1][1] / 2, y + 29, "none modeled", size=10, fill=FAINT, anchor="middle")
        x += cols[1][1]
        s.text(
            x + cols[2][1] / 2,
            y + 29,
            "yes" if cid in pub else "–",
            size=11,
            weight="bold" if cid in pub else "normal",
            fill=RED if cid in pub else "#c5cad1",
            anchor="middle",
        )
        x += cols[2][1]
        classes = [str(f.get("data_classification")) for f in m.flows if cid in (f.get("from"), f.get("to"))]
        top_cls = max(classes, key=lambda k: rank.index(k) if k in rank else -1) if classes else None
        sens = sorted(
            {str(d.get("category")) for d in c.get("sensitive_data") or [] if isinstance(d, dict) and d.get("category")}
        )
        if top_cls:
            s.text(
                x + cols[3][1] / 2,
                y + (21 if sens else 29),
                top_cls,
                size=10,
                weight="bold",
                fill={"Confidential": AMBER, "Restricted": RED}.get(top_cls, MUTED),
                anchor="middle",
            )
        else:
            s.text(x + cols[3][1] / 2, y + 29, "–", size=11, fill="#c5cad1", anchor="middle")
        if sens:
            s.text(
                x + cols[3][1] / 2,
                y + 36,
                clip(", ".join(sens), 9, cols[3][1] - 8),
                size=9,
                fill=MUTED,
                anchor="middle",
            )
        x += cols[3][1]
        aff = m.affected.get(cid, Counter())
        total = sum(aff.values())
        bx, bar_w = x + 6, cols[4][1] - 40
        if total:
            for sev in SEV:
                if aff.get(sev):
                    w = bar_w * aff[sev] / max_find
                    s.rect(bx, y + 12, w, 12, fill=SEV[sev], stroke="#fff", sw=0.5, rx=1, title=f"{aff[sev]} {sev}")
                    bx += w
            s.text(x + cols[4][1] - 8, y + 23, str(total), size=11, weight="bold", anchor="end")
            owned = m.owned.get(cid, 0)
            s.text(
                x + 6,
                y + 38,
                f"{owned} owned · {total - owned} shared" if total != owned else f"{owned} owned",
                size=9,
                fill=MUTED,
            )
        else:
            s.text(x + cols[4][1] / 2, y + 29, "none", size=10, fill=FAINT, anchor="middle")
        cells(cx0, y, cid)
        y += RH
    if cmap.get(SYSTEM_WIDE):
        s.path(f"M{X0} {y} L{W - 20} {y}", stroke=RULE, sw=1, dash="3 3")
        s.text(X0 + 6, y + 20, "System-wide", size=12, weight="bold", fill=NAVY)
        s.text(X0 + 6, y + 36, "evidence not tied to one component", size=10, fill=MUTED, italic=True)
        cells(cx0, y, SYSTEM_WIDE)
        y += RH
    s.path(f"M{X0} {y} L{W - 20} {y}", stroke=NAVY, sw=1.2)
    items = [("cell", EFF[e][1], EFF[e][0], e, EFF_TEXT[e]) for e in EFF]
    items += [
        ("cell", "#c5cad1", "#fff", "–", "no control of this domain evidenced on the component"),
        ("box", RED, RED, "", "threat bar: Critical · High · Medium — the counts on the Figure 1 nodes"),
        ("hex", RED, None, "none", "inbound flows without authentication — as in Figure 1"),
        ("hex", GREY, None, "unknown", "inbound flows whose authentication is unknown"),
    ]
    s.legend(
        y + 28,
        items,
        note="Figure 1 shows which STRIDE categories hit each component; this view shows which controls "
        "stand against them. Cells are placed by each control's implementation evidence (file → component paths; "
        "compose lines → service); a file shared by several components counts for each. Hover a cell for the individual "
        "controls; §6 holds the full assessment. Shared threats are merged from or instantiated on another component "
        "and count on both.",
    )
    return DetailFigure("2.3", number, title, take, s.render(number, title))


# ================================================================ entry point
def build_detail_figures(yaml_data: dict, inventory: dict | None, first_number: int = 3) -> dict[str, DetailFigure]:
    """§2 subsection → figure, numbered consecutively in section order; missing inputs leave a subsection out."""
    from figure_deployment import build as figure_deployment  # noqa: PLC0415 — figure_deployment imports this module

    m = Model(yaml_data, inventory)
    out: dict[str, DetailFigure] = {}
    number = first_number
    for build in (lambda n: figure_deployment(yaml_data, inventory, n), lambda n: figure_controls(m, n)):
        fig = build(number)
        if fig is not None:
            out[fig.key] = fig
            number += 1
    return out
