"""§2.2 Deployment and Technology figure: where each component runs and what it is built on.

Draws one deployment environment from ``.deployment-inventory.json`` (written by
``deployment_inventory.py`` during the scan) as nested boxes — cloud account or
cluster, network, service, workload — and places the model's components inside
the workload that runs the repository's image: container, process, framework,
embedded stores. Client components sit in the user-device column, the model's
outbound third parties in the right column, the CI systems and their publish
targets in a build lane underneath.

Each box carries its technology and version and at most three rule-chosen facts
(red: weakens a control, amber: needs a decision). Findings stay in Figure 1 and
§8, details in §6. Lines only run in corridors — straight where source and target
overlap, else bent once in the gap between two columns or in the gutter above
them — so no line runs along a border or through text.

When the environment deploys a single unit (one workload, or only a
Dockerfile), nesting adds no information, so ``build`` returns the same content
as a Markdown table instead of a figure.

The figure reads no repository file: a re-render shows the state of the scan.
``build`` returns ``None`` when the inventory declares neither a runtime nor an
environment; §2.2 then keeps its Mermaid diagram.
"""

from __future__ import annotations

import re
from collections import defaultdict
from functools import lru_cache

import yaml
from deployment_inventory import VOCAB_PATH, image_pin
from figure1_dfd import INK, MUTED
from figure_details import (
    AMBER,
    DETAIL_TABLE_MARKER,
    GREY,
    NAVY,
    NAVY_BG,
    RED,
    RED_BG,
    DetailFigure,
    Svg,
    W,
    md_cell,
    tw,
)

TITLE = "Deployment and Technology"
TONE = {"weak": RED, "decision": AMBER, "neutral": INK, "note": MUTED}
RANK = {"weak": 0, "decision": 1, "neutral": 2, "note": 3}
EMBEDDED_STORES = {"sqlite", "h2", "marsdb", "nedb", "lowdb", "leveldb", "rocksdb", "duckdb", "hsqldb", "derby"}
STYLE = {  # kind -> stroke, fill, stroke width, corner radius, dash
    "cloud": ("#b76e00", "#fffaf3", 1.3, 10, "6 4"),
    "cluster": ("#4f6d9c", "#f5f8fc", 1.3, 10, "6 4"),
    "network": ("#7a8ca6", "#f9fbfd", 1.1, 8, "4 3"),
    "service": (NAVY, "#fbfcfe", 1.2, 8, None),
    "workload": (NAVY, "#fbfcfe", 1.2, 8, None),
    "container": (NAVY, "#ffffff", 1.7, 8, None),
    "process": ("#8aa0bf", "#fbfcfe", 1.2, 8, None),
    "framework": (NAVY, "#ffffff", 1.2, 8, None),
    "store": ("#6b5b95", "#ffffff", 1.2, 8, None),
    "managed": ("#3f7a6b", "#ffffff", 1.2, 8, None),
    "external": (INK, "#ffffff", 1.2, 4, None),
}
ZONES = {
    "device": ("USER DEVICE", "#a0673f", "#fcf8f3"),
    "deploy": ("DEPLOYMENT", "#4f6d9c", "#f3f6fa"),
    "third": ("THIRD PARTIES", "#3f7a6b", "#f2f8f6"),
    "build": ("BUILD AND RELEASE", "#4b7a94", "#f3f8fa"),
}
PAD, HEAD, GAP, LH = 12, 30, 16, 14
DISPLAY = {
    "express": "Express",
    "angular": "Angular",
    "socket.io": "Socket.IO",
    "sqlite": "SQLite",
    "marsdb": "MarsDB",
    "h2": "H2",
    "spring": "Spring",
    "spring boot": "Spring Boot",
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "react": "React",
    "vue": "Vue",
    "next.js": "Next.js",
    "nestjs": "NestJS",
    "mongodb": "MongoDB",
    "postgresql": "PostgreSQL",
}


def display(name: str) -> str:
    """Known technologies in their own spelling; any other name exactly as the model or manifest writes it."""
    return DISPLAY.get(name.lower(), name)


def _store_of(token: str) -> str | None:
    """The embedded store a framework token names: its canonical name, a package alias from the
    technology vocabulary (`sqlite3`, `better-sqlite3`), or the name with a version digit or a
    `database` suffix appended (`sqlite3`, `h2database`)."""
    if token in EMBEDDED_STORES:
        return token
    for canon, names in (_vocab().get("frameworks") or {}).items():
        if canon in EMBEDDED_STORES and token in {str(n).lower() for n in names}:
            return canon
    for cand in (re.sub(r"\d+$", "", token), re.sub(r"database$", "", token)):
        if cand != token and cand in EMBEDDED_STORES:
            return cand
    return None


def _embedded(framework) -> list[str]:
    """Embedded stores named in a framework string, also in combined notation (`sequelize+sqlite`, `knex/duckdb`)."""
    text = str(framework or "").lower().strip()
    found = [_store_of(t) for t in [text, *re.split(r"[^a-z0-9.]+", text)] if t]
    return list(dict.fromkeys(s for s in found if s))


# ================================================================ text measurement (a margin wider than tw: nothing touches a border)
def text_w(s, size, bold=False) -> float:
    return tw(s, size, bold) * 1.06


def wrap_to(s, size, width, bold=False) -> list[str]:
    out, cur = [], ""
    for word in str(s).split():
        cand = (cur + " " + word).strip()
        if text_w(cand, size, bold) > width and cur:
            out.append(cur)
            cur = word
        else:
            cur = cand
    return out + ([cur] if cur else [])


def fit(s, size, width, bold=False) -> str:
    s = str(s)
    while text_w(s, size, bold) > width and len(s) > 4:
        s = s[:-2].rstrip() + "…"
    return s


# ================================================================ nested renderer
class Canvas:
    def __init__(self, cnum: dict, names: dict):
        self.s = Svg()
        self.cnum, self.names = cnum, names

    def chip_lines(self, w, cid):
        return wrap_to(f"{self.cnum[cid]} · {self.names[cid]}", 10, w - 24, True)[:2]

    def chip_h(self, w, cid):
        return 26 if len(self.chip_lines(w, cid)) == 1 else 40

    def chip(self, x, y, w, cid):
        self.s.rect(x, y, w, self.chip_h(w, cid), fill="#fff", stroke=NAVY, sw=1.2, rx=13)
        self.s.lines(x + 12, y + 17, self.chip_lines(w, cid), size=10, lh=14, weight="bold")

    def fact(self, x, y, w, fact) -> float:
        tone = fact.get("tone", "neutral")
        lines = wrap_to(fact["text"], 10, w, tone == "weak")
        self.s.lines(x, y + 10, lines, size=10, lh=LH, fill=TONE[tone], weight="bold" if tone == "weak" else "normal")
        return y + len(lines) * LH + 3


def render(node: dict, x, y, w, cv: Canvas, min_h=0.0, real=True) -> float:
    """Draw node at (x, y) with width w and return its height. The real pass measures first, then draws."""
    if node["kind"] == "bare":
        return _children(node, x, y, w, cv, real, pad=0) - y
    if real:
        h = render(node, x, y, w, Canvas(cv.cnum, cv.names), min_h, real=False)
        stroke, fill, sw, rx, dash = STYLE[node["kind"]]
        cv.s.rect(x, y, w, h, fill=fill, stroke=stroke, sw=sw, rx=rx, dash=dash)
        if node["kind"] == "container":
            cv.s.rect(x + 1, y + 1, w - 2, HEAD + 2, fill=NAVY_BG, stroke=NAVY_BG, rx=7)
        node["_pos"] = (x, y, w, h)
    s = cv.s
    hx = x + PAD
    size = 12.5 if node["kind"] in ("container", "framework", "process", "store") else 11.5
    if node["kind"] == "container":
        s.text(hx, y + 19, "CONTAINER", size=8.5, fill=NAVY, weight="bold")
        hx += text_w("CONTAINER", 8.5, True) + 8
    room = x + w - PAD - hx - (text_w(node.get("version", ""), 10.5) + 10 if node.get("version") else 0)
    tlines = wrap_to(node["title"], size, room, True)
    if len(tlines) > 3:
        tlines = tlines[:2] + [fit(" ".join(tlines[2:]), size, room, True)]
    tlines = tlines or [""]
    s.lines(hx, y + 19, tlines, size=size, lh=15, fill="#8a5200" if node["kind"] == "cloud" else NAVY, weight="bold")
    extra = 15 * (len(tlines) - 1)
    title = tlines[0]
    hx += text_w(title, size, True) + 8
    if node.get("version"):
        s.text(hx, y + 19, node["version"], size=10.5, fill=AMBER if _is_range(node["version"]) else MUTED)
        hx += text_w(node["version"], 10.5) + 8
    if node.get("badge"):
        lab, col, bg = node["badge"]
        if hx + text_w(lab, 8) + 16 < x + w - PAD:
            s.badge(hx, y + 19, lab, col, bg, size=8)
            hx += text_w(lab, 8) + 22
    if node.get("note") and x + w - PAD - hx > 60:
        s.text(x + w - PAD, y + 19, fit(node["note"], 9.5, x + w - PAD - hx - 10), size=9.5, fill=MUTED, anchor="end")
    cy = y + HEAD + 4 + extra
    iw = w - 2 * PAD
    for f in node.get("facts") or []:
        cy = cv.fact(x + PAD, cy, iw, f)
    if node.get("facts"):
        cy += 4
    comps = node.get("comps") or []
    if comps:
        cw = (iw - 12) / 2 if len(comps) > 1 else iw
        for r in range(0, len(comps), 2):
            row = comps[r : r + 2]
            for i, cid in enumerate(row):
                cv.chip(x + PAD + i * (cw + 12), cy, cw, cid)
            cy += max(cv.chip_h(cw, c) for c in row) + 6
        cy += 2
    if node.get("libs"):
        for ln in wrap_to(node["libs"], 9.5, iw):
            s.text(x + PAD, cy + 10, ln, size=9.5, fill=MUTED)
            cy += LH
        cy += 4
    if node.get("children"):
        cy = _children(node, x, cy + 2, w, cv, real, pad=PAD)
    return max(min_h, cy - y + PAD)


def _children(node, x, cy, w, cv, real, pad) -> float:
    kids = node.get("children") or []
    iw = w - 2 * pad
    if node.get("layout") == "row" and len(kids) > 1:
        for r in range(0, len(kids), 4):  # at most four side by side; further ones wrap to the next row
            row = kids[r : r + 4]
            n = len(row)
            cw = (iw - 12 * (n - 1)) / n
            rh = max(
                render(k, x + pad + i * (cw + 12), cy, cw, Canvas(cv.cnum, cv.names), 0, False)
                for i, k in enumerate(row)
            )
            for i, k in enumerate(row):
                render(k, x + pad + i * (cw + 12), cy, cw, cv, rh, real)
            cy += rh + (GAP if r + 4 < len(kids) else 0)
        return cy
    for i, k in enumerate(kids):
        cy += render(k, x + pad, cy, iw, cv, 0, real) + (GAP if i < len(kids) - 1 else 0)
    return cy


def _walk(node):
    yield node
    for k in node.get("children") or []:
        yield from _walk(k)


def _find(node, pred):
    return next((n for n in _walk(node) if pred(n)), None)


def _is_range(v: str) -> bool:
    return bool(re.search(r"^[\^~<>=*]|[*xX]$|\|\|", str(v).strip()))


# ================================================================ model → runtime subtree
@lru_cache(maxsize=1)
def _vocab() -> dict:
    return yaml.safe_load(VOCAB_PATH.read_text(encoding="utf-8")) or {}


def _cnum(comps: list[dict]) -> dict:
    """Same C-NN rule as Figure 1 and the §2 component table."""
    return {c["id"]: c["id"] if re.match(r"^C-\d+$", str(c["id"])) else f"C-{i:02d}" for i, c in enumerate(comps, 1)}


def _manifest_for(comp: dict, packages: list[dict]) -> dict | None:
    """The package manifest whose directory contains the component's paths most specifically."""
    paths = [str(p) for p in comp.get("paths") or [] if p]
    best, depth = None, -1
    for pkg in packages:
        mdir = pkg["manifest"].rpartition("/")[0]
        if all((not mdir) or p.startswith(mdir + "/") for p in paths[:3]) and paths:
            d = mdir.count("/") + (1 if mdir else 0)
            if d > depth:
                best, depth = pkg, d
    return best


def _framework_version(fw: str, pkg: dict | None) -> str:
    names = [n.lower() for n in (_vocab().get("frameworks") or {}).get(fw.lower(), [])]
    for e in (pkg or {}).get("entries") or []:
        if e["role"] == "framework" and e["name"].lower() in names:
            return e["version"]
    return ""


def _key_libs(pkg: dict | None, limit=4) -> str:
    entries = [e for e in (pkg or {}).get("entries") or [] if e["role"] != "framework"]
    order = ["identity", "data", "parse", "render", "edge", "llm"]
    entries.sort(key=lambda e: (order.index(e["role"]), e["name"]))
    seen, out = set(), []
    for e in entries:
        if e["role"] in seen and len(out) >= 2:
            continue
        seen.add(e["role"])
        out.append(f"{e['name']} {e['version']}".strip())
        if len(out) >= limit:
            break
    return " · ".join(out)


def _container(model_comps: list[dict], server: list[dict], stores: list[dict], inv: dict, image: str) -> dict:
    rt = inv.get("runtime") or {}
    packages = inv.get("packages") or []
    facts = []
    if rt.get("copies_repository"):
        sens = rt["copies_repository"]["sensitive"]
        facts.append(
            {
                "text": "image contains the whole repository" + (", including " + ", ".join(sens[:3]) if sens else ""),
                "tone": "weak" if sens else "note",
            }
        )
    if rt and (rt.get("user") is None or rt["user"]["value"].split(":")[0] in ("root", "0")):
        facts.append(
            {
                "text": "runs as root (no USER in the Dockerfile)" if rt.get("user") is None else "runs as root",
                "tone": "weak",
            }
        )
    by_fw: dict[str, list[dict]] = defaultdict(list)
    for c in server:
        by_fw[str(c.get("framework") or "application")].append(c)
    libs_shown: set[str] = set()
    fw_nodes = []
    for fw, cs in sorted(by_fw.items(), key=lambda kv: -len(kv[1])):
        pkg = _manifest_for(cs[0], packages)
        libs = ""
        if pkg and pkg["manifest"] not in libs_shown:
            libs = _key_libs(pkg)
            libs_shown.add(pkg["manifest"])
        fw_nodes.append(
            {
                "kind": "framework",
                "title": display(fw) if fw != "application" else "application code",
                "version": _framework_version(fw, pkg),
                "comps": [c["id"] for c in cs],
                "libs": libs,
                "children": [],
            }
        )
    process = {
        "kind": "process",
        "title": rt.get("runtime_label") or "application process",
        "note": "one process",
        "facts": [],
        "children": fw_nodes[:1]
        + ([{"kind": "bare", "layout": "row", "children": fw_nodes[1:]}] if fw_nodes[1:] else []),
        "_process": True,
    }
    store_nodes = []
    for c in stores:
        # Combined notation joins technologies with + / , or space; a package name keeps its own dashes and colons.
        parts = [t for t in re.split(r"[\s+/,]+", str(c.get("framework") or "").lower()) if t]
        pkg = _manifest_for(c, packages)
        store_nodes.append(
            {
                "kind": "store",
                "title": " + ".join(dict.fromkeys(display((_embedded(t) or [t])[0]) for t in parts))
                or c.get("name", "store"),
                "version": _framework_version(_embedded(c.get("framework"))[0], pkg),
                "comps": [c["id"]],
                "children": [],
                "facts": [{"text": "embedded in the process", "tone": "note"}],
            }
        )
    base = rt.get("base") or {}
    note = " · ".join(
        x
        for x in (
            base.get("image", "").split("/")[-1],
            f"user {rt['user']['value']}" if rt.get("user") else "",
            ":" + ",".join(rt.get("expose") or []) if rt.get("expose") else "",
        )
        if x
    )
    title = image or (f"built from {rt['dockerfile']}" if rt else "application container")
    floating = (image and image_pin(image) == "floating") or (not image and base.get("pin") == "floating")
    if base.get("pin") == "floating":
        facts.append({"text": f"base image {base['image'].split('/')[-1]} floats (no version tag)", "tone": "decision"})
    children = [process] + ([{"kind": "bare", "layout": "row", "children": store_nodes}] if store_nodes else [])
    return {
        "kind": "container",
        "title": title,
        "note": note,
        "badge": ("FLOATING", RED, RED_BG) if floating else None,
        "facts": sorted(facts, key=lambda f: RANK[f["tone"]])[:3],
        "children": children,
        "_container": True,
    }


def _tokens(s: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", s.lower())) - {
        "latest",
        "service",
        "server",
        "app",
        "application",
        "the",
        "and",
    }


def _place(
    env_tree: dict, comps: list[dict], server: list[dict], stores: list[dict], ext_stores: list[dict], inv: dict
) -> list[str]:
    """Put the runtime subtree into the workload that runs the repository image; chips into matching services.

    Returns the ids of components the environment gives no place.
    """
    workloads = [n for n in _walk(env_tree) if n["kind"] == "workload"]
    placed: set[str] = set()
    if workloads:
        host = workloads[0]
        container = _container(comps, server, stores, inv, host.get("image", ""))
        if container.get("badge"):  # the container's FLOATING badge already says it
            host["facts"] = [f for f in host.get("facts") or [] if not f["text"].endswith(" floats")]
        host.setdefault("children", []).append(container)
        placed |= {c["id"] for c in server + stores}
    services = [n for n in _walk(env_tree) if n["kind"] in ("service", "managed") and n is not env_tree]
    for c in ext_stores + ([] if workloads else server + stores):
        if c["id"] in placed:
            continue
        ctoks = _tokens(f"{c['id']} {c.get('name', '')} {c.get('framework', '')}")
        best = max(services, key=lambda n: len(ctoks & _tokens(n["title"] + " " + n.get("image", ""))), default=None)
        if best is not None and ctoks & _tokens(best["title"] + " " + best.get("image", "")):
            best.setdefault("comps", []).append(c["id"])
            placed.add(c["id"])
    return [c["id"] for c in server + stores + ext_stores if c["id"] not in placed]


def _to_render(node: dict) -> dict:
    """Inventory node → renderer node (facts already chosen by the scanner)."""
    out = {k: v for k, v in node.items() if k in ("kind", "title", "note", "role", "image", "layout", "facts", "comps")}
    out["children"] = [_to_render(k) for k in node.get("children") or []]
    if node.get("layout") == "row":  # an entry leads its row and an egress ends it: their lines then cross borders only
        out["children"].sort(key=lambda k: (k.get("role") != "entry", k.get("role") == "egress"))
    if node.get("image") and node["kind"] == "service":
        out["note"] = out.get("note") or node["image"].split("/")[-1]
    return out


def dev_clients(clients: list[dict], inv: dict) -> list[dict]:
    """One framework node per client component, with the version its package manifest declares."""
    out = []
    for c in clients:
        pkg = _manifest_for(c, inv.get("packages") or [])
        fw = str(c.get("framework") or "client code")
        out.append(
            {
                "kind": "framework",
                "title": display(fw),
                "version": _framework_version(fw, pkg),
                "comps": [c["id"]],
                "children": [],
            }
        )
    return out


def deployment_units(env: dict | None) -> int:
    """Units the environment deploys: workloads, managed services and services that run their own image.
    Without an environment the Dockerfile's container is the only unit."""
    if not env:
        return 1
    return sum(
        1
        for n in _walk(env["tree"])
        if n["kind"] in ("workload", "managed") or (n["kind"] == "service" and n.get("image"))
    )


# ================================================================ table (one deployment unit)
TONE_DOT = {"weak": "🔴", "decision": "🟠"}


def _facts_md(facts) -> str:
    return "; ".join(f"{TONE_DOT.get(f['tone'], '')} {md_cell(f['text'])}".strip() for f in facts or [])


def _node_md(n: dict, cnum: dict, where: str = "", nested: bool = False) -> str:
    """Title, version, component ids, note and facts of one renderer node, as one Markdown cell fragment.
    A nested fragment (one link of a chain) keeps its details in parentheses."""
    head = " ".join(md_cell(x) for x in (n.get("title"), n.get("version")) if x)
    ids = ", ".join(f"[{cnum[i]}](#{cnum[i].lower()})" for i in n.get("comps") or [] if i in cnum)
    extra = "; ".join(
        x for x in (ids, where, md_cell(n.get("note")) if n.get("note") else "", _facts_md(n.get("facts"))) if x
    )
    if not extra:
        return head
    return f"{head} ({extra})" if nested or ids or not head else f"{head}: {extra}"


def _table_rows(env, envs, tree, clients, thirds, inv, build_comps, cnum, names) -> list[str]:
    root = tree["children"][0] if tree["kind"] == "bare" else tree
    rows = ["| Layer | What runs there |", "|---|---|"]
    if env:
        chain = [
            _node_md(n, cnum, nested=True)
            for n in _walk(root)
            if n is not root and n["kind"] in ("cloud", "cluster", "network", "service", "workload", "managed")
        ]
        where = f"{md_cell(env['label'])} (`{md_cell(env['source'])}`)"
        rows.append(f"| Deployment | {where}" + (": " + " → ".join(chain) if chain else "") + " |")
    container = _find(tree, lambda n: n.get("_container"))
    if container:
        rows.append(f"| Container | {_node_md(container, cnum)} |")
        process = _find(container, lambda n: n.get("_process"))
        fws = [n for n in _walk(process) if n["kind"] == "framework"] if process else []
        if fws:
            libs = next((n["libs"] for n in fws if n.get("libs")), "")
            text = f"{md_cell(process['title'])}, one process: " + " · ".join(_node_md(n, cnum) for n in fws)
            rows.append(f"| Process | {text}" + (f"<br/>key libraries: {md_cell(libs)}" if libs else "") + " |")
        stores = [n for n in _walk(container) if n["kind"] == "store"]
        if stores:
            text = " · ".join(_node_md({**n, "facts": []}, cnum) for n in stores)
            rows.append(f"| Embedded stores | {text}, inside the same process |")
    for n in [k for k in (tree.get("children") or []) if tree["kind"] == "bare" and k is not root]:
        ids = ", ".join(f"[{cnum[i]}](#{cnum[i].lower()})" for i in n.get("comps") or [] if i in cnum)
        rows.append(f"| {md_cell(n['title'][0].upper() + n['title'][1:])} | {ids} |")
    if clients:
        rows.append(f"| Client | {' · '.join(_node_md(n, cnum) for n in clients)}, in the browser |")
    if thirds:
        where = "called from the browser"
        parts = [_node_md(t, cnum, where if t["_from_client"] else "", nested=True) for t in thirds]
        rows.append(f"| Third parties | {' · '.join(parts)} |")
    build = []
    for c in inv.get("ci") or []:
        text = md_cell(c["system"]) + (" → " + md_cell(", ".join(c["publishes"])) if c.get("publishes") else "")
        facts = _facts_md(c.get("facts", [])[:1])
        build.append(text + (f": {facts}" if facts else ""))
    rt, deps = inv.get("runtime"), inv.get("dependencies") or {}
    if rt:
        chain = " → ".join(
            [st["image"].split("/")[-1] for st in rt.get("build_stages") or []] + [rt["base"]["image"].split("/")[-1]]
        )
        text = f"container build (`{md_cell(rt['dockerfile'])}`): {md_cell(chain)}"
        if deps.get("ranges") and not deps.get("lockfile"):
            text += f"; 🟠 no lockfile: {deps['ranges']} version ranges resolved at build"
        build.append(text)
    if build_comps:
        build.append(
            "pipeline components " + ", ".join(f"[{cnum[c['id']]}](#{cnum[c['id']].lower()})" for c in build_comps)
        )
    note = _deploy_note(inv.get("ci") or [], env)
    if note:
        build.append(f"🟠 {md_cell(note)}")
    if build:
        rows.append(f"| Build and release | {'<br/>'.join(build)} |")
    if len(envs) > 1:
        others = "; ".join(f"{md_cell(e['label'])} (`{md_cell(e['source'])}`)" for e in envs[1:4])
        rows.append(f"| Also declared, not described | {others} |")
    return rows


# ================================================================ figure
def build(yaml_data: dict, inv: dict | None, number: int) -> DetailFigure | None:
    if not isinstance(inv, dict) or not (inv.get("runtime") or inv.get("environments")):
        return None
    comps = [c for c in yaml_data.get("components") or [] if isinstance(c, dict) and c.get("id")]
    if not comps:
        return None
    cnum = _cnum(comps)
    names = {c["id"]: str(c.get("name") or c["id"]) for c in comps}
    zones = {c["id"]: c.get("deployment_zones") or [] for c in comps}
    build_comps = [c for c in comps if "build-pipeline" in zones[c["id"]]]
    clients = [c for c in comps if c.get("tier") == "client" and c not in build_comps]
    data = [c for c in comps if c.get("tier") == "data" and c not in build_comps]
    stores = [c for c in data if _embedded(c.get("framework"))]
    ext_stores = [c for c in data if c not in stores]
    server = [c for c in comps if c not in build_comps + clients + data]

    envs = inv.get("environments") or []
    env = envs[0] if envs else None
    if env:
        tree = _to_render(env["tree"])
        unplaced = _place(tree, comps, server, stores, ext_stores, inv)
        if unplaced:  # below the environment: drawn inside it, the box would contradict its own title
            tree = {
                "kind": "bare",
                "children": [
                    tree,
                    {
                        "kind": "network",
                        "title": "components without a declared place",
                        "comps": unplaced,
                        "children": [],
                    },
                ],
            }
    else:  # only a Dockerfile: the container is the whole deployment
        tree = _container(comps, server, stores, inv, "")
        if ext_stores:
            tree = {
                "kind": "bare",
                "children": [
                    tree,
                    {
                        "kind": "network",
                        "title": "data stores outside the container",
                        "comps": [c["id"] for c in ext_stores],
                        "children": [],
                    },
                ],
            }

    # ---- third parties: external entities the system or its clients call
    ents = {e.get("id"): e for e in yaml_data.get("external_entities") or [] if isinstance(e, dict)}
    client_ids = {c["id"] for c in clients}
    outbound: dict[str, list[dict]] = defaultdict(list)
    for f in yaml_data.get("data_flows") or []:
        if isinstance(f, dict) and f.get("to") == "external" and f.get("to_entity") in ents:
            outbound[f["to_entity"]].append(f)
    thirds = []
    for eid, flows in outbound.items():
        from_client = all(f.get("from") in client_ids for f in flows)
        auth = [f.get("authentication") for f in flows if isinstance(f.get("authentication"), dict)]
        facts = []
        if any(a.get("scheme") == "none" for a in auth):
            proto = next((f.get("protocol") for f in flows if f.get("protocol")), "")
            facts.append({"text": f"{proto + ', ' if proto else ''}no authentication", "tone": "weak"})
        if any(a.get("flow") == "implicit" for a in auth):
            facts.append({"text": "OAuth implicit flow", "tone": "decision"})
        thirds.append(
            {
                "kind": "external",
                "title": str(ents[eid].get("name") or eid),
                "facts": facts[:2],
                "children": [],
                "_from_client": from_client,
                "_src": [f.get("from") for f in flows],
            }
        )
    thirds.sort(key=lambda n: (not n["_from_client"], n["title"]))

    if deployment_units(env) <= 1:  # one unit runs everything: nested boxes would add no layout, only size
        take = _takeaway(env, tree, server, stores, inv)
        rows = _table_rows(env, envs, tree, dev_clients(clients, inv), thirds, inv, build_comps, cnum, names)
        return DetailFigure("2.2", number, TITLE, take, markdown="\n".join([DETAIL_TABLE_MARKER, *rows]))

    cv = Canvas(cnum, names)
    s = cv.s
    take = _takeaway(env, tree, server, stores, inv)
    y0 = s.frame(number, TITLE, "deployment", "where each component runs and what it is built on", take)
    mark = len(s.parts)  # zones sized after their content are inserted here, below every box
    # One gutter lane and one corridor track per third party the browser calls: lanes never share a height,
    # and a lane enters its box from the side, so it never runs through the boxes stacked above it.
    lanes = sum(1 for t in thirds if t["_from_client"]) if clients else 0
    gut = 16 * lanes + 14 if lanes else 0
    top = y0 + gut
    DX, DW = 20, 232
    TW = 196 if thirds else 0
    TX = W - 20 - TW
    HX = DX + DW + 36
    HW = (TX - max(36, 28 + 8 * lanes) - HX) if thirds else (W - 20 - HX)
    box = tree["children"][0] if tree["kind"] == "bare" else tree  # a bare wrapper has no position of its own

    # ---- deployment column
    tree_h = render(tree, HX + 14, top + 34, HW - 28, Canvas(cnum, names), 0, False)
    deploy_h = tree_h + 34 + 14
    _zone(s, "deploy", HX, top, HW, deploy_h)
    render(tree, HX + 14, top + 34, HW - 28, cv, 0, True)

    # ---- device column: browser and the client components, or the model's human entry points
    bx, bw = DX + 14, DW - 28
    dev_nodes = dev_clients(clients, inv)
    y = top + 34
    s.rect(bx, y, bw, 28, fill="#fff", stroke=INK, sw=1.2, rx=4)
    s.text(bx + 12, y + 18, "Web browser" if clients else "Users and clients", size=11, weight="bold")
    browser = (bx, y, bw, 28)
    y += 40
    for n in dev_nodes:
        y += render(n, bx, y, bw, cv, 0, True) + 10
    dev_h = max(y - top + 6, 90)
    _zone(s, "device", DX, top, DW, dev_h, insert_at=mark)

    # ---- third-party column
    anchors = []
    if thirds:
        egress = _find(tree, lambda n: n.get("role") == "egress") or _find(tree, lambda n: n.get("_process")) or box
        ey = egress["_pos"][1] if "_pos" in egress else top + 34
        ty = top + 34
        for t in thirds:
            if not t["_from_client"]:
                ty = max(ty, ey + 4)
            h = render(t, TX + 14, ty, TW - 28, Canvas(cnum, names), 0, False)
            render(t, TX + 14, ty, TW - 28, cv, 0, True)
            anchors.append(t)
            ty += h + 18
        _zone(s, "third", TX, top, TW, ty - top - 2, insert_at=mark)

    # ---- connections
    entry = _find(tree, lambda n: n.get("role") == "entry") or _find(tree, lambda n: n.get("_container")) or box
    if "_pos" in entry:
        nx, ny, nw, nh = entry["_pos"]
        src = dev_nodes[0]["_pos"] if dev_nodes else browser
        ty_ = ny + 18
        if src[1] + 10 <= ty_ <= src[1] + src[3] - 10:
            s.path(f"M{src[0] + src[2]} {ty_} L{nx} {ty_}", stroke=NAVY, sw=1.5, marker="navy")
        else:
            gx = DX + DW + 18
            sy = src[1] + min(18, src[3] / 2)
            s.path(f"M{src[0] + src[2]} {sy} L{gx} {sy} L{gx} {ty_} L{nx} {ty_}", stroke=NAVY, sw=1.5, marker="navy")
        _chain_arrows(s, tree, entry)
    lane = 0
    for t in anchors:
        tx0, ty0, tw0, th0 = t["_pos"]
        weak = any(f["tone"] == "weak" for f in t["facts"])
        col, mk = (RED, "red") if weak else (GREY, "grey")
        if t["_from_client"] and clients:
            # lane 0 runs highest, starts leftmost and turns down rightmost: no two lanes cross
            gy = y0 + 10 + lane * 16
            gx = browser[0] + browser[2] - 30 - (lanes - 1 - lane) * 12
            cx = TX - 8 - lane * 8
            oy = ty0 + 18
            s.path(f"M{gx} {browser[1]} L{gx} {gy} L{cx} {gy} L{cx} {oy} L{tx0} {oy}", stroke=col, sw=1.5, marker=mk)
            label = fit(
                f"{', '.join(cnum[i] for i in dict.fromkeys(t['_src']) if i in cnum)} → {t['title']}", 9, HW - 40
            )
            lx = HX + HW / 2
            s.rect(lx - text_w(label, 9) / 2 - 6, gy - 8, text_w(label, 9) + 12, 15, fill="#fff", stroke="#fff", rx=2)
            s.text(lx, gy + 3, label, size=9, fill=col, anchor="middle")
            lane += 1
        else:
            egress = _find(tree, lambda n: n.get("role") == "egress") or _find(tree, lambda n: n.get("_process")) or box
            ex, ey, ew, eh = egress["_pos"]
            oy = ty0 + 18
            if ey + 8 <= oy <= ey + eh - 8:
                s.path(f"M{ex + ew} {oy} L{tx0} {oy}", stroke=col, sw=1.5, marker=mk)
            else:
                cx = HX + HW + 10  # left of the browser lanes' tracks
                s.path(f"M{ex + ew} {ey + 18} L{cx} {ey + 18} L{cx} {oy} L{tx0} {oy}", stroke=col, sw=1.5, marker=mk)

    # ---- build and release
    col_bottom = max(
        top + deploy_h, top + dev_h, (anchors[-1]["_pos"][1] + anchors[-1]["_pos"][3] + 16) if anchors else 0
    )
    y = _build_lane(cv, inv, env, col_bottom + 34, [c["id"] for c in build_comps], {c["id"]: c for c in comps})
    s.h = y
    s.legend(
        y + 26,
        [
            (
                "box",
                NAVY,
                "#fff",
                "",
                "box: where something runs — account, network, service, container, process, framework, store",
            ),
            ("box", NAVY, "#fff", "", "rounded chip: a component of the model (C-NN as in Figure 1)"),
            ("line", RED, None, "", "red: weakens a control"),
            ("line", AMBER, None, "", "amber: needs a decision; an amber version is a range"),
        ],
        note=_legend_note(envs),
    )
    return DetailFigure("2.2", number, TITLE, take, s.render(number, TITLE))


def _zone(s: Svg, key, x, y, w, h, insert_at: int | None = None):
    """A dashed column. A zone sized after its content is inserted at insert_at, underneath that content."""
    title, stroke, fill = ZONES[key]
    svg = (
        f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" rx="10" fill="{fill}" stroke="{stroke}" '
        f'stroke-width="1.2" stroke-dasharray="6 4"/>'
        f'<text x="{x + 14:.1f}" y="{y + 20:.1f}" font-size="10" fill="{stroke}" font-weight="bold">{title}</text>'
    )
    if insert_at is None:
        s.parts.append(svg)
    else:
        s.parts.insert(insert_at, svg)
    s.h = max(s.h, y + h)


def _chain_arrows(s: Svg, tree: dict, entry: dict):
    """entry → next stacked sibling → its workload: vertical arrows in the right part of the upper box."""
    parent = _find(tree, lambda n: entry in (n.get("children") or []))
    if not parent or (parent.get("layout") == "row"):
        target = _find(tree, lambda n: n["kind"] == "workload" and n is not entry)
        if target and "_pos" in target and target["_pos"][1] > entry["_pos"][1] + entry["_pos"][3]:
            px, py, pw, ph = entry["_pos"]
            vx = px + pw - 40
            s.path(f"M{vx} {py + ph} L{vx} {target['_pos'][1]}", stroke=NAVY, sw=1.5, marker="navy")
        return
    kids = parent["children"]
    i = kids.index(entry)
    prev = entry
    for nxt in kids[i + 1 :]:
        if "_pos" not in nxt or nxt["kind"] not in ("service", "workload", "managed"):
            break
        px, py, pw, ph = prev["_pos"]
        vx = px + pw - 40
        s.path(f"M{vx} {py + ph} L{vx} {nxt['_pos'][1]}", stroke=NAVY, sw=1.5, marker="navy")
        prev = nxt


def _top_segment(path: str) -> str:
    return str(path).split("/")[0]


def _build_lane(cv: Canvas, inv: dict, env: dict | None, by0: float, pipeline: list[str], comps: dict) -> float:
    """CI systems, the container build and the publish targets; the model's pipeline components sit in their CI box."""
    s = cv.s
    ci = inv.get("ci") or []
    rt = inv.get("runtime")
    deps = inv.get("dependencies") or {}
    if not ci and not rt and not pipeline:
        return by0 - 34
    systems = ci or [{"system": "no CI configuration", "source": "", "facts": [], "publishes": []}]
    x1, w1 = 36, 360
    held: list[list[str]] = [[] for _ in systems]
    for cid in pipeline:  # the CI system whose configuration the component's paths point at, else the first
        tops = {_top_segment(p) for p in comps[cid].get("paths") or []}
        i = next((k for k, c in enumerate(systems) if c["source"] and _top_segment(c["source"]) in tops), 0)
        held[i].append(cid)
    row_hs = [max(62, 46 + sum(cv.chip_h(w1 - 24, cid) + 6 for cid in ids) + 6) for ids in held]
    rows_h = sum(row_hs) + 10 * (len(row_hs) - 1)
    note = _deploy_note(ci, env)
    bh = 32 + rows_h + 10 + (18 if note else 0)
    title, stroke, fill = ZONES["build"]
    s.rect(20, by0, W - 40, bh, fill=fill, stroke=stroke, sw=1.2, rx=10, dash="6 4")
    s.text(34, by0 + 20, title, size=10, fill=stroke, weight="bold")
    x2, w2 = x1 + w1 + 50, 330
    x3 = x2 + w2 + 50
    w3 = W - 36 - x3
    top = by0 + 30
    if rt:
        s.rect(x2, top, w2, rows_h, fill="#fff", stroke=stroke, sw=1.2, rx=8)
        s.text(x2 + 12, top + 18, f"container build ({rt['dockerfile']})", size=11, weight="bold", fill=NAVY)
        chain = " → ".join(
            [st["image"].split("/")[-1] for st in rt.get("build_stages") or []] + [rt["base"]["image"].split("/")[-1]]
        )
        s.text(x2 + 12, top + 34, fit(chain, 9.5, w2 - 24), size=9.5, fill=MUTED)
        if deps.get("ranges") and not deps.get("lockfile"):
            s.text(
                x2 + 12,
                top + 48,
                fit(f"no lockfile: {deps['ranges']} version ranges resolved at build", 9.5, w2 - 24),
                size=9.5,
                fill=AMBER,
            )
    yy = top
    for c, ids, row_h in zip(systems, held, row_hs):
        s.rect(x1, yy, w1, row_h, fill="#fff", stroke=stroke, sw=1.2, rx=8)
        s.text(x1 + 12, yy + 18, fit(c["system"], 11, w1 - 24, True), size=11, weight="bold", fill=NAVY)
        f = (c.get("facts") or [None])[0]
        if f:
            s.text(x1 + 12, yy + 35, fit(f["text"], 9.5, w1 - 24), size=9.5, fill=TONE[f["tone"]])
        cy = yy + 46
        for cid in ids:
            cv.chip(x1 + 12, cy, w1 - 24, cid)
            cy += cv.chip_h(w1 - 24, cid) + 6
        if rt:
            s.path(f"M{x1 + w1} {yy + 31} L{x2} {yy + 31}", stroke=stroke, sw=1.5, marker="navy")
        if c.get("publishes"):
            s.rect(x3, yy, w3, 62, fill="#fff", stroke=stroke, sw=1.2, rx=8)
            s.text(
                x3 + 12, yy + 18, fit(", ".join(c["publishes"]), 11, w3 - 24, True), size=11, weight="bold", fill=NAVY
            )
            s.text(x3 + 12, yy + 35, "published by " + c["system"], size=9.5, fill=MUTED)
            src_x = x2 + w2 if rt else x1 + w1
            s.path(f"M{src_x} {yy + 31} L{x3} {yy + 31}", stroke=stroke, sw=1.5, marker="navy")
        yy += row_h + 10
    if note:
        s.text(x1, top + rows_h + 16, note, size=9.5, fill=AMBER)
    return by0 + bh


def _deploy_note(ci: list[dict], env: dict | None) -> str:
    if not env:
        return ""
    targets = " ".join(p for c in ci for p in c.get("publishes") or [])
    applied = "kubectl/Helm" in targets
    reaches = {
        "aws": "Amazon ECR" in targets or "terraform" in targets.lower(),
        "kubernetes": ("auto deploy" in targets) if env["source"].startswith(".gitlab") else applied,
        "openshift": applied,
        "helm": applied,
        "compose": True,
    }
    if reaches.get(env["platform"], True):
        return ""
    return f"No pipeline in the repository deploys to {env['label']}."


def _legend_note(envs: list[dict]) -> str:
    base = "Details per box — request pipeline, served paths, token handling — are in §6; findings per component in Figure 1 and §8."
    if len(envs) > 1:
        others = "; ".join(f"{e['label']} ({e['source']})" for e in envs[1:4])
        return f"Also declared in the repository, not drawn: {others}. " + base
    return base


def _takeaway(env: dict | None, tree: dict, server: list[dict], stores: list[dict], inv: dict) -> str:
    rt = inv.get("runtime") or {}
    where = {
        "aws": "one ECS task",
        "kubernetes": "one pod",
        "openshift": "one pod",
        "helm": "one pod",
        "compose": "one container",
    }
    parts = []
    host = _find(tree, lambda n: n.get("_container"))
    if host and server:
        what = f"{len(server)} server component{'s' if len(server) != 1 else ''}"
        if stores:
            what += f" and {len(stores)} embedded data store{'s' if len(stores) != 1 else ''}"
        runtime = rt.get("runtime_label") or "application"
        place = where.get(env["platform"], "one container") if env else "one container"
        verb = "runs" if len(server) == 1 and not stores else "run"
        parts.append(f"{what[0].upper() + what[1:]} {verb} in one {runtime} process in {place}.")
    facts = [f for n in _walk(tree) for f in n.get("facts") or []]
    weak = list(dict.fromkeys(f["text"] for f in facts if f["tone"] == "weak"))
    decision = list(dict.fromkeys(f["text"] for f in facts if f["tone"] == "decision"))
    floats = [d for d in decision if d.endswith(" floats") or " floats " in d]
    if len(floats) > 1:
        decision = [f"{len(floats)} images float on a moving tag"] + [d for d in decision if d not in floats]
    if weak:
        parts.append("Weakens a control: " + "; ".join(weak[:3]) + ".")
    elif decision:
        parts.append("Needs a decision: " + "; ".join(decision[:3]) + ".")
    return " ".join(parts) or "The repository declares where it runs; no setting in it weakens a control."
