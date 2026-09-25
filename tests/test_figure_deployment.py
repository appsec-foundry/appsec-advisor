"""Tests for scripts/figure_deployment.py — the §2.2 Deployment and Technology figure.

The figure is drawn from the model and the scan's deployment inventory. Each environment kind gets a neutral and a
renamed variant; every rendered figure must also be drawn cleanly: no line segment runs through a box that contains
neither of its ends, and no text runs past the right edge of the box that holds it. An environment with a single
deployment unit, or only a Dockerfile, yields the same content as a Markdown table instead of a figure.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import deployment_inventory as DI
import figure_deployment as FDEP
import pytest
from figure_details import tw

from tests.test_deployment_inventory import MANIFESTS, SHA, TF

NS = "{http://www.w3.org/2000/svg}"
SECOND_WORKLOAD = """---
apiVersion: apps/v1
kind: Deployment
metadata: {{name: {app}, namespace: {ns}}}
spec:
  template:
    metadata: {{labels: {{app: {app}}}}}
    spec:
      containers:
        - name: {app}
          image: registry.example/{app}:2.0.1
"""


def _names(variant: bool) -> dict:
    if variant:
        return {
            "ui": "portal",
            "api": "catalog",
            "auth": "identity",
            "ws": "notify",
            "db": "cache",
            "idx": "search",
            "llm": "Model Gateway",
            "idp": "Single Sign-On",
            "img": "catalog",
        }
    return {
        "ui": "web",
        "api": "orders",
        "auth": "login",
        "ws": "events",
        "db": "store",
        "idx": "index",
        "llm": "Language Model Server",
        "idp": "Identity Provider",
        "img": "orders",
    }


def _model(n: dict) -> dict:
    return {
        "meta": {"project": "Shop"},
        "components": [
            {
                "id": f"{n['ui']}-ui",
                "name": f"{n['ui'].title()} UI",
                "tier": "client",
                "framework": "react",
                "paths": ["ui/src/**"],
                "deployment_zones": ["client-device"],
            },
            {
                "id": f"{n['api']}-api",
                "name": f"{n['api'].title()} API",
                "tier": "application",
                "framework": "express",
                "paths": ["src/api/**"],
            },
            {
                "id": f"{n['auth']}-svc",
                "name": f"{n['auth'].title()} Service",
                "tier": "application",
                "framework": "express",
                "paths": ["src/auth/**"],
            },
            {
                "id": f"{n['ws']}-ws",
                "name": f"{n['ws'].title()} Channel",
                "tier": "application",
                "framework": "socket.io",
                "paths": ["src/ws/**"],
            },
            {
                "id": f"{n['db']}-db",
                "name": f"{n['db'].title()} Database",
                "tier": "data",
                "framework": "sqlite",
                "paths": ["src/db/**"],
            },
            {
                "id": f"{n['idx']}-idx",
                "name": f"{n['idx'].title()} Index",
                "tier": "data",
                "framework": "elasticsearch",
                "paths": [],
            },
            {
                "id": "pipeline",
                "name": "Build Pipeline",
                "tier": "application",
                "paths": [".github/**"],
                "deployment_zones": ["build-pipeline"],
            },
        ],
        "external_entities": [{"id": "ext-llm", "name": n["llm"]}, {"id": "ext-idp", "name": n["idp"]}],
        "data_flows": [
            {
                "id": "df-1",
                "from": f"{n['api']}-api",
                "to": "external",
                "to_entity": "ext-llm",
                "protocol": "HTTP",
                "authentication": {"scheme": "none"},
            },
            {
                "id": "df-2",
                "from": f"{n['ui']}-ui",
                "to": "external",
                "to_entity": "ext-idp",
                "protocol": "HTTPS",
                "authentication": {"scheme": "oauth2", "flow": "implicit"},
            },
        ],
        "threats": [],
    }


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _repo(tmp_path: Path, n: dict, env: str) -> Path:
    root = tmp_path / f"repo-{env}"
    _write(
        root,
        "Dockerfile",
        'FROM node:24 AS build\nRUN npm ci\nFROM node:24-slim\nCOPY . /app\nUSER 1000\nEXPOSE 3000\nCMD ["node", "app.js"]\n',
    )
    _write(
        root,
        "package.json",
        json.dumps(
            {
                "dependencies": {
                    "express": "^4.21.0",
                    "socket.io": "4.8.1",
                    "jsonwebtoken": "9.0.2",
                    "sqlite3": "5.1.7",
                    "react": "18.3.1",
                }
            }
        ),
    )
    _write(root, ".github/workflows/ci.yml", f"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@{SHA}\n")
    if env in ("k8s", "k8s2"):
        _write(
            root,
            "deploy/app.yaml",
            MANIFESTS.format(ns="shop", svc=f"{n['img']}-svc", app=n["img"], host=f"{n['img']}.example.test")
            + (SECOND_WORKLOAD.format(ns="shop", app=f"{n['idx']}-worker") if env == "k8s2" else ""),
        )
    elif env == "aws":
        _write(root, "infra/main.tf", TF.format(p=n["img"], port=80, proto="HTTP"))
    elif env == "compose":
        _write(
            root,
            "compose.yaml",
            f'services:\n  edge:\n    image: nginx:1.27.0\n    ports:\n      - "80:80"\n'
            f"  {n['idx']}:\n    image: elasticsearch:8.15.0\n",
        )
    return root


def _figure(tmp_path: Path, variant: bool, env: str):
    n = _names(variant)
    inv = DI.build_inventory(_repo(tmp_path, n, env))
    assert DI.validation_errors(inv) == []
    return n, inv, FDEP.build(_model(n), inv, 3)


# ---------------------------------------------------------------- drawing hygiene
def _num(v) -> float:
    return float(v or 0)


def _boxes(root) -> list[tuple[float, float, float, float]]:
    out = []
    for el in root.iter(f"{NS}rect"):
        stroke = el.get("stroke", "")
        if stroke in ("", "none", "#fff", "#ffffff", "#eef2f7") or _num(el.get("width")) < 8:
            continue
        out.append((_num(el.get("x")), _num(el.get("y")), _num(el.get("width")), _num(el.get("height"))))
    return out


def _inside(pt, box, strict=False) -> bool:
    x, y = pt
    bx, by, bw, bh = box
    m = 1.0 if strict else -0.5
    return bx + m < x < bx + bw - m and by + m < y < by + bh - m


def _segments(d: str):
    pts = [(float(a), float(b)) for a, b in re.findall(r"[ML]\s*(-?[\d.]+)[ ,]\s*(-?[\d.]+)", d)]
    return pts, list(zip(pts, pts[1:]))


def _crosses(seg, box) -> bool:
    (x1, y1), (x2, y2) = seg
    steps = max(2, int(max(abs(x2 - x1), abs(y2 - y1)) / 2))
    return any(
        _inside((x1 + (x2 - x1) * t / steps, y1 + (y2 - y1) * t / steps), box, strict=True) for t in range(steps + 1)
    )


def assert_drawn_cleanly(svg: str) -> None:
    root = ET.fromstring(svg)
    boxes = _boxes(root)
    for path in root.iter(f"{NS}path"):
        pts, segs = _segments(path.get("d", ""))
        if len(pts) < 2 or path.get("marker-end") is None:
            continue  # legend strokes and marker glyphs
        start, end = pts[0], pts[-1]
        for seg in segs:
            for box in boxes:
                if _inside(start, box) or _inside(end, box):
                    continue  # an ancestor the line leaves or the box it enters
                assert not _crosses(seg, box), f"line {path.get('d')} runs through box {box}"
    for text in root.iter(f"{NS}text"):
        content = "".join(text.itertext())
        if not content.strip() or text.get("text-anchor") in ("middle", "end") or text.get("transform"):
            continue
        x, y = _num(text.get("x")), _num(text.get("y"))
        size = _num(text.get("font-size")) or 11
        holders = [b for b in boxes if _inside((x + 1, y - size / 2), b)]
        if not holders:
            continue
        bx, _by, bw, _bh = min(holders, key=lambda b: b[2] * b[3])
        assert x + tw(content, size, text.get("font-weight") == "bold") <= bx + bw + 1, (
            f"text {content!r} runs past its box"
        )


# ---------------------------------------------------------------- environments
@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_kubernetes_manifests_nest_the_runtime_in_the_workload(tmp_path: Path, variant: bool):
    n, inv, fig = _figure(tmp_path, variant, "k8s2")
    assert fig.key == "2.2" and fig.number == 3 and fig.title == "Deployment and Technology"
    root = ET.fromstring(fig.svg)
    texts = " ".join("".join(t.itertext()) for t in root.iter(f"{NS}text"))
    for expected in (
        f"Route {n['img']}.example.test",
        f"Service {n['img']}-svc",
        "Node.js 24",
        "Express",
        "Socket.IO",
        "SQLite",
        n["llm"],
        "React",
    ):
        assert expected in texts, expected
    # the embedded store sits in the container, the external index gets no invented place
    assert "components without a declared place" in texts and f"{n['idx'].title()} Index" in texts
    assert fig.takeaway.startswith(
        "3 server components and 1 embedded data store run in one Node.js 24 process in one pod."
    )
    assert "plain HTTP also accepted" in fig.takeaway
    assert f"C-01 → {n['idp']}" in texts  # the browser's own call runs through the gutter
    assert_drawn_cleanly(fig.svg)


@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_aws_terraform_environment_and_deploy_note(tmp_path: Path, variant: bool):
    n, inv, fig = _figure(tmp_path, variant, "aws")
    texts = " ".join("".join(t.itertext()) for t in ET.fromstring(fig.svg).iter(f"{NS}text"))
    assert "AWS · eu-west-1" in texts and "ECS Fargate · 3 tasks" in texts and "Load balancer" in texts
    assert "in one ECS task" in fig.takeaway and "HTTP :80 from 0.0.0.0/0 — no TLS" in fig.takeaway
    assert "No pipeline in the repository deploys to AWS · eu-west-1." in texts
    assert_drawn_cleanly(fig.svg)
    # Negative: once a pipeline pushes to ECR the note disappears.
    inv["ci"][0]["publishes"] = ["Amazon ECR"]
    texts = " ".join("".join(t.itertext()) for t in ET.fromstring(FDEP.build(_model(n), inv, 3).svg).iter(f"{NS}text"))
    assert "No pipeline in the repository deploys" not in texts


@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_compose_images_hold_matching_components_by_name(tmp_path: Path, variant: bool):
    n, inv, fig = _figure(tmp_path, variant, "compose")
    compose_env = next(e for e in inv["environments"] if e["platform"] == "compose")
    idx_service = next(c for c in compose_env["tree"]["children"] if c["title"] == n["idx"])
    assert idx_service["kind"] == "service"
    texts = " ".join("".join(t.itertext()) for t in ET.fromstring(fig.svg).iter(f"{NS}text"))
    assert "docker compose host" in texts and "host port :80 on every interface" in texts
    assert "components without a declared place" in texts  # no service builds the repository: the runtime has no host
    assert_drawn_cleanly(fig.svg)


def test_dockerfile_only_describes_the_container_as_the_deployment(tmp_path: Path):
    n, inv, fig = _figure(tmp_path, False, "none")
    assert inv["environments"] == []
    assert fig.takeaway.startswith(
        "3 server components and 1 embedded data store run in one Node.js 24 process in one container."
    )
    assert not fig.svg and fig.markdown.startswith("<!-- detail-table -->\n| Layer | What runs there |")
    assert "| Container | built from Dockerfile" in fig.markdown
    assert "| Data stores outside the container | [C-06](#c-06) |" in fig.markdown


@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_one_deployment_unit_is_a_table_not_a_figure(tmp_path: Path, variant: bool):
    n, inv, fig = _figure(tmp_path, variant, "k8s")
    assert fig.key == "2.2" and not fig.svg
    rows = {ln.split(" | ")[0].lstrip("| "): ln for ln in fig.markdown.splitlines()[3:]}
    assert f"Route {n['img']}.example.test (" in rows["Deployment"]
    assert f"→ Service {n['img']}-svc (ClusterIP :8080 → 3000) → Deployment {n['img']}" in rows["Deployment"]
    assert rows["Process"].startswith(
        "| Process | Node.js 24, one process: Express ^4.21.0 ([C-02](#c-02), [C-03](#c-03))"
    )
    assert "SQLite 5.1.7 ([C-05](#c-05))" in rows["Embedded stores"]
    assert rows["Client"] == "| Client | React 18.3.1 ([C-01](#c-01)), in the browser |"
    assert f"{n['idp']} (called from the browser; 🟠 OAuth implicit flow)" in rows["Third parties"]
    assert f"{n['llm']} (🔴 HTTP, no authentication)" in rows["Third parties"]
    assert rows["Components without a declared place"] == "| Components without a declared place | [C-06](#c-06) |"
    assert "Build and release" in rows and "plain-secret-value" not in fig.markdown
    assert fig.takeaway.startswith(
        "3 server components and 1 embedded data store run in one Node.js 24 process in one pod."
    )
    # Negative: a second workload in the same environment keeps the nested figure.
    _, _, two = _figure(tmp_path / "two", variant, "k8s2")
    assert two.svg and not two.markdown


def test_table_keeps_inventory_strings_inert(tmp_path: Path):
    n, inv, _ = _figure(tmp_path, False, "k8s")
    inv["environments"][0]["tree"]["children"][0]["title"] = "<script>alert(1)</script> | [x](https://evil.example)"
    inv["environments"][0]["label"] = "`shell`"
    md = FDEP.build(_model(n), inv, 3).markdown
    assert "<script>" not in md and "&lt;script&gt;" in md
    assert "\\| \\[x\\](https://evil.example)" in md  # escaped: text, not a link
    assert "\\`shell\\`" in md
    assert all(ln.count(" | ") == 1 for ln in md.splitlines()[1:] if ln.startswith("| ") and "---" not in ln)


def test_further_environments_are_named_not_drawn(tmp_path: Path):
    n = _names(False)
    root = _repo(tmp_path, n, "aws")
    _write(root, "deploy/app.yaml", MANIFESTS.format(ns="shop", svc="s", app="a", host="h"))
    fig = FDEP.build(_model(n), DI.build_inventory(root), 3)
    texts = " ".join("".join(t.itertext()) for t in ET.fromstring(fig.svg).iter(f"{NS}text"))
    assert "Also declared in the repository, not drawn: OpenShift · namespace shop (deploy/app.yaml)." in texts


def test_nothing_to_draw_returns_none():
    """Negative: no runtime and no environment, or no components, leaves §2.2 to its Mermaid diagram."""
    model = _model(_names(False))
    assert FDEP.build(model, None, 3) is None
    assert FDEP.build(model, {"runtime": None, "environments": []}, 3) is None
    assert FDEP.build({"components": []}, {"runtime": {"x": 1}, "environments": []}, 3) is None


def test_hostile_inventory_strings_stay_text(tmp_path: Path):
    n, inv, _ = _figure(tmp_path, False, "k8s2")
    inv["environments"][0]["tree"]["children"][0]["title"] = "<script>alert(1)</script>"
    inv["environments"][0]["label"] = "</text><svg onload=1>"
    fig = FDEP.build(_model(n), inv, 3)
    tree = ET.fromstring(fig.svg)
    assert not {el.tag.rsplit("}", 1)[-1] for el in tree.iter()} & {"script", "foreignObject", "a"}
    assert not any(k.lower().startswith("on") for el in tree.iter() for k in el.attrib)


def test_hygiene_check_catches_a_line_through_a_box():
    """The drawing check itself: a line crossing a sibling box fails."""
    bad = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="400" height="200">'
        '<rect x="0" y="0" width="60" height="60" stroke="#000"/>'
        '<rect x="100" y="0" width="60" height="60" stroke="#000"/>'
        '<rect x="200" y="0" width="60" height="60" stroke="#000"/>'
        '<path d="M30 30 L230 30" marker-end="url(#arw-navy)"/></svg>'
    )
    with pytest.raises(AssertionError, match="runs through box"):
        assert_drawn_cleanly(bad)


# ---------------------------------------------------------------- placement and routing regressions
def _texts(svg: str) -> list[tuple[str, float, float]]:
    return [("".join(t.itertext()), _num(t.get("x")), _num(t.get("y"))) for t in ET.fromstring(svg).iter(f"{NS}text")]


def _rect_of(svg: str, stroke: str, dash: str) -> list[tuple[float, float, float, float]]:
    return [
        (_num(r.get("x")), _num(r.get("y")), _num(r.get("width")), _num(r.get("height")))
        for r in ET.fromstring(svg).iter(f"{NS}rect")
        if r.get("stroke") == stroke and r.get("stroke-dasharray") == dash
    ]


@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_build_pipeline_components_are_drawn_in_the_build_lane(tmp_path: Path, variant: bool):
    n = _names(variant)
    model = _model(n)
    if variant:
        model["components"][-1].update(id="release-flow", name="Release Workflow")
    inv = DI.build_inventory(_repo(tmp_path, n, "k8s2"))
    fig = FDEP.build(model, inv, 3)
    label = "Release Workflow" if variant else "Build Pipeline"
    chip = next((t for t in _texts(fig.svg) if t[0].endswith(label)), None)
    assert chip is not None, "the pipeline component has no chip"
    lane = next(t for t in _texts(fig.svg) if t[0] == "BUILD AND RELEASE")
    assert chip[2] > lane[2]  # drawn inside the build lane, not in the deployment
    assert_drawn_cleanly(fig.svg)


@pytest.mark.parametrize("count", [2, 4])
def test_several_third_parties_called_from_the_browser_keep_lines_and_labels_apart(tmp_path: Path, count: int):
    n = _names(count == 4)
    model = _model(n)
    ui = model["components"][0]["id"]
    for i in range(count):
        model["external_entities"].append({"id": f"cdn-{i}", "name": f"Asset Host {i}"})
        model["data_flows"].append(
            {"id": f"df-c{i}", "from": ui, "to": "external", "to_entity": f"cdn-{i}", "protocol": "HTTPS"}
        )
    fig = FDEP.build(model, DI.build_inventory(_repo(tmp_path, n, "k8s2")), 3)
    assert_drawn_cleanly(fig.svg)
    labels = sorted(t[2] for t in _texts(fig.svg) if " → " in t[0] and t[0].startswith("C-"))
    assert len(labels) == count + 1  # the identity provider plus the asset hosts
    assert all(b - a >= 15 for a, b in zip(labels, labels[1:])), labels
    takeaway_bottom = max(t[2] for t in _texts(fig.svg) if t[1] == 150)  # the takeaway lines
    assert labels[0] - 9 > takeaway_bottom + 4


@pytest.mark.parametrize("framework", ["sequelize+sqlite", "knex/duckdb"])
def test_embedded_store_is_recognized_in_a_combined_framework(tmp_path: Path, framework: str):
    n = _names(False)
    model = _model(n)
    model["components"][4]["framework"] = framework
    fig = FDEP.build(model, DI.build_inventory(_repo(tmp_path, n, "k8s")), 3)
    assert "1 embedded data store" in fig.takeaway
    # Negative: a server database in the same notation stays outside the process.
    model["components"][4]["framework"] = "sequelize+postgresql"
    assert "embedded data store" not in FDEP.build(model, DI.build_inventory(_repo(tmp_path, n, "k8s")), 3).takeaway


def test_components_without_a_place_are_drawn_outside_the_environment(tmp_path: Path):
    n = _names(False)
    fig = FDEP.build(_model(n), DI.build_inventory(_repo(tmp_path, n, "k8s2")), 3)
    cluster = [r for r in _rect_of(fig.svg, "#4f6d9c", "6 4") if r[1] > 150]
    env = min(cluster, key=lambda r: r[2] * r[3])  # the environment box; the larger one is the zone
    label = next(t for t in _texts(fig.svg) if t[0] == "components without a declared place")
    assert label[2] > env[1] + env[3], "drawn inside the environment it has no place in"
    assert_drawn_cleanly(fig.svg)


def test_names_keep_their_spelling_and_one_component_runs(tmp_path: Path):
    n = _names(False)
    model = _model(n)
    model["components"] = [model["components"][0], {**model["components"][1], "framework": "ai-sdk"}]
    fig = FDEP.build(model, DI.build_inventory(_repo(tmp_path, n, "k8s2")), 3)
    texts = [t[0] for t in _texts(fig.svg)]
    assert "ai-sdk" in texts and "Ai-sdk" not in texts
    assert fig.takeaway.startswith("1 server component runs in one")


@pytest.mark.parametrize(
    ("framework", "store"),
    [("sqlite3", "SQLite"), ("better-sqlite3", "SQLite"), ("h2database", "H2"), ("com.h2database:h2", "H2")],
)
def test_embedded_store_is_recognized_by_its_package_name(tmp_path: Path, framework: str, store: str):
    """A model names the store by its package or artifact; it still runs inside the process that embeds it."""
    n = _names(False)
    model = _model(n)
    model["components"][4]["framework"] = framework
    fig = FDEP.build(model, DI.build_inventory(_repo(tmp_path, n, "k8s")), 3)
    assert "1 embedded data store" in fig.takeaway
    assert (
        f"| Embedded stores | {store}" in fig.markdown and "[C-05](#c-05)" in fig.markdown.split("Embedded stores")[1]
    )
    assert "[C-05]" not in fig.markdown.split("Components without a declared place")[-1].split("\n")[0]


@pytest.mark.parametrize("framework", ["mysql2", "pg", "mongodb4"])
def test_server_database_packages_stay_outside_the_process(tmp_path: Path, framework: str):
    """Negative: a client package of a server database is not an embedded store."""
    n = _names(False)
    model = _model(n)
    model["components"][4]["framework"] = framework
    fig = FDEP.build(model, DI.build_inventory(_repo(tmp_path, n, "k8s")), 3)
    assert "embedded data store" not in fig.takeaway and "Embedded stores" not in fig.markdown
