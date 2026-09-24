"""Tests for scripts/figure_details.py and its §2 composition (Figure 3 deployment, the §2.3 controls table).

A neutral model and repository: an edge gateway, an orders service with an
in-process billing module, an admin console that publishes its own port, a
database and a build pipeline. The repository is scanned into the deployment
inventory once; the figures and the composer read that inventory, never the
repository. The variant renames every participant; the negative cases remove
the inputs one figure at a time.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import compose_threat_model as compose
import deployment_inventory as DI
import figure_details as FD
import pytest
import qa_checks
import yaml
from pregenerate_fragments import gen_architecture_diagrams

CONTRACT = Path(__file__).resolve().parents[1] / "data" / "sections-contract.yaml"

SHA = "0123456789abcdef0123456789abcdef01234567"


def _names(variant: bool) -> dict:
    if variant:
        return {
            "gw": "ingress-router",
            "gw_img": "example/router:3.1.0",
            "app": "catalog",
            "adm": "backoffice",
            "db": "warehouse-db",
            "gw_name": "Ingress Router",
            "app_name": "Catalog Service",
            "adm_name": "Backoffice Portal",
            "db_name": "Warehouse DB",
        }
    return {
        "gw": "edge",
        "gw_img": "nginx:1.27.0",
        "app": "orders",
        "adm": "admin",
        "db": "ledger-db",
        "gw_name": "Edge Proxy",
        "app_name": "Orders Service",
        "adm_name": "Admin Console",
        "db_name": "Ledger DB",
    }


def _repo(tmp_path: Path, n: dict) -> Path:
    root = tmp_path / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "src" / n["app"]).mkdir(parents=True)
    (root / "docker-compose.yml").write_text(
        "services:\n"
        f'  {n["gw"]}:\n    image: {n["gw_img"]}\n    ports:\n      - "8080:80"\n'
        f"    depends_on:\n      - {n['app']}\n      - {n['adm']}\n"
        f"  {n['app']}:\n    image: example/{n['app']}:latest\n"
        f'  {n["adm"]}:\n    image: example/{n["adm"]}:2.1.0\n    ports:\n      - "9443:9443"\n'
        '    environment:\n      ADMIN_AUTH_DISABLED: "true"\n      ADMIN_PASSWORD: s3cr3t-value\n'
        f"  {n['db']}:\n    image: postgres@sha256:{'a' * 64}\n",
        encoding="utf-8",
    )
    (root / "Dockerfile").write_text("FROM python:3.12-slim\nCOPY . /app\n", encoding="utf-8")
    (root / ".github" / "workflows" / "ci.yml").write_text(
        f"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: example/scan@{SHA}\n",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("flask==3.0.0\nrequests\n", encoding="utf-8")
    return root


def _admin_line(root: Path, n: dict) -> int:
    lines = (root / "docker-compose.yml").read_text().splitlines()
    return next(i for i, ln in enumerate(lines, 1) if ln.strip() == f"{n['adm']}:") + 2


def _model(root: Path | None, n: dict, controls: bool = True) -> dict:
    app, billing = f"{n['app']}-service", "billing"
    adm_line = _admin_line(root, n) if root else 1
    return {
        "meta": {"project": "Shop"},
        "components": [
            {"id": f"{n['gw']}-proxy", "name": n["gw_name"], "tier": "application", "paths": ["deploy/gateway.conf"]},
            {
                "id": app,
                "name": n["app_name"],
                "tier": "application",
                "paths": [f"src/{n['app']}/**/*.py"],
                "sensitive_data": [{"category": "credentials"}],
            },
            {
                "id": billing,
                "name": "Billing Module",
                "tier": "application",
                "paths": [
                    f"src/{n['app']}/billing/charge.py",
                    f"src/{n['app']}/billing/refund.py",
                    "static/billing.js",
                ],
            },
            {"id": f"{n['adm']}-console", "name": n["adm_name"], "tier": "application", "paths": ["admin/app.py"]},
            {"id": n["db"], "name": n["db_name"], "tier": "data", "paths": ["migrations/*.sql"]},
            {"id": "pipeline", "name": "Build Pipeline", "tier": "application", "paths": [".github/workflows/**"]},
        ],
        "external_entities": [{"id": "ext-customer", "name": "Customer"}, {"id": "ext-operator", "name": "Operator"}],
        "data_flows": [
            {
                "id": "df-1",
                "from": "external",
                "from_entity": "ext-customer",
                "to": f"{n['gw']}-proxy",
                "protocol": "HTTP",
                "data_classification": "Public",
                "authentication": {"scheme": "none"},
            },
            {
                "id": "df-2",
                "from": "external",
                "from_entity": "ext-operator",
                "to": f"{n['adm']}-console",
                "protocol": "HTTP",
                "data_classification": "Confidential",
                "authentication": {"scheme": "unknown"},
            },
            {
                "id": "df-3",
                "from": f"{n['gw']}-proxy",
                "to": app,
                "protocol": "HTTP",
                "data_classification": "Internal",
                "authentication": {"scheme": "none"},
            },
        ],
        "attack_surface": [
            {"entry_point": "GET /orders", "auth_required": False},
            {"entry_point": "admin UI", "auth_required": False},
            {"entry_point": "POST /pay", "auth_required": True},
        ],
        "security_controls": [
            {
                "domain": "Query Construction",
                "control": "Parameterized Database Access",
                "effectiveness": "Unsafe",
                "implementation": f"src/{n['app']}/db.py:12",
            },
            {
                "domain": "Identity",
                "control": "Route Authentication Gate",
                "effectiveness": "Weak",
                "implementation": f"docker-compose.yml:{adm_line}",
            },
            {"domain": "Operations", "control": "Lockfile hygiene", "effectiveness": "Missing", "implementation": ""},
            {
                "domain": "Data Protection",
                "control": "Transport Encryption",
                "effectiveness": "Partial",
                "implementation": "docker-compose.yml",
            },
        ]
        if controls
        else [],
        "threats": [
            {
                "id": "T-001",
                "title": "SQL injection in order search",
                "risk": "High",
                "component": app,
                "merged_from": [app, billing],
                "cwe": "CWE-89",
                "evidence": [{"file": f"src/{n['app']}/db.py", "line": 12}],
            },
            {
                "id": "T-002",
                "title": "Unpinned third-party action",
                "risk": "Medium",
                "component": "pipeline",
                "cwe": "CWE-829",
                "evidence": [{"file": ".github/workflows/ci.yml", "line": 4}],
            },
            {
                "id": "T-003",
                "title": "Floating base image",
                "risk": "Medium",
                "component": "pipeline",
                "cwe": "CWE-1104",
                "evidence": [{"file": "Dockerfile", "line": 1}],
            },
            {
                "id": "T-004",
                "title": "Admin port published without authentication",
                "risk": "Critical",
                "component": f"{n['adm']}-console",
                "cwe": "CWE-306",
                "evidence": [{"file": "docker-compose.yml", "line": adm_line}],
            },
        ],
    }


def _inventory(root: Path | None) -> dict | None:
    return DI.build_inventory(root) if root else None


def _svg_ok(svg: str) -> None:
    ET.fromstring(svg)  # well-formed
    assert "<script" not in svg and "href" not in svg


@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_deployment_figure_and_controls_table_render(tmp_path: Path, variant: bool):
    n = _names(variant)
    root = _repo(tmp_path, n)
    figs = FD.build_detail_figures(_model(root, n), _inventory(root))
    assert sorted(figs) == ["2.2", "2.3"]
    fig, table = figs["2.2"], figs["2.3"]
    _svg_ok(fig.svg)
    assert fig.number == 3 and not fig.markdown  # four compose services: several deployment units
    assert "Figure 3 — " in fig.svg and "DETAIL OF FIGURE 1" in fig.svg
    assert "Deployment and Technology" in fig.svg and n["gw"] in fig.svg
    assert table.markdown.startswith(FD.DETAIL_TABLE_MARKER + "\n| Component |") and not table.svg
    for view in (fig.svg, table.markdown):
        assert "s3cr3t-value" not in view  # environment values never reach a view


@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_controls_are_placed_by_implementation_evidence(tmp_path: Path, variant: bool):
    n = _names(variant)
    root = _repo(tmp_path, n)
    m = FD.Model(_model(root, n), _inventory(root))
    assert m.svc_comp[n["app"]] == f"{n['app']}-service" and m.in_process[f"{n['app']}-service"] == ["billing"]
    placed = {c["control"]: FD._control_targets(m, c) for c in m.controls}
    assert placed["Parameterized Database Access"] == {f"{n['app']}-service"}
    assert placed["Route Authentication Gate"] == {f"{n['adm']}-console"}  # compose line → service → component
    assert placed["Lockfile hygiene"] == {"pipeline"}  # no evidence, supply-chain domain → CI component
    assert placed["Transport Encryption"] == {FD.SYSTEM_WIDE}  # file without a line
    fig = FD.controls_table(m, 4)
    assert "| System-wide: evidence not tied to one component |" in fig.markdown
    row = next(ln for ln in fig.markdown.splitlines() if ln.startswith(f"| [C-02](#c-02) · {n['app_name']} |"))
    assert "🔴 Unsafe: Input / query" in row  # worst effectiveness per domain, named by the domain
    assert fig.takeaway.startswith("Every component that handles credentials (C-02)")


def test_domain_prefers_specific_controls():
    assert FD._domain_of({"control": "LLM Prompt Injection Guard"}) == "LLM"
    assert FD._domain_of({"control": "Transport Encryption"}) == "Transport"
    assert FD._domain_of({"control": "Output Encoding and XSS Prevention"}) == "Output\nencoding"


def test_threat_tally_uses_the_figure1_attribution():
    m = FD.Model(_model(None, _names(False)), None)
    # T-001 is merged from the billing module: counted there too, as on the Figure 1 node.
    assert m.affected["billing"]["High"] == 1 and m.owned["billing"] == 0
    assert m.threat_total == 4


def test_missing_inputs_drop_only_their_view():
    """Negative: without an inventory only the controls table renders."""
    n = _names(False)
    views = FD.build_detail_figures(_model(None, n), None)
    assert sorted(views) == ["2.3"] and views["2.3"].markdown and not views["2.3"].svg
    assert FD.build_detail_figures(_model(None, n, controls=False), None) == {}
    assert FD.build_detail_figures({"components": []}, {"runtime": None, "environments": []}) == {}


def test_hostile_names_are_escaped(tmp_path: Path):
    n = _names(False)
    root = _repo(tmp_path, n)
    model = _model(root, n)
    model["components"][0]["name"] = '<script>alert("x")</script> & co'
    model["external_entities"][0]["name"] = "</text><svg onload=1>"
    views = FD.build_detail_figures(model, _inventory(root))
    # The table keeps markup inert: escaped, never a tag or a link target.
    assert "<script>" not in views["2.3"].markdown and "&lt;script&gt;" in views["2.3"].markdown
    for fig in [v for v in views.values() if v.svg]:
        _svg_ok(fig.svg)
        tree = ET.fromstring(fig.svg)
        tags = {el.tag.rsplit("}", 1)[-1] for el in tree.iter()}
        # The markup stays text: no injected element, no event-handler attribute anywhere.
        assert not tags & {"script", "b", "foreignObject", "a"}
        assert sum(1 for el in tree.iter() if el.tag.endswith("}svg")) == 1
        assert not any(k.lower().startswith("on") for el in tree.iter() for k in el.attrib)
        assert '<script>alert("x")</script>' in "".join(tree.itertext())


# ---------------------------------------------------------------- composition
def _ctx(tmp_path: Path, model: dict, inventory: dict | None, repo: Path | None = None) -> compose.RenderContext:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    (out / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo) if repo else ""}), encoding="utf-8")
    inv_path = out / ".deployment-inventory.json"
    if inventory is None:
        inv_path.unlink(missing_ok=True)
    else:
        inv_path.write_text(json.dumps(inventory), encoding="utf-8")
    return compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data=model,
        triage={},
        fragments_dir=out / ".fragments",
        figure_basename="threat-model.figure1.svg",
    )


def test_composer_writes_figures_and_section_2_replaces_only_their_mermaid(tmp_path: Path):
    n = _names(False)
    root = _repo(tmp_path, n)
    ctx = _ctx(tmp_path, _model(root, n), _inventory(root))
    figures = compose._render_detail_figures(ctx)
    assert sorted(p.name for p in ctx.output_dir.glob("*.svg")) == ["threat-model.figure3.svg"]
    md = gen_architecture_diagrams(ctx.yaml_data, figures=figures)
    assert md.count("```mermaid") == 1  # §2.1 keeps its Mermaid diagram
    assert "![Figure 3 - Deployment and Technology](threat-model.figure3.svg)" in md
    assert FD.DETAIL_TABLE_MARKER + "\n| Component |" in md
    assert "| Component ID | Name | Tier | Source paths | Threats |" in md  # the §2.3 table stays
    assert "### 2.4" not in md
    for fig in figures.values():
        assert f"**Key takeaway:** {fig['takeaway']}" in md


def test_composer_never_reads_the_repository(tmp_path: Path):
    """Negative: a checkout next to the run without an inventory adds no deployment figure."""
    n = _names(False)
    root = _repo(tmp_path, n)
    ctx = _ctx(tmp_path, _model(root, n), None, repo=root)
    assert sorted(compose._render_detail_figures(ctx)) == ["2.3"]
    assert not list(ctx.output_dir.glob("*.svg"))


def test_composer_ignores_an_inventory_that_breaks_the_schema(tmp_path: Path):
    n = _names(False)
    root = _repo(tmp_path, n)
    bad = _inventory(root)
    bad["environments"][0]["tree"]["kind"] = "<script>"
    ctx = _ctx(tmp_path, _model(root, n), bad)
    assert sorted(compose._render_detail_figures(ctx)) == ["2.3"]
    assert any(".deployment-inventory.json ignored" in w for w in ctx.warnings)


def test_composer_removes_stale_figures_and_falls_back_to_mermaid(tmp_path: Path, monkeypatch):
    """Negative: fewer inputs delete old files; a builder crash keeps every Mermaid diagram."""
    n = _names(False)
    root = _repo(tmp_path, n)
    ctx = _ctx(tmp_path, _model(root, n), _inventory(root))
    compose._render_detail_figures(ctx)
    for stale in ("threat-model.figure4.svg", "threat-model.figure6.svg"):  # left by older runs
        (ctx.output_dir / stale).write_text("<svg/>", encoding="utf-8")
    ctx_no_inv = _ctx(tmp_path, _model(root, n), None)
    figures = compose._render_detail_figures(ctx_no_inv)
    assert sorted(figures) == ["2.3"]
    assert list(ctx.output_dir.glob("*.svg")) == []
    md = gen_architecture_diagrams(ctx_no_inv.yaml_data, figures=figures)
    assert md.count("```mermaid") == 2  # §2.1 and §2.2 keep their Mermaid diagrams

    def boom(*_a, **_k):
        raise RuntimeError("layout exploded")

    monkeypatch.setattr(FD, "build_detail_figures", boom)
    assert compose._render_detail_figures(ctx_no_inv) == {}
    assert any("detail figures: builder failed" in w for w in ctx_no_inv.warnings)
    assert list(ctx.output_dir.glob("*.svg")) == []
    assert gen_architecture_diagrams(ctx_no_inv.yaml_data, figures={}).count("```mermaid") == 3


def test_contract_and_qa_accept_a_detail_figure_only_when_its_file_exists(tmp_path: Path):
    n = _names(False)
    root = _repo(tmp_path, n)
    ctx = _ctx(tmp_path, _model(root, n), _inventory(root))
    md = gen_architecture_diagrams(ctx.yaml_data, figures=compose._render_detail_figures(ctx))
    pattern = yaml.safe_load(CONTRACT.read_text())["sections"]["architecture_diagrams"]["required_patterns"][0]
    assert re.search(pattern, md) and re.search(pattern, "```mermaid\nflowchart TD\n```")
    assert not re.search(pattern, "![Figure 3 - x](https://evil.example/x.svg)")
    report_md = ctx.output_dir / "threat-model.md"
    report_md.write_text(md, encoding="utf-8")
    assert qa_checks.check_diagram_compactness(report_md, CONTRACT).issues == []
    (ctx.output_dir / "threat-model.figure3.svg").unlink()
    issues = qa_checks.check_diagram_compactness(report_md, CONTRACT).issues
    assert issues == ["§2.2 Container Architecture: detail figure `threat-model.figure3.svg` is referenced but missing"]


def test_qa_accepts_a_detail_table_only_under_its_marker(tmp_path: Path):
    n = _names(False)
    ctx = _ctx(tmp_path, _model(None, n), None)
    md = gen_architecture_diagrams(ctx.yaml_data, figures=compose._render_detail_figures(ctx))
    report_md = ctx.output_dir / "threat-model.md"
    report_md.write_text(md, encoding="utf-8")
    assert qa_checks.check_diagram_compactness(report_md, CONTRACT).issues == []
    # Negative: a table without the generator's marker is no replacement for the diagram.
    report_md.write_text(md.replace(FD.DETAIL_TABLE_MARKER + "\n", ""), encoding="utf-8")
    issues = qa_checks.check_diagram_compactness(report_md, CONTRACT).issues
    assert issues == ["§2.3 Components: no mermaid block found — diagram is required"]


@pytest.mark.parametrize("variant", [False, True], ids=["neutral", "renamed"])
def test_takeaway_does_not_call_components_unprotected_when_controls_apply_system_wide(variant: bool):
    name = "Catalog" if variant else "Orders"
    model = {
        "components": [{"id": "C-01", "name": f"{name} API", "tier": "application", "paths": ["src/**"]}],
        "data_flows": [{"id": "df-1", "from": "user", "to": "C-01", "authentication": {"scheme": "none"}}],
        "security_controls": [{"control": "Password hashing", "effectiveness": "Weak", "implementation": ""}],
        "threats": [],
    }
    fig = FD.controls_table(FD.Model(model, None), 4)
    assert "no control evidenced at all" not in fig.takeaway
    assert "no component-specific control" in fig.takeaway and "1 control applies system-wide" in fig.takeaway
    # Negative: without a system-wide control the component really has none.
    model["security_controls"][0]["implementation"] = "other/x.py"
    model["components"].append({"id": "C-02", "name": "Other", "tier": "application", "paths": ["other/**"]})
    fig = FD.controls_table(FD.Model(model, None), 4)
    assert "no control evidenced at all (C-01)" in fig.takeaway


def test_missing_data_classification_is_not_drawn_as_none():
    model = {
        "components": [{"id": "C-01", "name": "API", "tier": "application", "paths": ["src/**"]}],
        "data_flows": [{"id": "df-1", "from": "user", "to": "C-01"}],
        "security_controls": [{"control": "Password hashing", "effectiveness": "Weak", "implementation": "src/a.py"}],
        "threats": [],
    }
    row = FD.controls_table(FD.Model(model, None), 4).markdown.splitlines()[3]
    assert row.startswith("| [C-01](#c-01) · API |") and "None" not in row and "| – |" in row
