"""Figure 1a/1b in the composed report: split condition, links, fallbacks and stale files (RA-29, RA-31)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import renderers.compose_threat_model as compose
import renderers.figure1b_svg as figure1b
import yaml
from renderers.figure_theme import light_images
from renderers.pregenerate_fragments import gen_architecture_diagrams

CI_COMPONENT = {
    "id": "release-automation",
    "name": "Release Automation",
    "tier": "application",
    "paths": [".github/workflows/**", "Dockerfile", "package.json"],
}
ACTORS = [
    {"id": "ACT-B", "label": "supply-chain-attacker", "heatmap_slug": "build-time", "active": True},
    {"id": "ACT-I", "label": "anonymous-internet-attacker", "heatmap_slug": "internet-anon", "active": True},
]


def _ctx(out: Path, *, runtime_threat=True, build_threat=True) -> compose.RenderContext:
    threats = []
    if runtime_threat:
        threats.append(
            {
                "id": "T-001",
                "title": "Query built from request data",
                "component": "api",
                "risk": "Critical",
                "effective_severity": "Critical",
                "cwe": "CWE-89",
                "actor_ids": ["ACT-I"],
                "evidence": [{"file": "src/query.py", "line": 12}],
            }
        )
    if build_threat:
        threats.append(
            {
                "id": "T-002",
                "title": "Dependencies installed without lockfile",
                "component": "release-automation",
                "risk": "High",
                "effective_severity": "High",
                "cwe": "CWE-1104",
                "actor_ids": ["ACT-B"],
                "evidence": [{"file": ".github/workflows/release.yml", "line": 9}],
            }
        )
    out.mkdir(parents=True, exist_ok=True)
    return compose.RenderContext(
        output_dir=out,
        contract={},
        yaml_data={
            "components": [
                {"id": "web", "name": "Web Client", "tier": "client", "paths": ["web/**"]},
                {"id": "api", "name": "Orders API", "tier": "application", "paths": ["src/**"]},
                {"id": "db", "name": "Orders Store", "tier": "data", "paths": ["db/**"]},
                CI_COMPONENT,
            ],
            "data_flows": [{"id": "df-1", "from": "api", "to": "db", "label": "queries", "protocol": "SQL"}],
            "threats": threats,
            "actors": ACTORS,
            "meta": {"project_name": "Orders"},
        },
        triage={},
        fragments_dir=out / ".fragments",
    )


def _write_ci_evidence(out: Path) -> None:
    (out / ".deployment-inventory.json").write_text(
        json.dumps(
            {
                "ci": [
                    {
                        "system": "GitHub Actions",
                        "source": ".github/workflows",
                        "facts": [],
                        "publishes": ["GitHub Container Registry"],
                    }
                ],
                "dependencies": {"manifests": 1, "declared": 10, "ranges": 9, "lockfile": False},
            }
        )
    )
    (out / ".config-scan-findings.json").write_text(
        json.dumps(
            {
                "findings": [],
                "supply_chain_facts": {
                    "version": 1,
                    "workflows": [{"file": ".github/workflows/release.yml"}],
                    "inputs": [],
                    "installs": [
                        {
                            "ecosystem": "npm",
                            "command": "npm install",
                            "lockfile_enforced": False,
                            "file": ".github/workflows/release.yml",
                            "line": 9,
                            "job": "image",
                        }
                    ],
                    "outputs": [
                        {
                            "kind": "container_image",
                            "file": ".github/workflows/release.yml",
                            "line": 14,
                            "pushed": True,
                            "job": "image",
                            "destination": {"registry": "ghcr.io", "repository": "acme/orders"},
                        }
                    ],
                    "capabilities": {},
                },
            }
        )
    )


def _paths(*actors):
    classes = {"internet-anon": ("injection", "T-001"), "build-time": ("supply-chain", "T-002")}
    return {"attack_paths": [{"class": classes[a][0], "actor": a, "findings": [classes[a][1]]} for a in actors]}


@pytest.fixture
def evidence(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    _write_ci_evidence(out)
    return out


def test_with_build_evidence_figure_1a_drops_the_pipeline_and_figure_1b_carries_it(evidence):
    ctx = _ctx(evidence)
    taxonomy = compose._load_attack_class_taxonomy()
    markdown = light_images(compose._render_figure1_svg(ctx, _paths("internet-anon", "build-time"), taxonomy))
    figure_1a = (evidence / "figure1.svg").read_text()
    assert "Release Automation" not in figure_1a
    assert "Figure 1a — Runtime Architecture and Threat Overview" in figure_1a
    assert "threats in the model" in figure_1a
    assert "![Figure 1a - Runtime Architecture and Threat Overview](figure1.svg)" in markdown
    strip = compose._figure1b_strip(ctx)
    assert strip.startswith("**Build pipeline**, not drawn in this runtime view: GitHub Actions.")
    assert "→ [Figure 1b](#figure-1b)" in strip
    block = light_images(compose._render_figure1b(ctx))
    assert block.startswith('<a id="figure-1b"></a>')
    assert "![Figure 1b - Supply Chain and Build](figure1b.svg)" in block
    assert (evidence / "figure1b.svg").read_text().startswith("<svg")
    view = json.loads((evidence / ".supply-chain-view.json").read_text())
    assert view["highlighted_path"]["finding"] == "F-002"


def test_without_build_evidence_nothing_changes_and_stale_files_go(tmp_path):
    out = tmp_path / "out"
    ctx = _ctx(out, build_threat=False)
    ctx.yaml_data["components"] = ctx.yaml_data["components"][:3]
    (out / "figure1b.svg").write_text("prior run")
    (out / "figure1b-dark.svg").write_text("prior run")
    (out / ".supply-chain-view.json").write_text("{}")
    taxonomy = compose._load_attack_class_taxonomy()
    compose._render_figure1_svg(ctx, _paths("internet-anon"), taxonomy)
    assert "Figure 1 — Architecture and Threat Overview" in (out / "figure1.svg").read_text()
    assert compose._figure1b_strip(ctx) == ""
    assert compose._render_figure1b(ctx) == ""
    assert not (out / "figure1b.svg").exists() and not (out / ".supply-chain-view.json").exists()
    assert not (out / "figure1b-dark.svg").exists()


def test_a_model_with_only_build_time_scenarios_still_draws_the_runtime(evidence):
    ctx = _ctx(evidence, runtime_threat=False)
    markdown = compose._render_figure1_svg(ctx, _paths("build-time"), compose._load_attack_class_taxonomy())
    assert "figure1.svg" in markdown
    assert "Orders API" in (evidence / "figure1.svg").read_text()


def test_a_failed_gate_renders_the_table_and_removes_the_stale_image(evidence, monkeypatch):
    ctx = _ctx(evidence)
    (evidence / "figure1b.svg").write_text("prior run")
    monkeypatch.setattr(figure1b, "render", lambda *args, **kwargs: ("", ["forced geometry failure"]))
    block = compose._render_figure1b(ctx)
    assert block.startswith('<a id="figure-1b"></a>')  # links resolve in either form
    assert "| From | To | Status | Evidence |" in block
    assert not (evidence / "figure1b.svg").exists()
    assert any("forced geometry failure" in w for w in ctx.warnings)


def test_a_custom_report_stem_names_the_supply_chain_figure_after_it(evidence):
    ctx = _ctx(evidence)
    ctx.figure_basename = "threat-model-orders.figure1.svg"
    assert "](threat-model-orders.figure1b.svg)" in light_images(compose._render_figure1b(ctx))
    assert (evidence / "threat-model-orders.figure1b-dark.svg").is_file()


def test_identified_actors_name_both_figures_and_link_the_build_attacker(evidence):
    ctx = _ctx(evidence)
    people = compose._overview_people(ctx)
    build = [p for p in people if p.get("slug") == "build-time"]
    assert len(build) == 1 and build[0]["figure"] == "1b"
    table = compose._render_actor_inventory(ctx, people)
    assert "Figure 1a draws" in table and "[Figure 1b](#figure-1b) draws" in table


def test_a_saved_diagram_that_draws_a_build_component_is_recognised(evidence):
    ctx = _ctx(evidence)
    assert compose._names_a_build_component(ctx, "flowchart TB\n  release-automation --> api")
    assert not compose._names_a_build_component(ctx, "flowchart TB\n  web --> api")


def test_container_diagram_leaves_the_build_plane_to_figure_1b_and_components_keep_it(evidence):
    ctx = _ctx(evidence)
    markdown = gen_architecture_diagrams(ctx.yaml_data, supply_chain_anchor="figure-1b")
    container, components = markdown.split("### 2.3 ", 1)
    container = container.split("### 2.2 ", 1)[1]
    mermaid = container.split("```mermaid", 1)[1].split("```", 1)[0]
    assert "Release Automation" not in mermaid
    assert "is shown in [Figure 1b](#figure-1b)" in container
    assert "Release Automation" in components
    assert "Release Automation" in gen_architecture_diagrams(ctx.yaml_data).split("### 2.3 ", 1)[0]


@pytest.mark.parametrize("runtime_threat", [True, False])
def test_every_attacker_has_one_code_in_the_actor_table_and_both_figures(evidence, runtime_threat):
    # Codes are assigned before Figure 1a drops the build-time actor, so no surface renumbers them.
    ctx = _ctx(evidence, runtime_threat=runtime_threat)
    paths = _paths("internet-anon", "build-time") if runtime_threat else _paths("build-time")
    compose._render_figure1_svg(ctx, paths, compose._load_attack_class_taxonomy())
    attackers = [p for p in compose._overview_people(ctx) if p["kind"] == "attacker"]
    codes = [p["code"] for p in attackers]
    assert all(codes) and len(set(codes)) == len(codes)
    build = next(p for p in attackers if p["slug"] == "build-time")
    assert compose._supply_chain_split(ctx)["actor"]["code"] == build["code"]
    assert f"{build['code']} · {build['name']}" in compose._figure1b_strip(ctx)
    compose._render_figure1b(ctx)
    assert f"Entry points of {build['code']} · {build['name']}" in (evidence / "figure1b.svg").read_text()
    figure_1a = (evidence / "figure1.svg").read_text()
    for runtime in (p for p in attackers if p["slug"] != "build-time"):
        assert f">{runtime['code']} · " in figure_1a  # the label may wrap after the code


def test_figure_1b_names_the_goal_and_counts_of_the_build_time_scenarios(evidence):
    ctx = _ctx(evidence)
    compose._render_figure1b(ctx)
    svg = (evidence / "figure1b.svg").read_text()
    goal = compose._supply_chain_split(ctx)["actor"]["goal"]
    assert goal["risk"] == "High"  # the scenario risk Figure 2 shows for the build-time finding
    assert figure1b.goal_text(compose._supply_chain_split(ctx)["actor"]).startswith("Goal of A")
    assert "1 CI system · 1 upstream source type · 0 delivery channels · 1 finding shown here" in svg
    assert "Goal of " in svg


def test_without_an_impact_figure_1b_draws_no_goal():
    assert figure1b.goal_text({"name": "Build Attacker", "code": "A3"}) == ""
    assert figure1b.goal_text(None) == ""


def test_figure_1b_links_the_control_section_from_the_heading_list(evidence):
    ctx = _ctx(evidence)
    ctx.contract = yaml.safe_load(compose.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
    ctx.eval_context["security_schema"] = "v2"
    assert "The control assessment is in [§6.11](#611-operations-runtime-and-supply-chain-controls)." in (
        compose._render_figure1b(ctx)
    )
    ctx.eval_context["render_security_architecture"] = False  # quick depth: no §6, no dangling link
    assert "control assessment" not in compose._render_figure1b(ctx)


def test_every_attack_class_control_section_names_a_section_6_heading():
    contract = yaml.safe_load(compose.DEFAULT_CONTRACT.read_text(encoding="utf-8"))
    headings = {
        sub["title"].partition(" ")[2]
        for sub in contract["sections"]["security_architecture"]["schema_v2"]["required_subsections"]
    }
    sections = [
        c["control_section"] for c in compose._load_attack_class_taxonomy()["classes"] if c.get("control_section")
    ]
    assert sections and set(sections) <= headings


SECTION_6 = (
    "### {n} File Parser and Outbound Request Controls\n\nparsers\n\n"
    "### {m} Operations Runtime and Supply Chain Controls\n\ncontrols\n"
)


def test_section_6_opens_the_supply_chain_controls_with_the_build_path(evidence):
    ctx = _ctx(evidence)
    md = compose._inject_supply_chain_paragraph(ctx, SECTION_6.format(n="6.10", m="6.11"))
    head, _, body = md.partition("### 6.11 Operations Runtime and Supply Chain Controls\n\n")
    assert "Build path" not in head  # only the build control section carries it
    block, _, rest = body.partition("\n\ncontrols")
    assert block.startswith("**Build path.** [Figure 1b](#figure-1b) shows the inputs")
    assert "that Orders evidences" in block
    assert re.search(
        r"^Highlighted path of .*\[F-002\]\(#f-002\).*: npm registry → GitHub Actions → ghcr\.io/acme/orders\.",
        block,
        re.MULTILINE,
    )
    assert ".github/workflows" not in block  # locations stay with the findings
    assert re.search(r"\*\*Attack entries:\*\*\n\n- \*\*Manipulated dependency\*\*\n  - .*\[F-002\]\(#f-002\)", block)
    assert "Not attributable" not in block
    assert rest == "\n"
    assert compose._inject_supply_chain_paragraph(ctx, md) == md  # a re-render adds no second block


def test_the_build_path_follows_the_heading_and_lists_findings_without_a_ci_owner(evidence):
    ctx = _ctx(evidence)
    ctx.yaml_data["meta"] = {"project_name": "Ledger"}
    ctx.yaml_data["threats"].append(
        {
            "id": "T-007",
            "title": "Deploy script logs the registry token",
            "component": "release-automation",
            "risk": "Medium",
            "effective_severity": "Medium",
            "cwe": "CWE-532",
            "evidence": [{"file": "scripts/publish.sh", "line": 3}],
        }
    )
    md = compose._inject_supply_chain_paragraph(ctx, SECTION_6.format(n="7.2", m="7.3"))
    block = md.split("### 7.3 Operations Runtime and Supply Chain Controls\n\n")[1].partition("\n\ncontrols")[0]
    assert "that Ledger evidences" in block
    assert re.search(
        r"\*\*Not attributable to a build step:\*\*\n\n- .*\[F-007\]\(#f-007\) — Deploy script logs the registry token$",
        block,
    )


def test_without_figure_1b_or_the_control_heading_section_6_is_unchanged(tmp_path, evidence):
    md = SECTION_6.format(n="6.10", m="6.11")
    ctx = _ctx(tmp_path / "no-build", build_threat=False)
    ctx.yaml_data["components"] = ctx.yaml_data["components"][:3]
    assert compose._inject_supply_chain_paragraph(ctx, md) == md
    without_heading = "### 6.10 File Parser and Outbound Request Controls\n\nparsers\n"
    assert compose._inject_supply_chain_paragraph(_ctx(evidence), without_heading) == without_heading
