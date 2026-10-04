"""Figure 1a/1b in the composed report: split condition, links, fallbacks and stale files (RA-29, RA-31)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import renderers.compose_threat_model as compose
import renderers.figure1b_svg as figure1b
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
    markdown = compose._render_figure1_svg(ctx, _paths("internet-anon", "build-time"), taxonomy)
    figure_1a = (evidence / "figure1.svg").read_text()
    assert "Release Automation" not in figure_1a
    assert "Figure 1a — Runtime Architecture and Threat Overview" in figure_1a
    assert "threats in the model" in figure_1a
    assert "![Figure 1a - Runtime Architecture and Threat Overview](figure1.svg)" in markdown
    strip = compose._figure1b_strip(ctx)
    assert strip.startswith("**Build pipeline**, not drawn in this runtime view: GitHub Actions.")
    assert "→ [Figure 1b](#figure-1b)" in strip
    block = compose._render_figure1b(ctx)
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
    (out / ".supply-chain-view.json").write_text("{}")
    taxonomy = compose._load_attack_class_taxonomy()
    compose._render_figure1_svg(ctx, _paths("internet-anon"), taxonomy)
    assert "Figure 1 — Architecture and Threat Overview" in (out / "figure1.svg").read_text()
    assert compose._figure1b_strip(ctx) == ""
    assert compose._render_figure1b(ctx) == ""
    assert not (out / "figure1b.svg").exists() and not (out / ".supply-chain-view.json").exists()


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
    assert "](threat-model-orders.figure1b.svg)" in compose._render_figure1b(ctx)


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
