"""Figure 1b renderer: clean geometry, legibility at delivery size, and the table form (RA-31)."""

from __future__ import annotations

import re

import renderers.figure1b_svg as figure
from model.build_supply_chain_view import build_view

ACTOR = {"name": "Build Pipeline Intruder", "subtitle": "tampers with what the build consumes"}


def _facts(ecosystems=("pip",), images=(("ghcr.io", "acme/ledger"),), actions=2):
    installs = [
        {
            "ecosystem": eco,
            "command": f"{eco} install",
            "lockfile_enforced": False,
            "file": ".github/workflows/build.yml",
            "line": 10 + i,
            "job": "image",
        }
        for i, eco in enumerate(ecosystems)
    ]
    inputs = [
        {
            "kind": "github_action",
            "reference": f"vendor/tool-{i}@v1",
            "pinning": "tag",
            "file": ".github/workflows/build.yml",
            "line": 5 + i,
            "job": "image",
        }
        for i in range(actions)
    ]
    outputs = [
        {
            "kind": "container_image",
            "file": ".github/workflows/build.yml",
            "line": 30 + i,
            "pushed": True,
            "job": "image",
            "destination": {"registry": reg, "repository": repo},
        }
        for i, (reg, repo) in enumerate(images)
    ]
    return {
        "version": 1,
        "workflows": [{"file": ".github/workflows/build.yml"}],
        "inputs": inputs,
        "outputs": outputs,
        "installs": installs,
    }


def _model(threats=()):
    return {
        "components": [{"id": "pipeline", "paths": [".github/workflows/*"]}],
        "threats": list(threats),
        "actors": [{"id": "ACT-B", "heatmap_slug": "build-time"}],
    }


def _threat(tid, cwe, line, risk="High", title="Dependency resolved by range"):
    return {
        "id": tid,
        "title": title,
        "cwe": cwe,
        "risk": risk,
        "effective_severity": risk,
        "actor_ids": ["ACT-B"],
        "component": "pipeline",
        "evidence": [{"file": ".github/workflows/build.yml", "line": line}],
    }


def _render(view, actor=ACTOR):
    svg, problems = figure.render(view, actor, ["⑤"], "Ledger Service")
    assert problems == [], problems
    return svg


def test_a_sparse_view_without_findings_or_attacker_renders_clean():
    view = build_view(
        _model(),
        {
            "version": 1,
            "workflows": [{"file": ".github/workflows/build.yml"}],
            "inputs": [],
            "outputs": [],
            "installs": [],
        },
        {},
    )
    svg = _render(view, actor=None)
    assert "Figure 1b — Supply Chain and Build" in svg
    assert "Running system" in svg and "→ Figure 1a" in svg
    assert "No reported finding establishes an attack entry." in svg


def test_a_complete_path_draws_numbered_steps_and_named_entries():
    view = build_view(_model([_threat("T-002", "CWE-1104", 10)]), _facts(), {})
    svg = _render(view)
    assert "Manipulated dependency" in svg
    assert "Path of F-002, step by step:" in svg
    assert re.search(r">1</text>", svg) and re.search(r">2</text>", svg)
    assert "Build Pipeline" in svg and "⑤" in svg  # the name may wrap inside the actor box


def test_every_cap_beyond_its_limit_aggregates_and_still_draws_clean():
    ecosystems = ("npm", "pip", "gomod", "cargo", "maven")
    images = tuple((f"registry{i}.example.net", f"team/service-{i}") for i in range(6))
    inventory = {
        "ci": [
            {"system": name, "source": src}
            for name, src in (
                ("GitHub Actions", ".github/workflows"),
                ("GitLab CI", ".gitlab-ci.yml"),
                ("Jenkins", "Jenkinsfile"),
                ("Travis CI", ".travis.yml"),
            )
        ]
    }
    threats = [_threat(f"T-{10 + i}", "CWE-1104", 10 + i, risk="Medium") for i in range(len(ecosystems))]
    view = build_view(_model(threats), _facts(ecosystems=ecosystems, images=images, actions=12), inventory)
    svg = _render(view)
    assert "more inputs (listed below)" in svg
    assert "Not drawn (ci)" in svg and "Not drawn (artifacts)" in svg


def test_long_unbroken_references_and_non_ascii_names_wrap_inside_their_boxes():
    images = (
        ("registry.very-long-subdomain.example-corporation.internal", "platform/ünïcödé-service-with-a-very-long-name"),
    )
    view = build_view(
        _model(
            [
                _threat(
                    "T-003",
                    "CWE-1104",
                    10,
                    title="Ein sehr langer Titel über eine Abhängigkeit ohne Sperrdatei — build.yml:10",
                )
            ]
        ),
        _facts(images=images),
        {},
    )
    svg = _render(view)
    assert "ünïcödé" in svg
    assert "— build.yml:10" not in svg  # the register's location suffix is not repeated in the box


def test_the_legibility_gate_measures_the_smallest_text_at_every_display_width(monkeypatch):
    view = build_view(_model(), _facts(), {})
    monkeypatch.setattr(figure, "MIN_EFFECTIVE_PX", 9.0)
    svg, problems = figure.render(view, ACTOR, [], "")
    assert svg == ""
    assert any("at the readme width" in p for p in problems)


def test_an_entry_whose_target_is_not_drawn_fails_the_geometry_check():
    view = build_view(_model([_threat("T-004", "CWE-1104", 10)]), _facts(), {})
    view["entries"][0]["element"] = "input:package:does-not-exist"
    svg, problems = figure.render(view, ACTOR, [], "")
    assert svg == "" and any("not drawn" in p for p in problems)


def test_the_table_form_carries_elements_relationships_entries_and_the_path():
    view = build_view(_model([_threat("T-005", "CWE-1104", 10)]), _facts(), {})
    table = figure.render_table(view, ACTOR, ["⑤"])
    assert "Build-time attacker: **Build Pipeline Intruder** ⑤" in table
    assert "| sources | PyPI |" in table
    assert "| evidenced |" in table and "| unknown |" in table
    assert "a · Manipulated dependency" in table
    assert "1. PyPI → GitHub Actions (`.github/workflows/build.yml:10`)" in table


def test_short_title_keeps_titles_without_a_location():
    assert figure.short_title("Missing npm Lockfile — package-lock.json") == "Missing npm Lockfile"
    assert figure.short_title("Build — release split") == "Build — release split"
