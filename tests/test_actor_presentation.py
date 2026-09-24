"""Custom roles affect attribution without making diagram size role-dependent."""

import copy

import pytest
from actor_presentation import path_groups
from figure1_dfd import scenarios_from_attack_paths

from tests.test_figure2_svg import IMPACTS, TAXONOMY, model, paths


def with_roles(count=20, component="worker", finding="T-017"):
    data = model(component, finding)
    data["actors"] = [
        {
            "id": f"ACT-R-{i}",
            "label": f"service-role-{i}",
            "access": ["internal-network"],
            "trust_positions": [f"delegated-{i}-authority"],
            "heatmap_slug": "internet-priv-user",
            "active": True,
        }
        for i in range(1, count + 1)
    ]
    data["threats"][0]["actor_ids"] = [a["id"] for a in data["actors"]]
    data["threats"][0]["primary_actor"] = "ACT-R-1"
    return data


@pytest.mark.parametrize("component,finding", [("worker", "T-017"), ("processor-east", "T-203")])
def test_twenty_roles_form_one_evidenced_group(component, finding):
    data = with_roles(component=component, finding=finding)
    original = copy.deepcopy(data)
    scenarios, actors = scenarios_from_attack_paths(data, paths(finding), TAXONOMY)
    assert len(actors) == len(scenarios) == 1
    assert actors[0]["slug"] == "internet-priv-user"
    assert "20 roles" in actors[0]["sub"]
    assert scenarios[0]["cids"] == [component]
    assert data == original


def test_distinct_access_groups_do_not_gain_each_others_findings():
    data = with_roles(2)
    data["actors"][1]["heatmap_slug"] = "build-time"
    data["threats"][0]["actor_ids"] = ["ACT-R-1"]
    data["threats"].append({**data["threats"][0], "id": "T-018", "component": "builder", "actor_ids": ["ACT-R-2"]})
    attack_paths = paths()
    attack_paths["attack_paths"][0]["findings"].append("F-018")
    scenarios, actors = scenarios_from_attack_paths(data, attack_paths, TAXONOMY)
    assert {a["slug"] for a in actors} == {"internet-priv-user", "build-time"}
    assert [(s["n"], s["cids"], s["fids"]) for s in scenarios] == [("1", ["worker"], [17]), ("1", ["builder"], [18])]


def test_unlinked_disabled_unmapped_and_legacy_roles_do_not_invent_attribution():
    baseline = scenarios_from_attack_paths(model(), paths(), TAXONOMY)
    for modification in ("unlinked", "disabled", "unmapped"):
        data = with_roles(1)
        if modification == "unlinked":
            data["threats"][0]["actor_ids"] = []
        elif modification == "disabled":
            data["actors"][0]["active"] = False
        else:
            data["actors"][0]["heatmap_slug"] = None
        assert scenarios_from_attack_paths(data, paths(), TAXONOMY) == baseline


@pytest.mark.parametrize("prefix", ["ACT-X", "ACT-D"])
def test_unused_automatic_roles_never_reappear_in_report_or_diagram(prefix, tmp_path, monkeypatch):
    from types import SimpleNamespace

    import compose_threat_model as composer

    data = with_roles()
    for index, actor in enumerate(data["actors"], 1):
        actor["id"] = f"{prefix}-{index}"
    data["threats"][0]["actor_ids"] = []
    ctx = SimpleNamespace(yaml_data=data, output_dir=tmp_path)
    assert composer._render_identified_actors(ctx, None, {}) == ""
    assert scenarios_from_attack_paths(data, paths(), TAXONOMY) == scenarios_from_attack_paths(
        model(), paths(), TAXONOMY
    )

    # One actual assignment draws that role's access group under the group's name; no persona is listed.
    data["threats"][0]["actor_ids"] = [f"{prefix}-1"]
    monkeypatch.setattr(composer, "_load_attack_paths_fragment", lambda *args: paths())
    inventory = composer._render_identified_actors(ctx, None, {})
    assert "| Privileged User | Attacker |" in inventory
    assert "service-role" not in inventory and prefix not in inventory
    assert "1 role;" in scenarios_from_attack_paths(data, paths(), TAXONOMY)[1][0]["sub"]


def test_declared_override_keeps_its_source_and_does_not_become_an_automatic_role():
    from actor_presentation import export_actors, inventory_actors

    actor = with_roles(1)["actors"][0]
    actor.update(id="ACT-D-04", _provenance={"layer": "repo"})
    exported = export_actors({"resolved_actors": [actor]})
    assert exported[0]["origin"] == "repo"
    assert inventory_actors({"actors": exported, "threats": []}) == exported


def test_public_source_does_not_fold_privileged_or_build_roles():
    data = with_roles(2)
    data["meta"] = {"public_source_repo": True, "open_user_registration": True}
    data["actors"][1]["heatmap_slug"] = "build-time"
    scenarios, actors = scenarios_from_attack_paths(data, paths(), TAXONOMY)
    assert {a["slug"] for a in actors} == {"internet-priv-user", "build-time"}
    assert len({s["n"] for s in scenarios}) == 1


def test_path_projection_keeps_unattributed_findings_in_legacy_group():
    data = with_roles(1)
    attack_paths = paths()
    attack_paths["attack_paths"][0]["findings"].append("F-999")
    groups = path_groups(data, attack_paths["attack_paths"][0])
    assert [(g["actor"], g["findings"]) for g in groups] == [
        ("internet-priv-user", ["F-017"]),
        ("internet-user", ["F-999"]),
    ]


def test_figure2_example_uses_its_attributed_access():
    from figure2_svg import build_figure2_data

    row = build_figure2_data(with_roles(), paths(), TAXONOMY, IMPACTS)["routes"][0]
    assert row["actor_slug"] == "internet-priv-user"
    assert row["prerequisite"] == "Access prerequisites: see the finding"


@pytest.mark.parametrize("detail", [False, True])
def test_grouped_roles_pass_svg_geometry_without_growing_with_role_count(tmp_path, detail):
    import xml.etree.ElementTree as ET

    from figure1_dfd import check_diagram

    from tests.test_figure1_dfd import _model

    dimensions = []
    for count in (1, 20):
        data, attack_paths, taxonomy = _model()
        data["actors"] = with_roles(count)["actors"]
        for threat in data["threats"]:
            threat["actor_ids"] = [a["id"] for a in data["actors"]]
        svg, errors = check_diagram(data, attack_paths, taxonomy, detail=detail)
        assert errors == []
        assert f"{count} role" in svg
        root = ET.fromstring(svg)
        dimensions.append((root.get("width"), root.get("height")))
        (tmp_path / f"roles-{count}.svg").write_text(svg)
    assert dimensions[0] == dimensions[1]


@pytest.mark.parametrize("id_key", ["id", "t_id"])
def test_inventory_names_configured_roles_inside_their_drawn_group_and_escapes_them(monkeypatch, tmp_path, id_key):
    from types import SimpleNamespace

    import compose_threat_model as composer

    data = with_roles()
    data["threats"][0][id_key] = data["threats"][0].pop("id")
    data["actors"][0]["label"] = "<img src=x> | [link](https://invalid) `x`"
    data["actors"].append({**data["actors"][1], "id": "ACT-R-21", "label": "unrelated-role"})
    monkeypatch.setattr(composer, "_load_attack_paths_fragment", lambda *args: paths())
    ctx = SimpleNamespace(yaml_data=data, output_dir=tmp_path)
    text = composer._render_identified_actors(ctx, None, {})
    rows = [line for line in text.splitlines() if line.startswith("| ") and "---" not in line][1:]
    assert len(rows) == 1 and rows[0].startswith("| Privileged User | Attacker |")
    assert all(f"service-role-{i}" in rows[0] for i in range(2, 21)) and "unrelated-role" in rows[0]
    assert "🟠 1" in rows[0]
    assert "ACT-R-" not in text
    assert "<img" not in text and "[link](https://invalid)" not in text
    assert "\\|" in text


def test_canonical_actor_shape_rejects_unknown_groups():
    from validate_intermediate import _schema_errors

    data = with_roles(1)
    data["actors"][0]["heatmap_slug"] = "invented-access"
    errors = _schema_errors("threat_model_output", data)
    assert any("actors" in e and "heatmap_slug" in e for e in errors)


def test_prose_cleanup_preserves_inventory_identity_only():
    from apply_prose_fixes import _humanize_actor_ids

    row = "| ACT-D-04 · insider-developer | internal-network |\n"
    source = "### Identified Actors\n\n" + row + "\n### Findings\n\nACT-D-04 can read the repository.\n"
    result, count = _humanize_actor_ids(source)
    assert row in result
    assert count == 1
    assert "ACT-D-04 can read" not in result


def test_primary_actor_and_finding_prerequisites_remain_distinct():
    from figure2_svg import build_figure2_data

    data = with_roles(2)
    data["actors"][1]["heatmap_slug"] = "build-time"
    data["threats"][0]["primary_actor"] = "ACT-R-2"
    data["threats"][0]["cvss_v4"] = {"vector": "CVSS:4.0/PR:N/VC:H"}
    row = build_figure2_data(data, paths(), TAXONOMY, IMPACTS)["routes"][0]
    assert row["actor_slug"] == "build-time"
    assert row["prerequisite"] == "No account required"


def test_attribution_keeps_victim_interaction():
    from figure2_svg import build_figure2_data

    row = build_figure2_data(with_roles(), paths(actor="victim-required"), TAXONOMY, IMPACTS)["routes"][0]
    assert row["victim"]
    assert "Victim interaction required" in row["prerequisite"]


def test_composed_figures_legend_and_inventory_share_custom_roles(tmp_path):
    import compose_threat_model as composer

    from tests.test_compose_threat_model import TestSecurityPostureV2

    data = TestSecurityPostureV2._yaml_seven_classes()
    data["actors"] = with_roles()["actors"]
    for threat in data["threats"]:
        threat["actor_ids"] = [a["id"] for a in data["actors"]]
    ctx, env = TestSecurityPostureV2._build_ctx(tmp_path, data)
    overview = composer._render_security_posture_at_a_glance(ctx, env, {"min_high_or_critical": 0})
    inventory = composer._render_identified_actors(ctx, env, {})
    assert "**Figure 1" in overview and "**Figure 2" in overview
    assert "(#identified-actors)" in overview
    assert "ACT-R-" not in inventory
    assert all(f"service-role-{i}" in inventory for i in range(1, 21))
    assert "20 roles" in (ctx.output_dir / "figure1.svg").read_text()
    assert "20 roles" in (ctx.output_dir / "figure2.svg").read_text()


def test_builder_persists_custom_roles_without_runtime_sidecar_dependency(tmp_path, monkeypatch):
    import json
    import sys

    import build_threat_model_yaml as builder
    import yaml

    from tests.test_build_threat_model_yaml import _write_min_intermediates
    from tests.test_validate_intermediate import _valid_resolved_actors

    _write_min_intermediates(tmp_path)
    resolution = _valid_resolved_actors()
    prototype = resolution["resolved_actors"][0]
    prototype["_provenance"]["layer"] = "repo"
    resolution["resolved_actors"] = [
        {**copy.deepcopy(prototype), **{k: v for k, v in role.items() if k != "active"}}
        for role in with_roles()["actors"]
    ]
    sidecar = tmp_path / ".actors-resolved.json"
    sidecar.write_text(json.dumps(resolution))
    monkeypatch.setattr(sys, "argv", [str(builder.__file__), str(tmp_path), "--repo-root", str(tmp_path)])
    assert builder.main() == 0
    sidecar.unlink()
    data = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    assert len(data["actors"]) == 20
    assert data["actors"][0]["id"] == "ACT-R-1"
    assert data["actors"][0]["trust_positions"] == ["delegated-1-authority"]
    assert data["actors"][0]["heatmap_slug"] == "internet-priv-user"


@pytest.mark.parametrize(
    ("slug", "meta", "expected"),
    [
        ("internet-anon", {"open_user_registration": True}, "Internet Attacker"),
        ("internet-user", {"open_user_registration": True}, "Internet Attacker"),
        ("repo-read", {"public_source_repo": True}, "Anonymous Internet Attacker"),
        ("internet-user", {}, "Authenticated Internet Attacker"),
        ("build-time", {"open_user_registration": True}, "Supply-Chain / Build Attacker"),
    ],
)
def test_attacker_names_follow_the_projection_every_figure_uses(slug, meta, expected):
    from actor_presentation import attacker_display

    assert attacker_display(slug, meta)[0] == expected
    # A caller's label vocabulary wins over the plugin one, except for the registration fold.
    override = {"internet-user": {"label": "Signed-in Visitor"}, "build-time": {"label": "Pipeline Intruder"}}
    renamed = attacker_display(slug, meta, override)[0]
    assert renamed == {
        "Supply-Chain / Build Attacker": "Pipeline Intruder",
        "Authenticated Internet Attacker": "Signed-in Visitor",
    }.get(expected, renamed)


def _report(table_names, context_names=(), legend_names=()):
    rows = "\n".join(f"| {name} | Attacker | access | ① | 🟠 1 |" for name in table_names)
    nodes = "\n".join(f'    A{i}["{name}"]' for i, name in enumerate(context_names))
    classes = "\n".join(f"    class A{i} attacker" for i in range(len(context_names)))
    bullets = "\n".join(f"- **{name}** — drives ① Scenario." for name in legend_names)
    return (
        "## Management Summary\n\n**Threat actors.** The actors below drive the paths.\n\n"
        f"{bullets}\n\n### Identified Actors\n\nIntro.\n\n| Actor | Type | Access | Scenarios | Attributed findings |\n"
        f"|---|---|---|---|---|\n{rows}\n\n---\n\n## 2. Architecture Diagrams\n\n### 2.1 System Context\n\n```mermaid\n"
        f"flowchart LR\n{nodes}\n{classes}\n```\n\n### 2.2 Container Architecture\n"
    )


@pytest.mark.parametrize("names", [("Web Attacker", "Portal Operator"), ("Clinic Intruder",)])
def test_actor_name_check_accepts_the_table_set_and_rejects_any_other_name(tmp_path, names):
    from qa_checks import check_actor_names

    md = tmp_path / "threat-model.md"
    md.write_text(_report([f"A{i + 1} · {n}" for i, n in enumerate(names)], names, names[:1]), encoding="utf-8")
    assert check_actor_names(md).issues == []

    md.write_text(_report(names, [*names, "End User<br/>(browser)"], ["Anonymous Internet Attacker"]), encoding="utf-8")
    issues = check_actor_names(md).issues
    assert len(issues) == 2
    assert any("§2.1" in i and "End User (browser)" in i for i in issues)
    assert any("legend" in i and "Anonymous Internet Attacker" in i for i in issues)


@pytest.mark.parametrize("names", [("Web Attacker", "Portal User"), ("Clinic Intruder", "Clinic Patient")])
def test_actor_name_check_covers_the_components_fallback_diagram(tmp_path, names):
    from qa_checks import check_actor_names

    def report(threat, legit):
        diagram = (
            "\n### 2.3 Components\n\n```mermaid\nflowchart TD\n"
            f'    INTERNET_ANON["fa:fa-user-secret {threat}"]:::threat\n'
            f'    VICTIM_REQUIRED["fa:fa-user {legit}"]:::legit\n'
            '    a["fa:fa-server A"]:::risk\n```\n'
        )
        return _report(names).replace(
            "\n### 2.2 Container Architecture\n", "\n### 2.2 Container Architecture\n" + diagram
        )

    md = tmp_path / "threat-model.md"
    md.write_text(report(*names), encoding="utf-8")
    assert check_actor_names(md).issues == []

    md.write_text(report("Anonymous Internet Attacker", names[1]), encoding="utf-8")
    issues = check_actor_names(md).issues
    assert issues == [
        "§2.3 Components names actor 'Anonymous Internet Attacker', which Figure 1 and Identified Actors do not show"
    ]


def test_actor_name_check_skips_reports_without_the_actor_table(tmp_path):
    from qa_checks import check_actor_names

    md = tmp_path / "threat-model.md"
    md.write_text(_report([], ["Anyone"]).replace("### Identified Actors", "### Something Else"), encoding="utf-8")
    assert check_actor_names(md).issues == []


def test_every_deterministic_section_names_the_figure1_actor_set(tmp_path):
    """The composed overview, legend, actor table and §2.1 pass the name check together."""
    import compose_threat_model as composer
    from qa_checks import check_actor_names

    from tests.test_compose_threat_model import TestSecurityPostureV2

    data = TestSecurityPostureV2._yaml_seven_classes()
    data["meta"] = {**(data.get("meta") or {}), "open_user_registration": True}
    data["external_entities"] = [
        {"id": "ext-member", "kind": "legitimate-role", "name": "Member", "access": "internet-anon"},
        {"id": "ext-operator", "kind": "legitimate-role", "name": "Operator", "access": "internet-priv-user"},
    ]
    ctx, env = TestSecurityPostureV2._build_ctx(tmp_path, data)
    overview = composer._render_security_posture_at_a_glance(ctx, env, {"min_high_or_critical": 0})
    inventory = composer._render_identified_actors(ctx, env, {})
    context = composer.gen_architecture_diagrams(data, people=composer._overview_people(ctx))
    md = tmp_path / "threat-model.md"
    md.write_text("\n\n".join([overview, inventory, "---", context]), encoding="utf-8")

    report = check_actor_names(md)
    assert report.issues == [] and report.ok >= 3
    assert "Admin" in inventory and "Privileged role" in inventory


@pytest.mark.parametrize(
    ("project", "expected"), [({"project_name": "ledger-portal"}, "ledger-portal"), ({}, "the system")]
)
def test_actor_table_intro_names_the_project_like_figure1(tmp_path, project, expected):
    import compose_threat_model as composer

    from tests.test_compose_threat_model import TestSecurityPostureV2

    data = TestSecurityPostureV2._yaml_seven_classes()
    data.pop("project", None)
    data["meta"] = {k: v for k, v in (data.get("meta") or {}).items() if k not in ("project", "project_name")}
    data["meta"].update(project)
    data["external_entities"] = [
        {"id": "ext-member", "kind": "legitimate-role", "name": "Member", "access": "internet-anon"}
    ]
    ctx, env = TestSecurityPostureV2._build_ctx(tmp_path, data)
    intro = composer._render_identified_actors(ctx, env, {}).split("\n\n")[1]
    assert intro.endswith(f" of {expected}. Each row gives that actor's access and the findings attributed to it.")
