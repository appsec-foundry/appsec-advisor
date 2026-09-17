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

    # One actual assignment admits only that role, never the rest of the catalogue.
    data["threats"][0]["actor_ids"] = [f"{prefix}-1"]
    monkeypatch.setattr(composer, "_load_attack_paths_fragment", lambda *args: paths())
    inventory = composer._render_identified_actors(ctx, None, {})
    assert "service-role-1 |" in inventory
    assert all(f"service-role-{i} |" not in inventory for i in range(2, 21))
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
def test_inventory_keeps_every_role_and_escapes_imported_access(monkeypatch, tmp_path, id_key):
    from types import SimpleNamespace

    import compose_threat_model as composer

    data = with_roles()
    data["threats"][0][id_key] = data["threats"][0].pop("id")
    data["actors"][0]["access"] = ["<img src=x> | [link](https://invalid) `x`"]
    data["actors"].append({**data["actors"][0], "id": "ACT-R-21", "label": "unrelated-role"})
    monkeypatch.setattr(composer, "_load_attack_paths_fragment", lambda *args: paths())
    ctx = SimpleNamespace(yaml_data=data, output_dir=tmp_path)
    text = composer._render_identified_actors(ctx, None, {})
    assert all(f"ACT-R-{i} · service-role-{i}" in text for i in range(1, 21))
    assert "ACT-R-21 · unrelated-role" in text
    assert "No displayed scenario" in text
    assert "[F-017](#f-017)" in text
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
    assert "No displayed scenario" not in inventory
    assert all(f"ACT-R-{i} · service-role-{i}" in inventory for i in range(1, 21))
    assert "[F-001](#f-001)" in inventory
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
