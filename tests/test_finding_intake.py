"""The raw-intake contract (FE-22): producers state claims, one function derives the legacy fields."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from model.finding_intake import CLAIMED_TIERS, apply_intake

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def test_dispatch_component_is_recorded_and_sets_the_established_fields():
    out = apply_intake({}, dispatch_component="api", component_name="API")
    assert out == {"dispatch_component": "api", "component_id": "api", "component_name": "API"}


def test_existing_component_is_kept_only_when_asked():
    record = {"component_id": "own", "component_name": "Own"}
    kept = apply_intake(dict(record), dispatch_component="api", component_name="API", keep_existing=True)
    replaced = apply_intake(dict(record), dispatch_component="api", component_name="API")

    assert (kept["component_id"], kept["component_name"], kept["dispatch_component"]) == ("own", "Own", "api")
    assert (replaced["component_id"], replaced["component_name"]) == ("api", "API")


@pytest.mark.parametrize("tier", sorted(CLAIMED_TIERS))
def test_a_claimed_tier_is_recorded_and_sets_the_established_tier(tier):
    out = apply_intake({}, dispatch_component="api", claimed_tier=tier)
    assert out["claimed_tier"] == out["evidence_tier"] == tier


@pytest.mark.parametrize("tier", [None, "", "proven", "verified", "Confirmed-Exploitable"])
def test_any_other_tier_is_ignored_and_leaves_the_default_to_downstream(tier):
    out = apply_intake({}, dispatch_component="api", claimed_tier=tier)
    assert "claimed_tier" not in out
    assert "evidence_tier" not in out


def test_an_analyzer_tier_already_on_the_record_is_not_touched_when_invalid():
    out = apply_intake({"evidence_tier": "odd"}, dispatch_component="api", claimed_tier="odd")
    assert out["evidence_tier"] == "odd"
    assert "claimed_tier" not in out


def test_nothing_is_written_without_a_component():
    assert apply_intake({}, dispatch_component=None) == {}


# Producers of a raw threat record. Each builds it as a dict literal that names its
# `stride` and `evidence`; none may write the three derived fields itself.
_PRODUCERS = {
    "model/merge_threats.py": {"_config_finding_to_threat", "_source_auth_finding_to_threat"},
    "analyzers/arch_coverage_to_threats.py": {"_build_threat"},
    "model/promote_verified_abuse_cases.py": None,
}
_DERIVED = {"component_id", "component_name", "evidence_tier"}


def _record_literals(path: Path, functions: set[str] | None):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    scopes = (
        [tree]
        if functions is None
        else [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in functions]
    )
    for scope in scopes:
        for node in ast.walk(scope):
            if isinstance(node, ast.Dict):
                keys = {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if {"stride", "evidence"} <= keys:
                    yield node, keys


@pytest.mark.parametrize("module", sorted(_PRODUCERS))
def test_producers_do_not_write_the_derived_fields_themselves(module):
    """A threat literal naming `stride` and `evidence` must leave component and tier to apply_intake."""
    literals = list(_record_literals(SCRIPTS / module, _PRODUCERS[module]))

    assert literals, f"{module}: no producer record literal found — update the guard with the code"
    for node, keys in literals:
        assert not (keys & _DERIVED), f"{module}:{node.lineno} writes {sorted(keys & _DERIVED)} outside apply_intake"
