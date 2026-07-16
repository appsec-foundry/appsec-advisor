"""Cross-config consistency for the weakness-class vocabulary.

`data/weakness-classes.yaml` clusters[] is the single source of truth for the
set of valid `weakness_class` values. Several other artifacts hand-repeat that
vocabulary and drift silently when a cluster is added or renamed:

  - both schema `weakness_class` enums (intermediate + output mirror), which
    `validate_intermediate` enforces against the emitted `weaknesses[]`;
  - `data/posture-rubric.yaml` theme_by_weakness_class routing;
  - `data/security-libraries.yaml` domains (implementation-strategy packs).

`merge_threats.build_weakness_register` clamps emitted classes against the YAML
clusters, NOT the schema enums — so a cluster present in the YAML but missing
from an enum passes the clamp and then hard-fails schema validation downstream.
This guard makes that drift a test failure instead of a runtime hard-fail.
(Regression: the 2026-07-14 `secret_management` cluster shipped without its
schema-enum entries.)
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
DATA = REPO_ROOT / "data"
SCHEMAS = REPO_ROOT / "schemas"


def _cluster_ids() -> set[str]:
    doc = yaml.safe_load((DATA / "weakness-classes.yaml").read_text())
    return {c["id"] for c in doc.get("clusters", [])}


def _weakness_class_enums(schema: dict) -> list[list[str]]:
    """Every `weakness_class` property enum anywhere in the schema tree."""
    found: list[list[str]] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            wc = node.get("weakness_class")
            if isinstance(wc, dict) and isinstance(wc.get("enum"), list):
                found.append(wc["enum"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    return found


def test_schema_enums_match_cluster_ids() -> None:
    clusters = _cluster_ids()
    for name in ("threats-merged.schema.yaml", "threat-model.output.schema.yaml"):
        schema = yaml.safe_load((SCHEMAS / name).read_text())
        enums = _weakness_class_enums(schema)
        assert enums, f"{name}: no weakness_class enum found (walker broke?)"
        for enum in enums:
            assert set(enum) == clusters, (
                f"{name}: weakness_class enum drifted from "
                f"weakness-classes.yaml clusters. "
                f"missing={clusters - set(enum)} extra={set(enum) - clusters}"
            )


def test_posture_rubric_themes_reference_known_classes() -> None:
    clusters = _cluster_ids()
    rubric = yaml.safe_load((DATA / "posture-rubric.yaml").read_text())
    keys = set(rubric.get("theme_by_weakness_class", {}))
    assert keys <= clusters, (
        f"posture-rubric.yaml theme_by_weakness_class references unknown weakness classes: {keys - clusters}"
    )


def test_security_library_domains_reference_known_classes() -> None:
    clusters = _cluster_ids()
    lib = yaml.safe_load((DATA / "security-libraries.yaml").read_text())
    keys = set(lib.get("domains", {}))
    assert keys <= clusters, f"security-libraries.yaml domains reference unknown weakness classes: {keys - clusters}"


def test_input_validation_mechanism_narrative_is_not_blacklist_asserting() -> None:
    """The blacklist-only-input-validation mechanism is also reached for the
    ARCH-INPUT-001 'missing centralized input validation' signal, so its narrative
    must hold when validation is ABSENT — not assert a blacklist that may not
    exist (insecure-spring-app W-003: register claimed a regex blacklist on paths
    that had no @Valid / bean-validation at all). Guards that regression."""
    doc = yaml.safe_load((DATA / "weakness-classes.yaml").read_text())
    m = (doc.get("mechanism_guidance") or {}).get("blacklist-only-input-validation")
    assert m, "blacklist-only-input-validation mechanism missing"
    name = m["weakness_name"].lower()
    desc = m["description"].lower()
    # Must not assert a present blacklist control as THE weakness.
    assert "relies on regex blacklist" not in name
    # Narrative must acknowledge the absent-validation case, not only blacklist.
    assert "absent" in desc
    # Fix direction stays allowlist/schema enforcement.
    assert "allowlist" in m["structural_fix"].lower() or "schema" in m["structural_fix"].lower()
