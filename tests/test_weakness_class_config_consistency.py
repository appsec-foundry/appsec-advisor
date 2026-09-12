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

import re
from pathlib import Path

import jsonschema
import pytest
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


def _mechanism_id_pattern(schema_name: str) -> str:
    """The `mechanism_id` pattern a schema states."""
    schema = yaml.safe_load((SCHEMAS / schema_name).read_text())

    def walk(node: object) -> str | None:
        if isinstance(node, dict):
            prop = node.get("mechanism_id")
            if isinstance(prop, dict) and prop.get("pattern"):
                return str(prop["pattern"])
            for v in node.values():
                found = walk(v)
                if found:
                    return found
        elif isinstance(node, list):
            for v in node:
                found = walk(v)
                if found:
                    return found
        return None

    pattern = walk(schema)
    assert pattern, f"{schema_name}: no mechanism_id pattern found (walker broke?)"
    return pattern


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


def test_curated_mechanism_ids_match_the_schema_pattern() -> None:
    """`build_weakness_register` returns a curated mechanism key verbatim, so a
    key that does not satisfy the schema's `mechanism_id` pattern would reach
    the emitted register and hard-fail post-merge validation."""
    pattern = re.compile(_mechanism_id_pattern("threats-merged.schema.yaml"))
    keys = list(yaml.safe_load((DATA / "weakness-classes.yaml").read_text()).get("mechanism_guidance") or {})
    assert keys, "weakness-classes.yaml carries no mechanism_guidance"
    lib = yaml.safe_load((DATA / "security-libraries.yaml").read_text())
    for domain in (lib.get("domains") or {}).values():
        control = (domain or {}).get("central_control") or {}
        if control.get("mechanism_id"):
            keys.append(str(control["mechanism_id"]))
    for key in keys:
        assert pattern.match(str(key)), f"mechanism id {key!r} violates {pattern.pattern}"


def test_both_schemas_state_the_same_mechanism_id_pattern() -> None:
    assert _mechanism_id_pattern("threats-merged.schema.yaml") == _mechanism_id_pattern(
        "threat-model.output.schema.yaml"
    )


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


def _annotation_catalog() -> dict:
    return yaml.safe_load((DATA / "weakness-classes.yaml").read_text())["diagram_annotations"]


def test_diagram_annotation_catalog_matches_schema() -> None:
    schema = yaml.safe_load((SCHEMAS / "figure1-annotations.schema.yaml").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.validate(_annotation_catalog(), schema)


@pytest.mark.parametrize("label", ["Client-Side Security Enforcement", "Authentication", "Input Validation"])
def test_diagram_annotation_schema_rejects_neutral_control_names(label) -> None:
    schema = yaml.safe_load((SCHEMAS / "figure1-annotations.schema.yaml").read_text())
    catalog = _annotation_catalog()
    catalog["labels"][label] = catalog["labels"].pop("Improper Client Trust")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(catalog, schema)


@pytest.mark.parametrize("qualifier", ["SQL Injection", "DOM-XSS", "SQLi/LDAPi", "LongTag"])
def test_attack_pattern_qualifiers_remain_single_short_abbreviations(qualifier) -> None:
    schema = yaml.safe_load((SCHEMAS / "figure1-annotations.schema.yaml").read_text())
    catalog = _annotation_catalog()
    catalog["labels"]["Unsafe Query Construction"]["cwe_qualifiers"]["CWE-89"] = qualifier
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(catalog, schema)


def test_diagram_annotations_have_unambiguous_assignments() -> None:
    catalog = _annotation_catalog()
    orders = [entry["tie_break_order"] for entry in catalog["labels"].values()]
    assert len(orders) == len(set(orders)), "Figure 1 tie-break positions must be unique"
    variants = [
        (entry.get("control_family", label), entry.get("variant_order", 0))
        for label, entry in catalog["labels"].items()
    ]
    assert len(variants) == len(set(variants)), "Control-family variant precedence must be unambiguous"
    for field in ("cwes", "mechanisms"):
        owners = {}
        for label, entry in catalog["labels"].items():
            for key in entry.get(field, []):
                assert key not in owners, f"{key} assigned to both {owners.get(key)} and {label}"
                owners[key] = label
        if field == "cwes":
            assert not owners.keys() & catalog["exceptions"].keys()
    for label, entry in catalog["labels"].items():
        qualifiers = entry.get("cwe_qualifiers", {})
        assert qualifiers.keys() <= set(entry["cwes"])
        assert all(len(f"{label} ({qualifier})") <= 36 for qualifier in qualifiers.values())


def test_diagram_annotations_cover_declared_cwes_and_curated_mechanisms() -> None:
    """Guard explicit CWE selectors in shipped catalogs, excluding the annotation
    catalog itself, comments, prose, pillar references and negative selectors.
    New supported values must gain a label or an individually reasoned exception.
    """
    supported = set()

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "diagram_annotations":
                    continue
                if key in {"cwe", "cwes", "cwe_any", "cwe_all"}:
                    values = value if isinstance(value, list) else [value]
                    supported.update(v for v in values if isinstance(v, str) and re.fullmatch(r"CWE-\d+", v))
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    for path in sorted(DATA.rglob("*.yaml")):
        walk(yaml.safe_load(path.read_text()))
    supported.update(yaml.safe_load((DATA / "cwe-taxonomy.yaml").read_text())["cwes"])
    catalog = _annotation_catalog()
    mapped = {cwe for entry in catalog["labels"].values() for cwe in entry["cwes"]}
    accounted = mapped | catalog["exceptions"].keys()
    assert supported <= accounted, f"Missing Figure 1 annotation decisions: {sorted(supported - accounted)}"
    assert catalog["exceptions"].keys() <= supported, "Remove exceptions for unsupported CWEs"

    vocabulary = yaml.safe_load((DATA / "weakness-classes.yaml").read_text())
    mechanisms = set(vocabulary["mechanism_guidance"])
    libraries = yaml.safe_load((DATA / "security-libraries.yaml").read_text())
    mechanisms.update(
        control["mechanism_id"]
        for domain in libraries["domains"].values()
        if (control := domain.get("central_control", {})).get("mechanism_id")
    )
    mapped_mechanisms = {m for entry in catalog["labels"].values() for m in entry.get("mechanisms", [])}
    assert mechanisms == mapped_mechanisms
