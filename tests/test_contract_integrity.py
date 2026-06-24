"""Integrity tests for data/sections-contract.yaml.

These tests catch authoring errors in the contract itself — the kind of
mistakes that would slip past the renderer because the renderer only checks
*what the contract says is required*, not whether the contract itself is
self-consistent. Examples:

  * An id in `document.order` has no matching `sections:` entry.
  * A section's `fragment` key points to a file that doesn't exist.
  * A section's `template` key points to a missing Jinja template.
  * A section's `schema` key points to a missing JSON Schema.
  * Two contract sections share the same heading.
  * A condition expression uses tokens the safe evaluator would reject.
  * `severity_taxonomy` is missing a key the renderer actually dereferences.

Running these tests on every PR means a broken contract cannot merge.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
SCHEMAS_DIR = REPO_ROOT / "schemas" / "fragments"
TEMPLATES_DIR = REPO_ROOT / "templates" / "fragments"


@pytest.fixture(scope="module")
def contract() -> dict:
    assert CONTRACT.is_file(), f"contract missing at {CONTRACT}"
    data = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "contract root must be a mapping"
    return data


# ---------------------------------------------------------------------------
# Basic shape
# ---------------------------------------------------------------------------


def test_contract_is_valid_yaml(contract):
    assert "document" in contract, "missing top-level 'document' block"
    assert "sections" in contract, "missing top-level 'sections' block"
    assert "order" in contract["document"], "missing 'document.order'"
    assert "severity_taxonomy" in contract, "missing 'severity_taxonomy'"


def test_contract_version_field_present(contract):
    assert "contract_version" in contract, "contract must declare a contract_version — bump it on breaking changes"


# ---------------------------------------------------------------------------
# document.order ↔ sections consistency
# ---------------------------------------------------------------------------


def _order_ids(contract) -> list[str]:
    ids = []
    for raw in contract["document"]["order"]:
        ids.append(raw if isinstance(raw, str) else raw["id"])
    return ids


def test_every_order_entry_has_matching_section(contract):
    ids = _order_ids(contract)
    sections = contract["sections"]
    missing = [sid for sid in ids if sid not in sections]
    assert not missing, (
        f"document.order references ids that don't exist in sections: {missing}\n"
        "Add the section definition or remove the entry from order."
    )


def test_every_section_is_in_order_or_used_as_subsection(contract):
    """Every sections: entry should be reachable either from document.order
    or as a sub-section (referenced by required_subsections / sub_sections of
    another section). Unreachable section definitions are dead code."""
    ids_in_order = set(_order_ids(contract))
    all_ids = set(contract["sections"].keys())

    # Sub-section-only ids: ms sub-sections, MS-inline-optional, etc.
    referenced_as_sub = set()
    for sec in contract["sections"].values():
        for sub in sec.get("required_subsections") or []:
            if isinstance(sub, str):
                referenced_as_sub.add(sub)
        for sub in sec.get("optional_subsections") or []:
            if isinstance(sub, dict) and "id" in sub:
                referenced_as_sub.add(sub["id"])

    unreachable = all_ids - ids_in_order - referenced_as_sub
    assert not unreachable, (
        f"sections with no reference from document.order or sub-sections: {unreachable}\n"
        "These will never render — remove them or wire them in."
    )


def test_no_duplicate_entries_in_order(contract):
    ids = _order_ids(contract)
    dupes = [sid for sid in set(ids) if ids.count(sid) > 1]
    assert not dupes, f"duplicate entries in document.order: {dupes}"


# ---------------------------------------------------------------------------
# File-path integrity: every template / schema / fragment path resolves
# ---------------------------------------------------------------------------


def test_every_template_path_exists(contract):
    missing = []
    for sid, sec in contract["sections"].items():
        tpl = sec.get("template")
        if tpl:
            path = TEMPLATES_DIR / tpl
            if not path.is_file():
                missing.append(f"{sid}.template = {tpl}")
        # Also check templates inside `sub_sections`.
        for sub in sec.get("sub_sections") or []:
            sub_tpl = sub.get("template")
            if sub_tpl:
                path = TEMPLATES_DIR / sub_tpl
                if not path.is_file():
                    missing.append(f"{sid}.{sub.get('id', '?')}.template = {sub_tpl}")
    assert not missing, f"dangling template paths: {missing}"


def test_every_schema_path_exists(contract):
    missing = []
    for sid, sec in contract["sections"].items():
        sch = sec.get("schema")
        if sch:
            path = SCHEMAS_DIR / sch
            if not path.is_file():
                missing.append(f"{sid}.schema = {sch}")
        for sub in sec.get("sub_sections") or []:
            sub_sch = sub.get("schema")
            if sub_sch:
                path = SCHEMAS_DIR / sub_sch
                if not path.is_file():
                    missing.append(f"{sid}.{sub.get('id', '?')}.schema = {sub_sch}")
    assert not missing, f"dangling schema paths: {missing}"


# ---------------------------------------------------------------------------
# Heading uniqueness + format
# ---------------------------------------------------------------------------


def test_section_headings_are_unique(contract):
    seen = {}
    for sid, sec in contract["sections"].items():
        h = (sec.get("heading") or "").strip()
        if not h:
            continue
        if h in seen:
            pytest.fail(
                f"duplicate section heading {h!r}: {seen[h]!r} and {sid!r}\n"
                f"Two sections cannot share a heading — ToC anchors would collide."
            )
        seen[h] = sid


def test_numbered_sections_match_heading_numbered_flag(contract):
    """A section that declares `heading_numbered: true` must have a heading
    that starts with `## N.`; one with `heading_numbered: false` must not.
    """
    bad = []
    for sid, sec in contract["sections"].items():
        heading = (sec.get("heading") or "").strip()
        declared = sec.get("heading_numbered")
        if declared is None or not heading:
            continue
        # Accept both `N.` and `Nx.` forms (e.g. `## 7b. Requirements Compliance`).
        has_number = bool(re.match(r"^#+\s+\d+[a-z]?\.\s", heading))
        if declared and not has_number:
            bad.append(f"{sid}: heading_numbered=true but heading {heading!r} lacks 'N.'")
        if not declared and has_number:
            bad.append(f"{sid}: heading_numbered=false but heading {heading!r} has 'N.'")
    assert not bad, "\n".join(bad)


# ---------------------------------------------------------------------------
# Condition expressions are safe to evaluate
# ---------------------------------------------------------------------------

_SAFE_COND = re.compile(r"^[\sA-Za-z0-9_\.\(\)\[\]'\",<>=!&|+\-]*$")


def test_all_condition_expressions_are_safe(contract):
    """Every `condition:` and `conditional:` string must match the
    safe-eval whitelist (compose_threat_model.eval_condition). A violation
    would raise ContractError at render-time — we want to catch it in tests."""
    violations = []

    def check(where: str, expr):
        if expr is None:
            return
        if not isinstance(expr, str):
            violations.append(f"{where}: non-string condition {expr!r}")
            return
        if not _SAFE_COND.fullmatch(expr):
            violations.append(f"{where}: unsafe tokens in {expr!r}")

    for raw in contract["document"]["order"]:
        if isinstance(raw, dict):
            check(f"document.order[{raw.get('id')}]", raw.get("condition"))

    for sid, sec in contract["sections"].items():
        check(f"sections.{sid}.conditional", sec.get("conditional"))
        for opt in sec.get("optional_subsections") or []:
            if isinstance(opt, dict):
                check(f"sections.{sid}.optional_subsections[{opt.get('id', '?')}].condition", opt.get("condition"))
        for sub in sec.get("sub_sections") or []:
            check(f"sections.{sid}.sub_sections[{sub.get('id', '?')}].conditional", sub.get("conditional"))

    assert not violations, "\n".join(violations)


COMPOSE_SRC = (REPO_ROOT / "scripts" / "compose_threat_model.py").read_text(encoding="utf-8")
_COND_KEYWORDS = {"not", "and", "or", "in", "len", "True", "False", "None"}


def _eval_context_keys(src: str) -> set[str]:
    """Keys compose populates into RenderContext.eval_context: the `eval_context={…}`
    dict-literal keys (brace-matched) plus every `eval_context["key"] =` assignment."""
    keys: set[str] = set()
    start = src.find("eval_context={")
    if start != -1:
        i = src.find("{", start)
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = src[i : j + 1]
        # only top-level dict keys (depth 1) — good enough: nested dicts here use
        # different key styles, and a stray nested key only widens the allowlist.
        keys |= set(re.findall(r"""["']([a-z_][a-z0-9_]*)["']\s*:""", block))
    keys |= set(re.findall(r"""eval_context\[["']([a-z_][a-z0-9_]*)["']\]\s*=""", src))
    return keys


def _condition_variables(expr: str) -> set[str]:
    """Variable names referenced by a safe-cond expression. Strips `[…]` enum
    lists (their members are literal values, not variables) and drops keywords."""
    no_lists = re.sub(r"\[[^\]]*\]", "", expr)
    return {t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", no_lists) if t not in _COND_KEYWORDS}


# Condition variables that are DOCUMENTARY only: their section is rendered by a
# special-case path that never calls eval_condition against eval_context, so the
# variable is intentionally not an eval_context key. `changelog` is one of the
# `("infobox", "changelog", "quick_mode_notice", "toc", "skipped_sections_placeholder")`
# document.order sections compose special-cases (compose_threat_model.py ~L1978);
# `len(changelog) > 0` documents intent but the changelog renderer self-gates.
# Keep this set MINIMAL and justified — every entry is a condition NOT enforced
# by the safe evaluator, so adding one knowingly forfeits that guard.
_DOCUMENTARY_CONDITION_VARS = {"changelog"}


def test_all_condition_variables_are_populated_in_eval_context(contract):
    """Every variable a `condition:`/`conditional:` references MUST be a key compose
    actually puts into `eval_context`. A condition on an unpopulated variable
    resolves to False silently (scripts/_safe_cond → env.get) — so the gated
    section NEVER renders and no error is raised. This is the systemic version of
    the 2026-06-24 `has_llm_surface` bug (referenced in the contract, populated
    nowhere → the AI/LLM Exposure gate was dead). General guard, all sections."""
    provided = _eval_context_keys(COMPOSE_SRC)
    assert provided, "could not extract any eval_context keys — extractor drifted"

    missing: list[str] = []

    def check(where: str, expr):
        if not isinstance(expr, str):
            return
        for var in _condition_variables(expr):
            if var not in provided and var not in _DOCUMENTARY_CONDITION_VARS:
                missing.append(f"{where}: '{var}' (in {expr!r}) not populated in eval_context")

    for raw in contract["document"]["order"]:
        if isinstance(raw, dict):
            check(f"document.order[{raw.get('id')}]", raw.get("condition"))
    for sid, sec in contract["sections"].items():
        check(f"sections.{sid}.conditional", sec.get("conditional"))
        for opt in sec.get("optional_subsections") or []:
            if isinstance(opt, dict):
                check(f"sections.{sid}.optional_subsections[{opt.get('id', '?')}]", opt.get("condition"))
        for sub in sec.get("sub_sections") or []:
            check(f"sections.{sid}.sub_sections[{sub.get('id', '?')}]", sub.get("conditional"))

    assert not missing, "Dead condition variable(s) — section would silently never render:\n" + "\n".join(missing)


# ---------------------------------------------------------------------------
# Severity / effectiveness taxonomy completeness
# ---------------------------------------------------------------------------


def test_severity_taxonomy_has_all_enum_values(contract):
    """The severity_taxonomy must define entries for every value that schemas
    or renderer can emit: critical/high/medium/low + red/yellow/green aliases
    (used by verdict & architecture_assessment fragments)."""
    needed = {"critical", "high", "medium", "low", "red", "yellow", "green"}
    have = set(contract.get("severity_taxonomy", {}).keys())
    missing = needed - have
    assert not missing, f"severity_taxonomy missing keys: {missing}"


def test_effectiveness_taxonomy_has_all_enum_values(contract):
    needed = {"adequate", "partial", "weak", "missing"}
    have = set(contract.get("effectiveness_taxonomy", {}).keys())
    missing = needed - have
    assert not missing, f"effectiveness_taxonomy missing keys: {missing}"


def test_severity_taxonomy_entries_have_emoji_and_label(contract):
    for k, v in contract["severity_taxonomy"].items():
        assert "emoji" in v, f"severity_taxonomy[{k}] missing 'emoji'"
        # Aliases (red/yellow/green) may have empty label; canonical values must have one.
        if k in ("critical", "high", "medium", "low"):
            assert v.get("label"), f"severity_taxonomy[{k}] missing 'label'"


# ---------------------------------------------------------------------------
# required_subsections shape — either a string (inline sub) or a dict with
# title | title_pattern. No silent surprises.
# ---------------------------------------------------------------------------


def test_required_subsections_entries_are_well_formed(contract):
    problems = []
    for sid, sec in contract["sections"].items():
        for i, sub in enumerate(sec.get("required_subsections") or []):
            if isinstance(sub, str):
                continue  # inline reference to another contract section
            if not isinstance(sub, dict):
                problems.append(
                    f"sections.{sid}.required_subsections[{i}]: must be str or dict, got {type(sub).__name__}"
                )
                continue
            if not (sub.get("title") or sub.get("title_pattern")):
                problems.append(
                    f"sections.{sid}.required_subsections[{i}]: dict entry must have 'title' or 'title_pattern'"
                )
    assert not problems, "\n".join(problems)


# ---------------------------------------------------------------------------
# §7 schema v2 drift resolution (2026-05-31).
# The strong per-auth-method enforcement (per-#### sequenceDiagram) was
# migrated onto the active schema_v2 rule, and §7.6 gained an approach-first
# rule. These lock that contract shape so the drift cannot silently reopen.
# ---------------------------------------------------------------------------


def _v2_rules(contract: dict) -> dict:
    return contract["sections"]["security_architecture"]["schema_v2"]["domain_required_rules"]


def test_v2_auth_method_decomposition_requires_flow_diagram(contract):
    rules = _v2_rules(contract)["7.2 Identity and Authentication Controls"]
    auth = next(r for r in rules if r.get("rule") == "auth_method_decomposition")
    assert auth.get("flow_methods_require_diagram") is True
    assert auth.get("flow_diagram_token") == "sequenceDiagram"
    tokens = auth.get("flow_method_tokens") or []
    # The grouped password block and the headline web flows must be gated.
    for needed in ("password-based", "oauth", "totp", "saml"):
        assert needed in tokens, f"{needed!r} missing from flow_method_tokens"


def test_v2_section76_has_validation_approach_first(contract):
    rules = _v2_rules(contract)
    key = "7.6 Input Boundary Validation Controls"
    assert key in rules, "§7.6 validation_approach_first rule key missing"
    rule = next(r for r in rules[key] if r.get("rule") == "validation_approach_first")
    assert rule.get("enforcement") == "error"
    assert rule.get("approach_heading_patterns"), "no approach_heading_patterns declared"
