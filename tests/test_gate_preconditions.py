"""Structural checks for the defect class that cost five runs.

Every one of those aborts had the same shape: a fail-closed consumer reading
data an optional, later, or derived producer had not supplied. The failures
looked like content faults and were diagnosed as such, so the checks here are
deliberately structural — they hold without executing a pipeline, which is the
only reason they would have fired before any of those runs started.

* **A hard gate's producers must be hard steps.** `auto_emitter_pass.sh` guards
  every emitter with `|| true` by design, so a 25-minute Stage 1 survives a
  failed enrichment. Two of those emitters feed the P1/P2 actionability gate —
  their own comments there say so — and without them that gate reports 96
  INVALID lines against the author on a model that is fine (juice-shop
  2026-08-06).
* **A fail-closed membership test needs a populated set.** A resolution set that
  is empty because its authority is absent rejects everything, turning "cannot
  check" into "all invalid" (juice-shop 2026-08-30, 116 rejected IDs, all 30
  distinct ones declared).
* **An abort must name the failure.** Diagnosis of every entry above started
  from the abort line, and twice that line named something benign.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import orchestration_controller as oc  # noqa: E402

# gate script -> producers that must have run as hard steps before it.
GATE_PRODUCERS = {
    "validate_mitigation_quality.py": (
        "backfill_scanner_remediation.py",
        "hydrate_mitigation_details.py",
    ),
}


def _hard_step_names(node: ast.AST) -> list[str]:
    """Script names run as hard, abort-on-failure steps, in source order.

    `_run_script` raises on a non-zero exit and `_step` returns False for the
    caller to propagate; both make the script a precondition. A name reached
    only through `auto_emitter_pass.sh` is deliberately not here — that pass
    swallows every failure, which is the whole point of the check.
    """
    names: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Name):
            continue
        if child.func.id not in {"_run_script", "_step"} or not child.args:
            continue
        first = child.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            names.append((child.lineno, first.value))
    return [name for _, name in sorted(names)]


@pytest.mark.parametrize("gate", sorted(GATE_PRODUCERS))
def test_every_hard_gate_is_preceded_by_its_producers(gate):
    tree = ast.parse((SCRIPTS / "orchestration_controller.py").read_text(encoding="utf-8"))
    call_sites = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        steps = _hard_step_names(node)
        if gate not in steps:
            continue
        call_sites += 1
        before = steps[: steps.index(gate)]
        for producer in GATE_PRODUCERS[gate]:
            assert producer in before, (
                f"{node.name} runs {gate} without {producer} as a hard step before it. "
                f"A best-effort producer feeding a fail-closed gate reports tooling "
                f"failure as content findings against the author."
            )
    assert call_sites, f"no call site found for {gate} — update GATE_PRODUCERS"


def _empty_literal(value: ast.AST | None) -> bool:
    if value is None:
        return False
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in {"set", "dict", "list"}:
        return not value.args
    if isinstance(value, ast.Set):
        return not value.elts
    if isinstance(value, (ast.List, ast.Dict)):
        return not (getattr(value, "elts", None) or getattr(value, "keys", None))
    return False


def _assigned_names(statement: ast.AST) -> list[ast.Name]:
    if isinstance(statement, ast.Assign):
        return [target for target in statement.targets if isinstance(target, ast.Name)]
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name) and statement.value is not None:
        return [statement.target]
    return []


def _unguarded_fail_closed_sets(tree: ast.AST) -> list[tuple[str, str, int]]:
    """Find `x = set()` filled only inside an `if`, then `not in`-tested outside.

    That shape cannot distinguish "nothing declared" from "no authority", so the
    membership test rejects every value whenever the conditional branch did not
    run. Only `not in` qualifies: the `in` form fails open and merely skips work.
    """
    findings: list[tuple[str, str, int]] = []
    for function in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        empty = {
            target.id: statement.lineno
            for statement in function.body
            for target in _assigned_names(statement)
            if _empty_literal(getattr(statement, "value", None))
        }
        if not empty:
            continue
        filled = set()
        for statement in function.body:
            if not isinstance(statement, ast.If):
                continue
            for node in ast.walk(statement):
                for target in _assigned_names(node):
                    if target.id in empty:
                        filled.add(target.id)
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id in empty
                    and node.func.attr in {"add", "update", "append", "setdefault"}
                ):
                    filled.add(node.func.value.id)
        for statement in function.body:
            if isinstance(statement, ast.If):
                continue
            for node in ast.walk(statement):
                if not isinstance(node, ast.Compare) or not any(isinstance(op, ast.NotIn) for op in node.ops):
                    continue
                for comparator in node.comparators:
                    if isinstance(comparator, ast.Name) and comparator.id in filled:
                        findings.append((function.name, comparator.id, node.lineno))
    return findings


# Dedup lists and exclusion sets, where an empty set correctly means "nothing
# excluded". Each entry is (script, function, name) and must stay justified.
KNOWN_FAIL_OPEN_SETS = {
    ("build_stride_dispatch_manifest.py", "_detect_cicd", "paths"),
    ("merge_threats.py", "_select_boundary_refs", "origins"),
    ("smoke_test_package.py", "check_surface_manifest", "declared"),
}


def test_no_resolution_set_rejects_everything_when_its_authority_is_absent():
    offenders = []
    for script in sorted(SCRIPTS.glob("*.py")):
        try:
            tree = ast.parse(script.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for function, name, lineno in _unguarded_fail_closed_sets(tree):
            if (script.name, function, name) in KNOWN_FAIL_OPEN_SETS:
                continue
            offenders.append(f"{script.name}:{lineno} {function}() tests membership against '{name}'")
    assert not offenders, (
        "A set that is empty because its authority never loaded rejects every value. "
        "Guard the membership test on the set being populated, or add the entry to "
        "KNOWN_FAIL_OPEN_SETS with the reason an empty set is correct there:\n  " + "\n  ".join(offenders)
    )


def test_an_abort_names_the_failure_and_not_the_warning_above_it():
    """No marker at all: the last non-benign line is the fault.

    Only some producers prefix a fault with `FATAL:`; most report it as plain
    `<script>: <exception>`. Reporting the first line instead logged a
    `TRUST_BOUNDARY_WARN` about a rejected evidence path as the cause of a run
    whose real fault was a schema violation, and that abort has no known cause
    to this day (2026-07-31).
    """
    detail = oc._abort_event_detail(
        "prepare_trust_boundary_context.py failed with exit 1: "
        "TRUST_BOUNDARY_WARN: candidate-1: rejected missing evidence file 'routes/index.ts'\n"
        "TRUST_BOUNDARY_WARN: candidate-3: rejected unsafe evidence path\n"
        "prepare_trust_boundary_context: 'trust_boundaries' is a required property"
    )

    assert "'trust_boundaries' is a required property" in detail
    assert "TRUST_BOUNDARY_WARN" not in detail
    assert "\n" not in detail


def test_an_abort_counts_findings_of_one_class_instead_of_picking_one():
    """N identical findings mean a systematic defect, and the count says so.

    Reporting one arbitrary exemplar of 116 `does not resolve` lines hid that
    *every* reference had failed, and the abort was read as analyzers inventing
    a handful of IDs (juice-shop 2026-08-30).
    """
    findings = "\n".join(
        f"INVALID: mitigation M-{index:03d}: fulfilled requirement 'AC-003' does not resolve" for index in range(40)
    )
    detail = oc._abort_event_detail(
        f"build_threat_model_yaml.py failed with exit 5: threats: 5 below severity floor\n"
        f"FATAL: schema validation failed\n{findings}"
    )

    assert re.search(r"\b40× ", detail)
    assert "does not resolve" in detail
    assert "\n" not in detail


def _triage_flags(tmp_path, *types):
    (tmp_path / ".triage-flags.json").write_text(
        json.dumps(
            {
                "version": 2,
                "generated_at": "2026-08-18T06:00:00Z",
                "flags": [
                    {
                        "flag_id": f"TF-{index + 1:03d}",
                        "type": value,
                        "severity": "warning",
                        "threat_ids": ["F-001"],
                        "message": "m",
                    }
                    for index, value in enumerate(types)
                ],
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_separator_drift_in_an_llm_enum_is_repaired_not_fatal(tmp_path):
    """One character must not end a completed Stage 1.

    The agent's own instruction file spells this token both ways, so it wrote
    the prose variant and the schema enum rejected it (juice-shop2 2026-08-18).
    Agent output is untrusted input: canonicalise the separator, then validate.
    """
    output = _triage_flags(tmp_path, "business-impact", "consistency")

    assert oc._canonicalize_triage_flag_types(output) == ["business-impact -> business_impact"]

    flags = json.loads((output / ".triage-flags.json").read_text(encoding="utf-8"))["flags"]
    assert [flag["type"] for flag in flags] == ["business_impact", "consistency"]


def test_a_value_the_schema_never_declared_is_left_for_the_validator(tmp_path):
    """Canonicalisation repairs spelling, never invents membership."""
    output = _triage_flags(tmp_path, "totally-unknown")

    assert oc._canonicalize_triage_flag_types(output) == []
    flags = json.loads((output / ".triage-flags.json").read_text(encoding="utf-8"))["flags"]
    assert flags[0]["type"] == "totally-unknown"


def test_the_accepted_flag_types_come_from_the_schema(tmp_path):
    """A second hand-maintained list here would be the same drift one layer down."""
    schema = yaml.safe_load((REPO_ROOT / "schemas" / "triage-flags.schema.yaml").read_text(encoding="utf-8"))
    declared = schema["properties"]["flags"]["items"]["properties"]["type"]["enum"]
    hyphenated = [value.replace("_", "-") for value in declared if "_" in value]
    assert hyphenated, "no underscore-bearing enum value left to drift"

    output = _triage_flags(tmp_path, *hyphenated)
    oc._canonicalize_triage_flag_types(output)

    flags = json.loads((output / ".triage-flags.json").read_text(encoding="utf-8"))["flags"]
    assert [flag["type"] for flag in flags] == [value for value in declared if "_" in value]


def test_an_abort_still_names_a_lone_finding_below_a_benign_first_line():
    """The case the marker rule was introduced for stays fixed."""
    detail = oc._abort_event_detail(
        "build_threat_model_yaml.py failed with exit 5: threats: 5 below severity floor dropped from register\n"
        "INVALID: threats[18].title must be a non-empty string"
    )

    assert "threats[18].title" in detail
    assert "×" not in detail
