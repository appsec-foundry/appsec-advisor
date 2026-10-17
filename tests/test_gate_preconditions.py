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
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


# gate script -> producers that must have run as hard steps before it.
GATE_PRODUCERS = {
    "validators/validate_mitigation_quality.py": (
        "model/backfill_scanner_remediation.py",
        "model/hydrate_mitigation_details.py",
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
    tree = ast.parse((SCRIPTS / "orchestrator/orchestration_controller.py").read_text(encoding="utf-8"))
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
    ("orchestrator/build_stride_dispatch_manifest.py", "_detect_cicd", "paths"),
    ("model/merge_threats.py", "_select_boundary_refs", "origins"),
    ("smoke_test_package.py", "check_surface_manifest", "declared"),
}


def test_no_resolution_set_rejects_everything_when_its_authority_is_absent():
    offenders = []
    for script in sorted(SCRIPTS.rglob("*.py")):
        if {"node_modules", "__pycache__"} & set(script.relative_to(SCRIPTS).parts):
            continue
        try:
            tree = ast.parse(script.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        relative = script.relative_to(SCRIPTS).as_posix()
        for function, name, lineno in _unguarded_fail_closed_sets(tree):
            if (relative, function, name) in KNOWN_FAIL_OPEN_SETS:
                continue
            offenders.append(f"{relative}:{lineno} {function}() tests membership against '{name}'")
    assert not offenders, (
        "A set that is empty because its authority never loaded rejects every value. "
        "Guard the membership test on the set being populated, or add the entry to "
        "KNOWN_FAIL_OPEN_SETS with the reason an empty set is correct there:\n  " + "\n  ".join(offenders)
    )
