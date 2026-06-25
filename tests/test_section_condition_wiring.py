"""Durable guard: every section/subsection presence-gate in the contract is wired.

The report's shape is declared in ``data/sections-contract.yaml``. Sections and
sub-sections may carry a ``condition`` gate (e.g. ``{ id: requirements_compliance,
condition: "check_requirements" }``). At render time ``compose_threat_model.py``
evaluates each gate against its ``eval_context`` dict via the restricted grammar
in ``scripts/_safe_cond.py``. That resolver does ``env.get(name)`` — so a condition
referencing a variable the renderer never puts into ``eval_context`` silently
resolves to ``False`` and the section disappears from every report, with no error.

This is the recurring failure mode behind a string of "authored but never
rendered" bugs (§Requirements Compliance, the MS AI/LLM Exposure callout, the
Critical Attack Tree). ``check_fragment_registry.py`` guards the *structural*
bijection (schema ↔ disk ↔ map ↔ contract) but does NOT evaluate conditions, so
none of those bugs were caught by a test.

These tests close that gap with two static invariants:

  1. Every variable read by a ``condition`` gate is a key the renderer actually
     provides in ``eval_context`` (catches the silent-skip class).
  2. Every ``condition`` gate parses under the safe grammar (catches a gate
     written with unsupported syntax — e.g. ``critical_count >= 2`` — that would
     abort compose at runtime instead of at commit time).

Scope: keys named exactly ``condition`` — the section/sub-section presence gates,
uniformly evaluated against ``eval_context``. Deliberately out of scope:
  * ``conditional`` (e.g. changelog ``len(changelog) > 0``) — a separate,
    richer evaluation mechanism, not the eval_context grammar.
  * ``per_critical_subsection_condition`` / ``intro_conditional`` — verified to be
    consumed by no script (dead keys); they cannot make a fragment go missing.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
COMPOSE = SCRIPTS / "compose_threat_model.py"


def _import(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_safe_cond = _import("_safe_cond")


# ---------------------------------------------------------------------------
# Collect every `condition` gate from the contract, with a path for diagnostics
# ---------------------------------------------------------------------------


def _collect_conditions(node, path: str, out: list[tuple[str, str]]) -> None:
    """Recursively gather (path, expr) for every value under a `condition` key."""
    if isinstance(node, dict):
        for key, val in node.items():
            child = f"{path}.{key}" if path else str(key)
            if key == "condition" and isinstance(val, str):
                out.append((child, val))
            else:
                _collect_conditions(val, child, out)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _collect_conditions(item, f"{path}[{i}]", out)


def _contract_conditions() -> list[tuple[str, str]]:
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = []
    _collect_conditions(contract, "", out)
    # Sanity: the contract is known to carry condition gates; an empty result
    # means the walk broke, not that the contract is genuinely gate-free.
    assert out, "no `condition` gates found in sections-contract.yaml — collector is broken"
    return out


# ---------------------------------------------------------------------------
# The keys compose_threat_model actually provides in `eval_context`
# ---------------------------------------------------------------------------


def _eval_context_keys() -> set[str]:
    """Statically extract every key the renderer writes into ``eval_context``.

    Sources: the ``eval_context={...}`` dict literal passed to ``RenderContext``,
    plus any later ``ctx.eval_context["x"] = ...`` mutation. Pure AST — robust to
    reordering, comments, and value changes; only a rename of ``eval_context``
    itself (which this test would rightly force an update for) breaks it.
    """
    tree = ast.parse(COMPOSE.read_text(encoding="utf-8"))
    keys: set[str] = set()

    for node in ast.walk(tree):
        # 1. Dict literal passed as the `eval_context=` keyword argument.
        if isinstance(node, ast.keyword) and node.arg == "eval_context" and isinstance(node.value, ast.Dict):
            for k in node.value.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
        # 2. `<obj>.eval_context["x"] = ...` subscript assignments.
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tgt in targets:
                if (
                    isinstance(tgt, ast.Subscript)
                    and isinstance(tgt.value, ast.Attribute)
                    and tgt.value.attr == "eval_context"
                    and isinstance(tgt.slice, ast.Constant)
                    and isinstance(tgt.slice.value, str)
                ):
                    keys.add(tgt.slice.value)

    # Sanity guard: a refactor that moved the dict must not make this test pass
    # vacuously. `check_requirements` is a long-standing gate key.
    assert "check_requirements" in keys, (
        f"AST extraction found no/unexpected eval_context keys — the test's locator is stale (found {sorted(keys)})"
    )
    return keys


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def test_every_condition_gate_parses() -> None:
    """Each `condition` gate uses the supported grammar (else compose aborts)."""
    bad: list[str] = []
    for path, expr in _contract_conditions():
        try:
            _safe_cond.referenced_names(expr)
        except _safe_cond.SafeCondError as e:
            bad.append(f"  {path}: {expr!r} — {e}")
    assert not bad, "unsupported condition grammar (would abort compose at runtime):\n" + "\n".join(bad)


def test_every_condition_variable_is_provided_by_eval_context() -> None:
    """Each variable a `condition` gate reads is set in the renderer's eval_context.

    A reference to a key the renderer never provides resolves to False and
    silently drops the section from every report (the §Requirements Compliance /
    AI-LLM-Exposure / Critical-Attack-Tree class of bug).
    """
    provided = _eval_context_keys()
    missing: list[str] = []
    for path, expr in _contract_conditions():
        for var in _safe_cond.referenced_names(expr):
            if var not in provided:
                missing.append(f"  {path}: condition {expr!r} reads {var!r} — never set in eval_context")
    assert not missing, (
        "section condition references a variable the renderer never provides; "
        "the section will silently never render. Add the key to eval_context in "
        "compose_threat_model.py (or fix the condition):\n" + "\n".join(missing)
    )
