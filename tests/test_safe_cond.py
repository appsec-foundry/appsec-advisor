"""Tests for scripts/_safe_cond.py — deterministic condition resolver."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def _import(name: str, file_name: str | None = None):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (file_name or f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def safe_cond():
    return _import("_safe_cond")


# ---------------------------------------------------------------------------
# Positive: real-world conditions from data/sections-contract.yaml
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr,env,want",
    [
        # bare-name bool lookups (the only conditions that reach eval_condition today)
        ("check_requirements", {"check_requirements": True}, True),
        ("check_requirements", {"check_requirements": False}, False),
        ("compose_warned", {}, False),  # missing name → falsy
        ("render_security_architecture", {"render_security_architecture": 1}, True),
        ("triage_has_warnings", {"triage_has_warnings": []}, False),  # empty list is falsy
        ("run_warned", {"run_warned": "yes"}, True),
        # not <name>
        ("not skip_attack_walkthroughs", {"skip_attack_walkthroughs": False}, True),
        ("not skip_attack_walkthroughs", {"skip_attack_walkthroughs": True}, False),
        ("not skip_attack_walkthroughs", {}, True),  # missing → not falsy → True
        # membership
        ("verdict_severity in [yellow, red]", {"verdict_severity": "red"}, True),
        ("verdict_severity in [yellow, red]", {"verdict_severity": "green"}, False),
        ("verdict_severity not in [yellow, red]", {"verdict_severity": "green"}, True),
        ("verdict_severity not in [yellow, red]", {"verdict_severity": "red"}, False),
        # quoted membership items
        ('verdict_severity in ["yellow", "red"]', {"verdict_severity": "yellow"}, True),
    ],
)
def test_supported_patterns(safe_cond, expr, env, want):
    assert safe_cond.resolve_condition(expr, env) is want


# ---------------------------------------------------------------------------
# Edge cases — falsy / non-string inputs return bool(expr)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("expr", ["", None, 0, False, []])
def test_falsy_inputs_return_false(safe_cond, expr):
    assert safe_cond.resolve_condition(expr, {}) is False


# ---------------------------------------------------------------------------
# Adversarial: would have slipped past the old regex-vorfilter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr",
    [
        # The classic sandbox-escape one-liner — all chars match the old whitelist
        "().__class__.__bases__[0].__subclasses__()",
        # Attribute walk
        "x.upper()",
        # List comprehension
        "[x for x in range(10)]",
        # Lambda
        "lambda: 1",
        # Numeric arithmetic — intentionally unsupported, must raise
        "1+1",
        # and/or chains — unsupported, must raise (push derived bools into env instead)
        "a and b",
        "a or b",
        # Comparison operators — unsupported
        "low_category_count > 0",
        "verdict_severity == red",
    ],
)
def test_adversarial_or_unsupported_raises(safe_cond, expr):
    with pytest.raises(safe_cond.SafeCondError):
        safe_cond.resolve_condition(expr, {"a": True, "b": True, "low_category_count": 5})


def test_pure_whitespace_raises(safe_cond):
    # Whitespace-only strings are non-empty (so don't fall through the
    # falsy short-circuit) but match no supported pattern — raise to
    # surface YAML typos rather than silently treat as False.
    with pytest.raises(safe_cond.SafeCondError):
        safe_cond.resolve_condition("   ", {})


def test_unknown_name_is_false(safe_cond):
    # bare-name lookups against missing keys evaluate as falsy, matching
    # the historical eval()-based behavior where env.get(n) returns None.
    assert safe_cond.resolve_condition("never_set", {}) is False


# ---------------------------------------------------------------------------
# Wiring: compose_threat_model.eval_condition still calls through
# ---------------------------------------------------------------------------


def test_eval_condition_adapter_raises_contract_error_on_bad_input():
    # eval_condition wraps SafeCondError in ContractError for the composer
    sys.modules.pop("compose_threat_model", None)
    ctm = _import("compose_threat_model")
    with pytest.raises(ctm.ContractError):
        ctm.eval_condition("__import__('os').system('id')", {})


def test_eval_condition_adapter_handles_supported_patterns():
    sys.modules.pop("compose_threat_model", None)
    ctm = _import("compose_threat_model")
    assert ctm.eval_condition("check_requirements", {"check_requirements": True}) is True
    assert ctm.eval_condition("not skip_attack_walkthroughs", {"skip_attack_walkthroughs": True}) is False
    assert ctm.eval_condition("v in [a, b]", {"v": "a"}) is True


def test_qa_safe_eval_cond_returns_false_on_malformed():
    sys.modules.pop("qa_checks", None)
    qa = _import("qa_checks")
    # qa side wraps SafeCondError → False (robust against typo'd YAML)
    assert qa._safe_eval_cond("().__class__.__bases__", {}) is False
    assert qa._safe_eval_cond("check_requirements", {"check_requirements": True}) is True


# ---------------------------------------------------------------------------
# referenced_names — the variable(s) a condition reads from eval_context.
# Single source of truth for the section-condition wiring guard
# (tests/test_section_condition_wiring.py).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr,want",
    [
        ("check_requirements", {"check_requirements"}),
        ("not skip_attack_walkthroughs", {"skip_attack_walkthroughs"}),
        # only the leading name is a variable — list items are string literals
        ("verdict_severity in [yellow, red]", {"verdict_severity"}),
        ('verdict_severity not in ["yellow", "red"]', {"verdict_severity"}),
        # falsy / non-string → references nothing
        ("", set()),
        (None, set()),
        (True, set()),
    ],
)
def test_referenced_names(safe_cond, expr, want):
    assert safe_cond.referenced_names(expr) == want


@pytest.mark.parametrize("expr", ["low_category_count > 0", "a and b", "lambda: 1"])
def test_referenced_names_raises_on_unsupported_grammar(safe_cond, expr):
    # Mirrors resolve_condition: unsupported expressions raise rather than
    # silently returning a bogus name set.
    with pytest.raises(safe_cond.SafeCondError):
        safe_cond.referenced_names(expr)
