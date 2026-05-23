"""Regression tests for scripts/walkthrough_renderer.py.

These guard the per-finding §3 Attack Walkthroughs render pipeline against
regressions that previously shipped to production:

  * `render_attack_steps` MUST substitute `{file}` / `{line}` / `{component}`
    placeholders in `attack_steps_template` and `generic_padding` before
    returning them. A scenario shorter than MIN_ATTACK_STEPS sentences caused
    the renderer to fall through to template padding without substitution,
    leaking literal `{file}:{line}` markers into the rendered Markdown (the
    2026-05 juice-shop run shipped `Send the crafted payload to the endpoint
    backed by \`{file}:{line}\`.` verbatim into §3.2 step 4).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "walkthrough_renderer.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


renderer = _load_module("walkthrough_renderer", SCRIPT_PATH)


def _make_threat(scenario: str, file_: str = "lib/insecurity.ts", line: int = 54) -> dict:
    return {
        "id": "T-001",
        "title": "JWT algorithm confusion",
        "component": "express-backend",
        "cwe": "CWE-290",
        "vektor": "internet-anon",
        "scenario": scenario,
        "evidence": [{"file": file_, "line": line, "excerpt": "expressJwt({ secret: pk })"}],
    }


class TestAttackStepsPlaceholderSubstitution:
    """Guard against `{file}`/`{line}`/`{component}` leaking into §3 output."""

    def test_default_template_padding_substitutes_file_and_line(self):
        # Scenario gives only 1 sentence — padding kicks in via template_steps
        # which contain the `{file}:{line}` and `{file}` placeholders.
        threat = _make_threat("Only one sentence.")
        steps = renderer.render_attack_steps(threat, template={})

        assert len(steps) >= renderer.MIN_ATTACK_STEPS

        for s in steps:
            assert "{file}" not in s, f"raw {{file}} leaked into step: {s!r}"
            assert "{line}" not in s, f"raw {{line}} leaked into step: {s!r}"
            assert "{component}" not in s, f"raw {{component}} leaked into step: {s!r}"

        # And the substituted concrete reference appears at least once.
        joined = " ".join(steps)
        assert "lib/insecurity.ts:54" in joined, (
            "expected substituted file:line in padded step body; got:\n"
            + "\n".join(steps)
        )

    def test_cwe_template_attack_steps_substitute_placeholders(self):
        # User-supplied template (e.g. cwe-89.yaml) also goes through the same
        # mapping. The fix in walkthrough_renderer.py applies
        # _format_template_string to BOTH template_steps and generic_padding
        # before appending.
        threat = _make_threat("Only one sentence.", file_="routes/login.ts", line=34)
        template = {
            "attack_steps_template": [
                "Issue the crafted UNION SELECT against `{file}:{line}` to exfiltrate the table.",
                "Confirm the dump in the response body returned from `{component}`.",
            ],
        }
        steps = renderer.render_attack_steps(threat, template=template)

        joined = " ".join(steps)
        assert "{file}" not in joined
        assert "{line}" not in joined
        assert "{component}" not in joined

        # Substituted concrete tokens must appear:
        assert "routes/login.ts:34" in joined
        assert "express-backend" in joined

    def test_long_scenario_still_substitutes_when_padding_used(self):
        # 4 short sentences from the scenario; MIN_ATTACK_STEPS is 6, so
        # 2 template steps still get appended via the padding path.
        long_scenario = (
            "Attacker probes the endpoint. The application logs the request. "
            "No alert fires. The session is never invalidated."
        )
        threat = _make_threat(long_scenario)
        steps = renderer.render_attack_steps(threat, template={})

        assert len(steps) >= renderer.MIN_ATTACK_STEPS
        for s in steps:
            assert "{file}" not in s and "{line}" not in s, (
                f"placeholder leaked from padding into step: {s!r}"
            )


class TestAttackStepsFallbackWhenNoScenario:
    """When `scenario` is missing the renderer still produces clean steps."""

    def test_empty_scenario_uses_template_with_substitution(self):
        threat = _make_threat("", file_="server.ts", line=187)
        steps = renderer.render_attack_steps(threat, template={})

        assert steps, "expected non-empty steps even with empty scenario"
        for s in steps:
            assert "{file}" not in s
            assert "{line}" not in s
        assert "server.ts:187" in " ".join(steps)
