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
            "expected substituted file:line in padded step body; got:\n" + "\n".join(steps)
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
            assert "{file}" not in s and "{line}" not in s, f"placeholder leaked from padding into step: {s!r}"


class TestSequenceDiagramAltElseBlock:
    """QA Check 8e/8.0 — every §3 sequenceDiagram must carry an
    `alt Current state — T-NNN` / `else After M-NNN — <mitigation>` block and
    each walkthrough must end with a `**Key takeaway:**` line. The per-CWE
    templates render flat diagrams, so the renderer injects this
    deterministically to stop the QA reviewer forcing a REPAIR_MODE pass."""

    def test_flat_template_gets_labelled_alt_else_block(self):
        threat = _make_threat("x", file_="routes/search.ts", line=23)
        flat = {
            "sequence_diagram": (
                "```mermaid\n"
                "sequenceDiagram\n"
                "    actor Attacker\n"
                "    participant API\n"
                "    Attacker->>API: payload\n"
                "    API-->>Attacker: rows\n"
                "```\n"
            )
        }
        out = renderer.render_sequence_diagram(threat, flat, "M-005", "Use parameterized queries — routes/search.ts")
        assert "alt Current state — F-001" in out  # T-NNN normalised to visible F-NNN
        assert "else After M-005 — Use parameterized queries" in out
        assert "    end" in out
        # Reuses the diagram's declared participants so it stays mermaid-valid.
        assert "Attacker->>API" in out

    def test_generic_fallback_alt_else_labels_enriched(self):
        # template={} → render_sequence_diagram uses the hardcoded generic
        # fallback which already has a bare `alt Current state` / `else After`.
        threat = _make_threat("x")
        out = renderer.render_sequence_diagram(threat, {}, "M-001", "Rotate key out of source — lib/insecurity.ts")
        assert "alt Current state — F-001" in out  # T-NNN normalised to visible F-NNN
        assert "else After M-001 — Rotate key out of source" in out
        # No duplicate alt block introduced.
        assert out.count("alt Current state") == 1

    def test_walkthrough_block_emits_key_takeaway(self):
        yaml_data = {
            "threats": [
                {
                    "id": "T-001",
                    "title": "SQL injection in search",
                    "component": "express-backend",
                    "cwe": "CWE-89",
                    "risk": "critical",
                    "evidence": [{"file": "routes/search.ts", "line": 23}],
                }
            ],
            "mitigations": [{"id": "M-005", "title": "Use parameterized queries", "threat_ids": ["T-001"]}],
            "assets": [],
            "attack_surface": [],
        }
        md = renderer.render_attack_walkthroughs_md(yaml_data)
        assert "**Key takeaway:**" in md
        assert "alt Current state — F-001" in md  # T-NNN normalised to visible F-NNN
        assert "else After M-005 — Use parameterized queries" in md


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


class TestSentenceSplittingRobustness:
    """Attack-step splitting must not tear abbreviations or code/SQL payloads
    across steps (user report 2026-06, §3.8)."""

    def test_eg_abbreviation_does_not_split(self):
        s = "A UNION SELECT payload (e.g. q=') can dump the schema."
        assert renderer._split_sentences(s) == ["A UNION SELECT payload (e.g. q=') can dump the schema"]

    def test_real_boundary_still_splits(self):
        s = "First sentence here. Second sentence here."
        assert renderer._split_sentences(s) == [
            "First sentence here",
            "Second sentence here",
        ]

    def test_code_span_internal_punctuation_does_not_split(self):
        s = "Call `a.b.c()` then. Next step starts."
        out = renderer._split_sentences(s)
        assert out == ["Call `a.b.c()` then", "Next step starts"]


class TestStepSqlFormattingGate:
    """SQL auto-backticking must wrap real SQL and leave prose alone."""

    def test_prose_opening_with_sql_verb_not_wrapped(self):
        out = renderer._format_step_code("A UNION SELECT payload (e.g. foo) can dump")
        assert "`UNION SELECT payload" not in out
        assert "`(e.g" not in out

    def test_real_sql_is_wrapped_and_prose_excluded(self):
        out = renderer._format_step_code("A second payload adding a SELECT from Users extracts all emails")
        assert "`SELECT from Users`" in out
        assert "extracts all emails" in out
        assert "`SELECT from Users extracts" not in out
