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


# ---------------------------------------------------------------------------
# Coverage extension — small pure helpers + slot renderers.
# ---------------------------------------------------------------------------


class TestShortTitle:
    def test_short_title_untouched_when_under_limit(self):
        assert renderer._short_title("brief", 70) == "brief"

    def test_short_title_truncates_with_ellipsis(self):
        long = "word " * 40
        out = renderer._short_title(long, 30)
        assert out.endswith("…")
        assert len(out) <= 30

    def test_short_title_drops_unbalanced_paren_suffix(self):
        # Truncation lands mid-paren → whole unbalanced suffix dropped.
        title = "A finding title that is quite long indeed (lib/insecurity.ts:24)"
        out = renderer._short_title(title, 50)
        assert out.endswith("…")
        # No unbalanced opening paren left in the truncated label.
        assert out.count("(") <= out.count(")")


class TestMermaidSafe:
    def test_strips_hostile_chars(self):
        out = renderer._mermaid_safe('a`b|c[d]e"f')
        assert "`" not in out
        assert "|" not in out
        assert "[" not in out and "]" not in out
        assert '"' not in out
        assert out == "ab/c(d)e'f"

    def test_empty(self):
        assert renderer._mermaid_safe("") == ""


class TestSentencesPerLine:
    def test_returns_one_sentence_per_line(self):
        out = renderer._sentences_per_line("First sentence. Second sentence.")
        assert out == ["First sentence.", "Second sentence."]

    def test_empty_paragraph(self):
        assert renderer._sentences_per_line("") == []

    def test_unsplittable_paragraph_returns_whole(self):
        out = renderer._sentences_per_line("nopunct here")
        assert out == ["nopunct here."]


class TestExcerpt:
    def test_none_evidence(self):
        assert renderer._excerpt(None) == ""

    def test_collapses_newlines(self):
        out = renderer._excerpt({"excerpt": "line1\nline2\rline3"})
        assert "\n" not in out and "\r" not in out
        assert out == "line1 line2 line3"

    def test_truncates_long(self):
        out = renderer._excerpt({"excerpt": "x" * 300}, limit=20)
        assert out.endswith("…")
        assert len(out) <= 20


class TestEndpointGuess:
    def test_explicit_method_path(self):
        assert renderer._endpoint_guess("attacker sends POST /api/Users now") == "POST /api/Users"

    def test_keyword_hint_fallback(self):
        out = renderer._endpoint_guess("a stored feedback comment is submitted")
        assert "Stored" in out

    def test_generic_fallback(self):
        out = renderer._endpoint_guess("nothing recognizable here")
        assert out == "Crafted HTTP request to the affected endpoint"

    def test_empty_returns_fallback(self):
        assert renderer._endpoint_guess("") == "Crafted HTTP request to the affected endpoint"


class TestLoadTemplates:
    def test_missing_dir_returns_empty(self, tmp_path):
        assert renderer.load_templates(tmp_path / "nope") == {}

    def test_loads_cwe_and_generic(self, tmp_path):
        (tmp_path / "CWE-89.yaml").write_text("cwe: CWE-89\nsequence_diagram: x\n", encoding="utf-8")
        (tmp_path / "_generic.yaml").write_text("foo: bar\n", encoding="utf-8")
        (tmp_path / "broken.yaml").write_text(": : not valid yaml :\n", encoding="utf-8")
        (tmp_path / "notdict.yaml").write_text("- justalist\n", encoding="utf-8")
        out = renderer.load_templates(tmp_path)
        assert "CWE-89" in out
        assert "_generic" in out
        # Broken / non-dict templates are skipped, not fatal.
        assert "BROKEN" not in out
        assert "NOTDICT" not in out

    def test_key_from_stem_when_no_cwe_field(self, tmp_path):
        (tmp_path / "CWE-22.yaml").write_text("sequence_diagram: x\n", encoding="utf-8")
        out = renderer.load_templates(tmp_path)
        assert "CWE-22" in out


class TestTemplateFor:
    def test_jwt_variant_selected(self):
        templates = {"CWE-327": {"k": "base"}, "CWE-327-JWT": {"k": "jwt"}}
        threat = {"title": "JWT algorithm confusion attack"}
        assert renderer._template_for("CWE-327", templates, threat) == {"k": "jwt"}

    def test_falls_back_to_generic(self):
        templates = {"_generic": {"k": "g"}}
        assert renderer._template_for("CWE-999", templates, {}) == {"k": "g"}

    def test_jwt_variant_absent_uses_base(self):
        templates = {"CWE-327": {"k": "base"}}
        threat = {"title": "jwt confusion"}
        assert renderer._template_for("CWE-327", templates, threat) == {"k": "base"}


class TestIndexBuilders:
    def test_mitigations_by_threat(self):
        ydata = {"mitigations": [{"id": "M-1", "threat_ids": ["T-1", "T-2"]}, "notadict"]}
        out = renderer._mitigations_by_threat(ydata)
        assert out["T-1"][0]["id"] == "M-1"
        assert "T-2" in out

    def test_assets_by_threat(self):
        ydata = {"assets": [{"id": "A-1", "linked_threats": ["T-1"]}, 42]}
        out = renderer._assets_by_threat(ydata)
        assert out["T-1"][0]["id"] == "A-1"

    def test_attack_surface_by_path(self):
        ydata = {"attack_surface": [{"entry_point": "/api/x", "auth_required": "JWT"}, {"no_ep": 1}]}
        out = renderer._attack_surface_by_path(ydata)
        assert "/api/x" in out

    def test_peers_by_cwe(self):
        out = renderer._peers_by_cwe([{"id": "T-1", "cwe": "CWE-89"}, {"id": "T-2", "cwe": "CWE-89"}])
        assert out["CWE-89"] == ["T-1", "T-2"]


class TestAttackerProfile:
    def test_default_when_unknown_vektor(self):
        out = renderer.render_attacker_profile({"vektor": "weird"}, {}, {})
        assert out == renderer.ATTACKER_PROFILES["internet-user"]

    def test_open_registration_suffix(self):
        out = renderer.render_attacker_profile({"vektor": "internet-user"}, {"open_user_registration": True}, {})
        assert renderer.OPEN_REG_SUFFIX.strip() in out

    def test_template_override(self):
        tmpl = {"attacker_profile_overrides": {"internet-anon": "OVERRIDDEN"}}
        out = renderer.render_attacker_profile({"vektor": "internet-anon"}, {}, tmpl)
        assert out == "OVERRIDDEN"


class TestPrerequisites:
    def test_substitutes_file(self):
        out = renderer.render_prerequisites({"vektor": "internet-user"}, {}, "routes/login.ts")
        assert any("routes/login.ts" in b for b in out)

    def test_enriched_with_auth_policy(self):
        surface = {"/login": {"auth_required": "session cookie"}}
        out = renderer.render_prerequisites({"vektor": "internet-user"}, surface, "routes/login")
        assert any("requires: session cookie" in b for b in out)


class TestBusinessImpact:
    def test_with_assets(self):
        out = renderer.render_business_impact({"risk": "critical", "component": "api"}, ["A-1", "A-2"])
        assert "Critical impact" in out
        assert "`A-1`" in out
        assert "`api`" in out

    def test_default_severity_when_missing(self):
        out = renderer.render_business_impact({}, [])
        assert "High impact" in out


class TestDetectionSignals:
    def test_empty_when_no_template_signals(self):
        assert renderer.render_detection_signals({}, {}) == []

    def test_substitution(self):
        tmpl = {"detection_signals": ["watch {component} at {file}:{line}"]}
        threat = {"component": "api", "evidence": [{"file": "x.ts", "line": 9}]}
        out = renderer.render_detection_signals(threat, tmpl)
        assert out == ["watch api at x.ts:9"]


class TestDefenseInDepth:
    def test_no_mitigations_fallback(self):
        bullets, pid = renderer.render_defense_in_depth({"id": "T-1"}, {})
        assert pid == "mitigation"
        assert any("not yet defined" in b for b in bullets)

    def test_with_mitigations_and_priority(self):
        idx = {"T-1": [{"id": f"M-{n}", "title": "Fix it — lib/x.ts", "priority": f"p{n}"} for n in range(1, 5)]}
        bullets, pid = renderer.render_defense_in_depth({"id": "T-1"}, idx)
        assert pid == "M-1"
        for n, digit in enumerate(("❶", "❷", "❸", "❹"), start=1):
            assert f"{digit} [M-{n}](#m-{n})" in bullets[n - 1]
        # Short-label rule: the ` — file` tail is dropped.
        assert all("lib/x.ts" not in bullet for bullet in bullets)

    def test_mitigation_without_title(self):
        idx = {"T-1": [{"id": "M-1"}]}
        bullets, _ = renderer.render_defense_in_depth({"id": "T-1"}, idx)
        assert "mitigation entry" in bullets[0]


class TestCrossReferences:
    def test_chain_and_siblings(self):
        peers = {"CWE-89": ["T-1", "T-2", "T-3"]}
        out = renderer.render_cross_references(
            {"id": "T-1", "cwe": "CWE-89", "component": "db"}, {"T-1": [4, 5]}, peers
        )
        assert any("Chain 4" in b for b in out)
        assert any("Sibling findings" in b and "F-2" in b for b in out)
        assert len(out) >= 3

    def test_standalone_no_chain_no_siblings(self):
        out = renderer.render_cross_references({"id": "T-9", "cwe": "CWE-79", "component": "ui"}, {}, {})
        assert any("standalone walkthrough" in b for b in out)
        assert any("none" in b for b in out)


class TestGenAdapter:
    def test_gen_attack_walkthroughs_returns_fragment(self):
        ydata = {
            "threats": [
                {
                    "id": "T-001",
                    "title": "SQL injection",
                    "risk": "critical",
                    "cwe": "CWE-89",
                    "vektor": "internet-anon",
                    "scenario": "Attacker sends GET /search?q=' UNION SELECT * FROM Users.",
                    "evidence": [{"file": "routes/search.ts", "line": 12}],
                }
            ]
        }
        out = renderer.gen_attack_walkthroughs(ydata)
        assert out.startswith("## 3. Attack Walkthroughs")
        assert "### 3.1" in out
        assert "WALKTHROUGH_FILL" not in out
        assert out.rstrip().endswith("<!-- generated:walkthrough_renderer -->")

    def test_heading_drops_emdash_file_line_tail(self):
        # The ` — file:line` tail must NOT appear in the §3 heading — it made
        # the GitHub heading anchor diverge from the composer link target and
        # broke every §3 ToC link. The concrete location still lives on the
        # **Source:** line.
        ydata = {
            "threats": [
                {
                    "id": "T-001",
                    "title": "Insecure Direct Object Reference — routes/address.ts:11",
                    "risk": "critical",
                    "cwe": "CWE-639",
                    "vektor": "internet-anon",
                    "scenario": "Attacker swaps the :id path param to read another user's record.",
                    "evidence": [{"file": "routes/address.ts", "line": 11}],
                }
            ]
        }
        out = renderer.gen_attack_walkthroughs(ydata)
        assert "### 3.1 Insecure Direct Object Reference\n" in out
        # The em-dash tail is gone from the heading line specifically.
        heading_line = next(ln for ln in out.splitlines() if ln.startswith("### 3.1"))
        assert "—" not in heading_line
        assert "address.ts:11" not in heading_line
        # …but the concrete location is still carried on the Source line.
        assert "routes/address.ts:11" in out


def test_weakness_class_strips_tail():
    assert (
        renderer._weakness_class("Insecure Direct Object Reference — routes/address.ts:11")
        == "Insecure Direct Object Reference"
    )
    # No tail → unchanged (e.g. a consolidated systemic title).
    assert renderer._weakness_class("Insecure Direct Object Reference") == "Insecure Direct Object Reference"


def test_zero_criticals_renders_honest_stub_without_diagram():
    """Regression: a clean report with zero Critical findings must render §3 as
    an honest stub — NO `sequenceDiagram` — so the contract's required-pattern
    gate (`has_authored_walkthroughs`) is not tripped.

    walkthrough_renderer only emits per-Critical blocks (each carrying a
    `sequenceDiagram`); Highs are never walked through (MAX_HIGH_WALKTHROUGHS=0),
    so a High-only report also produces the stub. Before this fix the renderer
    emitted the generic "one short walkthrough per Critical" intro with no
    blocks, and compose then hard-failed on the missing `sequenceDiagram`.
    """
    ydata = {
        "threats": [
            {
                "id": "T-001",
                "title": "Reflected XSS in search",
                "component": "frontend",
                "risk": "high",
                "cwe": "CWE-79",
                "vektor": "internet-anon",
                "scenario": "Attacker reflects a script payload via the q param.",
                "evidence": [{"file": "routes/search.ts", "line": 20}],
            }
        ]
    }
    md = renderer.render_attack_walkthroughs_md(ydata)
    assert md.lstrip().startswith("## 3. Attack Walkthroughs")
    assert "sequenceDiagram" not in md
    assert "No Critical findings" in md
    # The misleading "one short walkthrough per Critical" promise is gone.
    assert "one short walkthrough per Critical" not in md


def test_zero_threats_renders_honest_stub():
    """Empty threat list (nothing found at all) also yields the stub."""
    md = renderer.render_attack_walkthroughs_md({"threats": []})
    assert "sequenceDiagram" not in md
    assert "No Critical findings" in md
