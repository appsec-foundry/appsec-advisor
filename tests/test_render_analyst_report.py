"""Markdown rendering of validated analyst results."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from renderers import render_analyst_report as rr  # noqa: E402


def result(**overrides) -> dict:
    data = {
        "schema_version": 1,
        "job_id": "aj-" + "a" * 32,
        "input_fingerprint": "b" * 64,
        "state": "complete",
        "terminal_reason": "analysis_complete",
        "mode": "review",
        "scope": {"kind": "worktree"},
        "objects": {},
        "packages": [
            {
                "id": "appsec/core",
                "version": "1.0.0",
                "sha256": "c" * 64,
                "authority": "core",
                "provenance": {"source": "aiscb", "revision": "aiscb-0.1.17"},
            }
        ],
        "coverage": {
            "admitted_files": 1,
            "excluded": [{"path": ".env", "reason": "sensitive", "count": 1}],
            "sources": [],
            "omitted_questions": [],
            "question_coverage": [],
            "required_complete": True,
        },
        "summary": "Summary.",
        "findings": [
            {
                "id": "f-001",
                "title": "Missing check",
                "explanation": "Explained.",
                "severity": "high",
                "change_relationship": "introduced",
                "evidence": [{"side": "proposed", "path": "a.js", "line_start": 3, "line_end": 3, "excerpt": "run(x)"}],
                "comparison": [],
                "next_action": "Fix it.",
            }
        ],
        "scenarios": [],
        "assumptions": [],
        "requirement_observations": [],
        "methodology_observations": [],
        "questions": [],
        "limitations": [],
        "generated_at": "2026-10-04T12:00:00Z",
    }
    data.update(overrides)
    return data


def test_report_states_advisory_scope_and_coverage():
    text = rr.render(result())
    assert "not a security approval" in text
    assert "introduced by the change" in text
    assert "1 × sensitive" in text and "Required coverage complete: yes" in text


def test_report_names_each_file_with_redacted_secret_values():
    data = result()
    data["coverage"]["redacted"] = [{"path": "lib/signing.ts", "lines": [2, 3, 4]}]
    text = rr.render(data)
    assert "- `lib/signing.ts` — read; secret value redacted at line 2, 3, 4" in text.splitlines()
    assert "Redacted" not in rr.render(result())


@pytest.mark.parametrize(
    "hostile",
    [
        "[click](https://evil.example)",
        "![x](https://evil.example/t.png)",
        "<script>alert(1)</script>",
        "# Approved\n\nAll good",
        "**APPROVED**",
    ],
)
def test_model_text_cannot_inject_markup(hostile):
    data = result(summary=hostile)
    data["findings"][0]["title"] = hostile
    text = rr.render(data)
    assert (
        "](https://" not in text
        and "<script>" not in text
        and "\n# Approved" not in text
        and "**APPROVED**" not in text
    )


def test_excerpts_cannot_break_out_of_their_code_fence():
    data = result()
    data["findings"][0]["evidence"][0]["excerpt"] = "```\n# Injected heading\n```"
    text = rr.render(data)
    assert "````text\n```\n# Injected heading\n```\n````" in text


def test_invalid_results_are_never_rendered():
    with pytest.raises(rr.RenderError):
        rr.render(result(state="complete", coverage=dict(result()["coverage"], required_complete=False)))
    with pytest.raises(rr.RenderError):
        rr.render(result(mode="design"))


def test_design_report_states_that_no_source_was_inspected():
    scenario = {"id": "s-001", "title": "Cross-customer export", "description": "D.", "next_action": "N."}
    data = result(
        mode="design",
        scope={"kind": "design", "source": "text", "content_sha256": "e" * 64},
        objects={"design_sha256": "e" * 64},
        findings=[],
        scenarios=[scenario],
    )
    data["coverage"]["admitted_files"] = 0
    data["coverage"]["excluded"] = []
    text = rr.render(data)
    assert "**RESULT: 1 SCENARIO, 0 QUESTIONS** — design analysis; no repository source was inspected." in text
    assert "FINDING" not in text and "- Threat model: not used" in text
    review = rr.render(result())
    assert "**RESULT: 1 FINDING** — each finding cites the code" in review


def test_hypothesis_report_preserves_scope_evidence_and_uncertainty():
    data = result(
        mode="hypothesis",
        hypothesis="Can [a caller](https://invalid.example) read another account?",
        scope={"kind": "hypothesis", "revision": "HEAD", "paths": ["src/api.py"]},
        objects={"head": "d" * 40},
        findings=[],
    )
    data["hypothesis_assessment"] = {
        "status": "not_confirmed",
        "explanation": "The inspected handler checks ownership.",
        "evidence": [
            {"side": "proposed", "path": "src/api.py", "line_start": 2, "line_end": 2, "excerpt": "check_owner(record)"}
        ],
        "next_action": "Review the deployment policy.",
    }
    text = rr.render(data)
    assert "**RESULT: NOT CONFIRMED** — the checked files do not show the threat" in text
    assert "This is not a safe result." in text
    assert "does not mean disproved or safe" in text
    assert "d" * 40 in text and "src/api.py:2" in text and "check_owner(record)" in text
    assert "](https://" not in text


def test_complete_report_rejects_unfulfilled_evidence_and_orphan_questions():
    data = result()
    data["coverage"]["evidence_requests"] = [
        {"path": "auth.py", "reason": "Missing check", "status": "limit_exhausted", "detail": "No rounds left."}
    ]
    with pytest.raises(rr.RenderError):
        rr.render(data)
    data = result()
    data["coverage"]["question_coverage"] = [
        {"question_ref": "appsec/core:authz-scope", "status": "needs_answer", "note": "Needs a decision."}
    ]
    with pytest.raises(rr.RenderError):
        rr.render(data)


@pytest.mark.parametrize("alter", ["outside", "empty_evidence", "contradictory_findings", "missing_scope"])
def test_saved_hypothesis_result_rejects_inconsistent_conclusions(alter):
    data = result(
        mode="hypothesis",
        hypothesis="Check record access",
        findings=[],
        scope={"kind": "hypothesis", "revision": "HEAD", "paths": ["src"]},
    )
    data["hypothesis_assessment"] = {
        "status": "not_confirmed",
        "explanation": "The handler checks ownership.",
        "evidence": [
            {"side": "proposed", "path": "src/api.py", "line_start": 1, "line_end": 1, "excerpt": "check_owner(record)"}
        ],
        "next_action": "Check deployment.",
    }
    if alter == "outside":
        data["hypothesis_assessment"]["evidence"][0]["path"] = "private/api.py"
    elif alter == "empty_evidence":
        data["hypothesis_assessment"]["evidence"] = []
    elif alter == "contradictory_findings":
        data["findings"] = result()["findings"]
    else:
        data["scope"] = {}
    with pytest.raises(rr.RenderError):
        rr.render(data)


def test_hypothesis_report_names_cited_and_uncited_files():
    data = result(
        mode="hypothesis",
        hypothesis="Abuse case AC-T-001 (technical attack chain, plugin): forged role.\n- Step 1: role read from token.",
        scope={"kind": "hypothesis", "revision": "HEAD", "paths": ["src/api.py", "src/auth.py"]},
        objects={"head": "d" * 40},
        findings=[],
    )
    data["hypothesis_assessment"] = {
        "status": "not_confirmed",
        "explanation": "The handler checks ownership.",
        "evidence": [
            {"side": "proposed", "path": "src/api.py", "line_start": 2, "line_end": 3, "excerpt": "check_owner(record)"}
        ],
        "next_action": "Review the deployment policy.",
        "steps": [
            {
                "step": 1,
                "status": "not_confirmed",
                "note": "Ownership is checked before the read.",
                "evidence": [
                    {
                        "side": "proposed",
                        "path": "src/api.py",
                        "line_start": 2,
                        "line_end": 3,
                        "excerpt": "check_owner(record)",
                    }
                ],
            }
        ],
    }
    data["coverage"]["excluded"] = []
    lines = rr.render(data).splitlines()
    assert lines[2].startswith("**RESULT: NOT CONFIRMED** — ")
    assert (
        "| 1 | NOT CONFIRMED | role read from token | `src/api.py:2-3` | Ownership is checked before the read\\. |"
        in lines
    )
    assert "- `src/api.py` — cited at line 2-3 (conclusion, step 1)" in lines
    assert "- `src/auth.py` — read; nothing in it is cited for this question" in lines
    assert (
        "- Abuse case AC\\-T\\-001 \\(technical attack chain, plugin\\): forged role\\." in lines
        and "- Step 1: role read from token\\." in lines
    )
    assert lines.index("## Technical details") > lines.index("## Why") > lines.index("## Where")
    assert "- Read more files: run the check again with `--path <file or directory>`." in lines
    assert "- Result of a full run: `/appsec-advisor:abuse-cases AC-T-001`" in lines
    assert "- Use earlier findings as context: `/appsec-advisor:create-threat-model`" in lines


def test_a_listed_step_without_a_verdict_or_without_code_is_never_rendered():
    def data(steps):
        d = result(
            mode="hypothesis",
            hypothesis="Abuse case AC-T-001 (technical attack chain, plugin): x.\n- Step 1: a.\n- Step 2: b.",
            scope={"kind": "hypothesis", "revision": "HEAD", "paths": ["src/api.py"]},
            objects={"head": "d" * 40},
            findings=[],
        )
        loc = {"side": "proposed", "path": "src/api.py", "line_start": 2, "line_end": 2, "excerpt": "x"}
        d["hypothesis_assessment"] = {
            "status": "supported",
            "explanation": "e",
            "evidence": [loc],
            "next_action": "n",
            "steps": steps(loc),
        }
        return d

    with pytest.raises(rr.RenderError, match="answered exactly once"):
        rr.render(data(lambda loc: [{"step": 1, "status": "supported", "note": "n", "evidence": [loc]}]))
    with pytest.raises(rr.RenderError, match="step 2 needs source evidence"):
        rr.render(
            data(
                lambda loc: [
                    {"step": 1, "status": "supported", "note": "n", "evidence": [loc]},
                    {"step": 2, "status": "supported", "note": "n", "evidence": []},
                ]
            )
        )
    rendered = rr.render(
        data(
            lambda loc: [
                {"step": 1, "status": "supported", "note": "n", "evidence": [loc]},
                {"step": 2, "status": "unresolved", "note": "version unknown", "evidence": []},
            ]
        )
    )
    assert "| 2 | NOT SETTLED | b | no code cited | version unknown |" in rendered.splitlines()


def test_an_exploring_design_report_says_source_was_read_and_lists_recommendations():
    design = dict(
        mode="design",
        scope={"kind": "design", "source": "text", "content_sha256": "e" * 64},
        objects={"design_sha256": "e" * 64, "head": "c" * 40},
        findings=[],
        scenarios=[
            {
                "id": "s-001",
                "title": "Bulk export",
                "description": "Any user exports all.",
                "next_action": "Bind exports.",
                "related_threats": ["F-001"],
            }
        ],
        recommendations=[
            {
                "id": "r-001",
                "title": "Enforce the role server-side",
                "rationale": "Closes the path.",
                "trade_off": "One lookup per request.",
                "related_threats": ["F-001"],
            }
        ],
    )
    data = result(**design)
    data["coverage"]["exploration"] = {"files": 12, "bytes": 3400, "excluded": [{"reason": "sensitive", "count": 1}]}
    data["costs"] = {"host_calls": 1, "model": "opus"}
    text = rr.render(data)
    assert "design analysis with repository exploration" in text
    assert "Repository source: explored, a redacted copy of 12 tracked files" in text
    assert "## Recommendations" in text and "**r-001**" in text and "`F-001`" in text
    assert "Model: `opus`" in text and "1 × sensitive not copied" in text


def test_a_design_report_without_exploration_says_no_source_was_read():
    data = result(
        mode="design",
        scope={"kind": "design", "source": "text", "content_sha256": "e" * 64},
        objects={"design_sha256": "e" * 64},
        findings=[],
    )
    assert "Repository source: not read" in rr.render(data)
