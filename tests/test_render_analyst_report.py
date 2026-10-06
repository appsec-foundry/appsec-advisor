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
