"""Case set, repository setup, and deterministic scoring of the threat-analyst evaluation."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from validators import eval_analyst as ev  # noqa: E402

CASE = {
    "id": "review-x",
    "project": "p",
    "change": {"a.js": "changed\n"},
    "expect": {"weakness": {"file": "a.js", "cwe": [639], "keywords": ["owner"]}},
}


def test_the_shipped_case_set_is_valid_and_mixes_case_kinds():
    data = ev.load_cases()
    kinds = {next(iter(set(c["expect"]) & {"weakness", "benign", "themes"})) for c in data["cases"]}
    assert kinds == {"weakness", "benign", "themes"}
    assert len({c["id"] for c in data["cases"]}) == len(data["cases"])


def test_materialize_commits_the_project_and_the_change_separately(tmp_path):
    repo = ev.materialize({"a.js": "base\n", "lib/b.js": "b\n"}, CASE, tmp_path)
    log = subprocess.run(["git", "-C", str(repo), "log", "--oneline"], capture_output=True, text=True).stdout
    assert len(log.splitlines()) == 2 and (repo / "a.js").read_text() == "changed\n"
    diff = subprocess.run(
        ["git", "-C", str(repo), "diff", "--name-only", "HEAD~1", "HEAD"], capture_output=True, text=True
    )
    assert diff.stdout.split() == ["a.js"]


@pytest.mark.parametrize(
    ("finding", "found"),
    [
        ({"files": ["a.js"], "severity": "high", "cwe": None, "text": "No owner check"}, True),
        ({"files": ["a.js"], "severity": "high", "cwe": 639, "text": "Access issue"}, True),
        ({"files": ["b.js"], "severity": "high", "cwe": 639, "text": "No owner check"}, False),
        ({"files": ["a.js"], "severity": "low", "cwe": None, "text": "Style issue"}, False),
    ],
)
def test_a_weakness_counts_only_with_the_expected_file_and_a_matching_name(finding, found):
    assert ev.score_case(CASE, {"findings": [finding], "texts": []})["weakness_found"] is found


def test_benign_cases_count_serious_findings_and_design_cases_count_themes():
    benign = {"id": "b", "expect": {"benign": True}}
    findings = [{"files": ["a"], "severity": s, "cwe": None, "text": ""} for s in ("low", "medium", "critical")]
    assert ev.score_case(benign, {"findings": findings, "texts": []})["false_positives"] == 2
    design = {"id": "d", "expect": {"themes": [["expire", "expiry"], ["enumerat"], ["rate"]]}}
    score = ev.score_case(design, {"findings": [], "texts": ["Tokens must expire.", "Avoid user enumeration."]})
    assert (score["themes_covered"], score["themes_total"]) == (2, 3)


def test_both_engines_normalize_to_one_shape():
    analyst = {
        "state": "recorded",
        "result": {
            "summary": "S",
            "findings": [
                {
                    "title": "T",
                    "explanation": "E",
                    "severity": "high",
                    "evidence": [{"path": "a.js"}],
                    "comparison": [{"path": "b.js"}],
                }
            ],
            "scenarios": [{"title": "Sc", "description": "D"}],
            "recommendations": [{"title": "R", "rationale": "Ra"}],
            "assumptions": [{"statement": "Owner checked", "status": "contradicted", "evidence": [{"path": "c.js"}]}],
            "questions": [],
            "costs": {"usd": 0.12},
        },
    }
    out = ev.normalize(analyst)
    assert [f["files"] for f in out["findings"]] == [["a.js", "b.js"], ["c.js"]]
    assert out["usd"] == 0.12 and "R Ra" in out["texts"]
    direct = {
        "state": "recorded",
        "usd": 0.5,
        "direct": {
            "findings": [{"title": "T", "explanation": "E", "severity": "low", "file": "a.js", "cwe": 79}],
            "scenarios": ["x"],
            "recommendations": ["y"],
        },
    }
    assert ev.normalize(direct)["findings"][0] == {"files": ["a.js"], "severity": "low", "cwe": 79, "text": "T E"}
    assert ev.normalize({"state": "no_result"}) == {"findings": [], "texts": [], "usd": None}


def test_summary_and_unknown_configurations():
    rows = [
        {
            "config": "A",
            "case_id": "x",
            "state": "recorded",
            "score": {"weakness_found": True},
            "usd": 0.1,
            "seconds": 3,
        },
        {
            "config": "A",
            "case_id": "y",
            "state": "no_result",
            "score": {"false_positives": 1},
            "usd": None,
            "seconds": 2,
        },
    ]
    summary = ev.summarize(rows)["A"]
    assert summary["weaknesses"] == [1, 1] and summary["false_positives"] == 1 and summary["no_result"] == 1
    assert "| A " in ev.render_table({"A": summary})
    with pytest.raises(ev.EvalError):
        ev.parse_configs("A,Z")


def test_score_reads_recorded_results_without_calling_a_model(tmp_path):
    cases = tmp_path / "cases.yaml"
    cases.write_text(
        "schema_version: 1\nprojects: {p: {a.js: 'x'}}\n"
        "cases:\n  - {id: review-x, project: p, expect: {weakness: {file: a.js, keywords: [owner]}}}\n"
    )
    record = tmp_path / "out" / "E" / "review-x" / "record.json"
    record.parent.mkdir(parents=True)
    record.write_text(
        '{"state": "recorded", "usd": 0.4, "seconds": 9, "direct": {"findings": '
        '[{"title": "Owner", "explanation": "missing owner check", "severity": "high", "file": "a.js"}], '
        '"scenarios": [], "recommendations": []}}'
    )
    rows, summary = ev.score(tmp_path / "out", cases)
    assert rows[0]["score"] == {"weakness_found": True} and summary["E"]["usd"] == 0.4


def test_only_required_questions_are_answered():
    report = "- q-001 (optional): A?\n  Why: x\n- q-002 (required): B?\n  Why: y\n"
    assert ev._pending_question_ids(report) == ["q-002"]

