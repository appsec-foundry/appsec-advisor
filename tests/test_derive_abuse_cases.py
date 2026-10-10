"""Tests for model/derive_abuse_cases.py — bounded input and admitted output of
model-derived business abuse cases (decision AC-12)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import model.derive_abuse_cases as derive  # noqa: E402
import model.match_abuse_cases as matcher  # noqa: E402


def _run(tmp_path: Path, proposals: object) -> tuple[Path, dict]:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "refunds.ts").write_text("export function refund() {}\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo), "assessment_depth": "thorough"}))
    (out / ".components.json").write_text(
        json.dumps({"components": [{"id": "api", "name": "API", "description": "Handles refunds.", "paths": ["src"]}]})
    )
    (out / derive.OUTPUT_FILE).write_text(json.dumps({"cases": proposals}))
    return out, derive.admit(out)


def _proposal(title: str, **extra: object) -> dict:
    return {"title": title, "check": f"Check whether a customer can {title.lower()}.", **extra}


def test_derived_cases_are_validated_bounded_and_deduplicated(tmp_path: Path):
    proposals = [
        _proposal("Refund an order twice"),
        # Same title as a library case, in other case and punctuation.
        _proposal("user READS or changes data of another user, or tenant"),
        {"title": "No check stated"},
        _proposal("Cancel another customer's order", finding={"cwe": "CWE-639", "severity": "Critical"}),
        _proposal("Change a shipped order's address"),
        _proposal("Reuse a gift card after a refund"),
    ]
    out, result = _run(tmp_path, proposals)

    assert result["admitted"] == ["MODEL-AC-001", "MODEL-AC-002", "MODEL-AC-003"]
    reasons = [d["reason"] for d in result["dropped"]]
    assert "duplicates the title of an active case" in reasons
    assert any("check" in r for r in reasons)
    assert any(r.startswith("exceeds the limit of 3") for r in reasons)
    cases = yaml.safe_load((out / matcher.DERIVED_CASE_FILE).read_text())["abuse_cases"]
    assert all(c["kind"] == "descriptive" and c["check"] for c in cases)
    # The model classifies the finding but does not rate it.
    assert cases[1]["finding"] == {"cwe": "CWE-639"}


def test_admitted_cases_reach_the_matcher_as_derived(tmp_path: Path):
    out, _ = _run(tmp_path, [_proposal("Refund an order twice")])
    origins: dict[str, str] = {}
    import model.resolve_abuse_cases as rac

    cases, errors, rejected = rac.resolve_abuse_case_sources(
        None, None, repo_root=tmp_path / "repo", origins=origins, derived_case_file=out / matcher.DERIVED_CASE_FILE
    )
    assert errors == [] and rejected == []
    assert origins["MODEL-AC-001"] == "derived"


def test_a_derived_file_with_a_foreign_id_is_rejected_alone(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    bad = out / matcher.DERIVED_CASE_FILE
    bad.write_text(
        yaml.safe_dump(
            {
                "schema_version": 2,
                "abuse_cases": [{"id": "REPO-AC-001", "kind": "descriptive", "title": "t", "check": "c"}],
            }
        )
    )
    import model.resolve_abuse_cases as rac

    cases, errors, rejected = rac.resolve_abuse_case_sources(None, None, derived_case_file=bad)
    assert errors == [] and [r["path"] for r in rejected] == [matcher.DERIVED_CASE_FILE]
    assert all(not c["id"].startswith(("REPO-AC", "MODEL-AC")) for c in cases)


def test_no_or_unusable_output_admits_nothing_and_clears_a_stale_file(tmp_path: Path):
    out, result = _run(tmp_path, "not a list")
    assert result == {"admitted": [], "dropped": []}
    assert not (out / matcher.DERIVED_CASE_FILE).exists()
    (out / matcher.DERIVED_CASE_FILE).write_text("stale")
    assert derive.admit(out)["admitted"] == []
    assert not (out / matcher.DERIVED_CASE_FILE).exists()


def test_context_is_bounded_and_carries_no_source(tmp_path: Path):
    out, _ = _run(tmp_path, [])
    context = json.loads(derive.write_context(out).read_text())
    assert context["max_cases"] == 3
    assert context["components"] == [{"id": "api", "name": "API", "description": "Handles refunds."}]
    assert "User reads or changes data of another user or tenant" in context["active_case_titles"]
    assert "refund()" not in json.dumps(context)
