"""Cross-artifact run invariants: the checks themselves, and a frozen real run.

The frozen run (tests/fixtures/run_invariants/juice-shop-thorough) is a trimmed
copy of a thorough Juice Shop run whose defects were verified independently.
Each invariant it violates today is a strict xfail naming the fix that flips
it, so landing that fix turns the xfail into an unexpected pass and forces the
marker's removal.
"""

import json
from pathlib import Path

import pytest
import yaml
from validators import run_invariants as inv

FROZEN = Path(__file__).parent / "fixtures" / "run_invariants" / "juice-shop-thorough"


def _tracked() -> set[str]:
    return set((FROZEN / "tracked-files.txt").read_text(encoding="utf-8").split())


# ── frozen run ─────────────────────────────────────────────────────────────


@pytest.mark.xfail(
    strict=True, reason="fixed in the scanner, but this frozen run predates it: refresh the fixture from a new run"
)
def test_frozen_no_evidence_outside_target_inventory():
    assert inv.untracked_evidence(FROZEN, _tracked()) == []


@pytest.mark.xfail(strict=True, reason="pending core refactor: evidence basis derived after verdicts")
def test_frozen_confirmed_needs_verified_evidence():
    assert inv.confirmed_needs_verified(FROZEN) == []


@pytest.mark.xfail(strict=True, reason="pending core refactor: component finalize pass")
def test_frozen_component_matches_evidence_paths():
    assert inv.component_paths(FROZEN) == []


@pytest.mark.xfail(strict=True, reason="pending core refactor: finding identity across producers")
def test_frozen_reported_findings_have_unique_identity():
    assert inv.unique_identity(FROZEN) == []


def test_frozen_every_boundary_represented():
    assert inv.boundaries_represented(FROZEN) == []


def test_frozen_architect_coverage_ignores_refuted_exclusions():
    assert inv.architect_refuted(FROZEN) == []


# ── the checks on synthetic runs ───────────────────────────────────────────


def _threat(tid, **over):
    base = {
        "id": tid,
        "component": "api",
        "cwe": "CWE-89",
        "evidence": [{"file": "src/api/db.ts", "line": 10}],
        "evidence_tier": "confirmed-exploitable",
        "evidence_check": "verified",
        "evidence_flags": [],
    }
    base.update(over)
    return base


def _run(tmp_path, threats=None, boundaries=None, mermaid="", svg="", outcomes=None):
    data = {
        "components": [
            {"id": "web", "paths": ["web/**"]},
            {"id": "api", "paths": ["src/api/**"]},
        ],
        "trust_boundaries": boundaries or [],
        "threats": threats or [],
    }
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(data))
    md = f"# Report\n\n## 2. Architecture Diagrams\n\n```mermaid\n{mermaid}\n```\n\n## 3. Next\n"
    (tmp_path / "threat-model.md").write_text(md)
    if svg:
        (tmp_path / "threat-model.figure1.svg").write_text(svg)
    if outcomes is not None:
        review = {"application": {"outcomes": outcomes}, "dispatch_jobs": [{"status": "returned"}]}
        (tmp_path / ".architect-review.json").write_text(json.dumps(review))
    return tmp_path


def _outcome(tid, status="accepted", assessment="unchanged", reason="validated"):
    return {"t_id": tid, "status": status, "assessment": assessment, "remediation": "unchanged", "reason": reason}


def test_clean_synthetic_run_holds_every_invariant(tmp_path):
    run = _run(
        tmp_path,
        threats=[_threat("T-1"), _threat("T-2", evidence=[{"file": "src/api/db.ts", "line": 40}])],
        boundaries=[{"id": "tb-1"}, {"id": "tb-2"}],
        mermaid='subgraph TB["Trust boundary (tb-1)"]\nend',
        svg="<svg><text>tb-2</text></svg>",
        outcomes=[_outcome("T-1"), _outcome("T-2")],
    )
    assert inv.run_all(run, {"src/api/db.ts"}) == {name: [] for name in inv.run_all(run, set())}


@pytest.mark.parametrize(
    ("flags", "expected"),
    [([], 1), (["expected_file_absent"], 0)],
    ids=["untracked-flagged", "absence-exempt"],
)
def test_untracked_evidence(tmp_path, flags, expected):
    run = _run(
        tmp_path, threats=[_threat("T-1", evidence=[{"file": ".local/x.json", "line": 2}], evidence_flags=flags)]
    )
    assert len(inv.untracked_evidence(run, {"src/api/db.ts"})) == expected


def test_absence_kind_is_exempt_from_inventory(tmp_path):
    run = _run(tmp_path, threats=[_threat("T-1", evidence=[{"file": "lock.json", "kind": "absence"}])])
    assert inv.untracked_evidence(run, set()) == []


@pytest.mark.parametrize(
    ("check", "expected"),
    [("verified", 0), ("verified-prior", 0), ("ambiguous", 1), ("unchecked", 1), (None, 1)],
)
def test_confirmed_needs_verified(tmp_path, check, expected):
    run = _run(tmp_path, threats=[_threat("T-1", evidence_check=check)])
    assert len(inv.confirmed_needs_verified(run)) == expected


def test_practice_tier_may_be_unverified(tmp_path):
    run = _run(tmp_path, threats=[_threat("T-1", evidence_tier="insecure-practice", evidence_check="ambiguous")])
    assert inv.confirmed_needs_verified(run) == []


@pytest.mark.parametrize(
    ("component", "file", "expected"),
    [
        ("api", "src/api/db.ts", 0),
        ("api", "web/app.ts", 1),
        ("system-wide", "web/app.ts", 0),
        ("ghost", "src/api/db.ts", 1),
    ],
    ids=["match", "mismatch", "system-wide", "unmodelled-component"],
)
def test_component_paths(tmp_path, component, file, expected):
    run = _run(tmp_path, threats=[_threat("T-1", component=component, evidence=[{"file": file, "line": 3}])])
    assert len(inv.component_paths(run)) == expected


@pytest.mark.parametrize(
    ("first_line", "second", "expected"),
    [
        (10, {"evidence": [{"file": "src/api/db.ts", "line": 10}]}, 1),
        (10, {"evidence": [{"file": "./src/api/db.ts", "line": 10}]}, 1),
        (10, {"evidence": [{"file": "src/api/db.ts", "line": 11}]}, 0),
        (10, {"evidence": [{"file": "src/api/db.ts", "line": 10}], "cwe": "CWE-79"}, 0),
        (1, {"evidence": [{"file": "src/api/db.ts", "line": 1}]}, 0),
    ],
    ids=["same-site", "dot-slash-path", "other-line", "other-family", "file-level-line"],
)
def test_unique_identity(tmp_path, first_line, second, expected):
    first = {"evidence": [{"file": "src/api/db.ts", "line": first_line}]}
    run = _run(tmp_path, threats=[_threat("T-1", **first), _threat("T-2", **second)])
    assert len(inv.unique_identity(run)) == expected


def test_boundary_named_only_outside_a_diagram_is_not_represented(tmp_path):
    run = _run(tmp_path, boundaries=[{"id": "tb-1"}, {"id": "tb-4"}], mermaid='subgraph T["tb-1"]\nend')
    md = (run / "threat-model.md").read_text() + "\n*Trust boundaries not drawn above: (tb-4)*\n"
    (run / "threat-model.md").write_text(md)
    assert inv.boundaries_represented(run) == ["tb-4: not represented in any §2 diagram or figure"]


def test_boundary_in_figure_only_counts(tmp_path):
    run = _run(tmp_path, boundaries=[{"id": "tb-6"}], svg="<svg><text>tb-6</text></svg>")
    assert inv.boundaries_represented(run) == []


@pytest.mark.parametrize(
    ("boundary", "expected"),
    [
        ({"id": "tb-4", "surface": "in-process", "transition": []}, []),
        ({"id": "tb-4", "kind": "process"}, []),
        (
            {"id": "tb-4", "surface": "network", "transition": []},
            ["tb-4: not represented in any §2 diagram or figure"],
        ),
        (
            {"id": "tb-4", "surface": "in-process", "transition": ["privilege"]},
            ["tb-4: not represented in any §2 diagram or figure"],
        ),
    ],
    ids=["in-process-interface", "legacy-process-kind", "network-db-boundary", "in-process-with-transition"],
)
def test_internal_interfaces_need_no_diagram(tmp_path, boundary, expected):
    run = _run(tmp_path, boundaries=[{"id": "tb-1"}, boundary], mermaid='subgraph T["tb-1"]\nend')
    assert inv.boundaries_represented(run) == expected


@pytest.mark.parametrize(
    ("outcomes", "expected"),
    [
        ([_outcome("T-1")], 0),
        ([_outcome("T-1", status="unreviewed", assessment="unreviewed", reason="refuted")], 0),
        ([_outcome("T-1", status="unreviewed", assessment="unreviewed", reason="oversized")], 0),
        ([_outcome("T-1", assessment="unresolved")], 0),
    ],
    ids=["clean", "refuted-not-counted", "oversized-is-a-real-gap", "reviewer-unresolved-is-real"],
)
def test_architect_refuted(tmp_path, outcomes, expected):
    run = _run(tmp_path, outcomes=outcomes)
    assert len(inv.architect_refuted(run)) == expected


def test_architect_check_detects_a_coverage_that_counts_refuted_rows(tmp_path, monkeypatch):
    """The detector must still fire if the coverage function regresses to counting
    every outcome that is not accepted, refuted exclusions included."""
    refuted = _outcome("T-1", status="unreviewed", assessment="unreviewed", reason="refuted")
    run = _run(tmp_path, outcomes=[_outcome("T-2"), refuted])

    def regressed(value):
        rows = value["application"]["outcomes"]
        return {"unresolved_or_unreviewed": sum(r["status"] != "accepted" for r in rows)}

    monkeypatch.setattr(inv, "review_coverage", regressed)
    assert len(inv.architect_refuted(run)) == 1


def test_architect_check_without_review_artifact(tmp_path):
    assert inv.architect_refuted(_run(tmp_path)) == []
