"""Tests for scripts/eval_threat_model.py — the deterministic halves of the
eval-threat-model dev skill (prepare signals + aggregate find->verify merge).

The LLM JUDGE/VERIFY pass is not unit-testable; here we pin everything around it:
the brief/signal computation, the refute-by-default merge, scoring, and exit codes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import eval_threat_model as ev  # noqa: E402

FROZEN = Path(__file__).resolve().parent / "fixtures" / "e2e" / "frozen-run"


def _dump(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj), encoding="utf-8")


def _write_empty_sidecars(out: Path, *, skip: set[str] | None = None) -> None:
    skip = skip or set()
    for dim in ev.DIMENSIONS:
        if dim in skip:
            continue
        _dump(out / f"judge-{dim}.json", {"dimension": dim, "version": 1, "candidates": []})
        _dump(out / f"verify-{dim}.json", {"dimension": dim, "version": 1, "verdicts": []})


def _candidate(cand_id: str, severity: str, target_id: str, title: str, detail: str) -> dict:
    return {
        "cand_id": cand_id,
        "severity": severity,
        "target_id": target_id,
        "title": title,
        "detail": detail,
        "evidence": f"evidence for {cand_id}",
        "suggested_fix": f"fix {target_id}",
    }


# --------------------------------------------------------------------------- #
# normalize_stride
# --------------------------------------------------------------------------- #
def test_normalize_stride_full_name_passthrough():
    assert ev._normalize_stride("Tampering") == "Tampering"
    assert ev._normalize_stride("  Spoofing ") == "Spoofing"


def test_normalize_stride_letter_expands():
    assert ev._normalize_stride("E") == "Elevation of Privilege"
    assert ev._normalize_stride("I") == "Information Disclosure"


def test_normalize_stride_unknown_is_none():
    assert ev._normalize_stride("Bogus") is None
    assert ev._normalize_stride("") is None
    assert ev._normalize_stride(None) is None


# --------------------------------------------------------------------------- #
# prepare
# --------------------------------------------------------------------------- #
def test_prepare_frozen_run_builds_brief(tmp_path):
    out = tmp_path / "eval-out"
    rc = ev.prepare(FROZEN, out, repo=None)
    assert rc == 0

    brief = json.loads((out / "brief.json").read_text())
    assert brief["dimensions"] == ev.DIMENSIONS
    assert len(brief["components"]) == 2
    assert len(brief["threats"]) == 4

    sig = brief["signals"]["stride_coverage"]
    # C-01 carries only Tampering threats in the fixture; the other 5 are absent.
    assert sig["C-01"]["present"] == ["Tampering"]
    assert "Spoofing" in sig["C-01"]["absent"]
    assert len(sig["C-01"]["absent"]) == 5
    assert sig["C-02"]["present"] == ["Spoofing"]

    # C-02 has a single threat -> a low-threat signal, no zero-threat component.
    assert brief["signals"]["missed_surface"]["zero_threat_components"] == []
    assert "C-02" in brief["signals"]["missed_surface"]["low_threat_components"]

    # No --repo -> no deterministic path-existence findings.
    det = json.loads((out / "det-findings.json").read_text())
    assert det["findings"] == []


def test_prepare_with_repo_flags_missing_paths(tmp_path):
    repo = tmp_path / "repo"
    (repo / "routes").mkdir(parents=True)  # C-01 path exists; C-02 lib/insecurity.ts does not
    out = tmp_path / "eval-out"

    rc = ev.prepare(FROZEN, out, repo=repo)
    assert rc == 0

    det = json.loads((out / "det-findings.json").read_text())["findings"]
    assert len(det) == 1
    f = det[0]
    assert f["dimension"] == "recon_fidelity"
    assert f["severity"] == "medium"
    assert f["target_id"] == "C-02"
    assert "lib/insecurity.ts" in f["title"]

    brief = json.loads((out / "brief.json").read_text())
    assert brief["signals"]["recon_fidelity"]["missing_paths"] == [{"component": "C-02", "path": "lib/insecurity.ts"}]


def test_prepare_with_repo_treats_escaping_paths_as_missing(tmp_path):
    run = tmp_path / "run"
    repo = tmp_path / "repo"
    out = tmp_path / "eval-out"
    run.mkdir()
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("exists outside repo", encoding="utf-8")
    (repo / "inside.txt").write_text("exists inside repo", encoding="utf-8")
    (run / "threat-model.yaml").write_text(
        "\n".join(
            [
                "project: {}",
                "components:",
                "  - id: C-01",
                "    name: Escaping component",
                "    kind: service",
                f"    paths: ['inside.txt', '../outside.txt', '{outside}']",
                "threats: []",
                "mitigations: []",
            ]
        ),
        encoding="utf-8",
    )

    rc = ev.prepare(run, out, repo=repo)
    assert rc == 0

    brief = json.loads((out / "brief.json").read_text())
    assert brief["components"][0]["paths_exist"] == [
        {"path": "inside.txt", "exists": True},
        {"path": "../outside.txt", "exists": False},
        {"path": str(outside), "exists": False},
    ]
    missing = json.loads((out / "det-findings.json").read_text())["findings"]
    assert [f["title"] for f in missing] == [
        "Component C-01 references missing path '../outside.txt'",
        f"Component C-01 references missing path '{outside}'",
    ]


def test_prepare_missing_yaml_is_usage_error(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert ev.prepare(empty, tmp_path / "o", repo=None) == 2


def test_main_prepare_dispatch(tmp_path):
    out = tmp_path / "o"
    rc = ev.main(["prepare", "--run-dir", str(FROZEN), "--out", str(out)])
    assert rc == 0
    assert (out / "brief.json").is_file()


def test_main_prepare_bad_run_dir(tmp_path):
    rc = ev.main(["prepare", "--run-dir", str(tmp_path / "nope"), "--out", str(tmp_path / "o")])
    assert rc == 2


# --------------------------------------------------------------------------- #
# aggregate — find -> verify merge
# --------------------------------------------------------------------------- #
def _seed_eval_dir(tmp_path) -> Path:
    out = tmp_path / "eval-out"
    out.mkdir()
    _write_empty_sidecars(out, skip={"threat_plausibility", "missed_surface"})
    _dump(
        out / "det-findings.json",
        {
            "version": 1,
            "findings": [
                {
                    "id": "DET-001",
                    "dimension": "recon_fidelity",
                    "severity": "medium",
                    "target_id": "C-02",
                    "title": "missing path",
                    "detail": "x",
                    "source": "deterministic",
                }
            ],
        },
    )
    _dump(
        out / "judge-threat_plausibility.json",
        {
            "dimension": "threat_plausibility",
            "version": 1,
            "candidates": [
                _candidate(
                    "threat_plausibility-1",
                    "high",
                    "T-009",
                    "hallucinated GraphQL threat",
                    "no graphql in stack",
                ),
                _candidate("threat_plausibility-2", "medium", "T-005", "weakly grounded", "maybe"),
            ],
        },
    )
    _dump(
        out / "verify-threat_plausibility.json",
        {
            "dimension": "threat_plausibility",
            "version": 1,
            "verdicts": [
                {"cand_id": "threat_plausibility-1", "verdict": "real", "reason": "no graphql dep"},
                {"cand_id": "threat_plausibility-2", "verdict": "false_positive", "reason": "actually fits"},
            ],
        },
    )
    # A critical candidate with an explicit false-positive verdict must be dropped.
    _dump(
        out / "judge-missed_surface.json",
        {
            "dimension": "missed_surface",
            "version": 1,
            "candidates": [_candidate("missed_surface-1", "critical", "file-upload", "upload uncovered", "maybe")],
        },
    )
    _dump(
        out / "verify-missed_surface.json",
        {
            "dimension": "missed_surface",
            "version": 1,
            "verdicts": [{"cand_id": "missed_surface-1", "verdict": "false_positive", "reason": "covered"}],
        },
    )
    return out


def test_aggregate_keeps_only_real_verdicts(tmp_path):
    out = _seed_eval_dir(tmp_path)
    rc = ev.aggregate(out)

    res = json.loads((out / "eval-results.json").read_text())
    confirmed_ids = {f.get("cand_id") or f.get("id") for f in res["confirmed"]}
    # real high candidate + deterministic medium survive; false positives drop.
    assert confirmed_ids == {"threat_plausibility-1", "DET-001"}
    assert res["summary"]["by_severity"]["high"] == 1
    assert res["summary"]["by_severity"]["medium"] == 1
    assert res["summary"]["dropped_total"] == 2
    # exit 1 because a High defect is confirmed (gate-able).
    assert rc == 1

    review = (out / "EVAL-REVIEW.md").read_text()
    assert "hallucinated GraphQL threat" in review
    assert "Per-dimension" in review


def test_aggregate_refute_by_default_drops_false_positive_verdicts(tmp_path):
    out = _seed_eval_dir(tmp_path)
    ev.aggregate(out)
    res = json.loads((out / "eval-results.json").read_text())
    dropped_ids = {f["cand_id"] for f in res["dropped"]}
    assert "missed_surface-1" in dropped_ids  # critical, but explicit false_positive -> dropped
    assert "threat_plausibility-2" in dropped_ids  # explicit false_positive


def test_aggregate_missing_verdict_is_usage_error(tmp_path):
    out = _seed_eval_dir(tmp_path)
    _dump(
        out / "verify-missed_surface.json",
        {
            "dimension": "missed_surface",
            "version": 1,
            "verdicts": [],
        },
    )
    assert ev.aggregate(out) == 2
    assert not (out / "eval-results.json").exists()


def test_aggregate_no_high_exits_zero(tmp_path):
    out = tmp_path / "eval-out"
    out.mkdir()
    _write_empty_sidecars(out, skip={"recommendation_actionability"})
    _dump(
        out / "det-findings.json",
        {
            "version": 1,
            "findings": [
                {
                    "id": "DET-001",
                    "dimension": "recon_fidelity",
                    "severity": "medium",
                    "target_id": "C-01",
                    "title": "m",
                    "detail": "missing path",
                    "source": "deterministic",
                },
            ],
        },
    )
    _dump(
        out / "judge-recommendation_actionability.json",
        {
            "dimension": "recommendation_actionability",
            "version": 1,
            "candidates": [
                _candidate(
                    "recommendation_actionability-1",
                    "low",
                    "M-003",
                    "vague verification",
                    "verification is generic",
                )
            ],
        },
    )
    _dump(
        out / "verify-recommendation_actionability.json",
        {
            "dimension": "recommendation_actionability",
            "version": 1,
            "verdicts": [{"cand_id": "recommendation_actionability-1", "verdict": "real", "reason": "ok"}],
        },
    )
    rc = ev.aggregate(out)
    assert rc == 0  # only medium + low confirmed, nothing gating


def test_aggregate_missing_out_is_usage_error(tmp_path):
    assert ev.aggregate(tmp_path / "does-not-exist") == 2


def test_aggregate_missing_sidecars_is_usage_error(tmp_path):
    out = tmp_path / "eval-out"
    out.mkdir()
    _dump(out / "det-findings.json", {"version": 1, "findings": []})
    assert ev.aggregate(out) == 2


def test_aggregate_complete_empty_sidecars_is_clean_zero(tmp_path):
    out = tmp_path / "eval-out"
    out.mkdir()
    _dump(out / "det-findings.json", {"version": 1, "findings": []})
    _write_empty_sidecars(out)
    rc = ev.aggregate(out)
    assert rc == 0
    res = json.loads((out / "eval-results.json").read_text())
    assert res["summary"]["confirmed_total"] == 0
    assert "No confirmed" in (out / "EVAL-REVIEW.md").read_text() or "None" in (out / "EVAL-REVIEW.md").read_text()
