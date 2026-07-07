from __future__ import annotations

import json
from pathlib import Path

import guard_evidence_verification as guard
import yaml


def _write_yaml(output_dir: Path, data: dict) -> None:
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _read_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def _threats(verdicts: list[str]) -> list[dict]:
    out = []
    for i, v in enumerate(verdicts, start=1):
        t = {"id": f"T-{i:03d}", "title": "SQLi", "risk": "Critical"}
        if v:
            t["evidence_check"] = v
            t["evidence_flags"] = ["semantic_judgment"]
        out.append(t)
    return out


def test_degenerate_all_ambiguous_is_neutralized(tmp_path: Path) -> None:
    # 8 sampled, all ambiguous, 0 verified / 0 refuted → degenerate.
    _write_yaml(tmp_path, {"threats": _threats(["ambiguous"] * 8)})

    assert guard.guard(tmp_path) == 0

    data = _read_yaml(tmp_path)
    for t in data["threats"]:
        assert "evidence_check" not in t
        assert "evidence_flags" not in t


def test_healthy_distribution_is_left_untouched(tmp_path: Path) -> None:
    # Some verified → not degenerate even if ambiguity is high.
    verdicts = ["verified", "verified", "ambiguous", "ambiguous", "ambiguous", "ambiguous"]
    _write_yaml(tmp_path, {"threats": _threats(verdicts)})

    assert guard.guard(tmp_path) == 0

    data = _read_yaml(tmp_path)
    kept = [t.get("evidence_check") for t in data["threats"]]
    assert kept == verdicts


def test_refuted_signal_prevents_neutralization(tmp_path: Path) -> None:
    # A single refuted verdict is real signal → not degenerate.
    verdicts = ["refuted"] + ["ambiguous"] * 7
    _write_yaml(tmp_path, {"threats": _threats(verdicts)})

    assert guard.guard(tmp_path) == 0

    data = _read_yaml(tmp_path)
    assert data["threats"][0]["evidence_check"] == "refuted"
    assert data["threats"][1]["evidence_check"] == "ambiguous"


def test_small_sample_below_min_is_not_neutralized(tmp_path: Path) -> None:
    # 3 ambiguous < MIN_SAMPLE (5) → quick-mode-safe, left untouched.
    _write_yaml(tmp_path, {"threats": _threats(["ambiguous"] * 3)})

    assert guard.guard(tmp_path) == 0

    data = _read_yaml(tmp_path)
    assert all(t.get("evidence_check") == "ambiguous" for t in data["threats"])


def test_verified_prior_counts_as_verified_signal(tmp_path: Path) -> None:
    # A deterministic-floor "verified-prior" is real signal → not degenerate.
    verdicts = ["verified-prior"] + ["ambiguous"] * 7
    _write_yaml(tmp_path, {"threats": _threats(verdicts)})

    assert guard.guard(tmp_path) == 0

    data = _read_yaml(tmp_path)
    assert data["threats"][0]["evidence_check"] == "verified-prior"


def test_degenerate_annotates_side_channel_summary(tmp_path: Path) -> None:
    _write_yaml(tmp_path, {"threats": _threats(["ambiguous"] * 8)})
    (tmp_path / ".evidence-verification.json").write_text(
        json.dumps({"version": 1, "summary": {"ambiguous": 8}}), encoding="utf-8"
    )

    assert guard.guard(tmp_path) == 0

    summary = json.loads((tmp_path / ".evidence-verification.json").read_text(encoding="utf-8"))
    assert summary["degenerate_neutralized"] is True
    assert "all-ambiguous" in summary["degenerate_reason"]


def test_missing_yaml_is_best_effort_noop(tmp_path: Path) -> None:
    assert guard.guard(tmp_path) == 0


def test_is_degenerate_unit() -> None:
    assert guard.is_degenerate({"verified": 0, "refuted": 0, "ambiguous": 8, "sampled": 8})
    assert not guard.is_degenerate({"verified": 1, "refuted": 0, "ambiguous": 8, "sampled": 9})
    assert not guard.is_degenerate({"verified": 0, "refuted": 1, "ambiguous": 8, "sampled": 9})
    assert not guard.is_degenerate({"verified": 0, "refuted": 0, "ambiguous": 3, "sampled": 3})


def test_summary_degenerate_fires_despite_floor_verified(tmp_path: Path) -> None:
    # Real juice-shop 2026-07-05 case: the yaml carries floor-derived `verified`
    # verdicts (7) alongside the LLM's 51 `ambiguous`, so the yaml distribution
    # alone looks "healthy" (verified != 0). The LLM's own summary
    # (verified=0/refuted=0/ambiguous=51) is degenerate — the guard must read it
    # and strip ONLY the ambiguous verdicts, keeping the floor's verified.
    threats = _threats(["verified"] * 7 + ["ambiguous"] * 51)
    _write_yaml(tmp_path, {"threats": threats})
    (tmp_path / ".evidence-verification.json").write_text(
        json.dumps({"summary": {"verified": 0, "refuted": 0, "ambiguous": 51}}),
        encoding="utf-8",
    )

    assert guard.guard(tmp_path) == 0

    data = _read_yaml(tmp_path)
    kept = [t.get("evidence_check") for t in data["threats"]]
    assert kept.count("verified") == 7  # floor verdicts preserved
    assert kept.count("ambiguous") == 0  # LLM punts stripped
    assert kept.count(None) == 51


def test_summary_healthy_keeps_everything(tmp_path: Path) -> None:
    # A summary with real verified/refuted signal is NOT degenerate.
    _write_yaml(tmp_path, {"threats": _threats(["ambiguous"] * 8)})
    (tmp_path / ".evidence-verification.json").write_text(
        json.dumps({"summary": {"verified": 20, "refuted": 3, "ambiguous": 8}}),
        encoding="utf-8",
    )
    assert guard.guard(tmp_path) == 0
    data = _read_yaml(tmp_path)
    assert all(t.get("evidence_check") == "ambiguous" for t in data["threats"])


def test_summary_degenerate_unit() -> None:
    assert guard.summary_degenerate.__module__  # symbol exists
