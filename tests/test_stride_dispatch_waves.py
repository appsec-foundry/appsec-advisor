from __future__ import annotations

import json
from pathlib import Path

import pytest
import stride_dispatch_waves as waves

FIXTURES = Path(__file__).parent / "fixtures"


def _component(component_id: str) -> dict:
    return {
        "component_id": component_id,
        "component_name": component_id.replace("-", " ").title(),
        "component_paths": [f"services/{component_id}.py"],
        "component_complexity": "moderate",
        "max_turns": 22,
        "index_paths": {
            "prior_findings": "none",
            "known_threats": "none",
            "cross_repo": "none",
            "requirements_violations": "none",
            "relevant_actors": "none",
        },
    }


def _manifest(count: int) -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-07-20T12:00:00Z",
        "components": [_component(f"service-{index:02d}") for index in range(1, count + 1)],
    }


def _complete(output_dir: Path, component_id: str, *, threats: list | None = None) -> None:
    payload = {
        "component_id": component_id,
        "component_name": component_id,
        "started_at": "2026-07-20T12:00:00Z",
        "analyzed_at": "2026-07-20T12:01:00Z",
        "partial": False,
        "skipped_categories": [],
        "threats": [] if threats is None else threats,
    }
    (output_dir / f".stride-{component_id}.json").write_text(json.dumps(payload), encoding="utf-8")


def test_fifty_components_are_partitioned_without_dropping_or_reordering() -> None:
    manifest = _manifest(50)
    plan = waves.build_plan(manifest, concurrency=8)

    assert len(plan["waves"]) == 7
    assert [len(wave["component_ids"]) for wave in plan["waves"]] == [8, 8, 8, 8, 8, 8, 2]
    assert [cid for wave in plan["waves"] for cid in wave["component_ids"]] == [
        component["component_id"] for component in manifest["components"]
    ]
    waves.validate_plan(plan, manifest)


@pytest.mark.parametrize("concurrency", [True, 0, 33])
def test_concurrency_is_bounded(concurrency: int | bool) -> None:
    with pytest.raises(waves.WavePlanError, match="between 1 and 32"):
        waves.build_plan(_manifest(1), concurrency)


def test_resume_returns_only_incomplete_members_of_earliest_wave(tmp_path: Path) -> None:
    manifest = _manifest(5)
    plan = waves.build_plan(manifest, concurrency=3)
    _complete(tmp_path, "service-01")
    _complete(tmp_path, "service-03")

    result = waves.status(plan, manifest, tmp_path)

    assert result["status"] == "pending"
    assert result["complete"] == 2
    assert result["next_wave"]["index"] == 1
    assert [component["component_id"] for component in result["next_wave"]["components"]] == ["service-02"]


def test_complete_zero_finding_result_is_not_a_stub(tmp_path: Path) -> None:
    manifest = _manifest(1)
    plan = waves.build_plan(manifest, concurrency=8)
    _complete(tmp_path, "service-01")

    result = waves.status(plan, manifest, tmp_path)

    assert result["status"] == "complete"
    assert result["incomplete"] == []


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        ({"component_id": "service-01", "threats": [], "partial": True, "skipped_categories": []}, "partial"),
        (
            {"component_id": "service-01", "threats": [], "partial": False, "skipped_categories": ["Spoofing"]},
            "skipped_categories",
        ),
        ({"component_id": "wrong", "threats": [], "partial": False, "skipped_categories": []}, "mismatch"),
    ],
)
def test_partial_skipped_and_mismatched_results_fail_closed(tmp_path: Path, payload: dict, reason: str) -> None:
    path = tmp_path / ".stride-service-01.json"
    payload.setdefault("component_name", "Service")
    payload.setdefault("analyzed_at", "2026-07-20T12:01:00Z")
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert reason in (waves.completion_error(tmp_path, "service-01") or "")


def _stride_component_with(cwe: str, tcid: str) -> dict:
    """A schema-valid stride component whose sole threat carries the given
    CWE and threat_category_id — built from the shared valid_stride fixture."""
    data = json.loads((FIXTURES / "valid_stride.json").read_text(encoding="utf-8"))
    data["component_id"] = "service-01"
    data["partial"] = False
    data["skipped_categories"] = []
    data["threats"][0]["cwe"] = cwe
    data["threats"][0]["threat_category_id"] = tcid
    return data


def test_completion_accepts_th_unclassified_when_cwe_is_mappable(tmp_path: Path) -> None:
    """A component whose only defect is a TH-UNCLASSIFIED sentinel on a threat
    with a taxonomy-mappable CWE is accepted — the deterministic CWE→TH backfill
    runs BEFORE the schema gate, so the run no longer aborts on a defect it can
    fix. The file is rewritten canonically so merge sees the resolved id."""
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(_stride_component_with("CWE-601", "TH-UNCLASSIFIED")), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    repaired = json.loads(path.read_text(encoding="utf-8"))
    assert repaired["threats"][0]["threat_category_id"] == "TH-18"


def test_completion_rejects_th_unclassified_when_cwe_is_unmappable(tmp_path: Path) -> None:
    """A genuinely unmappable CWE keeps the sentinel and stays fatal — the
    backfill must not mask real classification gaps."""
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(_stride_component_with("CWE-99999", "TH-UNCLASSIFIED")), encoding="utf-8")

    reason = waves.completion_error(tmp_path, "service-01")
    assert reason is not None and "TH-UNCLASSIFIED" in reason


def test_plan_fingerprint_rejects_changed_manifest() -> None:
    original = _manifest(3)
    plan = waves.build_plan(original, concurrency=2)
    changed = _manifest(4)

    with pytest.raises(waves.WavePlanError, match="does not match"):
        waves.validate_plan(plan, changed)


def test_claim_persists_two_attempt_budget_across_resume(tmp_path: Path) -> None:
    manifest = _manifest(1)
    plan = waves.build_plan(manifest, concurrency=1)

    first, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is True
    assert first["wave"]["attempts"] == {"service-01": 1}

    second, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is True
    assert second["wave"]["attempts"] == {"service-01": 2}

    blocked, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is False
    assert blocked["status"] == "blocked"
    assert blocked["blocked_components"] == ["service-01"]


def test_reinitializing_with_new_concurrency_preserves_attempts(tmp_path: Path, capsys) -> None:
    manifest = _manifest(2)
    manifest_path = tmp_path / ".stride-dispatch-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert waves.main(["init", str(tmp_path), "--concurrency", "1"]) == 0
    capsys.readouterr()
    assert waves.main(["claim", str(tmp_path)]) == 0
    capsys.readouterr()

    assert waves.main(["init", str(tmp_path), "--concurrency", "2"]) == 0
    capsys.readouterr()
    plan = json.loads((tmp_path / waves.PLAN_NAME).read_text(encoding="utf-8"))
    assert plan["attempts"]["service-01"] == 1


def test_reinitializing_corrupt_same_manifest_plan_fails_closed(tmp_path: Path, capsys) -> None:
    manifest = _manifest(1)
    manifest_path = tmp_path / ".stride-dispatch-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    plan = waves.build_plan(manifest, concurrency=1)
    plan["attempts"] = {}
    (tmp_path / waves.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")

    assert waves.main(["init", str(tmp_path)]) == 2
    assert "attempts must cover" in capsys.readouterr().err


def test_cli_init_next_and_verify_round_trip(tmp_path: Path, capsys) -> None:
    manifest = _manifest(2)
    (tmp_path / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert waves.main(["init", str(tmp_path), "--concurrency", "1"]) == 0
    initialized = json.loads(capsys.readouterr().out)
    assert initialized["total_waves"] == 2

    assert waves.main(["next", str(tmp_path)]) == 0
    pending = json.loads(capsys.readouterr().out)
    assert pending["next_wave"]["components"][0]["component_id"] == "service-01"

    _complete(tmp_path, "service-01")
    _complete(tmp_path, "service-02")
    assert waves.main(["verify", str(tmp_path)]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["status"] == "complete"


def test_verify_cli_blocks_incomplete_coverage(tmp_path: Path, capsys) -> None:
    manifest = _manifest(1)
    (tmp_path / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert waves.main(["init", str(tmp_path)]) == 0
    capsys.readouterr()

    assert waves.main(["verify", str(tmp_path)]) == 1
    captured = capsys.readouterr()
    assert "do not continue to merge" in captured.err
