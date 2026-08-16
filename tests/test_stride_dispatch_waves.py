from __future__ import annotations

import json
from pathlib import Path

import pytest
import resolve_config
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


def _complete_attempt(output_dir: Path, component_id: str, attempt: int) -> None:
    canonical = output_dir / f".stride-{component_id}.json"
    _complete(output_dir, component_id)
    attempt_path = output_dir / waves.attempt_artifact(component_id, attempt)
    attempt_path.parent.mkdir(parents=True, exist_ok=True)
    canonical.replace(attempt_path)


def test_fifty_components_are_partitioned_without_dropping_or_reordering() -> None:
    manifest = _manifest(50)
    plan = waves.build_plan(manifest, concurrency=5)

    assert len(plan["waves"]) == 10
    assert [len(wave["component_ids"]) for wave in plan["waves"]] == [5] * 10
    assert [cid for wave in plan["waves"] for cid in wave["component_ids"]] == [
        component["component_id"] for component in manifest["components"]
    ]
    waves.validate_plan(plan, manifest)


def test_produced_wave_plan_validates_against_its_published_schema() -> None:
    plan = waves.build_plan(_manifest(2), concurrency=2)

    waves.validate_plan(plan, _manifest(2))

    assert plan["schema_version"] == 2


@pytest.mark.parametrize("concurrency", [True, 0, 6, 33])
def test_concurrency_is_bounded(concurrency: int | bool) -> None:
    with pytest.raises(waves.WavePlanError, match="between 1 and 5"):
        waves.build_plan(_manifest(1), concurrency)


def test_concurrency_cap_fits_worst_case_receipt_verification() -> None:
    assert waves.MAX_CONCURRENCY == resolve_config.STRIDE_DISPATCH_CONCURRENCY_MAX == 5
    assert 11 * waves.MAX_CONCURRENCY + 1 <= 64
    assert 11 * (waves.MAX_CONCURRENCY + 1) + 1 > 64


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
    plan = waves.build_plan(manifest, concurrency=5)
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


def test_completion_normalizes_drifted_cvss_v4_shape(tmp_path: Path) -> None:
    """A component whose only defect is a cvss_v4 in the analyzer's common
    drifted shape ({version, score} instead of {base_score, source}) is
    accepted — the deterministic cvss_v4 canonicaliser runs BEFORE the schema
    gate, mirroring the CWE→TH backfill, so the run no longer aborts on a defect
    the merge step would fix. The file is rewritten canonically so merge and any
    resume see the schema-valid form."""
    data = _stride_component_with("CWE-89", "TH-09")
    data["threats"][0]["cvss_v4"] = {
        "version": "4.0",
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
        "score": 9.3,
        "severity": "Critical",
    }
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    repaired = json.loads(path.read_text(encoding="utf-8"))["threats"][0]["cvss_v4"]
    assert repaired == {
        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
        "base_score": 9.3,
        "severity": "Critical",
        "source": "stride-analyzer",
    }


def _progress(output_dir: Path, component_id: str, step: int, label: str) -> Path:
    progress_dir = output_dir / ".progress"
    progress_dir.mkdir(parents=True, exist_ok=True)
    path = progress_dir / f"{component_id}.json"
    path.write_text(
        json.dumps(
            {
                "component_id": component_id,
                "component_name": component_id,
                "step": step,
                "total": 9,
                "label": label,
                "updated_at": "2026-07-20T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_status_finalizes_the_progress_counter_of_a_completed_component(tmp_path: Path) -> None:
    manifest = _manifest(2)
    plan = waves.build_plan(manifest, concurrency=2)
    _complete(tmp_path, "service-01")
    finished = _progress(tmp_path, "service-01", step=1, label="Loading context")
    running = _progress(tmp_path, "service-02", step=3, label="STRIDE: Spoofing")

    waves.status(plan, manifest, tmp_path)

    reconciled = json.loads(finished.read_text(encoding="utf-8"))
    assert (reconciled["step"], reconciled["label"]) == (9, waves.FINAL_PROGRESS_LABEL)
    # An incomplete component keeps its self-reported step — only a validated
    # output makes the remaining steps a fact.
    assert json.loads(running.read_text(encoding="utf-8"))["step"] == 3


def test_completed_component_without_progress_file_stays_without_one(tmp_path: Path) -> None:
    """Creating one would forge check_stride_dispatch's inline-collapse signal."""
    manifest = _manifest(1)
    plan = waves.build_plan(manifest, concurrency=1)
    _complete(tmp_path, "service-01")

    waves.status(plan, manifest, tmp_path)

    assert not (tmp_path / ".progress" / "service-01.json").exists()


def test_reconcile_progress_is_idempotent(tmp_path: Path) -> None:
    _complete(tmp_path, "service-01")
    _progress(tmp_path, "service-01", step=9, label=waves.FINAL_PROGRESS_LABEL)

    assert waves.reconcile_progress(tmp_path, "service-01") is False


def test_completion_defaults_an_absent_skipped_categories(tmp_path: Path) -> None:
    """A complete component that simply never wrote `skipped_categories` is
    accepted. The key is optional in the schema and the analyzer drops it when
    it authors the final file from scratch; on a `partial: false` file its
    absence can only mean "nothing skipped", so `None != []` blocked a wave over
    a non-defect. The default is persisted so merge and any resume see it."""
    data = _stride_component_with("CWE-89", "TH-09")
    del data["skipped_categories"]
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    assert json.loads(path.read_text(encoding="utf-8"))["skipped_categories"] == []


def test_completion_still_rejects_a_non_empty_skipped_categories(tmp_path: Path) -> None:
    """The default must not mask real skipped coverage."""
    data = _stride_component_with("CWE-89", "TH-09")
    data["skipped_categories"] = ["Repudiation"]
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert "skipped_categories" in (waves.completion_error(tmp_path, "service-01") or "")


def test_completion_drops_an_empty_attack_steps(tmp_path: Path) -> None:
    """`attack_steps: []` is a fatal minItems violation but carries no more
    information than an absent key — the §3 renderer ignores both. The analyzer
    writes it on control-absence findings it cannot phrase as attacker actions,
    so drop it deterministically instead of failing the component."""
    data = _stride_component_with("CWE-778", "TH-09")
    data["threats"][0]["attack_steps"] = []
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    assert "attack_steps" not in json.loads(path.read_text(encoding="utf-8"))["threats"][0]


def test_completion_drops_an_over_long_attack_step(tmp_path: Path) -> None:
    """juice-shop 2026-08-02: one 272-char step on ci-cd-pipeline failed the
    whole component and cost it a full re-dispatch. The step is dropped before
    the gate; the remaining two carry the walkthrough."""
    steps = [
        "An attacker opens a pull request that edits the workflow file.",
        "The workflow runs on the fork and reads the repository secrets.",
        "The attacker then " + "escalates further, " * 20,
    ]
    data = _stride_component_with("CWE-829", "TH-09")
    data["threats"][0]["attack_steps"] = steps
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    assert json.loads(path.read_text(encoding="utf-8"))["threats"][0]["attack_steps"] == steps[:2]


def test_completion_drops_an_off_enum_boundary_leg(tmp_path: Path) -> None:
    """juice-shop 2026-08-02: data-store-sqlite composed `leg` from the boundary
    name ("parameterized binding"). The label is optional, so it is dropped and
    the reference survives — the merge step applies the same rule, but only
    after this gate would already have re-dispatched the component."""
    data = _stride_component_with("CWE-89", "TH-09")
    threat = data["threats"][0]
    threat["boundary_refs"] = [
        {
            "boundary_id": "tb-3",
            "origin_component_id": "service-01",
            "rationale": "Raw string concatenation reaches the driver on this path.",
            "leg": "parameterized binding",
            "evidence_locations": [{"file": threat["evidence"]["file"], "line": threat["evidence"]["line"]}],
        }
    ]
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    ref = json.loads(path.read_text(encoding="utf-8"))["threats"][0]["boundary_refs"][0]
    assert "leg" not in ref
    assert ref["boundary_id"] == "tb-3"


@pytest.mark.parametrize(
    "bad_ref",
    [
        {
            "boundary_id": "tb-1",
            "rationale": "The missing authorization check occurs at this crossing.",
            "evidence_locations": [{"file": "src/service.py", "line": 10}],
        },
        {
            "id": "tb-1",
            "leg": "authorization",
            "rationale": "The missing authorization check occurs at this crossing.",
        },
        {
            "boundary_id": "tb-1",
            "origin_component_id": "service-01",
            "rationale": "The missing authorization check occurs at this crossing.",
            "evidence_locations": [{"file": "src/other.py", "line": 99}],
        },
    ],
)
def test_completion_drops_malformed_optional_boundary_ref_without_retry(tmp_path: Path, bad_ref: dict) -> None:
    data = _stride_component_with("CWE-89", "TH-01")
    data["threats"][0]["boundary_refs"] = [bad_ref]
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    assert json.loads(path.read_text(encoding="utf-8"))["threats"][0]["boundary_refs"] == []


@pytest.mark.parametrize("cwe, expected", [("CWE-799", "TH-12"), ("CWE-620", "TH-02")])
def test_completion_backfills_live_smoke_unclassified_cwes(tmp_path: Path, cwe: str, expected: str) -> None:
    data = _stride_component_with(cwe, "TH-UNCLASSIFIED")
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    assert json.loads(path.read_text(encoding="utf-8"))["threats"][0]["threat_category_id"] == expected


def test_completion_keeps_usable_attack_steps(tmp_path: Path) -> None:
    """Two or more real steps are authored content and stay untouched."""
    steps = [
        "An attacker registers an account against the public signup endpoint.",
        "The attacker replays the profile update with an added role field.",
    ]
    data = _stride_component_with("CWE-89", "TH-09")
    data["threats"][0]["attack_steps"] = steps
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    assert json.loads(path.read_text(encoding="utf-8"))["threats"][0]["attack_steps"] == steps


def test_completion_canonicalizes_discovery_escape_field_aliases(tmp_path: Path) -> None:
    data = _stride_component_with("CWE-89", "TH-09")
    data["discovery_escapes"] = [
        {
            "reason": "component-path-sampling",
            "unresolved_decision": "admin-route-authentication",
            "search_paths": ["routes/"],
            "selected_lens": None,
        }
    ]
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    assert waves.completion_error(tmp_path, "service-01") is None
    escape = json.loads(path.read_text(encoding="utf-8"))["discovery_escapes"][0]
    assert escape == {
        "reason": "component-path-sampling",
        "decision_key": "admin-route-authentication",
        "search_paths": ["routes/"],
        "lens": None,
    }


def test_completion_rejects_conflicting_discovery_escape_aliases(tmp_path: Path) -> None:
    data = _stride_component_with("CWE-89", "TH-09")
    data["discovery_escapes"] = [
        {
            "reason": "component-path-sampling",
            "decision_key": "canonical-decision",
            "unresolved_decision": "different-decision",
            "search_paths": ["routes/"],
        }
    ]
    path = tmp_path / ".stride-service-01.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    reason = waves.completion_error(tmp_path, "service-01")
    assert reason is not None
    assert "unresolved_decision" in reason


def test_plan_fingerprint_rejects_changed_manifest() -> None:
    original = _manifest(3)
    plan = waves.build_plan(original, concurrency=2)
    changed = _manifest(4)

    with pytest.raises(waves.WavePlanError, match="does not match"):
        waves.validate_plan(plan, changed)


def test_claim_persists_two_attempt_budget_across_resume(tmp_path: Path, monkeypatch) -> None:
    manifest = _manifest(1)
    plan = waves.build_plan(manifest, concurrency=1)
    now = [100]
    monkeypatch.setattr(waves.time, "time", lambda: now[0])

    first, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is True
    assert first["wave"]["attempts"] == {"service-01": 1}

    plan["wait_started_at"]["service-01"] = now[0]
    now[0] += waves.WAIT_DEADLINE_SECONDS
    second, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is True
    assert second["wave"]["attempts"] == {"service-01": 2}
    assert second["wave"]["retry_reasons"] == {"service-01": "missing output"}

    plan["wait_started_at"]["service-01"] = now[0]
    now[0] += waves.WAIT_DEADLINE_SECONDS
    blocked, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is False
    assert blocked["status"] == "blocked"
    assert blocked["blocked_components"] == ["service-01"]


def test_wait_status_joins_only_the_claimed_wave_not_future_waves(tmp_path: Path) -> None:
    manifest = _manifest(6)
    plan = waves.build_plan(manifest, concurrency=5)
    claimed, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is True
    current = [component["component_id"] for component in claimed["wave"]["components"]]
    for component_id in current:
        _complete_attempt(tmp_path, component_id, 1)

    result = waves.wait_status(plan, manifest, tmp_path, current, now=100)

    assert result["status"] == "complete"
    assert plan["attempts"]["service-06"] == 0
    assert not (tmp_path / ".stride-service-06.json").exists()


def test_wait_deadline_is_cumulative_across_bounded_poll_slices(tmp_path: Path) -> None:
    manifest = _manifest(1)
    manifest_path = tmp_path / ".stride-dispatch-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    (tmp_path / waves.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")

    first = waves.load_wait_status(tmp_path, ["service-01"], begin=True, now=100)
    pending = waves.load_wait_status(
        tmp_path,
        ["service-01"],
        begin=True,
        now=100 + waves.WAIT_DEADLINE_SECONDS - 1,
    )
    expired = waves.load_wait_status(
        tmp_path,
        ["service-01"],
        begin=True,
        now=100 + waves.WAIT_DEADLINE_SECONDS,
    )

    assert first["status"] == "pending"
    assert pending["status"] == "pending"
    assert pending["wait_started_at"] == 100
    assert expired["status"] == "expired"


def test_wait_rejects_an_undispatched_future_component(tmp_path: Path) -> None:
    manifest = _manifest(2)
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)

    with pytest.raises(waves.WavePlanError, match="exactly match the active dispatch claim"):
        waves.wait_status(plan, manifest, tmp_path, ["service-02"], now=100)


def test_wait_rejects_a_subset_of_the_active_claim(tmp_path: Path) -> None:
    manifest = _manifest(2)
    plan = waves.build_plan(manifest, concurrency=2)
    waves.claim(plan, manifest, tmp_path)

    with pytest.raises(waves.WavePlanError, match="exactly match the active dispatch claim"):
        waves.wait_status(plan, manifest, tmp_path, ["service-01"], now=100)


def test_claim_rejects_a_second_dispatch_before_the_active_join(tmp_path: Path) -> None:
    manifest = _manifest(1)
    plan = waves.build_plan(manifest, concurrency=1)
    first, changed = waves.claim(plan, manifest, tmp_path)

    second, changed_again = waves.claim(plan, manifest, tmp_path)

    assert changed is True
    assert first["status"] == "claimed"
    assert changed_again is False
    assert second["status"] == "in_flight"
    assert plan["attempts"]["service-01"] == 1
    # The claim already issued is repeated verbatim, so a re-read of the
    # dispatch boundary can answer with it instead of ending the run.
    assert second["wave"] == {"components": first["wave"]["components"], "attempts": {"service-01": 1}}


def test_claim_retries_only_after_the_active_join_deadline(tmp_path: Path, monkeypatch) -> None:
    manifest = _manifest(1)
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    plan["wait_started_at"]["service-01"] = 100
    monkeypatch.setattr(waves.time, "time", lambda: 100 + waves.WAIT_DEADLINE_SECONDS)

    retry, changed = waves.claim(plan, manifest, tmp_path)

    assert changed is True
    assert retry["status"] == "claimed"
    assert retry["wave"]["attempts"] == {"service-01": 2}


def test_late_prior_attempt_cannot_overwrite_promoted_retry(tmp_path: Path, monkeypatch) -> None:
    manifest = _manifest(1)
    plan = waves.build_plan(manifest, concurrency=1)
    waves.claim(plan, manifest, tmp_path)
    plan["wait_started_at"]["service-01"] = 100
    monkeypatch.setattr(waves.time, "time", lambda: 100 + waves.WAIT_DEADLINE_SECONDS)
    retry, changed = waves.claim(plan, manifest, tmp_path)
    assert changed is True
    assert retry["wave"]["attempts"] == {"service-01": 2}

    _complete_attempt(tmp_path, "service-01", 2)
    current = waves.wait_status(plan, manifest, tmp_path, ["service-01"], now=1000)
    assert current["status"] == "complete"
    promoted = (tmp_path / ".stride-service-01.json").read_bytes()

    late = tmp_path / waves.attempt_artifact("service-01", 1)
    late.parent.mkdir(parents=True, exist_ok=True)
    late.write_text('{"late": true}\n', encoding="utf-8")

    assert (tmp_path / ".stride-service-01.json").read_bytes() == promoted


def test_blocked_claim_reports_the_component_validation_reason(tmp_path: Path, capsys) -> None:
    manifest = _manifest(1)
    (tmp_path / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    plan = waves.build_plan(manifest, concurrency=1)
    plan["attempts"]["service-01"] = waves.DEFAULT_MAX_ATTEMPTS
    (tmp_path / waves.PLAN_NAME).write_text(json.dumps(plan), encoding="utf-8")
    data = _stride_component_with("CWE-89", "TH-09")
    data["discovery_escapes"] = [
        {
            "reason": "component-path-sampling",
            "decision_key": "admin-route-authentication",
            "search_paths": ["routes/"],
            "unexpected": True,
        }
    ]
    (tmp_path / ".stride-service-01.json").write_text(json.dumps(data), encoding="utf-8")

    assert waves.main(["claim", str(tmp_path)]) == 1
    error = capsys.readouterr().err
    assert "service-01: schema validation failed" in error
    assert "producer or contract defects" in error


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
    error = capsys.readouterr().err
    assert "schema validation failed at attempts" in error


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
