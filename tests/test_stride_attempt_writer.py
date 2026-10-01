"""The per-category STRIDE writer persists exactly what a full rewrite did (OR-36).

Every assertion compares the attempt file to the gate (`completion_error`) or the
log guard it must satisfy, so the rules hold for any component.
"""

from __future__ import annotations

import copy
import io
import json
import threading
from pathlib import Path

import orchestrator.stride_dispatch_waves as waves
import pytest
import runtime.agent_lifecycle as agent_lifecycle
import runtime.budget_watchdog as budget_watchdog
import runtime.stride_attempt_writer as writer

FIXTURES = Path(__file__).parent / "fixtures"
CATS = list(writer.CATEGORIES)


def _ready(tmp_path: Path, attempt: int = 1) -> Path:
    """One dispatched `api` attempt the writer and log guard both accept."""
    plan = tmp_path / ".dispatch-context" / "api" / "context-plan.json"
    plan.parent.mkdir(parents=True)
    analysis = {
        "depth": "full",
        "max_turns": 31,
        "sampling_required": False,
        "file_count": 1,
        "estimated_threat_count": "moderate",
        "stride_profile": {"stride_profile_label": "full"},
    }
    inputs = [
        {"context_id": "controls.component_evidence", "artifact_path": "evidence.json", "sha256": "1" * 64},
        {"context_id": "threats.component_taxonomy", "artifact_path": "taxonomy.json", "sha256": "2" * 64},
    ]
    plan.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "component_id": "api",
                "source_manifest_sha256": "0" * 64,
                "analysis": analysis,
                "lens_ids": [],
                "inputs": inputs,
            }
        ),
        encoding="utf-8",
    )
    job_id = f"stride:api:attempt-{attempt}"
    (tmp_path / ".context-routing-plan.json").write_text(
        json.dumps({"actions": [{"action_id": "phase9-stride", "job_ids": [job_id]}]}), encoding="utf-8"
    )
    (tmp_path / ".dispatch-waves.json").write_text(
        json.dumps({"active_claim": {"component_ids": ["api"], "attempts": {"api": attempt}}}), encoding="utf-8"
    )
    agent_lifecycle.register_call(
        tmp_path,
        {
            "agent_call_id": f"toolu_api_{attempt}",
            "session_id": "shared01",
            "agent": "stride-analyzer-v2",
            "agent_type": "appsec-advisor:appsec-stride-analyzer-v2",
            "model": "sonnet",
            "description": "STRIDE",
            "background": True,
            "action_id": "phase9-stride",
            "job_id": job_id,
            "component_id": "api",
            "attempt": attempt,
            "analysis_depth": "full",
            "max_turns": 31,
        },
    )
    return tmp_path / waves.attempt_artifact("api", attempt)


def _threat(category: str, number: int) -> dict:
    threat = copy.deepcopy(json.loads((FIXTURES / "valid_stride.json").read_text(encoding="utf-8"))["threats"][0])
    threat.update(local_id=f"api-{number:03d}", stride=category)
    return threat


def _run(monkeypatch, argv: list[str], stdin: str = "") -> int:
    monkeypatch.setattr(writer.sys, "stdin", io.StringIO(stdin))
    return writer.main(argv)


def _category(monkeypatch, tmp_path: Path, category: str, threats: list[dict], **extras) -> int:
    body = json.dumps({"threats": threats, **extras})
    return _run(monkeypatch, ["category", str(tmp_path), "--component-id", "api", "--category", category], body)


def _init(monkeypatch, tmp_path: Path) -> int:
    return _run(monkeypatch, ["init", str(tmp_path), "--component-id", "api", "--component-name", "API"])


def _finish(monkeypatch, tmp_path: Path, **extras) -> int:
    return _run(monkeypatch, ["finish", str(tmp_path), "--component-id", "api"], json.dumps(extras))


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_first_category_clears_the_seed_and_is_logged(tmp_path: Path, monkeypatch, capsys) -> None:
    path = _ready(tmp_path)
    assert _init(monkeypatch, tmp_path) == 0
    assert _load(path)["seed_only"] is True

    assert _category(monkeypatch, tmp_path, "Spoofing", [_threat("Spoofing", 1)]) == 0

    data = _load(path)
    assert "seed_only" not in data and data["partial"] is True
    assert data["skipped_categories"] == CATS[1:]
    assert "category complete: Spoofing" in (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["budget"] == "ok"
    progress = _load(tmp_path / ".progress" / "api.json")
    assert progress["step"] == writer.CATEGORY_FIRST_STEP


def test_the_budget_signal_reads_only_its_own_dispatch_job(tmp_path: Path, monkeypatch, capsys) -> None:
    _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    other = {
        "agent_call_id": "toolu_worker_1",
        "session_id": "shared01",
        "agent": "stride-analyzer-v2",
        "agent_type": "appsec-advisor:appsec-stride-analyzer-v2",
        "model": "sonnet",
        "description": "STRIDE",
        "background": True,
        "action_id": "phase9-stride",
        "job_id": "stride:worker:attempt-1",
        "component_id": "worker",
        "attempt": 1,
        "analysis_depth": "full",
        "max_turns": 31,
    }
    agent_lifecycle.register_call(tmp_path, other)
    budget_watchdog.observe_tool_uses(other, 30, tmp_path)

    _category(monkeypatch, tmp_path, "Spoofing", [])
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["budget"] == "ok"

    own = next(c for c in agent_lifecycle.running_calls(tmp_path) if c["component_id"] == "api")
    budget_watchdog.observe_tool_uses(own, 30, tmp_path)
    _category(monkeypatch, tmp_path, "Tampering", [])
    assert json.loads(capsys.readouterr().out.strip().splitlines()[-1])["budget"] == "critical"


def test_a_repeated_category_replaces_only_its_own_threats(tmp_path: Path, monkeypatch) -> None:
    path = _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    _category(monkeypatch, tmp_path, "Spoofing", [_threat("Spoofing", 1)])
    _category(monkeypatch, tmp_path, "Tampering", [_threat("Tampering", 2), _threat("Tampering", 3)])

    assert _category(monkeypatch, tmp_path, "Tampering", [_threat("Tampering", 4)]) == 0

    assert [t["local_id"] for t in _load(path)["threats"]] == ["api-001", "api-004"]


@pytest.mark.parametrize(
    ("threats", "fragment"),
    [
        ([{**_threat("Tampering", 2)}], "not 'Spoofing'"),
        ([{**_threat("Spoofing", 2), "local_id": "web-002"}], "must match api-NNN"),
        ([_threat("Spoofing", 2), _threat("Spoofing", 2)], "already used"),
        (["not an object"], "is not an object"),
    ],
    ids=["wrong-category", "foreign-id", "duplicate-id", "not-object"],
)
def test_an_invalid_threat_changes_nothing(tmp_path: Path, monkeypatch, capsys, threats, fragment) -> None:
    path = _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    before = path.read_bytes()

    assert _category(monkeypatch, tmp_path, "Spoofing", threats) == 2

    assert fragment in capsys.readouterr().err
    assert path.read_bytes() == before
    log = tmp_path / ".agent-run.log"
    assert not log.exists() or "category complete" not in log.read_text(encoding="utf-8")


def test_an_id_taken_by_another_category_is_refused(tmp_path: Path, monkeypatch) -> None:
    _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    _category(monkeypatch, tmp_path, "Spoofing", [_threat("Spoofing", 1)])
    assert _category(monkeypatch, tmp_path, "Tampering", [_threat("Tampering", 1)]) == 2


@pytest.mark.parametrize("owned", ["partial", "skipped_categories", "component_id", "coverage_declined"])
def test_writer_owned_fields_cannot_be_supplied(tmp_path: Path, monkeypatch, owned: str) -> None:
    _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    assert _category(monkeypatch, tmp_path, "Spoofing", [], **{owned: False}) == 2


def test_the_attempt_path_comes_from_the_owning_call_not_the_caller(tmp_path: Path, monkeypatch) -> None:
    """No argument names a path: an unknown component has no owning call, and a
    symlinked attempt file is refused instead of followed."""
    path = _ready(tmp_path)
    assert _run(monkeypatch, ["init", str(tmp_path), "--component-id", "../api", "--component-name", "x"]) == 2
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(outside)
    assert _init(monkeypatch, tmp_path) == 2
    assert outside.read_text(encoding="utf-8") == "{}"


def test_concurrent_category_writes_both_land(tmp_path: Path) -> None:
    path = _ready(tmp_path)
    writer.init(tmp_path, "api", "API")
    errors: list[Exception] = []

    def run(category: str, number: int) -> None:
        try:
            writer.write_category(tmp_path, "api", category, json.dumps({"threats": [_threat(category, number)]}))
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(cat, i + 1)) for i, cat in enumerate(CATS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    data = _load(path)
    assert data["skipped_categories"] == [] and len(data["threats"]) == 6


def test_finish_after_six_categories_passes_the_completion_gate(tmp_path: Path, monkeypatch) -> None:
    path = _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    for index, category in enumerate(CATS):
        _category(monkeypatch, tmp_path, category, [_threat(category, index + 1)])
    assert waves.completion_error(tmp_path, "api", attempt=1) == "partial is not false"

    assert _finish(monkeypatch, tmp_path, discovery_escapes=[]) == 0

    assert _load(path)["partial"] is False
    assert waves.completion_error(tmp_path, "api", attempt=1) is None


def test_a_budget_stop_stays_partial_with_only_unstarted_categories_skipped(tmp_path: Path, monkeypatch) -> None:
    path = _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    for index, category in enumerate(CATS[:3]):
        _category(monkeypatch, tmp_path, category, [_threat(category, index + 1)])

    assert _finish(monkeypatch, tmp_path) == 0

    data = _load(path)
    assert data["partial"] is True and data["skipped_categories"] == CATS[3:]
    assert waves.completion_error(tmp_path, "api", attempt=1) == "partial is not false"


def test_categories_persisted_before_a_declined_turn_survive(tmp_path: Path, monkeypatch) -> None:
    """The refusal path reads the same file: three persisted categories are kept."""
    _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    for index, category in enumerate(CATS[:3]):
        _category(monkeypatch, tmp_path, category, [_threat(category, index + 1)])
    agent_lifecycle.fail_call(tmp_path, "toolu_api_1", "subagent_stop:refusal")

    reason = waves.completion_error(tmp_path, "api", attempt=1) or ""

    assert reason.startswith(waves.REFUSAL_REASON_PREFIX) and "persisted before the declined turn are kept" in reason
    found = waves.best_persisted_attempt(tmp_path, "api", 1)
    assert found is not None and found[1]["skipped_categories"] == CATS[3:]


def test_init_keeps_a_resumed_attempt_and_reports_what_is_left(tmp_path: Path, monkeypatch, capsys) -> None:
    path = _ready(tmp_path, attempt=2)
    path.parent.mkdir(parents=True, exist_ok=True)
    resumed = {
        "component_id": "api",
        "component_name": "API",
        "analyzed_at": "2026-10-01T00:00:00Z",
        "partial": True,
        "resumed_from_attempt": 1,
        "skipped_categories": CATS[2:],
        "threats": [_threat("Spoofing", 1), _threat("Tampering", 2)],
    }
    path.write_text(json.dumps(resumed), encoding="utf-8")

    assert _init(monkeypatch, tmp_path) == 0

    assert _load(path) == resumed
    report = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert report["resumed"] is True and report["skipped_categories"] == CATS[2:]
    assert report["next_local_number"] == 3


def test_lens_entries_merge_by_item_and_escapes_append(tmp_path: Path, monkeypatch) -> None:
    path = _ready(tmp_path)
    _init(monkeypatch, tmp_path)
    escape = {"reason": "missing-control-proof", "decision_key": "k", "search_paths": ["src/"]}
    first = {"item": "LLM01", "disposition": "no-evidence", "reason": "checked"}
    _category(monkeypatch, tmp_path, "Spoofing", [], discovery_escapes=[escape], lens_coverage=[first])
    second = {"item": "LLM01", "disposition": "not-applicable", "reason": "no model call"}
    _category(monkeypatch, tmp_path, "Tampering", [], discovery_escapes=[escape], lens_coverage=[second])

    data = _load(path)
    assert data["discovery_escapes"] == [escape]
    assert data["lens_coverage"] == [second]
