from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import ValidationError

ROOT = Path(__file__).parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import agent_lifecycle  # noqa: E402
import log_event  # noqa: E402
import stride_progress  # noqa: E402
import write_stride_progress as progress  # noqa: E402


def _plan(output_dir: Path, depth: str) -> Path:
    directory = output_dir / ".dispatch-context" / "api"
    directory.mkdir(parents=True)
    path = directory / "context-plan.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "component_id": "api",
                "source_manifest_sha256": "0" * 64,
                "analysis": {
                    "depth": depth,
                    "max_turns": 31,
                    "sampling_required": False,
                    "file_count": 1,
                    "estimated_threat_count": "moderate",
                    "stride_profile": {"stride_profile_label": depth},
                },
                "lens_ids": [],
                "inputs": [
                    {
                        "context_id": "controls.component_evidence",
                        "artifact_path": "evidence.json",
                        "sha256": "1" * 64,
                    },
                    {
                        "context_id": "threats.component_taxonomy",
                        "artifact_path": "taxonomy.json",
                        "sha256": "2" * 64,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _claim(output_dir: Path, depth: str, *, attempt: int = 1, call_depth: str | None = None) -> dict:
    action_id = "phase9-stride"
    job_id = f"stride:api:attempt-{attempt}"
    (output_dir / ".context-routing-plan.json").write_text(
        json.dumps({"actions": [{"action_id": action_id, "job_ids": [job_id]}]}),
        encoding="utf-8",
    )
    (output_dir / ".dispatch-waves.json").write_text(
        json.dumps({"active_claim": {"component_ids": ["api"], "attempts": {"api": attempt}}}),
        encoding="utf-8",
    )
    agent_lifecycle.register_call(
        output_dir,
        {
            "agent_call_id": f"toolu_api_{attempt}",
            "session_id": "shared01",
            "agent": "stride-analyzer-v2",
            "agent_type": "appsec-advisor:appsec-stride-analyzer-v2",
            "model": "sonnet",
            "description": "STRIDE",
            "background": True,
            "action_id": action_id,
            "job_id": job_id,
            "component_id": "api",
            "attempt": attempt,
            "analysis_depth": call_depth or depth,
            "max_turns": 31,
        },
    )
    return {"action_id": action_id, "job_id": job_id, "attempt": attempt}


def test_depth_claim_is_validated_even_without_the_stride_agent_flag(tmp_path: Path) -> None:
    """The 2026-08-16 run logged `depth=full` for a `light` component.

    The guard used to run only when the caller named itself
    `--agent stride-analyzer-v2`, so omitting the flags bypassed it entirely.
    """
    _plan(tmp_path, "light")
    _claim(tmp_path, "light")

    rc = log_event.main(["log_event.py", str(tmp_path), "info", "AGENT_START", "component=api depth=full"])

    assert rc == 0
    logged = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert "depth=light" in logged
    assert "depth=full" not in logged


def test_a_depth_line_naming_no_dispatched_component_is_left_alone(tmp_path: Path) -> None:
    rc = log_event.main(["log_event.py", str(tmp_path), "info", "ORCHESTRATION_READY", "mode=full depth=standard"])

    assert rc == 0
    assert "depth=standard" in (tmp_path / ".agent-run.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("depth", ["full", "light"])
def test_progress_depth_comes_only_from_validated_context_plan(tmp_path: Path, depth: str) -> None:
    _plan(tmp_path, depth)
    claim = _claim(tmp_path, depth)
    payload = progress.write_progress(tmp_path, "api", "API", 2, 9, "Spoofing", ROOT)

    assert payload["analysis_depth"] == depth
    assert {key: payload[key] for key in claim} == claim
    persisted = json.loads((tmp_path / ".progress" / "api.json").read_text(encoding="utf-8"))
    assert persisted == payload


@pytest.mark.parametrize("depth", ["TBD", "screening", ""])
def test_noncanonical_context_depth_fails_at_producer_gate(tmp_path: Path, depth: str) -> None:
    _plan(tmp_path, depth)
    with pytest.raises(ValidationError):
        progress.write_progress(tmp_path, "api", "API", 1, 9, "Context", ROOT)
    assert not (tmp_path / ".progress" / "api.json").exists()


def test_missing_context_plan_fails_instead_of_guessing(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        progress.write_progress(tmp_path, "api", "API", 1, 9, "Context", ROOT)


def test_progress_rejects_wrong_component_identity(tmp_path: Path) -> None:
    path = _plan(tmp_path, "full")
    value = json.loads(path.read_text(encoding="utf-8"))
    value["component_id"] = "other"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="another component"):
        progress.write_progress(tmp_path, "api", "API", 1, 9, "Context", ROOT)


def test_cli_reports_invalid_step_without_writing(tmp_path: Path) -> None:
    _plan(tmp_path, "full")
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPTS / "write_stride_progress.py"),
            str(tmp_path),
            "api",
            "API",
            "10",
            "9",
            "bad",
            "--plugin-root",
            str(ROOT),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "progress step must be within its total" in result.stderr


@pytest.mark.parametrize("depth", ["full", "light"])
def test_agent_log_and_status_use_the_same_authoritative_depth(
    tmp_path: Path, depth: str, capsys: pytest.CaptureFixture[str]
) -> None:
    _plan(tmp_path, depth)
    claim = _claim(tmp_path, depth)
    rc = log_event.main(
        [
            "log_event.py",
            str(tmp_path),
            "step-start",
            "[Phase 9/11] [2/9] depth=TBD Spoofing",
            "--agent",
            "stride-analyzer-v2",
            "--component-id",
            "api",
        ]
    )
    assert rc == 0
    log = (tmp_path / ".agent-run.log").read_text(encoding="utf-8")
    assert f"component=api depth={depth}" in log
    assert f"action_id={claim['action_id']} job_id={claim['job_id']} attempt={claim['attempt']}" in log
    assert "depth=TBD" not in log
    appsec_progress = json.loads((tmp_path / ".appsec-progress.json").read_text(encoding="utf-8"))
    assert f"component=api depth={depth}" in appsec_progress["detail"]

    progress.write_progress(tmp_path, "api", "API", 2, 9, "Spoofing", ROOT)
    assert stride_progress.main(["stride_progress.py", str(tmp_path), "1", "--force"]) == 1
    status = capsys.readouterr().out
    assert f"({depth}) API" in status
    assert "TBD" not in status


def test_status_rejects_progress_that_contradicts_the_context_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _plan(tmp_path, "full")
    _claim(tmp_path, "full")
    progress.write_progress(tmp_path, "api", "API", 1, 9, "Context", ROOT)
    path = tmp_path / ".progress" / "api.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["analysis_depth"] = "light"
    path.write_text(json.dumps(value), encoding="utf-8")

    assert stride_progress.main(["stride_progress.py", str(tmp_path), "1", "--force"]) == 2
    assert "contradicts current context plan" in capsys.readouterr().err


def test_progress_rejects_stale_attempt_claim(tmp_path: Path) -> None:
    _plan(tmp_path, "full")
    _claim(tmp_path, "full", attempt=1)
    waves = json.loads((tmp_path / ".dispatch-waves.json").read_text(encoding="utf-8"))
    waves["active_claim"]["attempts"]["api"] = 2
    (tmp_path / ".dispatch-waves.json").write_text(json.dumps(waves), encoding="utf-8")
    with pytest.raises(ValueError, match="current dispatch claim"):
        progress.write_progress(tmp_path, "api", "API", 1, 9, "Context", ROOT)


def test_progress_rejects_call_depth_that_contradicts_plan(tmp_path: Path) -> None:
    _plan(tmp_path, "full")
    _claim(tmp_path, "full", call_depth="light")
    with pytest.raises(ValueError, match="authoritative analysis depth"):
        progress.write_progress(tmp_path, "api", "API", 1, 9, "Context", ROOT)


def test_status_rejects_old_v2_progress_when_new_attempt_is_active(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _plan(tmp_path, "full")
    _claim(tmp_path, "full", attempt=1)
    progress.write_progress(tmp_path, "api", "API", 1, 9, "Context", ROOT)
    waves = json.loads((tmp_path / ".dispatch-waves.json").read_text(encoding="utf-8"))
    waves["active_claim"]["attempts"]["api"] = 2
    (tmp_path / ".dispatch-waves.json").write_text(json.dumps(waves), encoding="utf-8")

    assert stride_progress.main(["stride_progress.py", str(tmp_path), "1", "--force"]) == 2
    assert "progress attempt contradicts current dispatch claim" in capsys.readouterr().err
