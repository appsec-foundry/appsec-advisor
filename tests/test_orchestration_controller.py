from __future__ import annotations

import json
import subprocess
from pathlib import Path

import orchestrator.orchestration_controller as controller
import pytest

ROOT = Path(__file__).resolve().parents[1]


# ── The blocked-lock question is decided here, not in the runtime ────────────
#
# A headless run printed the full "Held lock" menu into its log and then died at
# the controller gate (2026-09-05). The runtime was told to skip the question
# "under APPSEC_HEADLESS=1" — a condition it cannot evaluate, because it reads
# the action, never the environment. The decision now rides in the action.


def test_the_runtime_reads_the_field_instead_of_the_environment():
    """Drift guard on the instruction the fix exists for: §1a must gate on the
    action. The environment variable stays named elsewhere (§2a, as background
    to a field) — this asserts only that the lock section no longer asks the
    runtime to read it."""
    runtime = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    section = runtime.split("### 1a.")[1].split("### 2")[0]

    assert "ACTION.lock_prompt_needed" in section
    assert "APPSEC_HEADLESS" not in section


def test_compose_if_ready_requires_llm_fragments(tmp_path):
    """No render fragments on disk → cannot compose, caller must dispatch Stage 2."""
    output = tmp_path / "out"
    (output / ".fragments").mkdir(parents=True)
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    assert controller._compose_if_ready(output, "") is False


def test_compose_if_ready_blocks_when_requirements_export_fails(tmp_path, monkeypatch):
    output = tmp_path / "out"
    fragments = output / ".fragments"
    fragments.mkdir(parents=True)
    (fragments / "ms-verdict.json").write_text("{}", encoding="utf-8")
    (fragments / "security-architecture.md").write_text("## 6. Security Architecture\n", encoding="utf-8")

    def fake_run(cmd, **_kwargs):
        if any("renderers/compose_threat_model.py" in str(part) for part in cmd):
            (output / "threat-model.md").write_text("# Threat Model\n", encoding="utf-8")
        returncode = 1 if any("model/emit_requirement_trace_to_model.py" in str(part) for part in cmd) else 0
        return subprocess.CompletedProcess(cmd, returncode, "", "incomplete requirements assessment")

    monkeypatch.setattr(controller.subprocess, "run", fake_run)
    assert controller._compose_if_ready(output, "") is False
    blocked = json.loads((output / ".compose-blocked.json").read_text(encoding="utf-8"))
    assert blocked["step"] == "model/emit_requirement_trace_to_model.py"


def _valid_recon_signals() -> dict:
    keys = (
        "has_public_routes",
        "has_auth_surface",
        "has_role_concept",
        "has_secrets_in_repo",
        "has_ci_pipeline",
        "has_external_apis",
        "has_client_storage",
        "has_multi_tenancy_signal",
        "has_open_self_registration",
        "has_llm_surface",
    )
    return {
        "schema_version": 2,
        "signals": {key: False for key in keys},
        "signal_evidence": {key: {"status": "none", "locations": []} for key in keys},
        "signal_classification": {"has_open_self_registration": "deterministic"},
        "component_hints": [],
    }


def test_runtime_environment_opt_outs_are_absent():
    source = Path(controller.__file__).read_text(encoding="utf-8")
    assert "APPSEC_THIN_ORCHESTRATOR" not in source
    assert "APPSEC_CONTEXT_V2" not in source


# --- _emit / main: the CLI + exit-code boundary --------------------------------


# --- post-lock failure must release the lock -----------------------------------


# --- verbose/tracing markers ---------------------------------------------------


# --- _fetch_requirements arg modes ---------------------------------------------


# --- _run_script real failure + stream paths -----------------------------------


def test_run_script_raises_with_exit_code(monkeypatch):
    monkeypatch.setattr(
        controller.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 5, stdout="", stderr="boom"),
    )
    with pytest.raises(controller.ControllerError) as excinfo:
        controller._run_script("whatever.py", [])
    assert excinfo.value.exit_code == 5
    assert "boom" in str(excinfo.value)


def test_run_script_streams_when_not_quiet(monkeypatch, capsys):
    monkeypatch.setattr(
        controller.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout="OUT", stderr="ERR"),
    )
    controller._run_script("whatever.py", [], quiet=False)
    err = capsys.readouterr().err
    assert "OUT" in err
    assert "ERR" in err


# --- _prepasses WARN branch ----------------------------------------------------


# --- _duration_estimate fallbacks ----------------------------------------------


# --- _checkpoint_needs_render branches -----------------------------------------


# --- rebuild clean-slate note + actor-model env --------------------------------


def test_append_event_swallows_oserror(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    # output_dir.mkdir() raises because the parent path is a file → swallowed.
    controller._append_event(blocker / "sub", "EVENT", "detail")


# ---------------------------------------------------------------------------
# Interactive orchestrator-model prompt signal (thin-path ACTION)
# ---------------------------------------------------------------------------


# --- Bootstrap-stub recovery (2026-07-19) -----------------------------------
# `model/triage_compute_ranking.py --bootstrap-yaml` leaves a `meta._bootstrap` stub
# when Phase 11 is cut off. Every gate in `next` only tested that
# threat-model.yaml EXISTS, so the stub passed as canonical and the run
# continued on an empty model.


# ---------------------------------------------------------------------------
# Deterministic yaml-derived export backstop (_export_if_configured)
# ---------------------------------------------------------------------------


class TestIacSurfaceDetection:
    def test_detects_a_top_level_marker(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        assert controller._has_iac_surface(tmp_path) is True

    def test_detects_a_nested_marker(self, tmp_path):
        nested = tmp_path / "services" / "api"
        nested.mkdir(parents=True)
        (nested / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        assert controller._has_iac_surface(tmp_path) is True

    def test_detects_a_path_scoped_marker(self, tmp_path):
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text("on: push\n", encoding="utf-8")
        assert controller._has_iac_surface(tmp_path) is True

    def test_committed_agent_settings_are_a_surface_on_their_own(self, tmp_path):
        """A repository can carry a coding-agent posture and no IaC file at all;
        skipping the scan there would drop every agent_config check."""
        agent = tmp_path / ".claude"
        agent.mkdir()
        (agent / "settings.json").write_text('{"permissions": {"allow": []}}\n', encoding="utf-8")
        assert controller._has_iac_surface(tmp_path) is True

    def test_a_bare_yml_outside_workflows_is_not_a_surface(self, tmp_path):
        (tmp_path / "config.yml").write_text("a: 1\n", encoding="utf-8")
        assert controller._has_iac_surface(tmp_path) is False

    def test_empty_repository_has_no_surface(self, tmp_path):
        assert controller._has_iac_surface(tmp_path) is False

    def test_pruned_directories_do_not_select_a_surface(self, tmp_path):
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        assert controller._has_iac_surface(tmp_path) is False

    def test_hitting_the_entry_cap_fails_safe_to_true(self, tmp_path, monkeypatch):
        """An unwalked remainder must never silently drop the config scan."""
        (tmp_path / "a.txt").write_text("x", encoding="utf-8")
        monkeypatch.setattr(controller, "_IAC_WALK_MAX_ENTRIES", 0)
        assert controller._has_iac_surface(tmp_path) is True


class TestRetiredSelfReportedProvenance:
    """`signal_classification` and `component_hints[].classification` asked the
    producer to grade the reliability of its own output — a question a model
    that guesses cannot answer, and one no production code ever read. Both were
    `required`, so a wrong enum token in either killed a paid run.

    They stay declared until the next schema_version bump: `.recon-signals.json`
    is on the NEVER-delete list, so artifacts preserved from earlier runs still
    carry them and must keep validating under `additionalProperties: false`.
    """

    def _schema(self):
        return json.loads((ROOT / "schemas/recon-signals.schema.json").read_text(encoding="utf-8"))

    def test_neither_field_is_required(self):
        schema = self._schema()
        assert "signal_classification" not in schema["required"]
        assert "classification" not in schema["properties"]["component_hints"]["items"]["required"]

    def test_an_artifact_without_them_validates(self):
        value = _valid_recon_signals()
        value.pop("signal_classification")
        value["component_hints"] = [
            {"component_id": "backend-api", "component_type": "api-endpoint", "deployment_zones": ["internet"]}
        ]
        errors = list(controller.Draft202012Validator(self._schema()).iter_errors(value))
        assert errors == []

    def test_a_preserved_artifact_still_validates(self):
        """A run's own earlier output must not become invalid mid-migration."""
        value = _valid_recon_signals()
        value["component_hints"] = [
            {
                "component_id": "backend-api",
                "component_type": "api-endpoint",
                "deployment_zones": ["internet"],
                "classification": "deterministic",
            }
        ]
        errors = list(controller.Draft202012Validator(self._schema()).iter_errors(value))
        assert errors == []

    def test_the_producer_prompt_no_longer_teaches_the_retired_vocabulary(self):
        """The collision lived in the flattened template, not in the schema.

        `has_open_self_registration` appeared as an object-valued key whose inner
        `status` enum is `supporting|candidate|none`, and five lines later as a
        direct enum key valued `deterministic|llm-fallback`. Keeping either
        vocabulary in the prompt keeps the confusion available.
        """
        prompt = (ROOT / "agents/appsec-recon-scanner.md").read_text(encoding="utf-8")
        assert "signal_classification" not in prompt
        assert "llm-fallback" not in prompt


# ---------------------------------------------------------------------------
# REQ-BIZ-004 — a declared --context source reaches the run or stops it
# ---------------------------------------------------------------------------


def test_the_runtime_no_longer_writes_the_run_start_marker():
    """One producer for the marker. Both writing it would let the later write
    move the run boundary after the prepasses already read the earlier one."""
    runtime = (ROOT / "skills" / "create-threat-model" / "SKILL-full-runtime.md").read_text(encoding="utf-8")
    assert ".scan-start-epoch" not in runtime


# ---------------------------------------------------------------------------
# OR-8: a controller abort converges on the single terminator
# ---------------------------------------------------------------------------
