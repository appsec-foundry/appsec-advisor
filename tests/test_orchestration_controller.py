from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import build_abuse_case_contexts as abuse_contexts
import build_architecture_analysis_context as architecture_context
import build_post_stride_contexts as post_stride_contexts
import build_stride_evidence_bundles as evidence_bundles
import orchestration_controller as controller
import pytest

ROOT = Path(__file__).resolve().parents[1]


def _cfg(tmp_path: Path, mode: str = "full") -> dict:
    return {
        "mode": mode,
        "dry_run": False,
        "resume": False,
        "rerender": False,
        "output_dir": str(tmp_path / "out"),
        "repo_root": str(tmp_path / "repo"),
        "assessment_depth": "standard",
        "preflight_status": "preflight",
        "tracing": False,
        "verbose": False,
        "write_pdf": False,
        "write_html": False,
        "check_requirements": False,
        "incremental": False,
        "rebuild": mode == "rebuild",
        "skip_qa": False,
        "architect_review": False,
        "invocation_args": f"--{mode}",
        "reasoning_model": "sonnet-economy",
        "total_stages": 3,
    }


def _completed(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["test"], 0, stdout=stdout, stderr="")


@pytest.fixture(autouse=True)
def _grant_required_permissions(monkeypatch):
    """Controller unit tests should not depend on host Claude settings."""
    monkeypatch.setattr(controller.check_permissions, "diff_required", lambda required, granted: [])


def test_route_defaults_to_thin_for_full_or_rebuild(monkeypatch, tmp_path):
    # Default (no env): full/rebuild route to the compact runtime; incremental
    # keeps the legacy runtime.
    monkeypatch.delenv("APPSEC_THIN_ORCHESTRATOR", raising=False)
    monkeypatch.setattr(controller, "_resolve", lambda argv: _cfg(tmp_path, argv[0]))
    full = controller.route(["full"])
    rebuild = controller.route(["rebuild"])
    incremental = controller.route(["incremental"])
    assert full["runtime"] == "thin-full"
    assert rebuild["runtime"] == "thin-full"
    assert incremental["runtime"] == "legacy"


def test_route_defaults_to_compact_rerender(monkeypatch, tmp_path):
    monkeypatch.delenv("APPSEC_THIN_ORCHESTRATOR", raising=False)
    cfg = _cfg(tmp_path, "rerender")
    cfg["rerender"] = True
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    action = controller.route([])
    assert action["runtime"] == "thin-rerender"
    assert action["instruction_file"] == str(controller.THIN_RERENDER_RUNTIME)


@pytest.mark.parametrize("key", ["dry_run", "resume"])
def test_route_keeps_special_paths_on_legacy(monkeypatch, tmp_path, key):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    cfg[key] = True
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    assert controller.route([])["runtime"] == "legacy"


def test_rerender_with_deadline_keeps_legacy_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path, "rerender")
    cfg.update({"rerender": True, "max_cost_usd": 1})
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    assert controller.route([])["runtime"] == "legacy"


def test_compact_rerender_prepare_verifies_artifacts_and_dispatches_stage2(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path, "rerender")
    cfg["rerender"] = True
    output = Path(cfg["output_dir"])
    output.mkdir(parents=True)
    Path(cfg["repo_root"]).mkdir()
    for name in ("threat-model.yaml", ".threats-merged.json", ".triage-flags.json"):
        (output / name).write_text("{}", encoding="utf-8")
    fragments = output / ".fragments"
    fragments.mkdir()
    for name in ("system-overview.md", "assets.md", "security-architecture.md"):
        (fragments / name).write_text("fragment", encoding="utf-8")

    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed("lock acquired\n"))
    action = controller.prepare(["--rerender"])
    assert action["action"] == "dispatch_agent"
    assert action["mode"] == "rerender"
    assert action["stage"] == "stage2"
    assert action["instruction_file"] == str(controller.THIN_RERENDER_RUNTIME)
    assert Path(action["config_path"]).is_file()


def test_compact_rerender_prepare_fails_before_lock_when_artifacts_are_missing(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path, "rerender")
    cfg["rerender"] = True
    Path(cfg["output_dir"]).mkdir(parents=True)
    Path(cfg["repo_root"]).mkdir()
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    action = controller.prepare(["--rerender"])
    assert action["action"] == "abort"
    assert action["exit_code"] == 2
    assert ".threats-merged.json" in action["reason"]


@pytest.mark.parametrize("key", ["max_wall_time_seconds", "max_cost_usd"])
def test_route_keeps_deadline_paths_on_legacy(monkeypatch, tmp_path, key):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    cfg[key] = 60
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    assert controller.route([])["runtime"] == "legacy"


def test_route_rejects_context_v2_generation_on_legacy_runtime(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path)
    cfg.update({"runtime_generation": "context-v2", "max_wall_time_seconds": 1800})
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    with pytest.raises(controller.ControllerError, match="context-v2 requires the compact"):
        controller.route([])


def test_route_keeps_live_phase_on_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    monkeypatch.setenv("APPSEC_LIVE_PHASE", "1")
    monkeypatch.setattr(controller, "_resolve", lambda argv: _cfg(tmp_path))
    assert controller.route([])["runtime"] == "legacy"


def test_full_prepare_wipes_only_intermediates(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    output = Path(cfg["output_dir"])
    repo = Path(cfg["repo_root"])
    output.mkdir(parents=True)
    repo.mkdir()
    preserve = [
        "threat-model.md",
        "threat-model.yaml",
        "threat-model.sarif.json",
        ".threat-modeling-context.md",
        ".agent-run.log",
        ".hook-events.log",
    ]
    remove = [
        ".stride-api.json",
        ".threats-merged.json",
        ".triage-flags.json",
        ".merge-decisions.json",
        ".appsec-checkpoint",
        ".stage-stats.jsonl",
    ]
    for name in preserve + remove:
        (output / name).write_text("x", encoding="utf-8")
    (output / ".appsec-cache").mkdir()
    (output / ".appsec-cache" / "baseline.json").write_text("{}")
    (output / ".fragments").mkdir()
    (output / ".fragments" / "old.md").write_text("x")

    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(
        controller,
        "_run_script",
        lambda name, args, **kwargs: _completed("LOCK_ACQUIRED\n"),
    )
    monkeypatch.setattr(controller, "_prepasses", lambda cfg, receipts: None)
    monkeypatch.setattr(controller, "_fetch_requirements", lambda cfg: None)
    monkeypatch.setattr(
        controller.resolve_config,
        "render_run_plan",
        lambda *args: "Threat Model — Pre-flight\n",
    )

    action = controller.prepare(["--full"])
    assert controller._validate_action(action) == action
    assert action["action"] == "dispatch_agent"
    assert action["stage"] == "stage1"
    assert "Workspace\n  Cleanup  :" in action["run_plan"]
    assert "prior deliverables and baseline preserved" in action["run_plan"]
    assert all((output / name).exists() for name in preserve)
    assert (output / ".appsec-cache" / "baseline.json").exists()
    assert all(not (output / name).exists() for name in remove)
    assert not (output / ".fragments").exists()
    persisted = json.loads((output / ".skill-config.json").read_text())
    assert persisted["mode"] == "full"


def test_prepare_passes_detected_session_model_to_box(monkeypatch, tmp_path):
    # Thin-path fix: the controller must detect the host session model and pass
    # it to render_run_plan so the Pre-flight box can fold in the cost advisory.
    # (The rendered content itself is unit-tested in test_resolve_config.py.)
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    Path(cfg["output_dir"]).mkdir(parents=True)
    Path(cfg["repo_root"]).mkdir(exist_ok=True)
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(controller, "_run_script", lambda name, args, **kwargs: _completed("LOCK_ACQUIRED\n"))
    monkeypatch.setattr(controller, "_prepasses", lambda cfg, receipts: None)
    monkeypatch.setattr(controller, "_fetch_requirements", lambda cfg: None)
    monkeypatch.setattr(controller.detect_session_model, "detect_session_model", lambda *a, **k: "claude-sonnet-5")
    captured = {}

    def _spy(*args):
        captured["session_model"] = args[4] if len(args) > 4 else None
        return "Threat Model — Pre-flight\n"

    monkeypatch.setattr(controller.resolve_config, "render_run_plan", _spy)
    controller.prepare(["--full"])
    assert captured["session_model"] == "claude-sonnet-5"


def test_prepare_passes_empty_when_session_undetected(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    Path(cfg["output_dir"]).mkdir(parents=True)
    Path(cfg["repo_root"]).mkdir(exist_ok=True)
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(controller, "_run_script", lambda name, args, **kwargs: _completed("LOCK_ACQUIRED\n"))
    monkeypatch.setattr(controller, "_prepasses", lambda cfg, receipts: None)
    monkeypatch.setattr(controller, "_fetch_requirements", lambda cfg: None)

    # Detection raises → controller must swallow it and pass "" (fail-safe).
    def _boom(*a, **k):
        raise RuntimeError("transcript unreadable")

    monkeypatch.setattr(controller.detect_session_model, "detect_session_model", _boom)
    captured = {}

    def _spy(*args):
        captured["session_model"] = args[4] if len(args) > 4 else None
        return "Threat Model — Pre-flight\n"

    monkeypatch.setattr(controller.resolve_config, "render_run_plan", _spy)
    controller.prepare(["--full"])
    assert captured["session_model"] == ""


def test_rebuild_need_render_aborts_before_wipe(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path, "rebuild")
    output = Path(cfg["output_dir"])
    output.mkdir(parents=True)
    (output / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true\n",
        encoding="utf-8",
    )
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    action = controller.prepare(["--rebuild"])
    assert action["action"] == "abort"
    assert action["exit_code"] == 0
    assert "Use --resume" in action["reason"]
    assert (output / "threat-model.yaml").exists()


def test_rebuild_need_render_does_not_recommend_resume_for_context_v2(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path, "rebuild")
    output = Path(cfg["output_dir"])
    output.mkdir(parents=True)
    (output / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true runtime_generation=context-v2\n",
        encoding="utf-8",
    )
    (output / ".skill-config.json").write_text(
        json.dumps({"runtime_generation": "context-v2"}),
        encoding="utf-8",
    )
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)

    action = controller.prepare(["--rebuild"])

    assert action["action"] == "abort"
    assert "does not support --resume" in action["reason"]
    assert "--rebuild --force" in action["reason"]


def test_rebuild_cleanup_preserves_audit_logs(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path, "rebuild")
    output = Path(cfg["output_dir"])
    repo = Path(cfg["repo_root"])
    output.mkdir(parents=True)
    repo.mkdir()
    for name in (
        "threat-model.md",
        "threat-model.yaml",
        ".stride-api.json",
        ".agent-run.log",
        ".hook-events.log",
    ):
        (output / name).write_text("x", encoding="utf-8")
    (output / ".appsec-cache").mkdir()

    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(
        controller,
        "_run_script",
        lambda name, args, **kwargs: _completed("LOCK_ACQUIRED\n"),
    )
    monkeypatch.setattr(controller, "_prepasses", lambda cfg, receipts: None)
    monkeypatch.setattr(controller, "_fetch_requirements", lambda cfg: None)
    monkeypatch.setattr(
        controller.resolve_config,
        "render_run_plan",
        lambda *args: "Threat Model — Pre-flight\n",
    )

    action = controller.prepare(["--rebuild"], force=True)
    assert not (output / "threat-model.md").exists()
    assert not (output / "threat-model.yaml").exists()
    assert not (output / ".stride-api.json").exists()
    assert not (output / ".appsec-cache").exists()
    assert (output / ".agent-run.log").exists()
    assert (output / ".hook-events.log").exists()
    assert "changelog audit archived" in action["run_plan"]


def test_full_cleanup_does_not_delete_prefix_lookalikes(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    for name in (".stride-notes.md", ".merge-notes.md"):
        (output / name).write_text("user file", encoding="utf-8")
    controller._cleanup_full(output)
    assert (output / ".stride-notes.md").is_file()
    assert (output / ".merge-notes.md").is_file()


def test_rebuild_cleanup_does_not_delete_prefix_lookalikes(monkeypatch, tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    for name in ("threat-model-notes.txt", ".stride-notes.md", ".merge-notes.md"):
        (output / name).write_text("user file", encoding="utf-8")
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())
    controller._cleanup_rebuild(output)
    assert (output / "threat-model-notes.txt").is_file()
    assert (output / ".stride-notes.md").is_file()
    assert (output / ".merge-notes.md").is_file()


def test_rebuild_cleanup_preserves_current_config_and_removes_context_state(monkeypatch, tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    config = output / ".skill-config.json"
    config.write_text('{"runtime_generation":"context-v2"}', encoding="utf-8")
    for name in (".dispatch-context", ".merge-context"):
        directory = output / name
        directory.mkdir()
        (directory / "stale.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())

    removed = controller._cleanup_rebuild(output)

    assert config.read_text(encoding="utf-8") == '{"runtime_generation":"context-v2"}'
    assert ".dispatch-context/" in removed
    assert ".merge-context/" in removed
    assert not (output / ".dispatch-context").exists()
    assert not (output / ".merge-context").exists()


def test_cleanup_unlinks_runtime_directory_symlink_without_following(tmp_path):
    output = tmp_path / "out"
    outside = tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    (output / ".fragments").symlink_to(outside, target_is_directory=True)
    controller._cleanup_full(output)
    assert not (output / ".fragments").exists()
    assert (outside / "keep.txt").read_text() == "keep"


def test_persist_config_replaces_file_symlink_without_following(tmp_path):
    output = tmp_path / "out"
    outside = tmp_path / "outside.json"
    output.mkdir()
    outside.write_text('{"owner":"user"}', encoding="utf-8")
    (output / ".skill-config.json").symlink_to(outside)
    controller._persist_config(_cfg(tmp_path), output)
    assert not (output / ".skill-config.json").is_symlink()
    assert outside.read_text(encoding="utf-8") == '{"owner":"user"}'


def test_rebuild_archive_failure_aborts_before_deletion(monkeypatch, tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "threat-model.md").write_text("# report", encoding="utf-8")
    (output / "threat-model-changelog.md").write_text("# audit", encoding="utf-8")

    def fail_archive(*args, **kwargs):
        raise controller.ControllerError("archive failed")

    monkeypatch.setattr(controller, "_run_script", fail_archive)
    with pytest.raises(controller.ControllerError):
        controller._cleanup_rebuild(output)
    assert (output / "threat-model.md").is_file()
    assert (output / "threat-model-changelog.md").is_file()


def _name_patterns(path: Path, start: str, end: str) -> set[str]:
    text = path.read_text(encoding="utf-8")
    block = text[text.index(start) : text.index(end, text.index(start))]
    return set(re.findall(r'-name "([^"]+)"', block))


def test_full_cleanup_contract_matches_legacy_skill():
    patterns = _name_patterns(
        ROOT / "skills" / "create-threat-model" / "SKILL-impl.md",
        "### Full-run Pre-flight Intermediate Wipe",
        "### Skill-layer lock acquisition",
    )
    assert patterns == (controller._FULL_INTERMEDIATE_NAMES | set(controller._FULL_INTERMEDIATE_GLOBS))


def test_rebuild_cleanup_contract_matches_legacy_mode_file():
    patterns = _name_patterns(
        ROOT / "skills" / "create-threat-model" / "modes" / "rebuild-wipe.md",
        "# Rebuild Pre-flight Wipe",
        "The single-call form",
    )
    assert patterns == controller._REBUILD_NAMES | set(controller._REBUILD_GLOBS)
    assert ".skill-config.json" not in patterns


def test_rebuild_mode_archive_is_fail_closed():
    text = (ROOT / "skills" / "create-threat-model" / "modes" / "rebuild-wipe.md").read_text(encoding="utf-8")
    assert "if ! python3" in text
    assert "rebuild aborted before deletion" in text
    assert "render_changelog_audit.py" in text


def test_prepasses_restore_canonical_audit_events(monkeypatch, tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["output_dir"] = str(output)
    (output / ".route-inventory.json").write_text(
        json.dumps({"routes": [{"path": "/a"}, {"path": "/b"}]}),
        encoding="utf-8",
    )
    (output / ".source-auth-findings.json").write_text(
        json.dumps({"violations": 3}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        controller,
        "_run_script",
        lambda *args, **kwargs: _completed(),
    )
    receipts: list[str] = []
    controller._prepasses(cfg, receipts)
    log = (output / ".agent-run.log").read_text(encoding="utf-8")
    assert "skill-controller" in log
    assert "ROUTE_INVENTORY_PREPASS" in log
    assert ".route-inventory.json ready (2 routes)" in log
    assert "SOURCE_AUTH_PREPASS" in log
    assert "(3 authz finding(s))" in log
    assert len(receipts) == 3


def test_prepasses_run_database_separation_only_at_thorough_depth(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path)
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(
        controller,
        "_run_script",
        lambda name, args, **kwargs: (calls.append((name, args)) or _completed()),
    )
    controller._prepasses(cfg, [])
    assert "database_privilege_separation.py" not in [name for name, _ in calls]

    calls.clear()
    cfg["assessment_depth"] = "thorough"
    controller._prepasses(cfg, [])
    assert [name for name, _ in calls][:2] == ["route_inventory.py", "database_privilege_separation.py"]
    architecture_args = next(args for name, args in calls if name == "architecture_coverage_checks.py")
    assert architecture_args[-2:] == ["--assessment-depth", "thorough"]


def test_session_context_advisory_is_session_scoped(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "12345678-full")
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (tmp_path / ".hook-events.log").write_text(
        f"{old}  [other999]  INFO   SESSION_STOP  cache_read=99,000,000\n"
        f"{old}  [12345678]  INFO   SESSION_STOP  cache_read=8,500,000\n",
        encoding="utf-8",
    )
    advisory = controller._session_context_advisory(tmp_path)
    assert "8.5M cumulative cache-read" in advisory
    assert "throughput, not resident occupancy" in advisory
    assert "99" not in advisory


def test_session_context_advisory_labels_nonempty_session(monkeypatch, tmp_path):
    monkeypatch.setenv("CLAUDE_CODE_SESSION_ID", "12345678")
    old = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (tmp_path / ".hook-events.log").write_text(
        f"{old}  [12345678]  INFO   TOOL_END  ok\n",
        encoding="utf-8",
    )
    advisory = controller._session_context_advisory(tmp_path)
    assert "non-empty session signal: 1 prior event(s)" in advisory


def test_validator_advisory_reports_missing_dependencies(monkeypatch, tmp_path):
    monkeypatch.setattr(controller, "SCRIPT_DIR", tmp_path)
    monkeypatch.setattr(controller.shutil, "which", lambda name: None)
    real_is_file = Path.is_file

    def scoped_is_file(path):
        if str(path).startswith(("/usr/lib/node_modules", "/usr/local/lib/node_modules")):
            return False
        return real_is_file(path)

    monkeypatch.setattr(Path, "is_file", scoped_is_file)
    advisory = controller._validator_advisory()
    assert "jsdom" in advisory
    assert "mermaid" in advisory
    assert "@mermaid-js/mermaid-cli" in advisory
    assert "regex-only fallback" in advisory


def test_validator_advisory_honours_skip_env(monkeypatch):
    monkeypatch.setenv("APPSEC_SKIP_VALIDATOR_CHECK", "1")
    assert controller._validator_advisory() == ""


def test_lock_failure_happens_before_intermediate_cleanup(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path)
    output = Path(cfg["output_dir"])
    output.mkdir(parents=True)
    (output / ".stride-api.json").write_text("active run", encoding="utf-8")
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)

    def fail_lock(name, args, **kwargs):
        if name == "acquire_lock.py":
            raise controller.ControllerError("LOCK_BLOCKED", 3)
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fail_lock)
    with pytest.raises(controller.ControllerError):
        controller.prepare(["--full"])
    assert (output / ".stride-api.json").read_text() == "active run"


def test_next_action_rehydrates_from_filesystem(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")

    stage1 = controller.next_action(output)
    assert stage1["stage"] == "stage1"
    assert stage1["instruction_file"] == str(controller.THIN_STAGE1_RUNTIME)
    (output / "threat-model.yaml").write_text("meta: {}\n")
    stage2 = controller.next_action(output)
    assert stage2["stage"] == "stage2"
    assert stage2["instruction_file"] == str(controller.THIN_STAGE2_RUNTIME)
    (output / "threat-model.md").write_text("# report\n")
    (output / ".compose-blocked.json").write_text('{"step":"compose"}')
    assert controller.next_action(output)["stage"] == "stage3"
    assert not (output / ".compose-blocked.json").exists()
    (output / ".qa-status.json").write_text("{}")
    (output / ".appsec-checkpoint").write_text("phase=11 status=writing_output\n")
    assert controller.next_action(output)["action"] == "complete"
    assert not (output / ".appsec-checkpoint").exists()


def test_post_stage1_runs_compact_deterministic_gate_sequence(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    for name in (".recon-summary.md", ".threats-merged.json", ".triage-flags.json", "threat-model.yaml"):
        (output / name).write_text("{}", encoding="utf-8")
    (output / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true\n",
        encoding="utf-8",
    )

    scripts = []
    external = []

    def fake_script(name, args, **kwargs):
        scripts.append(name)
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_run_external", lambda command, **kwargs: external.append(command) or _completed())
    monkeypatch.setattr(controller, "_upgrade_bootstrap_yaml", lambda output_dir, config: True)

    action = controller.post_stage1(output)
    assert action["action"] == "run_gate"
    assert action["stage"] == "stage1"
    assert scripts == [
        "check_stride_dispatch.py",
        "enforce_yaml_invariants.py",
        "validate_intermediate.py",
        "triage_compute_ranking.py",
        "validate_mitigation_quality.py",
        "assert_completeness.py",
    ]
    assert external and external[0][0] == "bash"
    assert external[0][1].endswith("auto_emitter_pass.sh")


def test_post_stage1_fails_closed_on_missing_artifact(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    with pytest.raises(controller.ControllerError, match="required artifacts"):
        controller.post_stage1(output)


def test_post_stage1_rejects_stale_yaml_without_completion_checkpoint(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    for name in (".recon-summary.md", ".threats-merged.json", ".triage-flags.json", "threat-model.yaml"):
        (output / name).write_text("{}", encoding="utf-8")

    with pytest.raises(controller.ControllerError, match="completion checkpoint"):
        controller.post_stage1(output)


def test_stage1a_to_stage1b_controller_handoff_and_promotion(tmp_path):
    repo = tmp_path / "repo"
    output = tmp_path / "out"
    repo.mkdir()
    (repo / "src").mkdir()
    (repo / "src" / "api.py").write_text("value = 1\n", encoding="utf-8")
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    (output / ".recon-summary.md").write_text("# Recon\n", encoding="utf-8")
    (output / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [
                    {
                        "id": "api",
                        "name": "API",
                        "description": "Internet-facing API",
                        "paths": ["src/**"],
                        "tier": "application",
                        "deployment_zones": ["internet"],
                        "handles_sensitive_data": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    controller._run_script(
        "finalize_component_inventory.py",
        ["--repo-root", str(repo), "--output-dir", str(output)],
    )
    receipt_path = output / ".component-inventory-finalization.json"
    receipt_before = receipt_path.read_bytes()
    receipt = json.loads(receipt_before)
    (output / ".data-flows.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "component_inventory_fingerprint": receipt["component_inventory_fingerprint"],
                "data_flows": [
                    {
                        "id": "df-001",
                        "from": "external",
                        "to": "api",
                        "label": "HTTPS ingress",
                        "protocol": "HTTPS",
                        "data_classification": "Confidential",
                        "direction": "request-response",
                        "evidence": [],
                        "provenance": "architecture",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (output / ".assets.json").write_text(json.dumps({"schema_version": 1, "assets": []}), encoding="utf-8")
    (output / ".attack-surface-overrides.json").write_text(
        json.dumps({"schema_version": 1, "curations": {}, "additions": []}),
        encoding="utf-8",
    )
    (output / ".appsec-checkpoint").write_text(
        "phase=6 status=completed need_boundary_assessment=true\n",
        encoding="utf-8",
    )

    stage1a = controller.post_stage1a(output)
    assert stage1a["action"] == "dispatch_agent"
    assert stage1a["stage"] == "stage1b"
    assert stage1a["instruction_file"] == str(controller.THIN_STAGE1B_RUNTIME)
    assert receipt_path.read_bytes() == receipt_before

    assessment = json.loads((output / ".trust-boundary-assessment-input.json").read_text(encoding="utf-8"))
    signal_id = assessment["signals"][0]["id"]
    (output / ".trust-boundary-candidates.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "component_inventory_fingerprint": assessment["component_inventory_fingerprint"],
                "assessment_input_fingerprint": assessment["assessment_input_fingerprint"],
                "candidates": [
                    {
                        "candidate_key": "candidate-api-ingress",
                        "name": "Internet to API",
                        "from": "external",
                        "to": "api",
                        "kind": "network",
                        "assumption": "The API authenticates and authorizes protected operations.",
                        "evidence": [],
                        "confidence": "inferred",
                        "covered_signal_ids": [signal_id],
                        "covered_flow_ids": ["df-001"],
                    }
                ],
                "dispositions": [
                    {
                        "signal_id": signal_id,
                        "disposition": "boundary",
                        "candidate_keys": ["candidate-api-ingress"],
                        "rationale": "An external client crosses into the API enforcement domain.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    stage1b = controller.finalize_stage1b(output)
    assert stage1b["action"] == "run_gate"
    assert stage1b["stage"] == "stage1b"
    assert (output / ".appsec-checkpoint").read_text(encoding="utf-8") == (
        "phase=7 status=completed need_threat_analysis=true\n"
    )
    coverage = json.loads((output / ".trust-boundary-coverage.json").read_text(encoding="utf-8"))
    assert coverage["status"] == "pass"
    assert coverage["signals"][0]["boundary_ids"] == ["tb-1"]


def test_stage1a_budget_exhaustion_preserves_input_and_blocks_stage1b(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    for name in (
        ".recon-summary.md",
        ".components.json",
        ".component-inventory-finalization.json",
        ".data-flows.json",
        ".assets.json",
        ".attack-surface-overrides.json",
    ):
        (output / name).write_text("{}", encoding="utf-8")
    (output / ".appsec-checkpoint").write_text(
        "phase=6 status=completed need_boundary_assessment=true\n",
        encoding="utf-8",
    )
    (output / ".budget-critical").write_text("{}", encoding="utf-8")

    def fake_script(name, args, **kwargs):
        if name == "build_trust_boundary_assessment_input.py":
            (output / ".trust-boundary-assessment-input.json").write_text("{}", encoding="utf-8")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    with pytest.raises(controller.ControllerError, match="preserved for --resume"):
        controller.post_stage1a(output)

    assert (output / ".trust-boundary-assessment-input.json").is_file()
    assert (output / ".appsec-checkpoint").read_text(encoding="utf-8") == (
        "phase=7 status=aborted reason=budget-critical-before-boundary\n"
    )


def test_context_v2_budget_abort_does_not_recommend_resume():
    reason = controller._boundary_budget_abort_reason({"runtime_generation": "context-v2"})

    assert "cannot resume" in reason
    assert "fresh full or rebuild" in reason


def test_prepare_abuse_returns_bounded_parallel_action(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["skip_abuse_case_verification"] = False
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")

    def fake_script(name, args, **kwargs):
        if "list-candidates" in args:
            return _completed("AC-T-001\nAC-T-002\ninvalid/id\n")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.prepare_abuse(output)
    assert action["action"] == "dispatch_parallel"
    assert action["stage"] == "stage1d"
    assert action["instruction_file"] == str(controller.THIN_STAGE1D_RUNTIME)
    assert action["candidates"] == ["AC-T-001", "AC-T-002"]
    controller._validate_action(action)


def test_context_v2_prepare_abuse_dispatches_receipted_candidate_projections(tmp_path, monkeypatch, capsys):
    output = _write_context_v2_config(tmp_path, skip_abuse_case_verification=False)
    case = {
        "id": "AC-T-001",
        "title": "Stored script to token theft",
        "source": "mandatory",
        "attacker": {"actor_id": "anonymous", "initial_access": "unauthenticated"},
        "goal": "Steal an authenticated session.",
        "chain": [
            {
                "step": 1,
                "label": "Inject script",
                "grants": "script execution",
                "required": True,
                "probe": {"sink_patterns": ["innerHTML"]},
            }
        ],
    }
    match_row = {
        "abuse_case_id": "AC-T-001",
        "title": case["title"],
        "source": "mandatory",
        "structural_verdict": "candidate",
        "reason": None,
        "matched_finding_ids": ["T-001"],
        "step_matches": [
            {
                "step": 1,
                "label": "Inject script",
                "required": True,
                "grants": "script execution",
                "requires": None,
                "matched": True,
                "matched_finding_id": "T-001",
                "evidence": {"file": "routes/feedback.ts", "line": 12},
                "match_basis": "finding",
                "controls_found": [],
            }
        ],
        "case": case,
    }

    def fake_script(name, args, **kwargs):
        if name == "match_abuse_cases.py" and "match" in args:
            (output / ".abuse-case-matches.json").write_text(
                json.dumps({"schema_version": 1, "matches": [match_row]}), encoding="utf-8"
            )
        if name == "match_abuse_cases.py" and "list-candidates" in args:
            return _completed("AC-T-001\n")
        if name == "build_abuse_case_contexts.py":
            abuse_contexts.write_candidate(output, "AC-T-001")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.prepare_abuse(output)

    assert action["semantic_role"] == "abuse_case_verifier"
    assert action["dispatch_jobs"][0]["candidate_id"] == "AC-T-001"
    assert action["dispatch_jobs"][0]["input_artifacts"] == [".dispatch-context/abuse-cases/AC-T-001.json"]
    assert action["artifact_receipts"][0]["validation_status"] == "valid"
    assert controller._emit(action) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["context_plan"]["receipt_sha256"]
    assert emitted["dispatch_jobs"][0]["context_delivery_ids"]

    projection_path = output / ".dispatch-context/abuse-cases/AC-T-001.json"
    projection = json.loads(projection_path.read_text(encoding="utf-8"))
    projection["limits"]["source_chars"] = 1
    _rewrite_projection_with_current_size(projection_path, projection)
    with pytest.raises(controller.ControllerError, match="differs from its deterministic projection"):
        controller._context_v2_abuse_candidate_receipt(output, "AC-T-001", tmp_path / "repo")


def test_prepare_abuse_carries_candidate_titles_for_dispatch_labels(tmp_path, monkeypatch):
    """Without titles the verifier fan-out is a column of bare AC-ids in the
    agent list. Titles are advisory: an id with none stays unlabelled rather
    than blocking the dispatch."""
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["skip_abuse_case_verification"] = False
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    long_title = "Account takeover through " + "chained password reset " * 4
    (output / ".abuse-case-matches.json").write_text(
        json.dumps(
            {
                "matches": [
                    {"abuse_case_id": "AC-T-001", "title": "Stored XSS to admin session theft"},
                    {"abuse_case_id": "AC-T-002", "title": long_title},
                    {"abuse_case_id": "AC-T-003", "title": "not a candidate"},
                ]
            }
        ),
        encoding="utf-8",
    )

    def fake_script(name, args, **kwargs):
        if "list-candidates" in args:
            return _completed("AC-T-001\nAC-T-002\n")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.prepare_abuse(output)
    titles = action["candidate_titles"]
    assert titles["AC-T-001"] == "Stored XSS to admin session theft"
    assert len(titles["AC-T-002"]) <= 60 and titles["AC-T-002"].endswith("…")
    assert "AC-T-003" not in titles  # not dispatched → not labelled
    controller._validate_action(action)


def test_prepare_abuse_titles_absent_without_matcher_sidecar(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["skip_abuse_case_verification"] = False
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")

    def fake_script(name, args, **kwargs):
        return _completed("AC-T-001\n" if "list-candidates" in args else "")

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.prepare_abuse(output)
    assert action["candidate_titles"] == {}
    controller._validate_action(action)


def test_prepare_abuse_rejects_candidate_overflow_instead_of_truncating(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["skip_abuse_case_verification"] = False
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    candidates = "\n".join(f"AC-{index:03d}" for index in range(65))

    def fake_script(name, args, **kwargs):
        return _completed(candidates if "list-candidates" in args else "")

    monkeypatch.setattr(controller, "_run_script", fake_script)
    with pytest.raises(controller.ControllerError, match="maximum is 64"):
        controller.prepare_abuse(output)


def _abuse_output(tmp_path: Path) -> Path:
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["skip_abuse_case_verification"] = False
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return output


def _verdict(output: Path, ac_id: str, steps: list[dict]) -> None:
    (output / f".abuse-case-verdict-{ac_id}.json").write_text(
        json.dumps({"abuse_case_id": ac_id, "step_verdicts": steps}),
        encoding="utf-8",
    )


def test_prepare_abuse_never_redispatches_a_finalized_verdict(tmp_path, monkeypatch):
    # A second verifier for the same AC-ID overwrites the finished verdict file
    # with its write-first pre-seed; a cut-off re-run then reports the chain as
    # inconclusive. Finalized candidates must drop out of the fan-out.
    output = _abuse_output(tmp_path)
    _verdict(output, "AC-T-001", [{"step": 1, "verdict": "confirmed", "reason": "sink reachable"}])
    _verdict(output, "AC-T-002", [{"step": 1, "verdict": "inconclusive"}])

    def fake_script(name, args, **kwargs):
        return _completed("AC-T-001\nAC-T-002\n" if "list-candidates" in args else "")

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.prepare_abuse(output)
    assert action["action"] == "dispatch_parallel"
    assert action["candidates"] == ["AC-T-002"]
    assert any("already verified" in receipt for receipt in action["receipts"])
    controller._validate_action(action)


def test_prepare_abuse_skips_fan_out_when_every_candidate_is_verified(tmp_path, monkeypatch):
    output = _abuse_output(tmp_path)
    _verdict(output, "AC-T-001", [{"step": 1, "verdict": "confirmed", "reason": "sink reachable"}])

    def fake_script(name, args, **kwargs):
        return _completed("AC-T-001\n" if "list-candidates" in args else "")

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.prepare_abuse(output)
    assert action["action"] == "run_gate"
    assert action["candidates"] == []
    controller._validate_action(action)


def test_prepare_abuse_still_dispatches_a_partially_finalized_verdict(tmp_path, monkeypatch):
    output = _abuse_output(tmp_path)
    _verdict(
        output,
        "AC-T-001",
        [
            {"step": 1, "verdict": "confirmed", "reason": "sink reachable"},
            {"step": 2, "verdict": "inconclusive", "evidence": {"excerpt": ""}},
        ],
    )

    def fake_script(name, args, **kwargs):
        return _completed("AC-T-001\n" if "list-candidates" in args else "")

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.prepare_abuse(output)
    assert action["candidates"] == ["AC-T-001"]


def test_finalize_abuse_aborts_when_yaml_rebuild_fails_schema_validation(tmp_path, monkeypatch):
    # build_threat_model_yaml.py writes the yaml BEFORE validating it, so exit 5
    # leaves an invalid model on disk — it must not degrade to a receipt.
    output = _abuse_output(tmp_path)
    (output / ".abuse-case-verdicts.json").write_text("{}", encoding="utf-8")

    def fake_script(name, args, **kwargs):
        if name == "build_threat_model_yaml.py":
            raise controller.ControllerError(
                "build_threat_model_yaml.py failed with exit 5: FATAL: schema validation failed\n"
                "INVALID: threats[3].cvss.scope\nINVALID: mitigations[7].priority",
                5,
            )
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    with pytest.raises(controller.ControllerError) as excinfo:
        controller.finalize_abuse(output)
    assert excinfo.value.exit_code == 5
    reason = str(excinfo.value)
    assert "must not reach Stage 2" in reason
    assert "INVALID: threats[3].cvss.scope" in reason
    assert len(reason) <= 1000  # fits the action-manifest `reason` cap


def test_finalize_abuse_tolerates_a_soft_yaml_rebuild_failure(tmp_path, monkeypatch):
    # Exit 3 (missing intermediate) aborts before the write, so the prior yaml
    # is intact — that failure stays best-effort.
    output = _abuse_output(tmp_path)
    (output / ".abuse-case-verdicts.json").write_text("{}", encoding="utf-8")

    def fake_script(name, args, **kwargs):
        if name == "build_threat_model_yaml.py":
            raise controller.ControllerError(
                "build_threat_model_yaml.py failed with exit 3: FATAL: required intermediate missing",
                3,
            )
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.finalize_abuse(output)
    assert action["action"] == "run_gate"
    assert "build_threat_model_yaml.py: best-effort failure" in action["receipts"]
    controller._validate_action(action)


def test_prepare_stage2_selects_compact_parallel_runtime(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["enrich_arch_fragments"] = True
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.delenv("APPSEC_PARALLEL_RENDER", raising=False)
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())

    action = controller.prepare_stage2(output)
    assert action["action"] == "dispatch_parallel"
    assert action["instruction_file"] == str(controller.THIN_STAGE2_RUNTIME)
    controller._validate_action(action)


def test_prepare_stage2_retry_uses_single_renderer(tmp_path, monkeypatch):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["enrich_arch_fragments"] = True
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    (output / ".inline-shortcut-retry-count").write_text("1\n", encoding="utf-8")
    monkeypatch.delenv("APPSEC_PARALLEL_RENDER", raising=False)
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())

    action = controller.prepare_stage2(output)
    assert action["action"] == "dispatch_agent"
    assert action["instruction_file"] == str(controller.THIN_STAGE2_RUNTIME)
    controller._validate_action(action)


def test_compose_if_ready_requires_llm_fragments(tmp_path):
    """No render fragments on disk → cannot compose, caller must dispatch Stage 2."""
    output = tmp_path / "out"
    (output / ".fragments").mkdir(parents=True)
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    assert controller._compose_if_ready(output, "") is False


def test_next_action_composes_report_when_fragments_ready(tmp_path, monkeypatch):
    """The deterministic backstop: yaml + render fragments present but no .md →
    next_action composes the report itself (no Stage-2 re-dispatch), then routes
    to QA. Closes the 2026-07-02 thin-runtime gap (fragments authored, compose
    never ran)."""
    output = tmp_path / "out"
    frag = output / ".fragments"
    frag.mkdir(parents=True)
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    # The LLM-authored fragments the renderer would have produced.
    (frag / "ms-verdict.json").write_text("{}", encoding="utf-8")
    (frag / "security-architecture.md").write_text("## 6. Security Architecture\n", encoding="utf-8")

    md = output / "threat-model.md"
    commands = []

    def fake_run(cmd, **kwargs):
        # Simulate compose_threat_model.py writing the report; all steps succeed.
        commands.append(cmd)
        if any("compose_threat_model.py" in str(c) for c in cmd):
            md.write_text("# Threat Model\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(controller.subprocess, "run", fake_run)

    action = controller.next_action(output)
    assert md.is_file()  # composed deterministically
    assert action["stage"] == "stage3"  # routed to QA, NOT re-dispatched as stage2
    rendered_scripts = " ".join(" ".join(map(str, cmd)) for cmd in commands)
    assert "emit_general_mitigation_titles.py" in rendered_scripts
    assert "hydrate_mitigation_details.py" in rendered_scripts
    assert "validate_mitigation_quality.py" in rendered_scripts
    checkpoint = (output / ".appsec-checkpoint").read_text(encoding="utf-8")
    assert "phase=11 status=completed" in checkpoint


def test_next_action_recomposes_stale_report_when_checkpoint_needs_render(tmp_path, monkeypatch):
    output = tmp_path / "out"
    frag = output / ".fragments"
    frag.mkdir(parents=True)
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    (output / "threat-model.md").write_text("# stale report\n", encoding="utf-8")
    (output / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true\n",
        encoding="utf-8",
    )
    (frag / "ms-verdict.json").write_text("{}", encoding="utf-8")
    (frag / "security-architecture.md").write_text("## 7\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        if any("compose_threat_model.py" in str(item) for item in cmd):
            (output / "threat-model.md").write_text("# fresh report\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(controller.subprocess, "run", fake_run)

    action = controller.next_action(output)
    assert action["stage"] == "stage3"
    assert (output / "threat-model.md").read_text(encoding="utf-8") == "# fresh report\n"
    assert "phase=11 status=completed" in (output / ".appsec-checkpoint").read_text(encoding="utf-8")


def test_next_action_caps_stage2_fragment_retries(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")

    first = controller.next_action(output)
    second = controller.next_action(output)
    assert first["receipts"] == ["Stage-2 render fragments incomplete; retry 1/2"]
    assert second["receipts"] == ["Stage-2 render fragments incomplete; retry 2/2"]
    with pytest.raises(controller.ControllerError, match="after two retries"):
        controller.next_action(output)


def test_next_action_falls_back_to_stage2_when_compose_fails(tmp_path, monkeypatch):
    """If the deterministic compose cannot produce the .md, fall back to a
    Stage-2 agent dispatch (no regression vs. the pre-backstop behaviour)."""
    output = tmp_path / "out"
    frag = output / ".fragments"
    frag.mkdir(parents=True)
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)), encoding="utf-8")
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    (frag / "ms-verdict.json").write_text("{}", encoding="utf-8")
    (frag / "security-architecture.md").write_text("## 7\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, "", "boom")  # compose fails

    monkeypatch.setattr(controller.subprocess, "run", fake_run)

    action = controller.next_action(output)
    assert not (output / "threat-model.md").is_file()
    assert action["stage"] == "stage2"


def test_next_action_stamps_slug_deliverables_on_complete(tmp_path):
    """The deterministic slug-stamp backstop: a completed run whose config
    carries a non-null slug gets the postfix-stamped copy set produced by the
    `next` gate itself — no reliance on the trailing LLM-driven skill block that
    a compaction-resumed orchestrator can skip (2026-07-15 juice-shop)."""
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["slug"] = "juice-shop-standard-v0.5"
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    (output / "threat-model.md").write_text("# report\n", encoding="utf-8")
    (output / ".qa-status.json").write_text("{}", encoding="utf-8")

    action = controller.next_action(output)

    assert action["action"] == "complete"
    assert (output / "threat-model-juice-shop-standard-v0.5.md").is_file()
    assert (output / "threat-model-juice-shop-standard-v0.5.yaml").is_file()


def test_next_action_no_stamp_without_slug(tmp_path):
    """No slug configured → the `next` gate produces no stamped copies."""
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)  # no "slug" key
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
    (output / "threat-model.md").write_text("# report\n", encoding="utf-8")
    (output / ".qa-status.json").write_text("{}", encoding="utf-8")

    action = controller.next_action(output)

    assert action["action"] == "complete"
    assert not list(output.glob("threat-model-*.md"))


def test_stamp_if_configured_is_idempotent_for_current_report(tmp_path, monkeypatch):
    """A second `next` call at complete does not re-run the stamp when the
    stamped copy already reflects the current (unchanged) canonical report."""
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["slug"] = "s1"
    (output / "threat-model.md").write_text("# report\n", encoding="utf-8")
    (output / "threat-model-s1.md").write_text("# report\n", encoding="utf-8")

    calls = []
    real_run = controller.subprocess.run

    def counting_run(cmd, **kwargs):
        calls.append(cmd)
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(controller.subprocess, "run", counting_run)
    controller._stamp_if_configured(output, cfg)
    assert calls == []  # stamped copy already up to date → no subprocess


def test_action_schema_rejects_executable_command_field():
    with pytest.raises(controller.ControllerError):
        controller._validate_action(
            {
                "schema_version": 1,
                "action": "run_gate",
                "command": "rm -rf /",
            }
        )


def test_action_schema_requires_dispatch_contract_fields():
    with pytest.raises(controller.ControllerError):
        controller._validate_action(
            {
                "schema_version": 1,
                "action": "dispatch_agent",
                "mode": "full",
                "stage": "stage1",
            }
        )


def test_action_schema_rejects_unknown_dispatch_value():
    with pytest.raises(controller.ControllerError):
        controller._validate_action(
            {
                "schema_version": 1,
                "action": "dispatch_agent",
                "mode": "full",
                "stage": "stage1",
                "instruction_file": str(controller.LEGACY_RUNTIME),
                "config_path": "/tmp/.skill-config.json",
                "dispatch_values": {"shell_command": "rm -rf /"},
            }
        )


def test_action_schema_dispatch_keys_match_controller():
    schema = json.loads(controller.ACTION_SCHEMA.read_text(encoding="utf-8"))
    schema_keys = set(schema["properties"]["dispatch_values"]["propertyNames"]["enum"])
    controller_keys = set(controller._DISPATCH_KEYS) | set(controller._DISPATCH_EXTRA_KEYS)
    assert schema_keys == controller_keys


def _semantic_action(tmp_path: Path, jobs: list[dict]) -> dict:
    return {
        "schema_version": 1,
        "action": "dispatch_parallel",
        "mode": "full",
        "stage": "stage1",
        "instruction_file": str(controller.THIN_STAGE1_RUNTIME),
        "config_path": str(tmp_path / ".skill-config.json"),
        "dispatch_values": {"output_dir": str(tmp_path)},
        "dispatch_jobs": jobs,
    }


def _semantic_job(job_id: str = "architecture", component_id: str | None = None) -> dict:
    job = {
        "schema_version": 1,
        "job_id": job_id,
        "semantic_role": "architecture_analyst",
        "agent_type": "appsec-advisor:appsec-architecture-analyst",
        "model": "sonnet",
        "input_artifacts": [".recon-summary.md"],
        "output_artifacts": [".components.json"],
        "unresolved_decision_keys": [],
    }
    if component_id is not None:
        job["component_id"] = component_id
    return job


def test_action_semantics_accept_plugin_owned_role_dispatch(tmp_path):
    action = _semantic_action(tmp_path, [_semantic_job()])
    assert controller._validate_action(action) == action


def test_semantic_role_registry_is_closed_and_plugin_owned():
    schema = json.loads(controller.ACTION_SCHEMA.read_text(encoding="utf-8"))
    assert set(schema["$defs"]["semantic_role"]["enum"]) == set(controller.SEMANTIC_ROLE_REGISTRY)
    agent_enum = set(schema["$defs"]["dispatch_job"]["properties"]["agent_type"]["enum"])
    assert agent_enum == {f"appsec-advisor:{record['agent']}" for record in controller.SEMANTIC_ROLE_REGISTRY.values()}
    for role, record in controller.SEMANTIC_ROLE_REGISTRY.items():
        instruction = record["instruction"].resolve()
        assert instruction.is_relative_to(controller.PLUGIN_ROOT)
        assert instruction.is_file(), role
        assert "Agent" not in record["tools"], role
        for contract in record["output_contracts"]:
            assert contract.startswith("contract:") or (controller.PLUGIN_ROOT / contract).is_file(), (
                role,
                contract,
            )


def test_action_semantics_reject_agent_type_that_does_not_match_role(tmp_path):
    job = _semantic_job()
    job["agent_type"] = "appsec-advisor:appsec-control-analyst"
    with pytest.raises(controller.ControllerError, match="does not match semantic role"):
        controller._validate_action(_semantic_action(tmp_path, [job]))


def test_action_semantics_reject_model_that_does_not_match_role_routing(tmp_path):
    job = _semantic_job()
    job["model"] = "opus"
    with pytest.raises(controller.ControllerError, match="model does not match semantic role"):
        controller._validate_action(_semantic_action(tmp_path, [job]))


def test_action_semantics_reject_top_level_role_that_differs_from_jobs(tmp_path):
    action = _semantic_action(tmp_path, [_semantic_job()])
    action["semantic_role"] = "control_analyst"
    with pytest.raises(controller.ControllerError, match="does not match its dispatch job role"):
        controller._validate_action(action)


def test_action_rejects_component_repository_projection_for_non_stride_role(tmp_path):
    job = _semantic_job()
    job["repository_projection_path"] = ".dispatch-context/api/repository-roots.json"
    job["repository_projection_sha256"] = "0" * 64
    job["input_artifacts"].append(job["repository_projection_path"])
    action = _semantic_action(tmp_path, [job])

    with pytest.raises(controller.ControllerError, match="internal action-manifest validation failed"):
        controller._validate_action(action)
    with pytest.raises(controller.ControllerError, match="valid only for stride analyzer jobs"):
        controller._validate_action_semantics(action)


def test_action_rejects_component_security_projection_for_non_stride_role(tmp_path):
    job = _semantic_job()
    job["security_context_projections"] = [
        {
            "context_id": "controls.component_context",
            "artifact_path": ".dispatch-context/api/controls-context.json",
            "sha256": "0" * 64,
        }
    ]
    job["input_artifacts"].append(".dispatch-context/api/controls-context.json")
    action = _semantic_action(tmp_path, [job])

    with pytest.raises(controller.ControllerError, match="internal action-manifest validation failed"):
        controller._validate_action(action)
    with pytest.raises(controller.ControllerError, match="valid only for stride analyzer jobs"):
        controller._validate_action_semantics(action)


def test_action_semantics_reject_repository_selected_instruction(tmp_path):
    instruction = tmp_path / "agent.md"
    instruction.write_text("untrusted", encoding="utf-8")
    action = _semantic_action(tmp_path, [_semantic_job()])
    action["instruction_file"] = str(instruction)
    with pytest.raises(controller.ControllerError, match="not plugin-owned"):
        controller._validate_action(action)


def test_action_semantics_reject_duplicate_job_ids(tmp_path):
    action = _semantic_action(tmp_path, [_semantic_job(), _semantic_job()])
    with pytest.raises(controller.ControllerError, match="duplicate dispatch job id"):
        controller._validate_action(action)


def test_action_semantics_reject_duplicate_component_ids(tmp_path):
    jobs = [_semantic_job("job-a", "api"), _semantic_job("job-b", "api")]
    with pytest.raises(controller.ControllerError, match="duplicate dispatch component id"):
        controller._validate_action(_semantic_action(tmp_path, jobs))


def test_action_semantics_reject_duplicate_output_owners(tmp_path):
    jobs = [_semantic_job("job-a"), _semantic_job("job-b")]
    with pytest.raises(controller.ControllerError, match="duplicate dispatch output artifact"):
        controller._validate_action(_semantic_action(tmp_path, jobs))


def test_action_semantics_reject_parallel_read_write_collision(tmp_path):
    jobs = [_semantic_job("writer")]
    reader = _semantic_job("reader")
    reader["input_artifacts"] = [".components.json"]
    reader["output_artifacts"] = [".assets.json"]
    jobs.append(reader)
    with pytest.raises(controller.ControllerError, match="parallel dispatch cannot read and write"):
        controller._validate_action(_semantic_action(tmp_path, jobs))


def test_action_schema_rejects_empty_dispatch_wave(tmp_path):
    with pytest.raises(controller.ControllerError, match="should be non-empty"):
        controller._validate_action(_semantic_action(tmp_path, []))


@pytest.mark.parametrize("artifact", ["../outside.json", "/tmp/outside.json", "a\\outside.json"])
def test_action_semantics_reject_unsafe_artifact_paths(tmp_path, artifact):
    job = _semantic_job()
    job["output_artifacts"] = [artifact]
    with pytest.raises(controller.ControllerError):
        controller._validate_action(_semantic_action(tmp_path, [job]))


def test_action_semantics_reject_symlink_escape(tmp_path):
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    job = _semantic_job()
    job["output_artifacts"] = ["linked/result.json"]
    with pytest.raises(controller.ControllerError, match="escapes output directory"):
        controller._validate_action(_semantic_action(tmp_path, [job]))


def test_action_semantics_reject_oversized_canonical_action(tmp_path):
    action = _semantic_action(tmp_path, [_semantic_job()])
    action["dispatch_values"].update(
        {
            "invocation_args": "x" * 8192,
            "run_id": "x" * 8192,
            "scope": ["x" * 1000] * 32,
            "scan_manifest": "x" * 8192,
            "requirements_url_override": "x" * 8192,
        }
    )
    with pytest.raises(controller.ControllerError, match="65536-byte cap"):
        controller._validate_action(action)


def test_action_validation_fails_closed_without_jsonschema(tmp_path, monkeypatch):
    monkeypatch.setattr(controller, "Draft202012Validator", None)
    with pytest.raises(controller.ControllerError, match="dependency is unavailable"):
        controller._validate_action(_semantic_action(tmp_path, [_semantic_job()]))


def test_artifact_receipt_rejects_changed_bytes(tmp_path):
    artifact = tmp_path / "result.json"
    artifact.write_text(
        json.dumps({"version": 2, "generated_at": "2026-08-06T00:00:00Z", "model": "test", "decisions": []}),
        encoding="utf-8",
    )
    receipt = controller.create_artifact_receipt(
        tmp_path,
        "result.json",
        schema_id="schemas/merge-decisions.schema.json#v2",
        record_count=0,
    )
    assert controller.consume_artifact_receipt(tmp_path, receipt) == artifact.read_bytes()

    artifact.write_text(
        json.dumps(
            {
                "version": 2,
                "generated_at": "2026-08-06T00:00:00Z",
                "model": "changed",
                "decisions": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(controller.ControllerError, match="changed after validation"):
        controller.consume_artifact_receipt(tmp_path, receipt)


def test_artifact_receipt_requires_structural_validation(tmp_path):
    (tmp_path / "result.json").write_text("{}", encoding="utf-8")
    with pytest.raises(controller.ControllerError, match="schema validation failed"):
        controller.create_artifact_receipt(
            tmp_path,
            "result.json",
            schema_id="schemas/merge-decisions.schema.json#v2",
            record_count=0,
        )


def test_artifact_receipt_rejects_unknown_contract_version(tmp_path):
    (tmp_path / "result.json").write_text("{}", encoding="utf-8")
    with pytest.raises(controller.ControllerError, match="unregistered schema"):
        controller.create_artifact_receipt(
            tmp_path,
            "result.json",
            schema_id="schemas/merge-decisions.schema.json#v999",
            record_count=0,
        )


def test_artifact_receipt_accepts_optional_empty_mitigation_splits(tmp_path):
    (tmp_path / "overrides.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "additions": [
                    {
                        "id": "M-001",
                        "title": "Centralize secret rotation",
                        "threat_ids": ["T-001"],
                        "kind": "process",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    receipt = controller.create_artifact_receipt(
        tmp_path,
        "overrides.json",
        schema_id="schemas/fragments/mitigation-overrides.schema.json#v1",
        record_count=0,
    )

    assert receipt["record_count"] == 0


def test_verify_receipt_hashes_rejects_a_post_validation_change(tmp_path):
    artifact = tmp_path / "result.json"
    artifact.write_text("original\n", encoding="utf-8")
    expected = hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert controller.verify_receipt_hashes(tmp_path, [("result.json", expected)])["action"] == "run_gate"

    artifact.write_text("changed\n", encoding="utf-8")
    with pytest.raises(controller.ControllerError, match="changed after validation"):
        controller.verify_receipt_hashes(tmp_path, [("result.json", expected)])


def test_dispatch_values_supply_runtime_defaults(tmp_path):
    values = controller._dispatch_values(
        _cfg(tmp_path),
        {
            "estimate_total_pretty": "51 min",
            "estimate_stage1_min": 23,
            "estimate_stage2_min": 8,
            "estimate_stage3_min": 7,
            "estimate_stage4_min": 0,
            "estimate_source": "parametric",
        },
    )
    assert values["actor_discovery_model"] == "sonnet"
    assert values["refresh_actor_discovery"] is False
    assert values["reuse_recon_eligible"] is False
    assert values["write_pdf"] is False
    assert values["write_html"] is False
    assert "renderer_model" in values
    assert "abuse_verifier_model" in values
    assert "stride_concurrency" in values
    assert set(values) == set(controller._DISPATCH_KEYS) | set(controller._DISPATCH_EXTRA_KEYS)


def test_dispatch_values_preserve_slug(tmp_path):
    cfg = _cfg(tmp_path)
    cfg["slug"] = "juice-shop-quick"
    values = controller._dispatch_values(
        cfg,
        {
            "estimate_total_pretty": "51 min",
            "estimate_stage1_min": 23,
            "estimate_stage2_min": 8,
            "estimate_stage3_min": 7,
            "estimate_stage4_min": 0,
            "estimate_source": "parametric",
        },
    )
    assert values["slug"] == "juice-shop-quick"


def _write_context_v2_config(tmp_path: Path, **overrides) -> Path:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    cfg = _cfg(tmp_path)
    cfg["runtime_generation"] = "context-v2"
    cfg["run_id"] = "test-run"
    cfg["stride_profile"] = {"stride_profile_label": "full"}
    cfg["runtime_artifact_schema_versions"] = dict(controller.resolve_config.CONTEXT_V2_ARTIFACT_SCHEMA_VERSIONS)
    cfg.update(overrides)
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    return output


def _post_stride_threat(t_id: str = "T-001", *, risk: str = "Critical") -> dict:
    return {
        "t_id": t_id,
        "title": "Untrusted input reaches a sink",
        "scenario": "An attacker submits an untrusted value to the sink.",
        "risk": risk,
        "source": "stride",
        "evidence_summary": "The cited call consumes untrusted input.",
        "evidence": {"file": "app.py", "line": 1},
        "evidence_check": "unchecked",
        "component_id": "api",
        "stride": "Tampering",
        "cwe": "CWE-20",
        "evidence_tier": "confirmed-exploitable",
        "mitigation_title": "Validate input before the sink",
        "remediation": {
            "effort": "Low",
            "steps": ["Validate the value before use."],
            "verification": "Submit an invalid value and expect rejection.",
            "reference": "CWE-20",
        },
    }


def _write_post_stride_sources(tmp_path: Path, output: Path, threats: list[dict]) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text("sink(user_input)\n", encoding="utf-8")
    (output / ".threats-merged.json").write_text(json.dumps({"version": 1, "threats": threats}), encoding="utf-8")
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api", "tier": "application"}]}),
        encoding="utf-8",
    )


def test_context_v2_dispatch_clears_prior_output_but_preserves_in_place_input(tmp_path):
    output = _write_context_v2_config(tmp_path)
    stale = output / ".components.json"
    stale.write_text("stale", encoding="utf-8")
    controller._context_v2_dispatch(
        output,
        _cfg(tmp_path),
        role="architecture_analyst",
        job_id="architecture",
        input_artifacts=[".recon-summary.md"],
        output_artifacts=[".components.json"],
        decision_keys=["components"],
        receipts=[],
    )
    assert not stale.exists()

    repair = output / ".triage-flags.json"
    repair.write_text("current partial state", encoding="utf-8")
    controller._context_v2_dispatch(
        output,
        _cfg(tmp_path),
        role="triage_validator",
        job_id="triage-repair",
        input_artifacts=[".triage-flags.json"],
        output_artifacts=[".triage-flags.json"],
        decision_keys=["triage"],
        receipts=[],
    )
    assert repair.read_text(encoding="utf-8") == "current partial state"


def test_context_v2_replay_is_rejected_before_fresh_producer_output_is_cleared(tmp_path):
    output = _write_context_v2_config(tmp_path)
    cfg = json.loads((output / ".skill-config.json").read_text(encoding="utf-8"))
    action = controller._context_v2_dispatch(
        output,
        cfg,
        role="context_resolver",
        job_id="phase1-context",
        input_artifacts=[".skill-config.json"],
        output_artifacts=[".threat-modeling-context.md"],
        decision_keys=[],
        receipts=[],
    )
    controller.context_routing.resolve_action(
        action,
        output,
        semantic_roles=controller.SEMANTIC_ROLE_REGISTRY,
        model_keys=controller.SEMANTIC_ROLE_MODEL_KEYS,
    )
    produced = output / ".threat-modeling-context.md"
    produced.write_text("fresh producer output\n", encoding="utf-8")

    with pytest.raises(controller.ControllerError, match="dispatch replay rejected"):
        controller._context_v2_dispatch(
            output,
            cfg,
            role="context_resolver",
            job_id="phase1-context",
            input_artifacts=[".skill-config.json"],
            output_artifacts=[".threat-modeling-context.md"],
            decision_keys=[],
            receipts=[],
        )

    assert produced.read_text(encoding="utf-8") == "fresh producer output\n"


def test_context_v2_boundary_rejects_current_run_after_authoritative_abort(tmp_path):
    output = _write_context_v2_config(tmp_path)
    (output / ".scan-start-epoch").write_text("1\n", encoding="utf-8")
    (output / ".agent-run.log").write_text(
        "2026-08-14T12:43:31Z  [--------]  WARN   RUN_ABORTED  architecture artifacts missing\n",
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="authoritative RUN_ABORTED"):
        controller._load_context_v2_config(output)


def test_controller_abort_clears_live_tool_markers(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    active = output / ".active-tool-calls"
    active.mkdir()
    (active / "recon-scanner.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(controller.subprocess, "run", lambda *args, **kwargs: _completed())

    controller._aggregate_issues_on_abort(output, "producer contract failed")

    assert not active.exists() or list(active.iterdir()) == []
    assert "RUN_ABORTED" in (output / ".agent-run.log").read_text(encoding="utf-8")


def test_context_v2_begin_clears_optional_outputs_with_no_current_producer(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    optional = [
        output / ".evidence-verification.json",
        output / ".mitigation-overrides.json",
        output / ".tier-root-causes.json",
    ]
    for path in optional:
        path.write_text("stale", encoding="utf-8")
    monkeypatch.setattr(controller, "_recon_skip", lambda *_args: True)
    monkeypatch.setattr(controller, "_context_skip", lambda *_args: True)
    monkeypatch.setattr(controller, "_has_iac_surface", lambda *_args: False)
    monkeypatch.setattr(controller, "_context_v2_after_recon", lambda *_args: {"action": "run_gate"})

    assert controller.context_v2_begin(output) == {"action": "run_gate"}
    assert all(not path.exists() for path in optional)


def _write_minimal_context_v2_manifest(output: Path) -> None:
    (output / ".stride-dispatch-manifest.json").write_text(
        json.dumps({"context_version": 2, "components": [{"component_id": "api"}]}),
        encoding="utf-8",
    )


def _merge_candidates(*group_ids: str) -> dict:
    groups = [
        {
            "group_id": group_id,
            "group_key": "cwe_stride",
            "member_count": 2,
            "members": [{"index": 0}, {"index": 1}],
            "cwe": "CWE-79",
            "stride": "Tampering",
        }
        for group_id in group_ids
    ]
    return {
        "version": 1,
        "generated_at": "2026-08-06T00:00:00Z",
        "source_files": [".stride-api.json"],
        "threat_count_raw": len(groups) * 2,
        "threat_count_after_exact_dedup": len(groups) * 2,
        "candidate_group_count": len(groups),
        "candidate_group_count_total": len(groups),
        "auto_decision_count": 0,
        "auto_decisions": [],
        "threats": [],
        "candidate_groups": groups,
        "resolved_prior_findings": [],
    }


def _receipt_stub(output_dir: Path, artifact_path: str, *, schema_id: str, record_count: int) -> dict:
    path = output_dir / artifact_path
    return {
        "schema_version": 1,
        "artifact_path": artifact_path,
        "schema_id": schema_id,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "record_count": record_count,
        "validation_status": "valid",
    }


def _taxonomy_stub(output_dir: Path, component_id: str) -> tuple[str, str]:
    relative = f".taxonomy-slices/{component_id}/threat-category-taxonomy.yaml"
    path = output_dir / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("schema_version: 1\ncategories: []\ncwe_to_th: {}\n", encoding="utf-8")
    return relative, hashlib.sha256(path.read_bytes()).hexdigest()


def _write_architecture_receipt_inputs(output: Path, *, discovery_enabled: bool = False) -> None:
    (output / ".route-inventory.json").write_text(
        json.dumps(
            {
                "version": 1,
                "routes": [],
                "coverage": {"frameworks_detected": [], "unsupported_route_files": []},
            }
        ),
        encoding="utf-8",
    )
    actors = {
        "schema_version": 1,
        "quick_mode": False,
        "discovery_enabled": discovery_enabled,
        "discovery_skip_reason": None,
        "actors_inputs_fingerprint": "0" * 64,
        "alias_map": {},
        "resolved_actors": [],
        "confirmed_relevant": [],
        "inputs_questioned": [],
        "run_issues": [],
        "discovery_actor_count": 0,
        "rejected_discovery_actors": [],
    }
    static_actors = {
        "schema_version": 1,
        "actors_inputs_fingerprint": "0" * 64,
        "catalog_actors": [],
        "resolved_actors": [],
        "disabled_actors": [],
    }
    (output / ".actors-resolved.json").write_text(json.dumps(actors), encoding="utf-8")
    (output / ".actors-merged-static.json").write_text(json.dumps(static_actors), encoding="utf-8")
    architecture_context.build(output)


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
    )
    return {
        "schema_version": 2,
        "signals": {key: False for key in keys},
        "signal_evidence": {key: {"status": "none", "locations": []} for key in keys},
        "signal_classification": {"has_open_self_registration": "deterministic"},
        "component_hints": [],
    }


def _valid_recon_summary() -> str:
    return "\n".join(controller._required_recon_headings()) + "\n"


def _valid_threat_modeling_context() -> str:
    headings = (
        "# Threat Modeling Context",
        "## External Context",
        "## Business Context",
        "## Security Policy",
        "## Architecture Notes",
        "## API Surface",
        "## Deployment Topology",
        "## Data Model Summary",
        "## Architecture Decisions (ADRs)",
        "## Environment & Configuration",
        "## Recent Changes",
        "## Known Threats (Team-Provided)",
        "## Cross-Repository Dependency Threat Models",
    )
    return (
        "\n".join(
            [headings[0], headings[1], '<untrusted-data source="test">', "none", "</untrusted-data>", *headings[2:]]
        )
        + "\n"
    )


def _trust_boundary_assessment() -> dict:
    component = {
        "id": "api",
        "name": "API",
        "tier": "application",
        "deployment_zones": [],
        "handles_sensitive_data": False,
        "paths": ["src/**"],
    }
    source_context = {
        "route_inventory": {"status": "missing", "routes": []},
        "attack_surface_additions": [],
        "cross_repository": {"status": "missing", "entries": []},
        "recon_signals": {
            "values": {
                "has_public_routes": False,
                "has_auth_surface": False,
                "has_role_concept": False,
                "has_ci_pipeline": False,
                "has_external_apis": False,
                "has_client_storage": False,
                "has_multi_tenancy_signal": False,
            },
            "evidence": [],
        },
        "boundary_declarations": {"status": "missing", "fingerprint": None, "keys": []},
        "incremental": False,
    }
    return {
        "schema_version": 1,
        "component_inventory_fingerprint": "sha256:" + "1" * 64,
        "assessment_input_fingerprint": "sha256:" + "2" * 64,
        "assessment_depth": "standard",
        "components": [component, component | {"id": "db", "name": "Database", "tier": "data"}],
        "data_flows": [],
        "signals": [],
        "prior_boundary_identity_hints": [],
        "source_context": source_context,
    }


CONTEXT_V2_ENTRYPOINTS = (
    "context_v2_prepare_stride",
    "context_v2_post_stride",
    "context_v2_post_merge",
    "context_v2_post_evidence",
    "context_v2_post_triage",
    "context_v2_finalize",
)


@pytest.mark.parametrize("entrypoint", CONTEXT_V2_ENTRYPOINTS)
def test_context_v2_action_refuses_a_legacy_run(tmp_path, monkeypatch, entrypoint):
    output = _write_context_v2_config(tmp_path, runtime_generation="legacy")
    monkeypatch.setenv("APPSEC_CONTEXT_V2", "1")
    with pytest.raises(controller.ControllerError) as excinfo:
        getattr(controller, entrypoint)(output)
    assert "incompatible runtime generation" in str(excinfo.value)


@pytest.mark.parametrize("entrypoint", CONTEXT_V2_ENTRYPOINTS)
def test_context_v2_action_refuses_a_run_without_a_persisted_generation(tmp_path, monkeypatch, entrypoint):
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    cfg = _cfg(tmp_path)
    cfg.pop("runtime_generation", None)
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.setenv("APPSEC_CONTEXT_V2", "1")
    with pytest.raises(controller.ControllerError) as excinfo:
        getattr(controller, entrypoint)(output)
    assert "incompatible runtime generation" in str(excinfo.value)


def test_context_v2_action_refuses_stale_persisted_schema_versions(tmp_path):
    output = _write_context_v2_config(tmp_path)
    cfg_path = output / ".skill-config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["runtime_artifact_schema_versions"]["merge-review-context"] = 999
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    with pytest.raises(controller.ControllerError, match="artifact schema versions"):
        controller.context_v2_begin(output)


def test_context_v2_default_continues_without_an_environment_warning(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    _write_minimal_context_v2_manifest(output)
    monkeypatch.delenv("APPSEC_CONTEXT_V2", raising=False)

    def fake_script(name, args, **kwargs):
        if name == "stride_dispatch_waves.py" and args[0] == "claim":
            return _completed(json.dumps({"status": "complete"}))
        if name == "merge_threats.py" and args[0] == "collect":
            (output / ".merge-candidates.json").write_text(json.dumps(_merge_candidates()), encoding="utf-8")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_context_v2_after_merge", lambda *_a, **_k: {"action": "run_gate"})
    assert controller.context_v2_post_stride(output)["action"] == "run_gate"
    log_path = output / ".agent-run.log"
    assert not log_path.exists() or "RUNTIME_GENERATION_ENV_IGNORED" not in log_path.read_text(encoding="utf-8")


def test_context_v2_continues_persisted_generation_despite_legacy_override(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    _write_minimal_context_v2_manifest(output)
    monkeypatch.setenv("APPSEC_CONTEXT_V2", "0")

    def fake_script(name, args, **kwargs):
        if name == "stride_dispatch_waves.py" and args[0] == "claim":
            return _completed(json.dumps({"status": "complete"}))
        if name == "merge_threats.py" and args[0] == "collect":
            (output / ".merge-candidates.json").write_text(json.dumps(_merge_candidates()), encoding="utf-8")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_context_v2_after_merge", lambda *_a, **_k: {"action": "run_gate"})
    assert controller.context_v2_post_stride(output)["action"] == "run_gate"
    assert "RUNTIME_GENERATION_ENV_IGNORED" in (output / ".agent-run.log").read_text(encoding="utf-8")


@pytest.mark.parametrize("entrypoint", ("post_stage1", "post_stage1a"))
def test_legacy_stage1_gate_refuses_a_context_v2_run(tmp_path, entrypoint):
    output = _write_context_v2_config(tmp_path)
    with pytest.raises(controller.ControllerError) as excinfo:
        getattr(controller, entrypoint)(output)
    assert "incompatible runtime generation" in str(excinfo.value)


def test_context_v2_post_stride_dispatches_merger_only_for_ambiguous_groups(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    _write_minimal_context_v2_manifest(output)
    calls: list[tuple[str, list[str]]] = []

    def fake_script(name, args, **kwargs):
        calls.append((name, args))
        if name == "stride_dispatch_waves.py" and args[0] == "claim":
            return _completed(json.dumps({"status": "complete"}))
        if name == "merge_threats.py" and args[0] == "collect":
            (output / ".merge-candidates.json").write_text(
                json.dumps(_merge_candidates("G-aaaaaaaa")),
                encoding="utf-8",
            )
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    action = controller.context_v2_post_stride(output)
    names = [name for name, _ in calls]
    assert names[:4] == [
        "validate_dispatch_manifest.py",
        "stride_dispatch_waves.py",
        "stride_dispatch_waves.py",
        "merge_threats.py",
    ]
    assert names.count("merge_threats.py") == 1
    assert action["action"] == "dispatch_agent"
    assert action["semantic_role"] == "threat_merger"
    assert action["unresolved_decision_keys"] == ["G-aaaaaaaa"]
    assert action["dispatch_jobs"][0]["input_artifacts"] == [".merge-context/candidates.json"]
    assert action["dispatch_jobs"][0]["output_artifacts"] == [".merge-decisions.json"]
    assert action["artifact_receipts"][0]["artifact_path"] == ".merge-context/candidates.json"


def test_context_v2_prepare_stride_returns_bounded_bundle_jobs(tmp_path, monkeypatch, capsys):
    output = _write_context_v2_config(tmp_path, max_stride_components=12)
    (output / ".stride-analyst-context.json").write_text("{}", encoding="utf-8")
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api"}, {"id": "worker"}]}),
        encoding="utf-8",
    )
    calls: list[tuple[str, list[str]]] = []

    def fake_script(name, args, **kwargs):
        calls.append((name, args))
        if name == "build_stride_dispatch_manifest.py":
            components = []
            for component_id in ("api", "worker"):
                bundle_dir = output / ".dispatch-context" / component_id
                bundle_dir.mkdir(parents=True)
                bundle_path = bundle_dir / "evidence-bundle.json"
                bundle_path.write_text(
                    json.dumps(
                        {
                            "component": {"id": component_id},
                            "path_routing": {
                                "focus_paths": [f"src/{component_id}"],
                                "exclude_paths": [],
                            },
                            "source_slices": [],
                        }
                    ),
                    encoding="utf-8",
                )
                component = {
                    "component_id": component_id,
                    "focus_paths": [f"src/{component_id}"],
                    "exclude_paths": [],
                    "evidence_bundle_path": f".dispatch-context/{component_id}/evidence-bundle.json",
                    "cheap_stride": component_id == "worker",
                }
                if component_id == "api":
                    architecture_attributes = {"security_role": "Route public API requests."}
                    architecture = {
                        "schema_version": 1,
                        "component_id": component_id,
                        "source": "stride-analyst-context-v1",
                        "source_content_sha256": hashlib.sha256(
                            controller._canonical_json_bytes(architecture_attributes)
                        ).hexdigest(),
                        "attributes": architecture_attributes,
                    }
                    architecture_path = bundle_dir / "architecture-context.json"
                    architecture_path.write_text(json.dumps(architecture), encoding="utf-8")
                    component["architecture_context_path"] = (
                        f".dispatch-context/{component_id}/architecture-context.json"
                    )
                    component["architecture_context_sha256"] = hashlib.sha256(
                        architecture_path.read_bytes()
                    ).hexdigest()
                    attributes = {"business_purpose": "Serve customer requests."}
                    business = {
                        "schema_version": 1,
                        "component_id": component_id,
                        "source": "stride-analyst-context-v1",
                        "source_content_sha256": hashlib.sha256(
                            controller._canonical_json_bytes(attributes)
                        ).hexdigest(),
                        "attributes": attributes,
                    }
                    business_path = bundle_dir / "business-context.json"
                    business_path.write_text(json.dumps(business), encoding="utf-8")
                    component["business_context_path"] = f".dispatch-context/{component_id}/business-context.json"
                    component["business_context_sha256"] = hashlib.sha256(business_path.read_bytes()).hexdigest()
                components.append(component)
            (output / ".stride-dispatch-manifest.json").write_text(
                json.dumps({"context_version": 2, "components": components}),
                encoding="utf-8",
            )
        elif name == "stride_dispatch_waves.py" and args[0] == "claim":
            components = json.loads((output / ".stride-dispatch-manifest.json").read_text(encoding="utf-8"))[
                "components"
            ]
            return _completed(
                json.dumps(
                    {
                        "status": "claimed",
                        "wave": {
                            "components": components,
                            "attempts": {"api": 1, "worker": 1},
                            "retry_reasons": {"api": "schema validation failed: discovery_escapes[0]"},
                        },
                    }
                )
            )
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_validated_json_receipt", _receipt_stub)
    monkeypatch.setattr(
        controller,
        "_context_v2_taxonomy_slice",
        _taxonomy_stub,
    )
    action = controller.context_v2_prepare_stride(output)
    assert action["action"] == "dispatch_parallel"
    assert [job["component_id"] for job in action["dispatch_jobs"]] == ["api", "worker"]
    assert all(job["semantic_role"] == "stride_analyzer" for job in action["dispatch_jobs"])
    assert all(job["agent_type"] == "appsec-advisor:appsec-stride-analyzer-v2" for job in action["dispatch_jobs"])
    assert all(job["model"] == "sonnet" for job in action["dispatch_jobs"])
    assert [job["analysis_depth"] for job in action["dispatch_jobs"]] == ["full", "light"]
    assert all(
        job["taxonomy_slice_sha256"] == _taxonomy_stub(output, job["component_id"])[1]
        for job in action["dispatch_jobs"]
    )
    assert all(job["taxonomy_slice_path"] in job["input_artifacts"] for job in action["dispatch_jobs"])
    assert all(job["context_plan_path"] in job["input_artifacts"] for job in action["dispatch_jobs"])
    assert all(".stride-dispatch-manifest.json" not in job["input_artifacts"] for job in action["dispatch_jobs"])
    assert all("focus_paths" not in job and "exclude_paths" not in job for job in action["dispatch_jobs"])
    assert all(
        f".dispatch-context/{job['component_id']}/evidence-bundle.json" in job["input_artifacts"]
        for job in action["dispatch_jobs"]
    )
    assert all(
        job["unresolved_decision_keys"] == ["stride:S", "stride:T", "stride:R", "stride:I", "stride:D", "stride:E"]
        for job in action["dispatch_jobs"]
    )
    assert len(action["artifact_receipts"]) == 8
    assert (
        sum(
            receipt["schema_id"] == "schemas/stride-component-context-plan.schema.json#v1"
            for receipt in action["artifact_receipts"]
        )
        == 2
    )
    manifest_sha256 = hashlib.sha256((output / ".stride-dispatch-manifest.json").read_bytes()).hexdigest()
    for job in action["dispatch_jobs"]:
        component_plan = json.loads((output / job["context_plan_path"]).read_text(encoding="utf-8"))
        assert component_plan["source_manifest_sha256"] == manifest_sha256
        assert component_plan["analysis"] == {
            "depth": job["analysis_depth"],
            "estimated_threat_count": job["estimated_threat_count"],
            "file_count": job["file_count"],
            "max_turns": job["max_turns"],
            "sampling_required": job["sampling_required"],
            "stride_profile": {"stride_profile_label": "full"},
        }
        assert component_plan["lens_ids"] == job["lens_ids"]
        expected_contexts = {"controls.component_evidence", "threats.component_taxonomy"}
        if job["component_id"] == "api":
            expected_contexts.add("architecture.component_context")
            assert job["architecture_context_path"] in job["input_artifacts"]
            expected_contexts.add("business.component_context")
            assert job["business_context_path"] in job["input_artifacts"]
        else:
            assert "architecture_context_path" not in job
            assert all("architecture-context.json" not in path for path in job["input_artifacts"])
            assert "business_context_path" not in job
            assert all("business-context.json" not in path for path in job["input_artifacts"])
        assert {row["context_id"] for row in component_plan["inputs"]} == expected_contexts
        assert "focus_paths" not in component_plan and "exclude_paths" not in component_plan
        assert job.get("repository_projection_path") is None
        assert ".stride-repository-registry.json" not in job["input_artifacts"]
    wave_calls = [args[0] for name, args in calls if name == "stride_dispatch_waves.py"]
    assert wave_calls == ["init", "claim"]

    assert controller._emit(action) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["context_plan"]["artifact_path"] == ".context-routing-plan.json"
    assert emitted["context_plan"]["receipt_path"] == ".context-routing-plan.receipt.json"
    assert all(len(job["context_delivery_ids"]) == 14 for job in emitted["dispatch_jobs"])
    assert all(".context-routing-plan.json" not in job["input_artifacts"] for job in emitted["dispatch_jobs"])
    run_log = (output / ".agent-run.log").read_text(encoding="utf-8")
    assert "CONTEXT_V2_STRIDE_RETRY" in run_log
    assert "api=schema validation failed: discovery_escapes[0]" in run_log
    assert "CONTEXT_ROUTING_ACTIVE" in run_log

    shared_manifest = json.loads(json.dumps(action))
    shared_manifest["dispatch_jobs"][0]["input_artifacts"].append(".stride-dispatch-manifest.json")
    with pytest.raises(controller.ControllerError, match="not the shared dispatch manifest"):
        controller._validate_action(shared_manifest)

    shared_registry = json.loads(json.dumps(action))
    shared_registry["dispatch_jobs"][0]["input_artifacts"].append(".stride-repository-registry.json")
    with pytest.raises(controller.ControllerError, match="not the shared registry"):
        controller._validate_action(shared_registry)

    missing_plan_receipt = json.loads(json.dumps(action))
    missing_plan_receipt["artifact_receipts"] = [
        receipt
        for receipt in missing_plan_receipt["artifact_receipts"]
        if receipt["artifact_path"] != ".dispatch-context/api/context-plan.json"
    ]
    with pytest.raises(controller.ControllerError, match="requires one exact-byte receipt"):
        controller._validate_action(missing_plan_receipt)

    manifest_path = output / ".stride-dispatch-manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest_path.write_bytes(manifest_bytes + b" ")
    with pytest.raises(controller.ControllerError, match="stale for the dispatch manifest"):
        controller._validate_action(action)
    manifest_path.write_bytes(manifest_bytes)

    component_plan = output / ".dispatch-context/api/context-plan.json"
    component_plan.write_bytes(component_plan.read_bytes() + b" ")
    with pytest.raises(controller.ControllerError, match="component context plan hash is stale"):
        controller._validate_action(action)


def test_component_security_context_is_receipted_and_reconstructed_from_manifest_source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    component = {
        "component_id": "api",
        "component_name": "API",
        "component_description": "Public API",
        "component_paths": ["src/**"],
        "component_complexity": "moderate",
        "max_turns": 10,
        "controls": ["Authorization middleware"],
        "index_paths": {
            "prior_findings": "none",
            "known_threats": "none",
            "cross_repo": "none",
            "requirements_violations": "none",
            "relevant_actors": "none",
            "trust_boundaries": "none",
        },
    }
    manifest = evidence_bundles.build_all(
        output,
        repo,
        {"schema_version": 1, "components": [component]},
    )
    manifest_path = output / ".stride-dispatch-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    declared = [
        {key: row[key] for key in ("context_id", "artifact_path", "sha256")}
        for row in manifest["components"][0]["security_context_projections"]
    ]
    receipts = [
        controller._validated_json_receipt(
            output,
            row["artifact_path"],
            schema_id="schemas/stride-component-security-context.schema.json#v1",
            record_count=1,
        )
        for row in declared
    ]
    job = {
        "component_id": "api",
        "security_context_projections": declared,
        "input_artifacts": [row["artifact_path"] for row in declared],
    }

    validated = controller._validate_stride_component_security_contexts(output, job, receipts)
    assert [row["context_id"] for row in validated] == ["controls.component_context"]

    changed = json.loads(manifest_path.read_text(encoding="utf-8"))
    changed["components"][0]["controls"] = ["Changed control claim"]
    manifest_path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(controller.ControllerError, match="stale for its source index"):
        controller._validate_stride_component_security_contexts(output, job, receipts)


def test_component_security_context_reconstruction_applies_shared_budget(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "out"
    source_dir = output / ".dispatch-context" / "api"
    source_dir.mkdir(parents=True)
    known_path = source_dir / "known-threats.json"
    known_path.write_text(
        json.dumps([f"known-{index}-" + "x" * 4000 for index in range(32)]),
        encoding="utf-8",
    )
    component = {
        "component_id": "api",
        "component_name": "API",
        "component_description": "Public API",
        "component_paths": ["src/**"],
        "component_complexity": "moderate",
        "max_turns": 10,
        "controls": [f"control-{index}-" + "y" * 4000 for index in range(32)],
        "index_paths": {
            "prior_findings": "none",
            "known_threats": known_path.relative_to(output).as_posix(),
            "cross_repo": "none",
            "requirements_violations": "none",
            "relevant_actors": "none",
            "trust_boundaries": "none",
        },
    }
    manifest = evidence_bundles.build_all(
        output,
        repo,
        {"schema_version": 1, "components": [component]},
    )
    (output / ".stride-dispatch-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    declared = [
        {key: row[key] for key in ("context_id", "artifact_path", "sha256")}
        for row in manifest["components"][0]["security_context_projections"]
    ]
    receipts = []
    for row in declared:
        value = json.loads((output / row["artifact_path"]).read_text(encoding="utf-8"))
        receipts.append(
            controller._validated_json_receipt(
                output,
                row["artifact_path"],
                schema_id="schemas/stride-component-security-context.schema.json#v1",
                record_count=len(value["records"]),
            )
        )
    job = {
        "component_id": "api",
        "security_context_projections": declared,
        "input_artifacts": [row["artifact_path"] for row in declared],
    }

    validated = controller._validate_stride_component_security_contexts(output, job, receipts)

    assert {row["context_id"] for row in validated} == {
        "controls.component_context",
        "threats.known_threats",
    }
    assert sum(row["limits"]["estimated_tokens"] for row in validated) <= evidence_bundles.MAX_ESTIMATED_TOKENS


def test_component_repository_projection_contains_only_admitted_related_roots(tmp_path):
    output = tmp_path / "out"
    context = output / ".dispatch-context" / "api"
    context.mkdir(parents=True)
    source_registry = output / ".stride-repository-registry.json"
    source_registry.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "repositories": [
                    {
                        "repository_id": "billing",
                        "kind": "related",
                        "root": str((tmp_path / "billing").resolve()),
                        "declared_name": "Billing",
                        "declared_threat_model": str((tmp_path / "billing" / "threat-model.md").resolve()),
                    },
                    {
                        "repository_id": "orders",
                        "kind": "related",
                        "root": str((tmp_path / "orders").resolve()),
                        "declared_name": "Orders",
                        "declared_threat_model": str((tmp_path / "orders" / "threat-model.md").resolve()),
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    bundle = {
        "source_slices": [
            {"repository_id": "primary"},
            {"repository_id": "orders"},
        ],
        "repository_state": [
            {"repository_id": "primary"},
            {"repository_id": "orders"},
        ],
    }

    projection = controller._write_stride_component_repository_roots(
        output,
        component_id="api",
        bundle=bundle,
        source_registry_path=source_registry,
    )

    assert projection is not None
    relative, receipt = projection
    value = json.loads((output / relative).read_text(encoding="utf-8"))
    assert relative == ".dispatch-context/api/repository-roots.json"
    assert value["component_id"] == "api"
    assert value["repositories"] == [
        {
            "repository_id": "orders",
            "kind": "related",
            "root": str((tmp_path / "orders").resolve()),
        }
    ]
    assert value["source_registry_sha256"] == hashlib.sha256(source_registry.read_bytes()).hexdigest()
    job = {
        "component_id": "api",
        "repository_projection_path": relative,
        "repository_projection_sha256": receipt["sha256"],
        "input_artifacts": [relative],
    }
    controller._validate_stride_component_repository_roots(output, job, bundle, [receipt])

    bundle_path = context / "evidence-bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    taxonomy_path = output / ".taxonomy-slices" / "api" / "threat-category-taxonomy.yaml"
    taxonomy_path.parent.mkdir(parents=True)
    taxonomy_path.write_text("version: 1\n", encoding="utf-8")
    manifest_path = output / ".stride-dispatch-manifest.json"
    manifest_path.write_text('{"context_version":2}', encoding="utf-8")
    plan_path, plan_receipt = controller._write_stride_component_context_plan(
        output,
        component_id="api",
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        analysis={
            "depth": "full",
            "max_turns": 10,
            "sampling_required": False,
            "file_count": 1,
            "estimated_threat_count": "low",
            "stride_profile": {"stride_profile_label": "full"},
        },
        lens_ids=[],
        bundle_path=".dispatch-context/api/evidence-bundle.json",
        bundle_sha256=hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        taxonomy_path=".taxonomy-slices/api/threat-category-taxonomy.yaml",
        taxonomy_sha256=hashlib.sha256(taxonomy_path.read_bytes()).hexdigest(),
        repository_projection_path=relative,
        repository_projection_sha256=receipt["sha256"],
    )
    job.update(
        {
            "analysis_depth": "full",
            "max_turns": 10,
            "sampling_required": False,
            "file_count": 1,
            "estimated_threat_count": "low",
            "lens_ids": [],
            "evidence_bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
            "taxonomy_slice_path": ".taxonomy-slices/api/threat-category-taxonomy.yaml",
            "taxonomy_slice_sha256": hashlib.sha256(taxonomy_path.read_bytes()).hexdigest(),
            "context_plan_path": plan_path,
            "context_plan_sha256": plan_receipt["sha256"],
            "input_artifacts": [
                plan_path,
                ".dispatch-context/api/evidence-bundle.json",
                ".taxonomy-slices/api/threat-category-taxonomy.yaml",
                relative,
            ],
        }
    )
    controller._validate_stride_component_context_plan(
        output,
        job,
        [receipt, plan_receipt],
        {"stride_profile_label": "full"},
    )

    projection_path = output / relative
    projection_bytes = projection_path.read_bytes()
    root_drift = json.loads(projection_bytes)
    root_drift["repositories"][0]["root"] = str((tmp_path / "billing").resolve())
    projection_path.write_text(json.dumps(root_drift, sort_keys=True) + "\n", encoding="utf-8")
    drift_receipt = controller._validated_json_receipt(
        output,
        relative,
        schema_id="schemas/stride-component-repository-roots.schema.json#v1",
        record_count=1,
    )
    drift_job = {**job, "repository_projection_sha256": drift_receipt["sha256"]}
    with pytest.raises(controller.ControllerError, match="drifted from the controller registry"):
        controller._validate_stride_component_repository_roots(output, drift_job, bundle, [drift_receipt])
    projection_path.write_bytes(projection_bytes)

    duplicate_id = json.loads(projection_bytes)
    duplicate_id["repositories"].append(
        {
            "repository_id": "orders",
            "kind": "related",
            "root": str((tmp_path / "billing").resolve()),
        }
    )
    projection_path.write_text(json.dumps(duplicate_id, sort_keys=True) + "\n", encoding="utf-8")
    duplicate_sha256 = hashlib.sha256(projection_path.read_bytes()).hexdigest()
    duplicate_receipt = {
        "schema_version": 1,
        "artifact_path": relative,
        "schema_id": "schemas/stride-component-repository-roots.schema.json#v1",
        "sha256": duplicate_sha256,
        "record_count": 1,
        "validation_status": "valid",
    }
    duplicate_job = {**job, "repository_projection_sha256": duplicate_sha256}
    with pytest.raises(controller.ControllerError, match="does not match the bundle source slices"):
        controller._validate_stride_component_repository_roots(
            output,
            duplicate_job,
            bundle,
            [duplicate_receipt],
        )
    projection_path.write_bytes(projection_bytes)

    projection_path.write_bytes(projection_bytes + b" ")
    with pytest.raises(controller.ControllerError, match="projection hash is stale"):
        controller._validate_stride_component_repository_roots(output, job, bundle, [receipt])
    projection_path.write_bytes(projection_bytes)

    source_registry.write_bytes(source_registry.read_bytes() + b" ")
    with pytest.raises(controller.ControllerError, match="stale for the controller registry"):
        controller._validate_stride_component_repository_roots(output, job, bundle, [receipt])


def test_component_repository_projection_is_omitted_without_related_source_slices(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    source_registry = output / ".stride-repository-registry.json"
    source_registry.write_text('{"schema_version":1,"repositories":[]}', encoding="utf-8")

    result = controller._write_stride_component_repository_roots(
        output,
        component_id="api",
        bundle={"source_slices": [{"repository_id": "primary"}]},
        source_registry_path=source_registry,
    )

    assert result is None
    assert not (output / ".dispatch-context/api/repository-roots.json").exists()


def test_component_repository_projection_rejects_unknown_bundle_repository(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    source_registry = output / ".stride-repository-registry.json"
    source_registry.write_text('{"schema_version":1,"repositories":[]}', encoding="utf-8")

    with pytest.raises(controller.ControllerError, match="absent from the controller registry"):
        controller._write_stride_component_repository_roots(
            output,
            component_id="api",
            bundle={"source_slices": [{"repository_id": "unknown"}]},
            source_registry_path=source_registry,
        )


def test_context_v2_post_stride_claims_retry_before_verify_or_merge(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    bundle_dir = output / ".dispatch-context" / "api"
    bundle_dir.mkdir(parents=True)
    bundle_path = bundle_dir / "evidence-bundle.json"
    bundle_path.write_text(
        json.dumps({"component": {"id": "api"}, "source_slices": []}),
        encoding="utf-8",
    )
    component = {
        "component_id": "api",
        "evidence_bundle_path": ".dispatch-context/api/evidence-bundle.json",
    }
    (output / ".stride-dispatch-manifest.json").write_text(
        json.dumps({"context_version": 2, "components": [component]}),
        encoding="utf-8",
    )
    calls: list[tuple[str, list[str]]] = []

    def fake_script(name, args, **kwargs):
        calls.append((name, args))
        if name == "stride_dispatch_waves.py" and args[0] == "claim":
            return _completed(
                json.dumps({"status": "claimed", "wave": {"components": [component], "attempts": {"api": 2}}})
            )
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_validated_json_receipt", _receipt_stub)
    monkeypatch.setattr(
        controller,
        "_context_v2_taxonomy_slice",
        _taxonomy_stub,
    )
    action = controller.context_v2_post_stride(output)

    assert action["action"] == "dispatch_parallel"
    assert action["dispatch_jobs"][0]["component_id"] == "api"
    assert [name for name, _ in calls[:2]] == ["validate_dispatch_manifest.py", "stride_dispatch_waves.py"]
    assert all(name not in {"merge_threats.py"} for name, _ in calls)


def test_context_v2_taxonomy_slice_is_bounded_and_fingerprinted(tmp_path):
    output = tmp_path / "out"
    output.mkdir()

    relative, digest = controller._context_v2_taxonomy_slice(output, "backend-api")

    path = output / relative
    payload = path.read_bytes()
    assert relative == ".taxonomy-slices/backend-api/threat-category-taxonomy.yaml"
    assert len(payload) <= 32_768
    assert hashlib.sha256(payload).hexdigest() == digest
    assert b"cwe_to_th:" in payload


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ("schema_version: 1\ncategories:\n  - id: TH-01\ncwe_to_th: {}\n", "validation failed"),
        (
            "schema_version: 1\ncategories: []\ncwe_to_th:\n  CWE-79: [TH-01]\n",
            "maps CWEs to absent categories",
        ),
    ],
)
def test_context_v2_taxonomy_slice_rejects_invalid_contract(tmp_path, monkeypatch, payload, message):
    output = tmp_path / "out"
    output.mkdir()

    def fake_slice(_name, args, **_kwargs):
        component_id = args[args.index("--component-id") + 1]
        path = output / ".taxonomy-slices" / component_id / "threat-category-taxonomy.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(payload, encoding="utf-8")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_slice)

    with pytest.raises(controller.ControllerError, match=message):
        controller._context_v2_taxonomy_slice(output, "api")


def test_context_v2_prepare_stride_rejects_bundle_escape_after_external_gate(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    (output / ".stride-analyst-context.json").write_text("{}", encoding="utf-8")
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api"}]}),
        encoding="utf-8",
    )
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"component": {"id": "api"}, "source_slices": []}), encoding="utf-8")

    def fake_script(name, args, **kwargs):
        if name == "build_stride_dispatch_manifest.py":
            (output / ".stride-dispatch-manifest.json").write_text(
                json.dumps(
                    {
                        "context_version": 2,
                        "components": [
                            {
                                "component_id": "api",
                                "evidence_bundle_path": "../outside.json",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
        elif name == "stride_dispatch_waves.py" and args[0] == "claim":
            return _completed(
                json.dumps(
                    {
                        "status": "claimed",
                        "wave": {
                            "attempts": {"api": 1},
                            "components": [
                                {
                                    "component_id": "api",
                                    "evidence_bundle_path": "../outside.json",
                                }
                            ],
                        },
                    }
                )
            )
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    with pytest.raises(controller.ControllerError, match="unsafe artifact path"):
        controller.context_v2_prepare_stride(output)


def test_context_v2_candidate_free_success_runs_to_stage2_handoff_without_agent(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path, evidence_verifier_max_findings=30)
    _write_minimal_context_v2_manifest(output)
    calls: list[str] = []

    def fake_script(name, args, **kwargs):
        calls.append(name)
        if name == "stride_dispatch_waves.py" and args[0] == "claim":
            return _completed(json.dumps({"status": "complete"}))
        if name == "merge_threats.py" and args[0] == "collect":
            (output / ".merge-candidates.json").write_text(
                json.dumps(_merge_candidates()),
                encoding="utf-8",
            )
        elif name == "merge_threats.py" and args[0] == "finalize":
            (output / ".threats-merged.json").write_text(
                json.dumps({"version": 1, "generated_at": "2026-08-06T00:00:00Z", "threats": []}),
                encoding="utf-8",
            )
        elif name == "triage_validate_ratings.py":
            (output / ".triage-flags.json").write_text(
                json.dumps({"version": 1, "flags": []}),
                encoding="utf-8",
            )
        elif name == "build_threat_model_yaml.py":
            (output / "threat-model.yaml").write_text("meta: {}\n", encoding="utf-8")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(
        controller,
        "_run_external",
        lambda command, **_kwargs: calls.append(Path(command[1]).name) or _completed(),
    )
    action = controller.context_v2_post_stride(output)
    assert action["action"] == "run_gate"
    assert action["stage"] == "stage1c"
    assert "semantic_role" not in action
    assert calls[:5] == [
        "validate_dispatch_manifest.py",
        "stride_dispatch_waves.py",
        "stride_dispatch_waves.py",
        "merge_threats.py",
        "merge_threats.py",
    ]
    assert "triage_validate_ratings.py" in calls
    assert "triage_compute_ranking.py" in calls
    assert "build_threat_model_yaml.py" in calls
    assert calls.index("validate_intermediate.py") < calls.index("auto_emitter_pass.sh")
    assert calls.index("auto_emitter_pass.sh") < calls.index("validate_mitigation_quality.py")
    assert "appsec-threat-analyst" not in json.dumps(action)
    assert "runtime_generation=context-v2" in (output / ".appsec-checkpoint").read_text(encoding="utf-8")


def test_context_v2_after_merge_dispatches_evidence_only_when_sample_has_work(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path, evidence_verifier_max_findings=30)
    _write_post_stride_sources(tmp_path, output, [_post_stride_threat()])

    def fake_script(name, args, **kwargs):
        if name == "build_post_stride_contexts.py":
            post_stride_contexts.write_evidence_context(output, tmp_path / "repo", "standard", 30)
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_validated_json_receipt", _receipt_stub)
    action = controller._context_v2_after_merge(output, _cfg(tmp_path) | {"evidence_verifier_max_findings": 30})
    assert action["semantic_role"] == "evidence_verifier"
    assert action["unresolved_decision_keys"] == ["sampled_evidence_verdicts"]
    assert action["dispatch_jobs"][0]["output_artifacts"] == [
        ".evidence-verification.json",
    ]


def _rewrite_projection_with_current_size(path: Path, value: dict) -> None:
    for _ in range(3):
        payload = (json.dumps(value, indent=2, sort_keys=False) + "\n").encode()
        value["limits"]["serialized_bytes"] = len(payload)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def test_evidence_projection_reconstruction_rejects_schema_valid_limit_drift(tmp_path):
    output = _write_context_v2_config(tmp_path, evidence_verifier_max_findings=30)
    _write_post_stride_sources(tmp_path, output, [_post_stride_threat()])
    path = post_stride_contexts.write_evidence_context(output, tmp_path / "repo", "standard", 30)
    value = json.loads(path.read_text(encoding="utf-8"))
    value["limits"]["selected_samples"] = 0
    _rewrite_projection_with_current_size(path, value)

    with pytest.raises(controller.ControllerError, match="differs from its deterministic projection"):
        controller._context_v2_evidence_projection_receipt(
            output,
            _cfg(tmp_path) | {"evidence_verifier_max_findings": 30},
        )


@pytest.mark.parametrize("generated", [True, False])
def test_synthesis_projection_reconstruction_rejects_schema_valid_limit_drift(tmp_path, generated):
    output = _write_context_v2_config(tmp_path)
    _write_post_stride_sources(tmp_path, output, [_post_stride_threat()])
    generated_path, mitigation_path = post_stride_contexts.write_synthesis_contexts(output)
    path = generated_path if generated else mitigation_path
    value = json.loads(path.read_text(encoding="utf-8"))
    value["limits"]["ordering_key"] = "canonical merged threat order"
    value["limits"]["max_records"] = 512
    record_key = "threats" if generated else "mitigations"
    value[record_key][0]["t_id"] = "T-999"
    _rewrite_projection_with_current_size(path, value)

    with pytest.raises(controller.ControllerError, match="differs from its deterministic projection"):
        controller._context_v2_synthesis_projection_receipt(output, generated=generated)


def test_context_v2_normalizes_producer_authored_stride_profile_before_schema_gate(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    path = output / ".stride-analyst-context.json"
    path.write_text(
        json.dumps(
            {
                "_stride_profile": "x" * 397,
                "backend-api": {
                    "interfaces": ["REST API"],
                    "estimated_threat_count": 8,
                },
            }
        ),
        encoding="utf-8",
    )

    controller._normalize_context_v2_analyst_context(output)

    normalized = controller._validate_json_artifact(
        path,
        controller.PLUGIN_ROOT / "schemas" / "stride-analyst-context.schema.json",
        contract="stride-analyst-context-v1",
    )
    assert "_stride_profile" not in normalized
    assert normalized["backend-api"]["estimated_threat_count"] == 8


def test_context_v2_analyst_context_allows_more_than_legacy_component_count(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    component_ids = [f"service-{index:03d}" for index in range(70)]
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": value} for value in component_ids]}),
        encoding="utf-8",
    )
    (output / ".stride-analyst-context.json").write_text(
        json.dumps({value: {"interfaces": ["internal"]} for value in component_ids}),
        encoding="utf-8",
    )

    value = controller._validate_context_v2_analyst_context(output)

    assert len(value) == 70


def test_context_v2_analyst_context_rejects_unknown_component_id(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api"}]}),
        encoding="utf-8",
    )
    (output / ".stride-analyst-context.json").write_text(
        json.dumps({"invented-service": {"controls": ["none"]}}),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="unknown component IDs: invented-service"):
        controller._validate_context_v2_analyst_context(output)


def test_context_v2_analyst_context_rejects_out_of_scope_routing_before_manifest_build(tmp_path):
    output = tmp_path / "out"
    repo = tmp_path / "repo"
    output.mkdir()
    (repo / "services" / "realtime").mkdir(parents=True)
    (repo / "shared").mkdir()
    (repo / "services" / "realtime" / "entry.ts").write_text("export const start = true\n", encoding="utf-8")
    (repo / "shared" / "handler.ts").write_text("export const handle = true\n", encoding="utf-8")
    (output / ".components.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "components": [{"id": "realtime-service", "paths": ["services/realtime/**"]}],
            }
        ),
        encoding="utf-8",
    )
    (output / ".stride-analyst-context.json").write_text(
        json.dumps({"realtime-service": {"focus_paths": ["shared/handler.ts"]}}),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="routing validation failed.*outside the component paths"):
        controller._validate_context_v2_analyst_context(output, repo_root=repo)


def test_context_v2_analyst_context_rejects_oversized_routing_list(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api"}]}),
        encoding="utf-8",
    )
    (output / ".stride-analyst-context.json").write_text(
        json.dumps({"api": {"focus_paths": [f"src/file-{index}.py" for index in range(17)]}}),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="stride-analyst-context-v1 validation failed"):
        controller._validate_context_v2_analyst_context(output)


def test_context_v2_analyst_context_rejects_blank_routing_path(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api"}]}),
        encoding="utf-8",
    )
    (output / ".stride-analyst-context.json").write_text(
        json.dumps({"api": {"exclude_paths": ["   "]}}),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="stride-analyst-context-v1 validation failed"):
        controller._validate_context_v2_analyst_context(output)


@pytest.mark.parametrize("overlay", [{}, {"controls": []}, {"interfaces": ""}])
def test_context_v2_analyst_context_rejects_empty_component_overlays(tmp_path, overlay):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api"}]}),
        encoding="utf-8",
    )
    (output / ".stride-analyst-context.json").write_text(
        json.dumps({"api": overlay}),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="stride-analyst-context-v1 validation failed"):
        controller._validate_context_v2_analyst_context(output)


def test_context_v2_analyst_context_rejects_oversized_artifact(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".components.json").write_text(
        json.dumps({"schema_version": 1, "components": [{"id": "api"}]}),
        encoding="utf-8",
    )
    (output / ".stride-analyst-context.json").write_text(
        " " * (controller.MAX_STRIDE_ANALYST_CONTEXT_BYTES + 1),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="1048576-byte cap"):
        controller._validate_context_v2_analyst_context(output)


def test_context_v2_after_evidence_skips_triage_agent_and_dispatches_only_root_cause_synthesis(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    _write_post_stride_sources(tmp_path, output, [_post_stride_threat()])

    def fake_script(name, args, **kwargs):
        if name == "triage_validate_ratings.py":
            (output / ".triage-flags.json").write_text(
                json.dumps({"version": 2, "flags": []}),
                encoding="utf-8",
            )
        if name == "build_post_stride_contexts.py":
            post_stride_contexts.write_synthesis_contexts(output)
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_validated_json_receipt", _receipt_stub)
    action = controller.context_v2_post_evidence(output)
    assert action["semantic_role"] == "post_stride_synthesizer"
    assert action["unresolved_decision_keys"] == ["tier_root_causes"]
    assert all(job["semantic_role"] != "triage_validator" for job in action["dispatch_jobs"])


def test_evidence_verification_semantics_reject_inconsistent_counts(tmp_path):
    path = tmp_path / ".evidence-verification.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "generated_at": "2026-08-06T12:00:00Z",
                "model_id": "sonnet",
                "depth": "quick",
                "summary": {
                    "total_threats": 4,
                    "sampled": 2,
                    "verified": 1,
                    "refuted": 0,
                    "ambiguous": 0,
                    "unchecked": 2,
                },
                "flags": [
                    {
                        "flag_id": "EV-001",
                        "t_id": "T-001",
                        "verdict": "verified",
                        "reason": "The cited sink is present.",
                        "line_excerpt": "query(input)",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="do not partition sampled"):
        controller._validate_evidence_verification(path)


def test_evidence_verification_rejects_sidechannel_annotation_drift(tmp_path):
    path = tmp_path / ".evidence-verification.json"
    threats = tmp_path / ".threats-merged.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "generated_at": "2026-08-06T12:00:00Z",
                "model_id": "sonnet",
                "depth": "quick",
                "summary": {
                    "total_threats": 1,
                    "sampled": 1,
                    "verified": 1,
                    "refuted": 0,
                    "ambiguous": 0,
                    "unchecked": 0,
                },
                "flags": [
                    {
                        "flag_id": "EV-001",
                        "t_id": "T-001",
                        "verdict": "verified",
                        "reason": "The cited sink is present.",
                        "line_excerpt": "query(input)",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    threats.write_text(
        json.dumps(
            {
                "version": 1,
                "threats": [
                    {
                        "t_id": "T-001",
                        "evidence_check": "ambiguous",
                        "evidence_flags": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="verdict does not match merged threat T-001"):
        controller._validate_evidence_verification(path, threats)


def test_evidence_verification_rejects_total_that_does_not_match_merged_artifact(tmp_path):
    path = tmp_path / ".evidence-verification.json"
    threats = tmp_path / ".threats-merged.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "generated_at": "2026-08-06T12:00:00Z",
                "model_id": "sonnet",
                "depth": "quick",
                "summary": {
                    "total_threats": 0,
                    "sampled": 0,
                    "verified": 0,
                    "refuted": 0,
                    "ambiguous": 0,
                    "unchecked": 0,
                },
                "flags": [],
            }
        ),
        encoding="utf-8",
    )
    threats.write_text(
        json.dumps({"version": 1, "threats": [{"t_id": "T-001"}]}),
        encoding="utf-8",
    )

    with pytest.raises(controller.ControllerError, match="does not match the merged threat count"):
        controller._validate_evidence_verification(path, threats)


def test_context_v2_invalid_evidence_summary_is_nonfatal_enrichment(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    (output / ".evidence-verification.json").write_text("{}", encoding="utf-8")
    guard_calls = []

    monkeypatch.setattr(
        controller,
        "_validate_evidence_verification",
        lambda *paths: (_ for _ in ()).throw(controller.ControllerError("invalid evidence contract")),
    )
    monkeypatch.setattr(
        controller,
        "_best_effort_script",
        lambda output_dir, name, args, receipts: guard_calls.append((name, list(args), list(receipts))),
    )
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())
    monkeypatch.setattr(controller, "_context_v2_after_triage", lambda output_dir, cfg: {"action": "sentinel"})

    assert controller._context_v2_after_evidence(output, _cfg(tmp_path)) == {"action": "sentinel"}
    assert guard_calls == [
        (
            "guard_evidence_verification.py",
            [str(output), "--ignore-summary"],
            ["evidence verification rejected: invalid contract"],
        )
    ]


def test_context_v2_applies_receipted_evidence_verdicts_controller_side(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path, evidence_verifier_max_findings=20)
    _write_post_stride_sources(tmp_path, output, [_post_stride_threat()])
    post_stride_contexts.write_evidence_context(output, tmp_path / "repo", "standard", 20)
    (output / ".evidence-verification.json").write_text(
        json.dumps(
            {
                "version": 1,
                "generated_at": "2026-08-09T12:00:00Z",
                "model_id": "sonnet",
                "depth": "standard",
                "summary": {
                    "total_threats": 1,
                    "sampled": 1,
                    "verified": 1,
                    "refuted": 0,
                    "ambiguous": 0,
                    "unchecked": 0,
                },
                "flags": [
                    {
                        "flag_id": "EV-001",
                        "t_id": "T-001",
                        "verdict": "verified",
                        "reason": "The cited sink is present.",
                        "line_excerpt": "sink(user_input)",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def fake_script(name, args, **kwargs):
        if name == "triage_validate_ratings.py":
            (output / ".triage-flags.json").write_text(json.dumps({"version": 2, "flags": []}), encoding="utf-8")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_best_effort_script", lambda *args, **kwargs: True)
    monkeypatch.setattr(controller, "_context_v2_after_triage", lambda *_args: {"action": "sentinel"})

    assert controller._context_v2_after_evidence(output, _cfg(tmp_path)) == {"action": "sentinel"}
    threat = json.loads((output / ".threats-merged.json").read_text())["threats"][0]
    assert threat["evidence_check"] == "verified"
    assert threat["evidence_flags"][0]["flag_id"] == "EV-001"


def test_context_v2_rejected_evidence_application_preserves_canonical_merge(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path, evidence_verifier_max_findings=20)
    _write_post_stride_sources(tmp_path, output, [_post_stride_threat()])
    post_stride_contexts.write_evidence_context(output, tmp_path / "repo", "standard", 20)
    verification = {
        "version": 1,
        "generated_at": "2026-08-09T12:00:00Z",
        "model_id": "sonnet",
        "depth": "standard",
        "summary": {
            "total_threats": 1,
            "sampled": 1,
            "verified": 1,
            "refuted": 0,
            "ambiguous": 0,
            "unchecked": 0,
        },
        "flags": [
            {
                "flag_id": "EV-001",
                "t_id": "T-001",
                "verdict": "verified",
                "reason": "The cited sink is present.",
                "line_excerpt": "sink(user_input)",
            }
        ],
    }
    (output / ".evidence-verification.json").write_text(json.dumps(verification), encoding="utf-8")
    original = (output / ".threats-merged.json").read_bytes()
    validation_calls = 0

    def validate_sidechannel(*_paths):
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 1:
            return verification
        raise controller.ControllerError("staged evidence correspondence failed")

    def fake_script(name, args, **kwargs):
        if name == "triage_validate_ratings.py":
            (output / ".triage-flags.json").write_text(json.dumps({"version": 2, "flags": []}), encoding="utf-8")
        return _completed()

    monkeypatch.setattr(controller, "_validate_evidence_verification", validate_sidechannel)
    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_best_effort_script", lambda *args, **kwargs: True)
    monkeypatch.setattr(controller, "_context_v2_after_triage", lambda *_args: {"action": "sentinel"})

    assert controller._context_v2_after_evidence(output, _cfg(tmp_path)) == {"action": "sentinel"}
    assert (output / ".threats-merged.json").read_bytes() == original
    assert not (output / ".dispatch-context/post-stride/threats-merged-verified.json").exists()


def test_context_v2_dispatches_triage_only_when_deterministic_ranking_fails(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    (output / ".threats-merged.json").write_text(
        json.dumps({"version": 1, "threats": [{"t_id": "T-001"}]}),
        encoding="utf-8",
    )

    def fake_script(name, args, **kwargs):
        if name == "triage_validate_ratings.py":
            (output / ".triage-flags.json").write_text(
                json.dumps({"version": 1, "flags": []}),
                encoding="utf-8",
            )
        if name == "triage_compute_ranking.py":
            raise controller.ControllerError("semantic ranking fallback required")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake_script)
    monkeypatch.setattr(controller, "_validated_json_receipt", _receipt_stub)
    action = controller.context_v2_post_evidence(output)
    assert action["semantic_role"] == "triage_validator"
    assert action["unresolved_decision_keys"] == ["triage_ranking"]
    assert action["dispatch_jobs"][0]["output_artifacts"] == [
        ".triage-flags.json",
        ".threats-merged.json",
    ]


def test_context_v2_post_merge_rejects_decisions_for_unknown_group(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    (output / ".merge-candidates.json").write_text(
        json.dumps(_merge_candidates("G-aaaaaaaa")),
        encoding="utf-8",
    )
    candidate_payload = (output / ".merge-candidates.json").read_bytes()
    controller._write_merge_review_context(output, json.loads(candidate_payload), candidate_payload)
    (output / ".merge-decisions.json").write_text(
        json.dumps(
            {
                "version": 2,
                "generated_at": "2026-08-05T00:00:00Z",
                "model": "sonnet",
                "decisions": [
                    {
                        "group_id": "G-bbbbbbbb",
                        "action": "keep",
                        "member_indices": [0],
                        "rationale": "Distinct mechanisms.",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())
    with pytest.raises(controller.ControllerError, match="unknown groups"):
        controller.context_v2_post_merge(output)


def test_context_v2_post_merge_rejects_omitted_candidate_group(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    (output / ".merge-candidates.json").write_text(
        json.dumps(_merge_candidates("G-aaaaaaaa")),
        encoding="utf-8",
    )
    candidate_payload = (output / ".merge-candidates.json").read_bytes()
    controller._write_merge_review_context(output, json.loads(candidate_payload), candidate_payload)
    (output / ".merge-decisions.json").write_text(
        json.dumps(
            {
                "version": 2,
                "generated_at": "2026-08-06T00:00:00Z",
                "model": "sonnet",
                "decisions": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())

    with pytest.raises(controller.ControllerError, match="omits candidate groups"):
        controller.context_v2_post_merge(output)


def test_context_v2_post_merge_accepts_disjoint_partial_cluster_decisions(tmp_path, monkeypatch):
    output = _write_context_v2_config(tmp_path)
    candidates = _merge_candidates("G-e7a248ce")
    candidates["candidate_groups"][0]["member_count"] = 3
    candidates["candidate_groups"][0]["members"] = [{"index": 0}, {"index": 1}, {"index": 2}]
    (output / ".merge-candidates.json").write_text(json.dumps(candidates), encoding="utf-8")
    payload = (output / ".merge-candidates.json").read_bytes()
    controller._write_merge_review_context(output, candidates, payload)
    (output / ".merge-decisions.json").write_text(
        json.dumps(
            {
                "version": 2,
                "generated_at": "2026-08-06T00:00:00Z",
                "model": "sonnet",
                "decisions": [
                    {
                        "group_id": "G-e7a248ce",
                        "action": "merge",
                        "member_indices": [0, 2],
                        "merge_target_index": 0,
                        "rationale": "Same authorization defect.",
                    },
                    {
                        "group_id": "G-e7a248ce",
                        "action": "keep",
                        "member_indices": [1],
                        "rationale": "Distinct validation defect.",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(controller, "_validated_json_receipt", _receipt_stub)
    monkeypatch.setattr(controller, "consume_artifact_receipt", lambda *_args, **_kwargs: b"")
    monkeypatch.setattr(controller, "_run_script", lambda *args, **kwargs: _completed())
    monkeypatch.setattr(controller, "_context_v2_after_merge", lambda *_args, **_kwargs: {"action": "run_gate"})

    assert controller.context_v2_post_merge(output) == {"action": "run_gate"}


def test_context_v2_merge_decisions_reject_overlapping_partial_subsets():
    candidates = _merge_candidates("G-e7a248ce")
    decisions = {
        "version": 2,
        "generated_at": "2026-08-07T00:00:00Z",
        "model": "sonnet",
        "decisions": [
            {
                "group_id": "G-e7a248ce",
                "action": "merge",
                "member_indices": [0, 1],
                "merge_target_index": 0,
                "rationale": "Members zero and one share one mechanism.",
            },
            {
                "group_id": "G-e7a248ce",
                "action": "keep",
                "member_indices": [1],
                "rationale": "Member one remains distinct.",
            },
        ],
    }

    with pytest.raises(controller.ControllerError, match="overlapping member subsets"):
        controller._validate_context_v2_merge_decision_subsets(decisions, candidates)


def test_duration_estimate_forwards_resolved_profile(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path, "rebuild")
    cfg.update(
        {
            "architect_review": True,
            "skip_qa": True,
            "skip_abuse_case_verification": True,
            "max_stride_components": 7,
        }
    )
    captured: list[str] = []

    def fake_run(name, args, **kwargs):
        assert name == "estimate_duration.py"
        captured.extend(args)
        return _completed(
            json.dumps(
                {
                    "total_pretty": "42 min",
                    "stage1_min": 20,
                    "source": "parametric",
                }
            )
        )

    monkeypatch.setattr(controller, "_run_script", fake_run)
    estimate = controller._duration_estimate(cfg)
    assert estimate["estimate_total_pretty"] == "42 min"
    assert estimate["estimate_stage1_min"] == 20
    assert "--architect-review" in captured
    assert "--skip-qa" in captured
    assert "--skip-abuse-cases" in captured
    assert captured[captured.index("--mode") + 1] == "rebuild"
    assert captured[captured.index("--max-stride-components") + 1] == "7"


def test_thin_runtime_is_default_with_opt_out(monkeypatch, tmp_path):
    # Post-parity flip: the compact runtime is the default for full/rebuild;
    # APPSEC_THIN_ORCHESTRATOR=0 is the explicit opt-out back to legacy.
    cfg = _cfg(tmp_path)
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.delenv("APPSEC_THIN_ORCHESTRATOR", raising=False)
    assert controller.route([])["runtime"] == "thin-full"
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "0")
    assert controller.route([])["runtime"] == "legacy"


def test_agents_routes_to_orchestration_action_contract():
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "docs/internal/contracts/orchestration-actions.md" in agents


# --- _emit / main: the CLI + exit-code boundary --------------------------------


def test_emit_returns_zero_for_non_abort_action(capsys):
    code = controller._emit(
        {
            "schema_version": 1,
            "action": "complete",
            "mode": "full",
            "stage": "complete",
            "config_path": "/tmp/.skill-config.json",
            "dispatch_values": {},
        }
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["action"] == "complete"


def test_emit_returns_exit_code_for_valid_abort(capsys):
    code = controller._emit(
        {
            "schema_version": 1,
            "action": "abort",
            "reason": "blocked",
            "exit_code": 3,
        }
    )
    assert code == 3
    assert json.loads(capsys.readouterr().out)["exit_code"] == 3


def test_emit_rewrites_invalid_action_to_abort(capsys):
    code = controller._emit(
        {
            "schema_version": 1,
            "action": "run_gate",
            "command": "rm -rf /",
        }
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["action"] == "abort"
    assert "validation failed" in payload["reason"]
    assert code == 2


def test_main_route_end_to_end(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    monkeypatch.setattr(controller, "_resolve", lambda argv: _cfg(tmp_path))
    code = controller.main(["route", "--", "--full"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["action"] == "load_runtime"
    assert payload["runtime"] == "thin-full"


def test_main_next_end_to_end(tmp_path, capsys):
    output = tmp_path / "out"
    output.mkdir()
    (output / ".skill-config.json").write_text(json.dumps(_cfg(tmp_path)))
    code = controller.main(["next", "--output-dir", str(output)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["stage"] == "stage1"


def test_main_maps_controller_error_to_exit_code(monkeypatch, tmp_path, capsys):
    def boom(_path):
        raise controller.ControllerError("rehydrate failed", 4)

    monkeypatch.setattr(controller, "next_action", boom)
    code = controller.main(["next", "--output-dir", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 4
    assert payload["action"] == "abort"
    assert payload["exit_code"] == 4


def test_main_prepare_forwards_force_flag(monkeypatch, capsys):
    seen: dict[str, object] = {}

    def fake_prepare(argv, *, force=False):
        seen["argv"] = argv
        seen["force"] = force
        return {"schema_version": 1, "action": "abort", "reason": "x", "exit_code": 0}

    monkeypatch.setattr(controller, "prepare", fake_prepare)
    controller.main(["prepare", "--force", "--", "--rebuild"])
    assert seen["force"] is True
    assert seen["argv"] == ["--rebuild"]


# --- post-lock failure must release the lock -----------------------------------


def test_post_lock_controller_error_releases_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    output = Path(cfg["output_dir"])
    repo = Path(cfg["repo_root"])
    output.mkdir(parents=True)
    repo.mkdir()
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)

    def run(name, args, **kwargs):
        if name == "acquire_lock.py":
            (output / ".appsec-lock").write_text("pid=1\n", encoding="utf-8")
            return _completed("LOCK_ACQUIRED\n")
        if name == "validate_cache.py":
            raise controller.ControllerError("validate boom", 4)
        return _completed()

    monkeypatch.setattr(controller, "_run_script", run)
    with pytest.raises(controller.ControllerError):
        controller.prepare(["--full"])
    assert not (output / ".appsec-lock").exists()


def test_post_lock_oserror_is_wrapped_and_releases_lock(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    output = Path(cfg["output_dir"])
    repo = Path(cfg["repo_root"])
    output.mkdir(parents=True)
    repo.mkdir()
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(controller, "_activate_markers", lambda cfg: None)

    def run(name, args, **kwargs):
        if name == "acquire_lock.py":
            (output / ".appsec-lock").write_text("pid=1\n", encoding="utf-8")
            return _completed("LOCK_ACQUIRED\n")
        if name == "validate_cache.py":
            raise OSError("disk full")
        return _completed()

    monkeypatch.setattr(controller, "_run_script", run)
    with pytest.raises(controller.ControllerError) as excinfo:
        controller.prepare(["--full"])
    assert "preflight filesystem operation failed" in str(excinfo.value)
    assert not (output / ".appsec-lock").exists()


# --- verbose/tracing markers ---------------------------------------------------


def test_markers_activate_then_deactivate(monkeypatch, tmp_path):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    uid = controller.os.getuid()
    controller._activate_markers({"verbose": True, "tracing": True})
    assert (tmp_path / f".appsec-verbose-{uid}").exists()
    assert (tmp_path / f".appsec-tracing-{uid}").exists()
    controller._deactivate_markers()
    assert not (tmp_path / f".appsec-verbose-{uid}").exists()
    assert not (tmp_path / f".appsec-tracing-{uid}").exists()


def test_deactivate_markers_is_idempotent(monkeypatch, tmp_path):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    controller._deactivate_markers()  # nothing to remove → no error


# --- _fetch_requirements arg modes ---------------------------------------------


def _capture_fetch_args(monkeypatch, cfg) -> list[str]:
    captured: dict[str, list[str]] = {}

    def fake(name, args, **kwargs):
        captured["args"] = args
        return _completed()

    monkeypatch.setattr(controller, "_run_script", fake)
    controller._fetch_requirements(cfg)
    return captured["args"]


def test_fetch_requirements_require_mode(monkeypatch, tmp_path):
    args = _capture_fetch_args(
        monkeypatch,
        {"output_dir": str(tmp_path), "check_requirements": True},
    )
    assert "--require" in args


def test_fetch_requirements_override_url(monkeypatch, tmp_path):
    args = _capture_fetch_args(
        monkeypatch,
        {
            "output_dir": str(tmp_path),
            "check_requirements": True,
            "requirements_url_override": "https://example/reqs.yaml",
        },
    )
    assert "--requirements" in args
    assert "https://example/reqs.yaml" in args


def test_fetch_requirements_disabled(monkeypatch, tmp_path):
    args = _capture_fetch_args(
        monkeypatch,
        {"output_dir": str(tmp_path), "check_requirements": False},
    )
    assert "--no-requirements" in args


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


def test_prepasses_warns_when_route_inventory_missing(monkeypatch, tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    cfg = _cfg(tmp_path)
    cfg["output_dir"] = str(output)
    monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())
    receipts: list[str] = []
    controller._prepasses(cfg, receipts)
    log = (output / ".agent-run.log").read_text(encoding="utf-8")
    assert "Phase 6 fallback remains active" in log
    assert "WARN" in log
    assert len(receipts) == 3


# --- _duration_estimate fallbacks ----------------------------------------------


def test_duration_estimate_falls_back_on_error(monkeypatch, tmp_path):
    def boom(name, args, **kwargs):
        raise controller.ControllerError("estimate boom")

    monkeypatch.setattr(controller, "_run_script", boom)
    estimate = controller._duration_estimate(_cfg(tmp_path))
    assert estimate["estimate_total_pretty"] == "25 min"
    assert estimate["estimate_source"] == "parametric"


def test_duration_estimate_ignores_non_dict_json(monkeypatch, tmp_path):
    monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed("[1, 2, 3]"))
    estimate = controller._duration_estimate(_cfg(tmp_path))
    assert estimate["estimate_stage1_min"] == 25


# --- _checkpoint_needs_render branches -----------------------------------------


def test_checkpoint_needs_render_true(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=10b status=completed need_render=true\n", encoding="utf-8")
    assert controller._checkpoint_needs_render(tmp_path) is True


def test_checkpoint_needs_render_true_when_stale_report_present(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text(
        "phase=10b status=completed need_render=true\n",
        encoding="utf-8",
    )
    (tmp_path / "threat-model.md").write_text("x", encoding="utf-8")
    assert controller._checkpoint_needs_render(tmp_path) is True


def test_checkpoint_needs_render_requires_completed_status(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=10b need_render=true\n", encoding="utf-8")
    assert controller._checkpoint_needs_render(tmp_path) is False


def test_checkpoint_needs_render_false_for_other_phase(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=9 need_render=true\n", encoding="utf-8")
    assert controller._checkpoint_needs_render(tmp_path) is False


def test_checkpoint_needs_render_handles_empty_checkpoint(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("", encoding="utf-8")
    assert controller._checkpoint_needs_render(tmp_path) is False


# --- rebuild clean-slate note + actor-model env --------------------------------


def test_rebuild_clean_slate_note(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path, "rebuild")
    output = Path(cfg["output_dir"])
    repo = Path(cfg["repo_root"])
    output.mkdir(parents=True)
    repo.mkdir()
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(controller, "_run_script", lambda name, args, **kwargs: _completed("lock\n"))
    monkeypatch.setattr(controller, "_prepasses", lambda cfg, receipts: None)
    monkeypatch.setattr(controller, "_fetch_requirements", lambda cfg: None)
    monkeypatch.setattr(
        controller.resolve_config,
        "render_run_plan",
        lambda *args: "Threat Model — Pre-flight\n",
    )
    action = controller.prepare(["--rebuild"])
    assert "clean slate" in action["run_plan"]


def test_next_action_aborts_on_unreadable_config(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    with pytest.raises(controller.ControllerError):
        controller.next_action(output)


def test_prepare_surfaces_validator_and_session_advisories(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_THIN_ORCHESTRATOR", "1")
    cfg = _cfg(tmp_path)
    output = Path(cfg["output_dir"])
    repo = Path(cfg["repo_root"])
    output.mkdir(parents=True)
    repo.mkdir()
    monkeypatch.setattr(controller, "_resolve", lambda argv: cfg)
    monkeypatch.setattr(controller, "_run_script", lambda name, args, **kwargs: _completed("lock\n"))
    monkeypatch.setattr(controller, "_prepasses", lambda cfg, receipts: None)
    monkeypatch.setattr(controller, "_fetch_requirements", lambda cfg: None)
    monkeypatch.setattr(
        controller.resolve_config,
        "render_run_plan",
        lambda *args: "Threat Model — Pre-flight\n",
    )
    monkeypatch.setattr(controller, "_validator_advisory", lambda: "install mermaid")
    monkeypatch.setattr(controller, "_session_context_advisory", lambda output_dir: "non-empty session")
    action = controller.prepare(["--full"])
    assert "install mermaid" in action["run_plan"]
    assert "non-empty session" in action["run_plan"]
    log = (output / ".agent-run.log").read_text(encoding="utf-8")
    assert "VALIDATOR_ADVISORY" in log
    assert "SESSION_CONTEXT_ADVISORY" in log


def test_resolve_strips_force_before_config(monkeypatch):
    seen: dict[str, list[str]] = {}

    def fake_resolve(argv, root):
        seen["argv"] = argv
        return {"mode": "full"}

    monkeypatch.setattr(controller.resolve_config, "resolve", fake_resolve)
    controller._resolve(["--force", "--full"])
    assert "--force" not in seen["argv"]
    assert "--full" in seen["argv"]


def test_append_event_swallows_oserror(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    # output_dir.mkdir() raises because the parent path is a file → swallowed.
    controller._append_event(blocker / "sub", "EVENT", "detail")


def test_unlink_matching_handles_missing_directory(tmp_path):
    assert controller._unlink_matching(tmp_path / "absent", {"x"}, ()) == []


def test_persist_config_replaces_org_profile_symlink(tmp_path):
    output = tmp_path / "out"
    outside = tmp_path / "outside-org.json"
    output.mkdir()
    outside.write_text('{"owner":"user"}', encoding="utf-8")
    (output / ".org-profile-effective.json").symlink_to(outside)
    controller._persist_config(_cfg(tmp_path), output)
    assert not (output / ".org-profile-effective.json").is_symlink()
    assert outside.read_text(encoding="utf-8") == '{"owner":"user"}'


def test_dispatch_values_uses_actor_model_env(monkeypatch, tmp_path):
    monkeypatch.setenv("APPSEC_ACTOR_DISCOVERY_MODEL", "opus")
    values = controller._dispatch_values(
        _cfg(tmp_path),
        {
            "estimate_total_pretty": "25 min",
            "estimate_stage1_min": 25,
            "estimate_stage2_min": 8,
            "estimate_stage3_min": 7,
            "estimate_stage4_min": 4,
            "estimate_source": "parametric",
        },
    )
    assert values["actor_discovery_model"] == "opus"


# ---------------------------------------------------------------------------
# Interactive orchestrator-model prompt signal (thin-path ACTION)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "session,headless,expected",
    [
        ("claude-sonnet-5", False, True),  # Sonnet-5 session diverges from 4.6 rec
        ("claude-opus-4-8", False, True),  # Opus session diverges too
        ("claude-sonnet-4-6", False, False),  # matches rec → no prompt
        ("", False, False),  # undetected → no prompt (fail-safe)
        ("claude-opus-4-8", True, False),  # headless → suppressed
    ],
)
def test_orchestrator_prompt_needed_signal(monkeypatch, tmp_path, session, headless, expected):
    plugin_root = Path(__file__).resolve().parent.parent
    monkeypatch.setattr(controller.detect_session_model, "detect_session_model", lambda: session)
    if headless:
        monkeypatch.setenv("APPSEC_HEADLESS", "1")
    else:
        monkeypatch.delenv("APPSEC_HEADLESS", raising=False)
    action = controller.prepare(["--repo", str(plugin_root), "--output", str(tmp_path / "out"), "--keep-runtime-files"])
    assert action["action"] == "dispatch_agent"
    assert action["session_model"] == session
    assert action["orchestrator_prompt_needed"] is expected
    if expected:
        # a divergent, interactive run must carry the fields the SKILL prompt needs
        assert action["orchestrator_recommended_model"]
        assert action["orchestrator_recommendation_reason"]


# --- Bootstrap-stub recovery (2026-07-19) -----------------------------------
# `triage_compute_ranking.py --bootstrap-yaml` leaves a `meta._bootstrap` stub
# when Phase 11 is cut off. Every gate in `next` only tested that
# threat-model.yaml EXISTS, so the stub passed as canonical and the run
# continued on an empty model.


def _write_yaml(path: Path, meta: dict) -> None:
    import yaml

    path.write_text(yaml.safe_dump({"meta": meta, "threats": []}), encoding="utf-8")


def test_canonical_yaml_needs_no_upgrade(tmp_path):
    _write_yaml(tmp_path / "threat-model.yaml", {"analysis_version": 3})
    assert controller._upgrade_bootstrap_yaml(tmp_path, {}) is True


def test_bootstrap_stub_without_intermediates_falls_back(tmp_path):
    """Nothing to rebuild from → False so `next` re-dispatches Stage 1 rather
    than composing a report out of an empty model."""
    _write_yaml(tmp_path / "threat-model.yaml", {"analysis_version": 3, "_bootstrap": True})
    assert controller._upgrade_bootstrap_yaml(tmp_path, {}) is False


def test_unreadable_yaml_is_not_claimed_by_the_bootstrap_gate(tmp_path):
    """An unparseable yaml is a different failure owned by downstream gates —
    this helper must not change that behaviour."""
    (tmp_path / "threat-model.yaml").write_text("{[ broken", encoding="utf-8")
    assert controller._upgrade_bootstrap_yaml(tmp_path, {}) is True


def test_missing_yaml_is_not_claimed_by_the_bootstrap_gate(tmp_path):
    assert controller._upgrade_bootstrap_yaml(tmp_path, {}) is True


def test_bootstrap_stub_is_upgraded_when_rebuild_succeeds(tmp_path, monkeypatch):
    """Positive path: the rebuild script clears the marker → True, and `next`
    proceeds on a canonical model."""
    import yaml

    yaml_path = tmp_path / "threat-model.yaml"
    _write_yaml(yaml_path, {"analysis_version": 3, "_bootstrap": True})

    def _fake_run(cmd, **kwargs):
        assert "build_threat_model_yaml.py" in " ".join(str(c) for c in cmd)
        yaml_path.write_text(
            yaml.safe_dump({"meta": {"analysis_version": 3}, "threats": [], "attack_surface": [{"id": "AS-1"}]}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(controller.subprocess, "run", _fake_run)
    assert controller._upgrade_bootstrap_yaml(tmp_path, {"repo_root": str(tmp_path)}) is True
    assert "_bootstrap" not in yaml.safe_load(yaml_path.read_text(encoding="utf-8"))["meta"]


def test_bootstrap_upgrade_survives_a_failing_rebuild(tmp_path, monkeypatch):
    _write_yaml(tmp_path / "threat-model.yaml", {"analysis_version": 3, "_bootstrap": True})
    monkeypatch.setattr(
        controller.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "boom"),
    )
    assert controller._upgrade_bootstrap_yaml(tmp_path, {}) is False


# ---------------------------------------------------------------------------
# Deterministic yaml-derived export backstop (_export_if_configured)
# ---------------------------------------------------------------------------

_DRAGON_SOURCE = ROOT / "tests" / "fixtures" / "threat-dragon" / "threat-model.source.yaml"


def _export_run_dir(tmp_path: Path, **cfg_overrides) -> tuple[Path, dict]:
    """A run that has reached completion: yaml + report + QA status on disk."""
    output = tmp_path / "out"
    output.mkdir()
    (output / "threat-model.yaml").write_text(_DRAGON_SOURCE.read_text(encoding="utf-8"), encoding="utf-8")
    (output / "threat-model.md").write_text("# report\n", encoding="utf-8")
    (output / ".qa-status.json").write_text("{}", encoding="utf-8")
    cfg = _cfg(tmp_path)
    cfg.update(cfg_overrides)
    return output, cfg


def test_threatdragon_export_is_produced_without_an_llm_step(tmp_path):
    """The regression: --threatdragon was only ever triggered by Phase-11
    substeps of the analyst, which the thin runtime never reaches — so the run
    promised the artefact and shipped nothing."""
    output, cfg = _export_run_dir(tmp_path, write_threatdragon=True)

    controller._export_if_configured(output, cfg)

    exported = output / "threat-model.threatdragon.json"
    assert exported.is_file()
    assert json.loads(exported.read_text(encoding="utf-8"))["version"]


def test_export_backstop_is_skipped_when_not_requested(tmp_path):
    output, cfg = _export_run_dir(tmp_path, write_threatdragon=False, write_sarif=False)

    controller._export_if_configured(output, cfg)

    assert not (output / "threat-model.threatdragon.json").exists()
    assert not (output / "threat-model.sarif.json").exists()


def test_export_backstop_leaves_an_existing_artefact_alone(tmp_path, monkeypatch):
    """Idempotent: an export the analyst already wrote is never regenerated."""
    output, cfg = _export_run_dir(tmp_path, write_threatdragon=True)
    (output / "threat-model.threatdragon.json").write_text('{"mine": true}', encoding="utf-8")

    calls = []
    monkeypatch.setattr(controller.subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    controller._export_if_configured(output, cfg)

    assert calls == []
    assert json.loads((output / "threat-model.threatdragon.json").read_text(encoding="utf-8")) == {"mine": True}


def test_export_backstop_never_raises_into_next(tmp_path, monkeypatch):
    output, cfg = _export_run_dir(tmp_path, write_threatdragon=True)
    monkeypatch.setattr(
        controller.subprocess,
        "run",
        lambda cmd, **kw: (_ for _ in ()).throw(OSError("boom")),
    )
    controller._export_if_configured(output, cfg)  # must not propagate


def test_export_backstop_needs_a_model_to_derive_from(tmp_path):
    output, cfg = _export_run_dir(tmp_path, write_threatdragon=True)
    (output / "threat-model.yaml").unlink()

    controller._export_if_configured(output, cfg)

    assert not (output / "threat-model.threatdragon.json").exists()


def test_next_action_exports_before_stamping(tmp_path):
    """Ordering matters: stamp_threat_model.py copies the export, so the export
    must exist by the time the stamp runs."""
    output, cfg = _export_run_dir(tmp_path, write_threatdragon=True, slug="s1")
    (output / ".skill-config.json").write_text(json.dumps(cfg), encoding="utf-8")

    action = controller.next_action(output)

    assert action["action"] == "complete"
    assert (output / "threat-model.threatdragon.json").is_file()
    assert (output / "threat-model-s1.threatdragon.json").is_file()


def _context_v2_run(tmp_path: Path, **overrides) -> Path:
    """A context-v2 run directory with a repo root that exists."""
    (tmp_path / "repo").mkdir(exist_ok=True)
    return _write_context_v2_config(tmp_path, **overrides)


def _context_v2_prepass_stub(output: Path):
    def run(name, _args, **_kwargs):
        if name == "build_threat_modeling_context.py":
            (output / ".threat-modeling-context.md").write_text(_valid_threat_modeling_context(), encoding="utf-8")
        return _completed("{}")

    return run


class TestContextV2ReconWave:
    def test_every_semantic_role_has_pre_handoff_contract_enforcement(self):
        classified = controller.CONTEXT_V2_PRODUCER_GATED_ROLES | controller.CONTEXT_V2_CONTROLLER_RECOVERY_ROLES

        assert classified == set(controller.SEMANTIC_ROLE_REGISTRY)
        assert controller.CONTEXT_V2_PRODUCER_GATED_ROLES.isdisjoint(controller.CONTEXT_V2_CONTROLLER_RECOVERY_ROLES)

    def test_begin_builds_context_and_dispatches_only_recon_when_iac_exists(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        (tmp_path / "repo" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))
        action = controller.context_v2_begin(output)
        assert action["action"] == "dispatch_parallel"
        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert roles == ["recon_scanner"]
        assert not (output / ".config-scan-findings.json").exists()
        assert (output / ".threat-modeling-context.md").is_file()
        assert any(receipt["artifact_path"] == ".threat-modeling-context.md" for receipt in action["artifact_receipts"])
        recon = next(job for job in action["dispatch_jobs"] if job["semantic_role"] == "recon_scanner")
        assert recon["output_artifacts"] == [".recon-summary.md", ".recon-signals.json"]

    def test_begin_writes_a_config_scan_stub_without_iac_surface(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))
        action = controller.context_v2_begin(output)
        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert "config_scanner" not in roles
        stub = json.loads((output / ".config-scan-findings.json").read_text(encoding="utf-8"))
        assert stub["findings"] == []
        assert "parse_error" in stub

    def test_invalid_optional_recon_patterns_are_not_delivered(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)

        def fake_script(name, _args, **_kwargs):
            if name == "build_threat_modeling_context.py":
                (output / ".threat-modeling-context.md").write_text(_valid_threat_modeling_context(), encoding="utf-8")
            return _completed("{}")

        monkeypatch.setattr(controller, "_run_script", fake_script)

        action = controller.context_v2_begin(output)

        recon = next(job for job in action["dispatch_jobs"] if job["semantic_role"] == "recon_scanner")
        assert recon["input_artifacts"] == [".skill-config.json"]
        assert not (output / ".recon-patterns.json").exists()
        assert not any(receipt["artifact_path"] == ".recon-patterns.json" for receipt in action["artifact_receipts"])

    def test_a_full_run_always_re_resolves_context(self, tmp_path, monkeypatch):
        """An existing context file survives full cleanup; presence is not a cache hit."""
        output = _context_v2_run(tmp_path)
        (output / ".threat-modeling-context.md").write_text("stale\n", encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))
        action = controller.context_v2_begin(output)
        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert "context_resolver" not in roles
        assert (output / ".threat-modeling-context.md").read_text(encoding="utf-8") != "stale\n"

    def test_incremental_reuses_context_newer_than_head(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path, incremental=True)
        (output / ".threat-modeling-context.md").write_text(_valid_threat_modeling_context(), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))
        monkeypatch.setattr(controller.subprocess, "run", lambda *a, **k: _completed("1\n"))
        action = controller.context_v2_begin(output)
        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert "context_resolver" not in roles

    def test_incremental_re_resolves_context_older_than_head(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path, incremental=True)
        (output / ".threat-modeling-context.md").write_text("stale\n", encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))
        future = str(int(Path(output / ".threat-modeling-context.md").stat().st_mtime) + 10_000)
        monkeypatch.setattr(controller.subprocess, "run", lambda *a, **k: _completed(future + "\n"))
        action = controller.context_v2_begin(output)
        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert "context_resolver" not in roles
        assert (output / ".threat-modeling-context.md").read_text(encoding="utf-8") != "stale\n"

    def test_begin_reuses_recon_when_the_fingerprint_is_unchanged(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path, incremental=True)
        (tmp_path / "repo" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (output / ".recon-summary.md").write_text(_valid_recon_summary(), encoding="utf-8")
        (output / ".recon-signals.json").write_text(json.dumps(_valid_recon_signals()), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))
        monkeypatch.setattr(
            controller,
            "_context_v2_after_recon",
            lambda *_a, **_k: {"action": "dispatch_agent", "dispatch_jobs": []},
        )
        action = controller.context_v2_begin(output)
        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert "recon_scanner" not in roles

    def test_begin_does_not_reuse_legacy_free_form_recon_evidence(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path, incremental=True)
        (output / ".recon-summary.md").write_text(_valid_recon_summary(), encoding="utf-8")
        legacy = _valid_recon_signals()
        legacy["schema_version"] = 1
        legacy["signal_evidence"] = {key: "none" for key in legacy["signals"]}
        (output / ".recon-signals.json").write_text(json.dumps(legacy), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))

        action = controller.context_v2_begin(output)

        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert "recon_scanner" in roles

    def test_begin_runs_recon_when_the_fingerprint_check_fails(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path, incremental=True)
        (output / ".recon-summary.md").write_text("prior\n", encoding="utf-8")

        def fake_script(name, args, **kwargs):
            if name == "baseline_state.py":
                raise controller.ControllerError("fingerprint changed")
            if name == "build_threat_modeling_context.py":
                (output / ".threat-modeling-context.md").write_text(_valid_threat_modeling_context(), encoding="utf-8")
            return _completed("{}")

        monkeypatch.setattr(controller, "_run_script", fake_script)
        action = controller.context_v2_begin(output)
        roles = [job["semantic_role"] for job in action["dispatch_jobs"]]
        assert "recon_scanner" in roles

    def test_begin_continues_deterministically_when_the_wave_is_empty(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path, incremental=True)
        (output / ".recon-summary.md").write_text(_valid_recon_summary(), encoding="utf-8")
        (output / ".recon-signals.json").write_text(json.dumps(_valid_recon_signals()), encoding="utf-8")
        (output / ".threat-modeling-context.md").write_text(_valid_threat_modeling_context(), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed("{}"))
        monkeypatch.setattr(controller.subprocess, "run", lambda *a, **k: _completed("1\n"))
        monkeypatch.setattr(controller, "_context_v2_after_recon", lambda *_a, **_k: {"action": "dispatch_agent"})
        assert controller.context_v2_begin(output)["action"] == "dispatch_agent"


class TestContextV2PostRecon:
    def _prepare(self, tmp_path, **overrides):
        output = _context_v2_run(tmp_path, **overrides)
        (output / ".recon-summary.md").write_text(_valid_recon_summary(), encoding="utf-8")
        (output / ".threat-modeling-context.md").write_text(_valid_threat_modeling_context(), encoding="utf-8")
        (output / ".recon-signals.json").write_text(json.dumps(_valid_recon_signals()), encoding="utf-8")
        _write_architecture_receipt_inputs(output)
        return output

    def test_post_recon_requires_the_recon_summary(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())
        with pytest.raises(controller.ControllerError, match="recon-summary"):
            controller.context_v2_post_recon(output)

    def test_invalid_optional_config_scan_is_replaced_before_downstream_use(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        (output / ".config-scan-findings.json").write_text("not json\n", encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *_a, **_k: _completed())

        def best_effort(_output, name, args, _receipts, **_kwargs):
            return not (name == "validate_intermediate.py" and args[0] == "config_scan_findings")

        monkeypatch.setattr(controller, "_best_effort_script", best_effort)
        monkeypatch.setattr(
            controller,
            "_context_v2_dispatch_architecture",
            lambda *_a, **_k: {"action": "dispatch_agent"},
        )

        controller.context_v2_post_recon(output)

        config = json.loads((output / ".config-scan-findings.json").read_text(encoding="utf-8"))
        assert config == {"parse_error": "skipped: no IaC surface detected", "findings": []}

    def test_post_recon_reproduces_config_scan_from_catalog_before_validation(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        repo = tmp_path / "repo"
        (repo / "Dockerfile").write_text("FROM runtime:latest\n", encoding="utf-8")
        (output / ".config-scan-findings.json").write_text("{}\n", encoding="utf-8")
        calls = []

        monkeypatch.setattr(controller, "_run_script", lambda *_a, **_k: _completed())

        def best_effort(_output, name, args, _receipts, **_kwargs):
            calls.append((name, args))
            if name == "config_iac_scanner.py":
                (output / ".config-scan-findings.json").write_text("{}\n", encoding="utf-8")
            return True

        monkeypatch.setattr(controller, "_best_effort_script", best_effort)
        monkeypatch.setattr(
            controller,
            "_context_v2_dispatch_architecture",
            lambda *_a, **_k: {"action": "dispatch_agent"},
        )

        controller.context_v2_post_recon(output)

        config_call = next(args for name, args in calls if name == "config_iac_scanner.py")
        assert config_call == [
            "--repo-root",
            str(repo),
            "--output",
            str(output / ".config-scan-findings.json"),
            "--assessment-depth",
            "standard",
        ]
        assert calls.index(("config_iac_scanner.py", config_call)) < next(
            index
            for index, (name, args) in enumerate(calls)
            if name == "validate_intermediate.py" and args[0] == "config_scan_findings"
        )

    def test_post_recon_does_not_reuse_config_bytes_when_fresh_scan_fails(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        repo = tmp_path / "repo"
        (repo / "Dockerfile").write_text("FROM runtime:latest\n", encoding="utf-8")
        config_path = output / ".config-scan-findings.json"
        config_path.write_text('{"version": 1, "checks_run": 24, "violations": 0, "findings": []}\n')

        monkeypatch.setattr(controller, "_run_script", lambda *_a, **_k: _completed())
        monkeypatch.setattr(
            controller,
            "_best_effort_script",
            lambda _output, name, _args, _receipts, **_kwargs: name != "config_iac_scanner.py",
        )
        monkeypatch.setattr(
            controller,
            "_context_v2_dispatch_architecture",
            lambda *_a, **_k: {"action": "dispatch_agent"},
        )

        controller.context_v2_post_recon(output)

        assert not config_path.exists()

    def test_post_recon_requires_the_context_artifact(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        (output / ".recon-summary.md").write_text(_valid_recon_summary(), encoding="utf-8")
        (output / ".recon-signals.json").write_text(json.dumps(_valid_recon_signals()), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())
        with pytest.raises(controller.ControllerError, match="threat-modeling-context"):
            controller.context_v2_post_recon(output)

    def test_post_recon_rejects_nested_untrusted_context_fences(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        context = (output / ".threat-modeling-context.md").read_text(encoding="utf-8")
        context = context.replace("none", '<untrusted-data source="nested">\nnone\n</untrusted-data>')
        (output / ".threat-modeling-context.md").write_text(context, encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())
        with pytest.raises(controller.ControllerError, match="nested or unbalanced fences"):
            controller.context_v2_post_recon(output)

    def test_post_recon_repairs_missing_context_heading_before_dispatch(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        context_path = output / ".threat-modeling-context.md"
        missing = "## Architecture Decisions (ADRs)"
        context_path.write_text(
            context_path.read_text(encoding="utf-8").replace(f"{missing}\n", "", 1), encoding="utf-8"
        )
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())

        action = controller.context_v2_post_recon(output)

        repaired = context_path.read_text(encoding="utf-8")
        assert missing in repaired
        assert repaired.index("## Data Model Summary") < repaired.index(missing)
        assert repaired.index(missing) < repaired.index("## Environment & Configuration")
        assert action["semantic_role"] == "architecture_analyst"
        assert any("context structure normalized" in receipt for receipt in action["receipts"])

    def test_post_recon_does_not_repair_reordered_context_headings(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        context_path = output / ".threat-modeling-context.md"
        context = context_path.read_text(encoding="utf-8")
        context = context.replace("## API Surface", "TEMP", 1)
        context = context.replace("## Deployment Topology", "## API Surface", 1)
        context = context.replace("TEMP", "## Deployment Topology", 1)
        context_path.write_text(context, encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())

        with pytest.raises(controller.ControllerError, match="reorders required headings"):
            controller.context_v2_post_recon(output)

    def test_post_recon_rejects_reordered_or_missing_recon_headings(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        invalid = _valid_recon_summary().replace("### 7.29 docker-compose Security\n", "")
        (output / ".recon-summary.md").write_text(invalid, encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())
        with pytest.raises(controller.ControllerError, match=r"missing or reorders security section 7\.29"):
            controller.context_v2_post_recon(output)

    def test_post_recon_rejects_invalid_signal_contract(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        (output / ".recon-signals.json").write_text("{}", encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())
        with pytest.raises(controller.ControllerError, match="recon-signals-v2 validation failed"):
            controller.context_v2_post_recon(output)

    def test_post_recon_rejects_nonexistent_signal_evidence(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        signals = _valid_recon_signals()
        signals["signals"]["has_auth_surface"] = True
        signals["signal_evidence"]["has_auth_surface"] = {
            "status": "supporting",
            "locations": [{"file": "invented/auth.ts", "line": 1}],
        }
        (output / ".recon-signals.json").write_text(json.dumps(signals), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())

        with pytest.raises(controller.ControllerError, match="missing or unsafe file"):
            controller.context_v2_post_recon(output)

    def test_post_recon_rejects_invalid_architecture_projection(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        projection_path = output / ".dispatch-context/architecture/route-context.json"
        projection = json.loads(projection_path.read_text(encoding="utf-8"))
        projection["limits"]["max_routes"] = 97
        projection_path.write_text(json.dumps(projection), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())

        with pytest.raises(controller.ControllerError, match="architecture-route-context.*validation failed"):
            controller.context_v2_post_recon(output)

    def test_post_recon_rejects_stale_recon_projection(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        projection_path = output / ".dispatch-context/architecture/recon-summary-context.json"
        projection = json.loads(projection_path.read_text(encoding="utf-8"))
        projection["source"]["sha256"] = "f" * 64
        projection_path.write_text(json.dumps(projection), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())

        with pytest.raises(controller.ControllerError, match="stale for .recon-summary.md"):
            controller.context_v2_post_recon(output)

    @pytest.mark.parametrize("projection_name", ["recon-summary-context.json", "route-context.json"])
    def test_post_recon_rejects_schema_valid_projection_drift(self, tmp_path, monkeypatch, projection_name):
        output = self._prepare(tmp_path)
        projection_path = output / ".dispatch-context" / "architecture" / projection_name
        projection = json.loads(projection_path.read_text(encoding="utf-8"))
        if projection_name == "recon-summary-context.json":
            projection["sections"][0]["lines"] = ["schema-valid replacement"]
        else:
            projection["coverage"]["frameworks_detected"] = ["unknown"]
        projection_path.write_text(json.dumps(projection), encoding="utf-8")
        monkeypatch.setattr(controller, "_run_script", lambda *a, **k: _completed())

        with pytest.raises(controller.ControllerError, match="differs from its deterministic projection"):
            controller.context_v2_post_recon(output)

    def test_quick_depth_resolves_static_actors_but_skips_discovery(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path, assessment_depth="quick")
        calls: list[tuple[str, list[str]]] = []
        monkeypatch.setattr(
            controller, "_run_script", lambda name, args, **k: (calls.append((name, args)), _completed())[1]
        )
        action = controller.context_v2_post_recon(output)
        assert action["semantic_role"] == "architecture_analyst"
        assert not any(name == "actor_discovery_cache.py" for name, _ in calls)
        resolver = [args for name, args in calls if name == "resolve_actors.py"]
        assert resolver and "--quick" in resolver[0]

    def test_thorough_depth_runs_the_database_separation_scan(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path, assessment_depth="thorough")
        calls: list[str] = []
        monkeypatch.setattr(controller, "_run_script", lambda name, args, **k: (calls.append(name), _completed())[1])
        controller.context_v2_post_recon(output)
        assert "database_privilege_separation.py" in calls

    def test_standard_depth_omits_the_database_separation_scan(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        calls: list[str] = []
        monkeypatch.setattr(controller, "_run_script", lambda name, args, **k: (calls.append(name), _completed())[1])
        controller.context_v2_post_recon(output)
        assert "database_privilege_separation.py" not in calls

    def test_discovery_disabled_by_repo_config_goes_straight_to_architecture(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        calls: list[str] = []
        monkeypatch.setattr(controller, "_run_script", lambda name, args, **k: (calls.append(name), _completed())[1])
        action = controller.context_v2_post_recon(output)
        assert action["semantic_role"] == "architecture_analyst"
        assert "actor_discovery_cache.py" not in calls

    def test_discovery_cache_miss_dispatches_the_discoverer(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        _write_architecture_receipt_inputs(output, discovery_enabled=True)

        def fake_script(name, args, **kwargs):
            if name == "actor_discovery_cache.py":
                return _completed("cache-key-1" if args[0] == "compute" else "miss")
            return _completed()

        monkeypatch.setattr(controller, "_run_script", fake_script)
        action = controller.context_v2_post_recon(output)
        assert action["semantic_role"] == "actor_discoverer"
        assert action["dispatch_jobs"][0]["output_artifacts"] == [".actors-discovered.json"]
        static_receipt = next(
            receipt
            for receipt in action["artifact_receipts"]
            if receipt["artifact_path"] == ".actors-merged-static.json"
        )
        assert static_receipt["schema_id"] == "schemas/actors-merged-static.schema.yaml#v1", (
            "ST-1: the static actor receipt must validate the bytes against their own contract"
        )
        controller.consume_artifact_receipt(output, static_receipt)

    def test_raw_recon_warning_does_not_expand_actor_projection(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        summary_path = output / ".recon-summary.md"
        summary_path.write_text(
            _valid_recon_summary() + "\n" + "\n".join(f"additional raw evidence {index}" for index in range(300)),
            encoding="utf-8",
        )
        _write_architecture_receipt_inputs(output, discovery_enabled=True)

        def fake_script(name, args, **kwargs):
            if name == "actor_discovery_cache.py":
                return _completed("cache-key-1" if args[0] == "compute" else "miss")
            return _completed()

        monkeypatch.setattr(controller, "_run_script", fake_script)
        action = controller.context_v2_post_recon(output)

        assert action["semantic_role"] == "actor_discoverer"
        projection_path = output / ".dispatch-context/architecture/recon-summary-context.json"
        projection = json.loads(projection_path.read_text(encoding="utf-8"))
        payload = projection_path.read_bytes()
        bindings = json.loads((ROOT / "data/context-routing-bindings.json").read_text(encoding="utf-8"))
        profile = bindings["limit_profiles"]["recon_projection"]
        assert projection["source"]["line_count"] > controller.TARGET_RECON_SUMMARY_LINES
        assert projection["limits"]["retained_lines"] <= controller.TARGET_RECON_SUMMARY_LINES, (
            "CR-7: raw recon growth must not expand semantic delivery"
        )
        assert payload.count(b"\n") <= profile["max_lines"], (
            "CR-7: the actor and architecture projection must stay within its physical-line limit"
        )
        assert len(payload) <= profile["max_bytes"], (
            "CR-7: the actor and architecture projection must stay within its byte limit"
        )
        assert any(
            receipt["artifact_path"] == ".dispatch-context/architecture/recon-summary-context.json"
            for receipt in action["artifact_receipts"]
        )

    def test_discovery_cache_hit_skips_the_discoverer(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        _write_architecture_receipt_inputs(output, discovery_enabled=True)

        def fake_script(name, args, **kwargs):
            if name == "actor_discovery_cache.py":
                return _completed("cache-key-1" if args[0] == "compute" else "hit")
            return _completed()

        monkeypatch.setattr(controller, "_run_script", fake_script)
        assert controller.context_v2_post_recon(output)["semantic_role"] == "architecture_analyst"


class TestContextV2PostActors:
    def _prepare(self, tmp_path):
        output = _context_v2_run(tmp_path)
        (output / ".recon-summary.md").write_text(_valid_recon_summary(), encoding="utf-8")
        _write_architecture_receipt_inputs(output)
        return output

    @staticmethod
    def _script(calls: list[tuple[str, list[str]]], *, invalid_discovery: bool = False):
        def fake_script(name, args, **kwargs):
            calls.append((name, args))
            if name == "actor_discovery_cache.py" and args[0] == "compute":
                return _completed("cache-key-1")
            if invalid_discovery and name == "validate_intermediate.py" and args[0] == "actors_discovered":
                raise controller.ControllerError("invalid discovery contract")
            return _completed()

        return fake_script

    def test_valid_discovery_feeds_the_resolver_and_dispatches_architecture(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        calls: list[tuple[str, list[str]]] = []
        monkeypatch.setattr(controller, "_run_script", self._script(calls))
        action = controller.context_v2_post_actors(output)
        assert action["semantic_role"] == "architecture_analyst"
        resolver = [args for name, args in calls if name == "resolve_actors.py"]
        assert resolver and "--discovery-output" in resolver[0]
        # Valid output is never overwritten with the empty-discovery stub.
        assert not any(name == "actor_discovery_cache.py" and args[0] == "write-empty" for name, args in calls)

    def test_invalid_discovery_degrades_to_the_static_actor_set(self, tmp_path, monkeypatch):
        output = self._prepare(tmp_path)
        calls: list[tuple[str, list[str]]] = []
        monkeypatch.setattr(controller, "_run_script", self._script(calls, invalid_discovery=True))
        action = controller.context_v2_post_actors(output)
        assert action["semantic_role"] == "architecture_analyst"
        write_empty = [args for name, args in calls if name == "actor_discovery_cache.py" and args[0] == "write-empty"]
        assert write_empty
        # The stub must carry the same key the dispatch decision used.
        assert "cache-key-1" in write_empty[0]


class TestContextV2ArchitectureAndBoundary:
    def test_post_architecture_gates_then_dispatches_the_boundary_analyst(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        (output / ".trust-boundary-assessment-input.json").write_text(
            json.dumps(_trust_boundary_assessment()), encoding="utf-8"
        )
        gated: list[bool] = []

        def gate(_output, _cfg, *, controller_owned_handoff=False):
            gated.append(controller_owned_handoff)

        monkeypatch.setattr(controller, "_gate_architecture_stage", gate)
        action = controller.context_v2_post_architecture(output)
        assert gated == [True]
        assert action["semantic_role"] == "trust_boundary_analyst"
        assert action["dispatch_jobs"][0]["output_artifacts"] == [".trust-boundary-candidates.json"]
        receipt = action["artifact_receipts"][0]
        assert receipt["record_count"] == 2
        assert receipt["validation_status"] == "valid"
        # The receipt must bind the exact bytes on disk, not the agent's word.
        controller.consume_artifact_receipt(output, receipt)
        (output / ".trust-boundary-assessment-input.json").write_text("{}", encoding="utf-8")
        with pytest.raises(controller.ControllerError):
            controller.consume_artifact_receipt(output, receipt)

    def test_post_architecture_propagates_a_failed_gate(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)

        def fail(*_a, **_k):
            raise controller.ControllerError("architecture artifacts missing")

        monkeypatch.setattr(controller, "_gate_architecture_stage", fail)
        with pytest.raises(controller.ControllerError, match="architecture artifacts missing"):
            controller.context_v2_post_architecture(output)

    def test_context_v2_gate_finalizes_inventory_binds_fingerprint_and_writes_checkpoint(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        for name in (
            ".recon-summary.md",
            ".components.json",
            ".data-flows.json",
            ".assets.json",
            ".attack-surface-overrides.json",
        ):
            (output / name).write_text("{}", encoding="utf-8")
        fingerprint = "sha256:" + "a" * 64
        calls: list[tuple[str, list[str]]] = []

        def fake_script(name, args, **_kwargs):
            calls.append((name, args))
            if name == "finalize_component_inventory.py" and "--validate-only" not in args:
                (output / ".component-inventory-finalization.json").write_text(
                    json.dumps(
                        {
                            "schema_version": 1,
                            "component_inventory_fingerprint": fingerprint,
                            "component_ids": ["api"],
                            "injected_component_ids": [],
                            "collapsed_duplicate_count": 0,
                        }
                    ),
                    encoding="utf-8",
                )
            return _completed()

        monkeypatch.setattr(controller, "_run_script", fake_script)
        controller._gate_architecture_stage(output, _cfg(tmp_path), controller_owned_handoff=True)

        finalizer_calls = [args for name, args in calls if name == "finalize_component_inventory.py"]
        assert len(finalizer_calls) == 2
        assert "--validate-only" not in finalizer_calls[0]
        assert "--validate-only" in finalizer_calls[1]
        assert (
            json.loads((output / ".data-flows.json").read_text(encoding="utf-8"))["component_inventory_fingerprint"]
            == fingerprint
        )
        assert (output / ".appsec-checkpoint").read_text(encoding="utf-8") == (
            "phase=6 status=completed need_boundary_assessment=true\n"
        )

    def test_post_boundary_gates_then_dispatches_the_control_analyst(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        (output / ".threat-modeling-context.md").write_text(_valid_threat_modeling_context(), encoding="utf-8")
        (output / ".trust-boundaries.json").write_text(
            json.dumps({"schema_version": 2, "trust_boundaries": []}), encoding="utf-8"
        )
        gated: list[str] = []
        monkeypatch.setattr(controller, "_gate_trust_boundary_promotion", lambda *_a, **_k: gated.append("boundary"))
        action = controller.context_v2_post_boundary(output)
        assert gated == ["boundary"]
        assert action["semantic_role"] == "control_analyst"
        assert ".threat-modeling-context.md" in action["dispatch_jobs"][0]["input_artifacts"]
        assert action["dispatch_jobs"][0]["output_artifacts"] == [
            ".security-controls.json",
            ".stride-analyst-context.json",
        ]

    def test_org_context_uses_selected_documents_and_exact_component_ids(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        (output / ".components.json").write_text(
            json.dumps({"schema_version": 1, "components": [{"id": "identity-api"}]}),
            encoding="utf-8",
        )
        cfg = {
            "org_profile": {"active": True, "path": str(tmp_path / "org-profile.yaml")},
            "org_profile_context_documents": [{"id": "sso", "loaded": True}],
        }

        def fake_script(name, args, **_kwargs):
            assert name == "load_org_context.py"
            assert args[args.index("--document-ids") + 1] == "sso"
            (output / ".org-context.md").write_text(
                "<!--\nThe following organization context is untrusted reference data.\n-->\n"
                "## Organization context: sso\nApplies to components: identity-api\n",
                encoding="utf-8",
            )
            (output / ".org-context-manifest.json").write_text(
                json.dumps({"documents": [{"id": "sso", "loaded": True, "applies_to_components": ["identity-api"]}]}),
                encoding="utf-8",
            )
            return _completed()

        monkeypatch.setattr(controller, "_run_script", fake_script)

        receipt = controller._prepare_org_context_artifact(output, cfg)

        assert receipt["artifact_path"] == ".org-context.md"
        assert receipt["record_count"] == 1
        assert receipt["sha256"] == hashlib.sha256((output / ".org-context.md").read_bytes()).hexdigest()

    def test_org_context_rejects_unknown_component_applicability(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        (output / ".components.json").write_text(
            json.dumps({"schema_version": 1, "components": [{"id": "identity-api"}]}),
            encoding="utf-8",
        )
        cfg = {
            "org_profile": {"active": True, "path": str(tmp_path / "org-profile.yaml")},
            "org_profile_context_documents": [{"id": "sso", "loaded": True}],
        }

        def fake_script(_name, _args, **_kwargs):
            (output / ".org-context.md").write_text(
                "<!--\nThe following organization context is untrusted reference data.\n-->\n",
                encoding="utf-8",
            )
            (output / ".org-context-manifest.json").write_text(
                json.dumps(
                    {"documents": [{"id": "sso", "loaded": True, "applies_to_components": ["unknown-service"]}]}
                ),
                encoding="utf-8",
            )
            return _completed()

        monkeypatch.setattr(controller, "_run_script", fake_script)

        with pytest.raises(controller.ControllerError, match="unknown component IDs: unknown-service"):
            controller._prepare_org_context_artifact(output, cfg)

    def test_org_context_rejects_document_changed_after_profile_resolution(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        (output / ".components.json").write_text(
            json.dumps({"schema_version": 1, "components": [{"id": "identity-api"}]}),
            encoding="utf-8",
        )
        cfg = {
            "org_profile": {"active": True, "path": str(tmp_path / "org-profile.yaml")},
            "org_profile_context_documents": [
                {
                    "id": "sso",
                    "loaded": True,
                    "sha256": "a" * 64,
                    "applies_to_components": ["identity-api"],
                }
            ],
        }

        def fake_script(_name, _args, **_kwargs):
            (output / ".org-context.md").write_text(
                "<!--\nThe following organization context is untrusted reference data.\n-->\n",
                encoding="utf-8",
            )
            (output / ".org-context-manifest.json").write_text(
                json.dumps(
                    {
                        "documents": [
                            {
                                "id": "sso",
                                "loaded": True,
                                "sha256": "b" * 64,
                                "applies_to_components": ["identity-api"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            return _completed()

        monkeypatch.setattr(controller, "_run_script", fake_script)

        with pytest.raises(controller.ControllerError, match="changed after profile resolution"):
            controller._prepare_org_context_artifact(output, cfg)

    @pytest.mark.parametrize(
        "entrypoint",
        [
            "context_v2_begin",
            "context_v2_post_recon",
            "context_v2_post_actors",
            "context_v2_post_architecture",
            "context_v2_post_boundary",
        ],
    )
    def test_pre_stride_actions_refuse_a_legacy_run(self, tmp_path, entrypoint):
        output = _context_v2_run(tmp_path, runtime_generation="legacy")
        with pytest.raises(controller.ControllerError, match="incompatible runtime generation"):
            getattr(controller, entrypoint)(output)


class TestStage1RuntimeSelection:
    """prepare() hands the skill the runtime that matches the run's generation."""

    def test_the_two_stage1_runtimes_are_distinct_files(self):
        assert controller.THIN_STAGE1_RUNTIME.name == "SKILL-thin-stage1.md"
        assert controller.THIN_STAGE1_V2_RUNTIME.name == "SKILL-thin-stage1-v2.md"

    def test_both_stage1_runtimes_are_plugin_owned(self):
        owned = controller._plugin_owned_instruction_paths()
        assert controller.THIN_STAGE1_RUNTIME.resolve() in owned
        assert controller.THIN_STAGE1_V2_RUNTIME.resolve() in owned

    def test_context_v2_actions_name_the_v2_runtime(self, tmp_path, monkeypatch):
        output = _context_v2_run(tmp_path)
        monkeypatch.setattr(controller, "_run_script", _context_v2_prepass_stub(output))
        action = controller.context_v2_begin(output)
        assert action["instruction_file"] == str(controller.THIN_STAGE1_V2_RUNTIME)

    @pytest.mark.parametrize(
        ("generation", "expected"),
        [("legacy", "SKILL-thin-stage1.md"), ("context-v2", "SKILL-thin-stage1-v2.md")],
    )
    def test_stage1_runtime_follows_the_persisted_generation(self, tmp_path, generation, expected):
        cfg = _cfg(tmp_path)
        cfg["runtime_generation"] = generation
        assert controller._stage1_runtime_for(cfg).name == expected

    def test_a_run_without_a_generation_falls_back_to_legacy(self, tmp_path):
        cfg = _cfg(tmp_path)
        cfg.pop("runtime_generation", None)
        assert controller._stage1_runtime_for(cfg) is controller.THIN_STAGE1_RUNTIME


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
