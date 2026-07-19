from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

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
    assert (output / "threat-model.yaml").exists()


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

    assert controller.next_action(output)["stage"] == "stage1"
    (output / "threat-model.yaml").write_text("meta: {}\n")
    assert controller.next_action(output)["stage"] == "stage2"
    (output / "threat-model.md").write_text("# report\n")
    assert controller.next_action(output)["stage"] == "stage3"
    (output / ".qa-status.json").write_text("{}")
    assert controller.next_action(output)["action"] == "complete"


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


def test_checkpoint_needs_render_false_when_report_present(tmp_path):
    (tmp_path / ".appsec-checkpoint").write_text("phase=10b need_render=true\n", encoding="utf-8")
    (tmp_path / "threat-model.md").write_text("x", encoding="utf-8")
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
