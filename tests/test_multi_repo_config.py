"""Combined settings preserve operator policy without a primary source root."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import resolve_config as config
from runtime.multi_repo_scope import AssessmentScope, RepositoryView

ROOT = Path(__file__).resolve().parents[1]


def scope(tmp_path):
    views = tuple(
        RepositoryView(f"repo-{i:016x}", tmp_path / f"source-{i}", "a" * 40, "b" * 64, {"app.py": b"value = 1\n"})
        for i in (1, 2)
    )
    return AssessmentScope(views, tmp_path / "output")


def test_configuration_never_runs_git_helpers_on_selected_roots(tmp_path, monkeypatch):
    selected = scope(tmp_path)

    def forbidden(*args):
        pytest.fail("captured configuration must not invoke repository Git helpers")

    monkeypatch.setattr(config, "_count_source_files", forbidden)
    resolved = config.resolve_assessment(selected, ["--no-requirements"], ROOT)
    assert resolved["mode"] == "full" and resolved["assessment_scope"] == "multiple-repositories"
    assert "repo_root" not in resolved
    assert resolved["repository_ids"] == sorted(r.repository_id for r in selected.repositories)
    assert not selected.output.exists()


def test_argument_order_does_not_change_shared_policy(tmp_path):
    selected = scope(tmp_path)
    reversed_scope = AssessmentScope(tuple(reversed(selected.repositories)), selected.output)
    first = config.resolve_assessment(selected, ["--no-requirements"], ROOT, model="haiku")
    second = config.resolve_assessment(reversed_scope, ["--no-requirements"], ROOT, model="haiku")
    assert first == second


def test_explicit_stage_pin_wins_over_shared_model(tmp_path):
    resolved = config.resolve_assessment(
        scope(tmp_path), ["--no-requirements", "--stride-model", "sonnet"], ROOT, model="haiku"
    )
    assert resolved["stride_model"] == "sonnet" and resolved["triage_model"] == "haiku"


@pytest.mark.parametrize("depth", ["quick", "standard"])
def test_combined_assessment_moves_economy_stride_off_sonnet_46(tmp_path, monkeypatch, depth):
    monkeypatch.delenv("APPSEC_STRIDE_MODEL", raising=False)
    arguments = ["--no-requirements", "--assessment-depth", depth]
    resolved = config.resolve_assessment(scope(tmp_path), arguments, ROOT)
    assert resolved["stride_model"] == config.SONNET5
    assert f"STRIDE: {config.SONNET5}" in resolved["reasoning_label"]
    # Only STRIDE moves; the other economy roles keep their pins (discovery: MD-10).
    single = config.resolve(
        ["--repo", str(tmp_path), "--output", str(tmp_path / "single"), "--full", *arguments],
        ROOT,
        create_output_dir=False,
        source_count=1,
    )
    assert single["stride_model"] == config.SONNET46
    assert resolved["stride_model_moved_from"] == config.SONNET46
    moved = {"stride_model", "recon_scanner_model"}
    assert {k: v for k, v in resolved.items() if k.endswith("_model") and k not in moved} == {
        k: v for k, v in single.items() if k.endswith("_model") and k not in moved
    }


def test_controller_discovery_leaves_the_haiku_recon_default(tmp_path, monkeypatch):
    monkeypatch.delenv("APPSEC_RECON_SCANNER_MODEL", raising=False)
    arguments = ["--no-requirements"]
    single = config.resolve(
        ["--repo", str(tmp_path), "--output", str(tmp_path / "single"), "--full", *arguments],
        ROOT,
        create_output_dir=False,
        source_count=1,
    )
    assert single["recon_scanner_model"] == config.HAIKU
    assert config.resolve_assessment(scope(tmp_path), arguments, ROOT)["recon_scanner_model"] == config.SONNET5
    # An explicit role pin or shared model still wins.
    assert config.resolve_assessment(scope(tmp_path), arguments, ROOT, model="haiku")["recon_scanner_model"] == "haiku"
    monkeypatch.setenv("APPSEC_RECON_SCANNER_MODEL", config.HAIKU)
    assert config.resolve_assessment(scope(tmp_path), arguments, ROOT)["recon_scanner_model"] == config.HAIKU


@pytest.mark.parametrize("origin", ["environment", "shared"])
def test_explicit_sonnet_46_stride_is_kept_and_warned(tmp_path, monkeypatch, origin):
    from orchestrator import orchestration_controller as controller

    monkeypatch.delenv("APPSEC_STRIDE_MODEL", raising=False)
    if origin == "environment":
        monkeypatch.setenv("APPSEC_STRIDE_MODEL", config.SONNET46)
    model = config.SONNET46 if origin == "shared" else None
    resolved = config.resolve_assessment(scope(tmp_path), ["--no-requirements"], ROOT, model=model)
    assert resolved["stride_model"] == config.SONNET46
    lineup, warning = controller._assessment_model_lines(resolved)
    assert f"{config.SONNET46} (" in lineup and "stride_analyzer" in lineup
    assert warning and "returning a result" in warning and "stride_model_moved_from" not in resolved


def test_default_combined_lineup_shows_the_stride_move_without_a_warning(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as controller

    monkeypatch.delenv("APPSEC_STRIDE_MODEL", raising=False)
    resolved = config.resolve_assessment(scope(tmp_path), ["--no-requirements"], ROOT)
    lineup, warning = controller._assessment_model_lines(resolved)
    stride_group = next(group for group in lineup.removeprefix("Models: ").split("; ") if "stride_analyzer" in group)
    assert stride_group.startswith(config.SONNET5)
    assert warning is None


def test_an_explicit_latest_sonnet_stride_is_not_reported_as_a_move(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as controller

    monkeypatch.setenv("APPSEC_STRIDE_MODEL", config.SONNET5)
    resolved = config.resolve_assessment(scope(tmp_path), ["--no-requirements"], ROOT)
    assert resolved["stride_model"] == config.SONNET5 and "stride_model_moved_from" not in resolved
    assert controller._assessment_model_lines(resolved)[1] is None


@pytest.mark.parametrize("origin", ["cli", "environment"])
def test_shared_model_cannot_bypass_the_opus_ceiling(tmp_path, monkeypatch, origin):
    arguments = ["--no-requirements"]
    if origin == "cli":
        arguments.append("--no-opus")
    else:
        monkeypatch.setenv("APPSEC_DISABLE_OPUS", "1")
    resolved = config.resolve_assessment(scope(tmp_path), arguments, ROOT, model="opus")
    assert resolved["opus_disabled"]
    assert all("opus" not in str(resolved.get(key, "")).lower() for key in config._MODEL_FIELDS)


@pytest.mark.parametrize(
    "arguments",
    [
        ["--resume"],
        ["--repo", "/elsewhere"],
        ["--output", "/elsewhere"],
        ["--rerender"],
        ["--incremental"],
        ["--rebuild"],
        ["--dry-run"],
    ],
)
def test_lifecycle_or_scope_flags_cannot_replace_admitted_authority(tmp_path, arguments):
    with pytest.raises(SystemExit):
        config.resolve_assessment(scope(tmp_path), arguments, ROOT)


@pytest.mark.parametrize("value", [-1, True, 320001])
def test_captured_source_counts_are_bounded(value):
    with pytest.raises(SystemExit):
        config.resolve([], ROOT, create_output_dir=False, source_count=value)
