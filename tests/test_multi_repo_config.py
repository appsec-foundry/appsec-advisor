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
