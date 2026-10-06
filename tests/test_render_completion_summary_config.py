"""The completion summary describes the run the files on disk came from.

Guards three rules of `renderers/render_completion_summary.py`:

* The switches that record what a run requested come from the resolved
  `.skill-config.json` whenever it exists — the file the exports and the slug
  stamp already read — so argv can no longer make the summary contradict the
  deliverables on disk. Argv still decides for a directory without a config.
* The Architect line reports the editorial pass's `outcome`, not its release
  `status`, which stays `pass` for every outcome.
* The export backstop covers every deliverable the controller can produce.
"""

from __future__ import annotations

import json
import re
import types
from pathlib import Path

import orchestrator.orchestration_controller as oc
import pytest
import renderers.render_completion_summary as rcs

_RECEIPT = Path(__file__).resolve().parents[1] / "scripts" / "renderers/render_editorial_receipt.py"


def _write_config(output_dir: Path, **values) -> None:
    (output_dir / ".skill-config.json").write_text(json.dumps(values), encoding="utf-8")


def _outputs_block(stdout: str) -> str:
    return stdout.split("\nOutputs\n", 1)[1].split("\n\n", 1)[0]


def _run_main(output_dir: Path, *flags: str) -> int:
    return rcs.main(["--output-dir", str(output_dir), "--repo-root", str(output_dir), *flags])


# ---------------------------------------------------------------------------
# Run switches come from the resolved config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("key", rcs._RUN_SWITCHES)
def test_resolved_switches_carry_the_config_value(tmp_path, key, value):
    _write_config(tmp_path, **{key: value})
    assert rcs.resolved_run_switches(tmp_path) == {key: value}


def test_presentation_switches_stay_with_the_invocation(tmp_path):
    _write_config(tmp_path, slug="s", verbose=True, quiet=True, plugin_dev=True)
    assert rcs.resolved_run_switches(tmp_path) == {}


@pytest.mark.parametrize("body", [None, "[1, 2]", "{not json"])
def test_missing_or_unreadable_config_leaves_argv_in_charge(tmp_path, body):
    if body is not None:
        (tmp_path / ".skill-config.json").write_text(body, encoding="utf-8")
    assert rcs.resolved_run_switches(tmp_path) == {}


def test_argv_cannot_make_the_summary_contradict_the_run(tmp_path, capsys):
    (tmp_path / "threat-model.md").write_text("# Threat Model\n", encoding="utf-8")
    requested = {key: True for key, _label, _basename in rcs._REQUESTABLE_DELIVERABLES}
    _write_config(tmp_path, architect_review=True, **requested)
    for _key, _label, basename in rcs._REQUESTABLE_DELIVERABLES:
        (tmp_path / basename).write_text("x", encoding="utf-8")

    rc = _run_main(
        tmp_path,
        "--no-write-sarif",
        "--no-write-pentest-tasks",
        "--no-write-threatdragon",
        "--no-architect-review",
    )

    out = capsys.readouterr().out
    assert rc == 0
    outputs = _outputs_block(out)
    for _key, _label, basename in rcs._REQUESTABLE_DELIVERABLES:
        assert str(tmp_path / basename) in outputs, f"{basename} was requested and produced but not listed"
    assert "Architect : skipped" not in out


@pytest.mark.parametrize("flag, listed", [("--write-sarif", True), ("--no-write-sarif", False)])
def test_argv_decides_without_a_resolved_config(tmp_path, capsys, flag, listed):
    (tmp_path / "threat-model.md").write_text("# Threat Model\n", encoding="utf-8")
    (tmp_path / "threat-model.sarif.json").write_text("{}", encoding="utf-8")

    assert _run_main(tmp_path, flag) == 0

    outputs = _outputs_block(capsys.readouterr().out)
    assert (str(tmp_path / "threat-model.sarif.json") in outputs) is listed


# ---------------------------------------------------------------------------
# Architect line reports the editorial outcome
# ---------------------------------------------------------------------------


def test_every_receipt_outcome_has_summary_words():
    """An outcome the receipt can emit must not fall through to raw text."""
    emitted = {
        word
        for line in _RECEIPT.read_text(encoding="utf-8").splitlines()
        if re.match(r"\s*outcome = ", line)
        for word in re.findall(r'"([a-z_]+)"', line)
    }
    assert emitted, "the receipt's outcome assignments moved — update this extractor"
    assert emitted <= set(rcs._ARCHITECT_OUTCOME_WORDS)


@pytest.mark.parametrize("outcome", sorted(rcs._ARCHITECT_OUTCOME_WORDS))
def test_architect_line_reports_the_outcome_not_the_release_status(tmp_path, outcome):
    status = {"status": "pass", "outcome": outcome, "edits_applied": 3}
    (tmp_path / ".architect-status.json").write_text(json.dumps(status), encoding="utf-8")

    line = rcs._summary_architect(tmp_path, {"architect_review": True})

    assert line != "pass"
    if outcome in {"failed", "incomplete"}:
        assert "no validated result" in line, "must agree with the receipt's own wording"
    if outcome in {"applied", "partial"}:
        assert "3 block" in line


@pytest.mark.parametrize(
    ("unreviewed", "unresolved", "corrected", "expected"),
    [
        (5, 0, 0, "not performed — none of 5 findings reviewed"),
        (2, 0, 1, "incomplete — 1 assessment(s), 0 mitigation(s) corrected; 2/5 unreviewed"),
        (
            2,
            1,
            1,
            "incomplete — 1 assessment(s), 0 mitigation(s) corrected; 2/5 unreviewed; 1 left open for manual review",
        ),
        (0, 5, 0, "reviewed — 0 assessment(s), 0 mitigation(s) corrected; 5 left open for manual review"),
        (0, 0, 1, "reviewed — 1 assessment(s), 0 mitigation(s) corrected"),
    ],
    ids=["none-reviewed", "partial", "partial-and-open", "all-open-is-reviewed", "complete"],
)
def test_semantic_review_that_covered_nothing_reads_as_not_performed(
    tmp_path, unreviewed, unresolved, corrected, expected
):
    status = {
        "status": "pass",
        "outcome": "incomplete" if unreviewed else "reviewed",
        "review_kind": "semantic",
        "findings_recorded": 5,
        "unreviewed": unreviewed,
        "unresolved": unresolved,
        "assessment_corrected": corrected,
        "remediation_corrected": 0,
    }
    (tmp_path / ".architect-status.json").write_text(json.dumps(status), encoding="utf-8")
    assert rcs._summary_architect(tmp_path, {"architect_review": True}) == expected


def test_status_without_outcome_is_still_reported(tmp_path):
    (tmp_path / ".architect-status.json").write_text('{"status": "repair_required"}', encoding="utf-8")
    assert rcs._summary_architect(tmp_path, {"architect_review": True}) == "repair required"


@pytest.mark.parametrize("body", ["[]", '"pass"', "{not json"])
def test_malformed_status_is_unreadable_not_a_crash(tmp_path, body):
    (tmp_path / ".architect-status.json").write_text(body, encoding="utf-8")
    assert rcs._summary_architect(tmp_path, {"architect_review": True}) == "status unreadable"


# ---------------------------------------------------------------------------
# Export backstop covers every controller-produced deliverable
# ---------------------------------------------------------------------------


def test_backstop_covers_every_deliverable_the_controller_produces(tmp_path, monkeypatch):
    produced = {key: script for key, script, _basename in oc._YAML_DERIVED_EXPORTS}
    key, script, _basename = oc._PENTEST_TASKS_EXPORT
    produced[key] = script
    (tmp_path / "threat-model.yaml").write_text("threats: []\n", encoding="utf-8")
    (tmp_path / ".threats-merged.json").write_text("[]", encoding="utf-8")
    _write_config(tmp_path, **dict.fromkeys(produced, True))
    invoked: list[str] = []
    monkeypatch.setattr(
        rcs.subprocess,
        "run",
        lambda argv, **_kw: invoked.append(
            Path(argv[1]).relative_to(Path(rcs.__file__).resolve().parents[1]).as_posix()
        )
        or types.SimpleNamespace(returncode=1),
    )

    rcs._export_deliverables_if_configured(tmp_path)

    assert sorted(invoked) == sorted(produced.values())


def _identity_args(argv):
    import argparse

    ns = argparse.Namespace(
        repo_root=None,
        mode=None,
        reasoning_model=None,
        assessment_depth=None,
        plugin_dev=False,
        verbose=False,
        quiet=False,
        issues_only=False,
    )
    for key, value in argv.items():
        setattr(ns, key, value)
    return ns


@pytest.mark.parametrize(
    ("config", "argv", "expected"),
    [
        (
            {"repo_root": "/srv/a", "mode": "rebuild", "assessment_depth": "thorough", "reasoning_model": "sonnet"},
            {},
            ("/srv/a", "rebuild", "thorough", "sonnet"),
        ),
        (
            {"repo_root": "/srv/a", "assessment_depth": "thorough"},
            {"assessment_depth": "quick"},
            ("/srv/a", "full", "quick", "opus"),
        ),
        ({}, {"repo_root": Path("/work/b")}, ("/work/b", "full", "standard", "opus")),
    ],
    ids=["config-only", "flag-overrides", "no-config"],
)
def test_run_identity_comes_from_the_run_config(config, argv, expected):
    args = _identity_args(argv)
    rcs._apply_run_identity(args, config)
    assert (str(args.repo_root), args.mode, args.assessment_depth, args.reasoning_model) == expected


@pytest.mark.parametrize(
    "config",
    [{"repo_root": "/srv/a", "assessment_depth": "exhaustive"}, {"mode": "full"}],
    ids=["unknown-depth", "no-repository"],
)
def test_unusable_run_identity_is_refused(config):
    with pytest.raises(ValueError):
        rcs._apply_run_identity(_identity_args({}), config)


def test_verbosity_follows_the_run_config():
    args = _identity_args({"repo_root": Path("/srv/a")})
    rcs._apply_run_identity(args, {"verbose": True, "quiet": False, "plugin_dev": None})
    assert (args.verbose, args.quiet, args.plugin_dev) == (True, False, False)
