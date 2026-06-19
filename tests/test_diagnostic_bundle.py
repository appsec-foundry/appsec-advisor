"""Tests for scripts/diagnostic_bundle.py — the anonymised user→maintainer
error-report bundle.

The central guarantee is negative: a bundle must NEVER contain threat-model
results, finding evidence, component names/paths, the scanned-repo path/name, or
any source. `test_collect_no_leak_*` plant unique marker strings in a synthetic
run dir and assert none of them survive into the produced bundle. The rest are
fast unit tests over the scrub / aggregate / inventory helpers.
"""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

import diagnostic_bundle as db
import pytest

REPO_ROOT = "/home/victim/private-repo"
REPO_NAME = "private-repo"
SECRET = "SUPERSECRETFINDING_xyz"


# ── scrub ──────────────────────────────────────────────────────────────────


def test_scrub_replaces_repo_root_and_name():
    line = f"scanning {REPO_ROOT}/src/login.js in {REPO_NAME} repo"
    out = db._scrub_line(line, REPO_ROOT, REPO_NAME)
    assert REPO_ROOT not in out
    assert REPO_NAME not in out
    assert "<repo>" in out


def test_scrub_strips_paths_quotes_emails_tokens():
    line = "err 'SQL injection in admin panel' at /etc/passwd by dev@corp.com key=" + "A" * 40
    out = db._scrub_line(line, None, None)
    assert "SQL injection" not in out  # quoted finding title gone
    assert "/etc/passwd" not in out
    assert "dev@corp.com" not in out
    assert "A" * 40 not in out
    assert "<str>" in out and "<path>" in out and "<email>" in out and "<token>" in out


def test_scrub_keeps_structured_prefix():
    line = "2026-06-19T05:42:44Z  [--------]  ERROR  stride-merger  AGENT_ERROR  schema invalid"
    out = db._scrub_line(line, None, None)
    # timestamp + level + component + event survive (no slashes / quotes there)
    assert "ERROR" in out and "stride-merger" in out and "AGENT_ERROR" in out


def test_scrub_text_is_per_line():
    text = f"{REPO_ROOT}/a\nclean line\n"
    out = db._scrub_text(text, REPO_ROOT, REPO_NAME)
    assert out.count("\n") == 2
    assert REPO_ROOT not in out
    assert "clean line" in out


# ── aggregate ──────────────────────────────────────────────────────────────


def test_as_items_tolerant_of_shape():
    assert db._as_items([{"a": 1}, "junk"]) == [{"a": 1}]
    assert db._as_items({"threats": [{"a": 1}]}, "threats") == [{"a": 1}]
    assert db._as_items({"nope": 1}, "threats") == []
    assert db._as_items(None) == []


def test_histogram_counts_sorted_ignores_none():
    items = [{"severity": "High"}, {"severity": "High"}, {"severity": "Low"}, {"other": 1}]
    assert db._histogram(items, "severity") == {"High": 2, "Low": 1}


def test_aggregate_emits_counts_not_content(tmp_path: Path):
    (tmp_path / ".components.json").write_text(
        json.dumps({"components": [{"name": SECRET, "type": "process", "tier": "app"}]})
    )
    (tmp_path / ".triage-flags.json").write_text(
        json.dumps({"threats": [{"title": SECRET, "severity": "High", "stride": "Spoofing"}]})
    )
    agg = db._aggregate(tmp_path)
    assert agg["components"]["count"] == 1
    assert agg["components"]["by_type"] == {"process": 1}
    assert agg["threats"] == {"count": 1, "by_severity": {"High": 1}, "by_stride": {"Spoofing": 1}}
    assert SECRET not in json.dumps(agg)  # titles/names never aggregated


def test_aggregate_falls_back_to_merged_when_no_triage(tmp_path: Path):
    (tmp_path / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"severity": "Medium", "stride": "Tampering"}]})
    )
    agg = db._aggregate(tmp_path)
    assert agg["threats"]["count"] == 1


# ── safe config ────────────────────────────────────────────────────────────


def test_safe_config_keeps_scalars_drops_paths(tmp_path: Path):
    (tmp_path / ".skill-config.json").write_text(
        json.dumps(
            {
                "assessment_depth": "quick",
                "incremental": False,
                "max_stride_components": 10,
                "output_dir": "/home/victim/private-repo/docs/security",
                "long_value": "x" * 60,
            }
        )
    )
    safe = db._safe_config(tmp_path)
    assert safe["assessment_depth"] == "quick"
    assert safe["incremental"] is False
    assert safe["max_stride_components"] == 10
    assert "output_dir" not in safe  # has a slash → dropped
    assert "long_value" not in safe  # > 40 chars → dropped


# ── inventory ──────────────────────────────────────────────────────────────


def test_inventory_is_metadata_only(tmp_path: Path):
    (tmp_path / "threat-model.yaml").write_text(SECRET)
    (tmp_path / ".threats-merged.json").write_text("[]")
    sub = tmp_path / ".fragments"
    sub.mkdir()
    (sub / "a.md").write_text("body")
    inv = db._inventory(tmp_path)
    assert inv["threat-model.yaml"]["sensitive_content_excluded"] is True
    assert "sha256:" in inv["threat-model.yaml"]["sha256"]
    assert SECRET not in json.dumps(inv)  # content never enters inventory
    assert inv[".fragments/"]["file_count"] == 1


# ── run shape ──────────────────────────────────────────────────────────────


def test_run_shape_collects_progress_stages_and_scrubbed_error(tmp_path: Path):
    (tmp_path / ".appsec-progress.json").write_text(
        json.dumps({"phase": "9", "step": "merge", "status": "running", "event": "PHASE_START"})
    )
    (tmp_path / ".stage-stats.jsonl").write_text(
        '{"stage": "recon", "seconds": 12, "status": "ok"}\nnot-json\n{"stage": "stride", "seconds": 30}\n'
    )
    (tmp_path / ".agent-run.log").write_text(
        f"ts  [s]  INFO   recon  SCAN_START  fine\nts  [s]  ERROR  merger  AGENT_ERROR  failed at {REPO_ROOT}/x.js\n"
    )
    shape = db._run_shape(tmp_path, REPO_ROOT, REPO_NAME)
    assert shape["last_progress"]["phase"] == "9"
    assert len(shape["stages"]) == 2  # bad line skipped
    assert shape["error_count"] == 1
    assert REPO_ROOT not in shape["last_error"]
    assert "<repo>" in shape["last_error"]  # repo-root scrub takes precedence over the generic path regex


# ── collect / inspect end-to-end ───────────────────────────────────────────


def _synthetic_run(d: Path) -> None:
    """A run dir seeded with marker strings that must NOT escape into a bundle."""
    (d / "threat-model.yaml").write_text(f"findings:\n  - title: {SECRET}\n")
    (d / "threat-model.md").write_text(f"# {SECRET}\n")
    (d / ".threats-merged.json").write_text(
        json.dumps({"threats": [{"title": SECRET, "severity": "High", "stride": "Spoofing"}]})
    )
    (d / ".components.json").write_text(
        json.dumps({"components": [{"name": SECRET, "type": "process", "tier": "app", "paths": [f"{REPO_ROOT}/a"]}]})
    )
    (d / ".triage-flags.json").write_text(
        json.dumps({"threats": [{"title": SECRET, "severity": "High", "stride": "Spoofing"}]})
    )
    (d / ".skill-config.json").write_text(json.dumps({"assessment_depth": "quick", "out": REPO_ROOT}))
    (d / ".appsec-progress.json").write_text(json.dumps({"phase": "11", "status": "phase_completed"}))
    (d / ".stage-stats.jsonl").write_text('{"stage": "recon", "seconds": 5}\n')
    (d / ".agent-run.log").write_text(
        f"ts  [s]  INFO   recon   SCAN_START   ok\n"
        f"ts  [s]  ERROR  merger  AGENT_ERROR  '{SECRET}' at {REPO_ROOT}/login.js mail dev@corp.com\n"
    )
    (d / ".hook-events.log").write_text(f"ts  [s]  INFO  hook  PRE  {REPO_ROOT}/x\n")


def _extract_all_text(tgz: Path, into: Path) -> str:
    with tarfile.open(tgz, "r:gz") as tar:
        tar.extractall(into)
    return "\n".join(p.read_text(errors="replace") for p in into.rglob("*") if p.is_file())


def test_collect_no_leak(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    tgz = db.collect(run, tmp_path / "out", REPO_ROOT)
    assert tgz.exists() and tgz.suffix == ".tgz"

    blob = _extract_all_text(tgz, tmp_path / "x")
    assert SECRET not in blob  # no finding title / component name anywhere
    assert REPO_ROOT not in blob  # no scanned-repo path
    assert REPO_NAME not in blob  # no scanned-repo name
    assert "dev@corp.com" not in blob  # no email
    assert "threat-model.yaml" in blob  # but its NAME is in the inventory


def test_collect_bundle_structure_and_counts(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    tgz = db.collect(run, tmp_path / "out", REPO_ROOT)
    with tarfile.open(tgz, "r:gz") as tar:
        names = [m.name.split("/", 1)[1] for m in tar.getmembers() if m.isfile()]
    assert "env-manifest.json" in names
    assert "run-summary.json" in names
    assert "inventory.json" in names
    assert "logs/agent-run.log" in names
    assert "logs/hook-events.log" in names

    data = db._read_bundle(tgz)
    assert data["summary"]["counts"]["threats"]["count"] == 1
    assert data["summary"]["shape"]["error_count"] == 1
    assert data["env"]["config"]["assessment_depth"] == "quick"
    assert data["inventory"]["threat-model.yaml"]["sensitive_content_excluded"] is True


def test_collect_into_explicit_tgz_path(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    target = tmp_path / "my-bundle.tgz"
    out = db.collect(run, target, REPO_ROOT)
    assert out == target and target.exists()


def test_collect_without_repo_root(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    # repo_root unknown: the exact-string scrub can't run, but the path/quote
    # regexes still strip the marker-bearing log line.
    tgz = db.collect(run, tmp_path / "out", None)
    blob = _extract_all_text(tgz, tmp_path / "x")
    assert SECRET not in blob  # quoted → <str> regardless of repo_root


def test_inspect_tgz_and_dir(tmp_path: Path, capsys):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    tgz = db.collect(run, tmp_path / "out", REPO_ROOT)

    assert db.inspect(tgz) == 0
    out = capsys.readouterr().out
    assert "environment" in out and "anonymised counts" in out and "content excluded" in out

    # unpacked dir form
    extract = tmp_path / "unpacked"
    with tarfile.open(tgz, "r:gz") as tar:
        tar.extractall(extract)
    inner = next(extract.iterdir())
    assert db.inspect(inner) == 0


def test_inspect_log_tail_is_scrubbed(tmp_path: Path, capsys):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    tgz = db.collect(run, tmp_path / "out", REPO_ROOT)

    assert db.inspect(tgz, log_tail=40) == 0
    out = capsys.readouterr().out
    assert "scrubbed log tail" in out
    assert "AGENT_ERROR" in out  # the event survives
    assert SECRET not in out and REPO_ROOT not in out  # but its content stays scrubbed


def test_bundle_text_reads_member_in_memory(tmp_path: Path):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    tgz = db.collect(run, tmp_path / "out", REPO_ROOT)
    log = db._bundle_text(tgz, "logs/agent-run.log")
    assert log is not None and "AGENT_ERROR" in log
    assert db._bundle_text(tgz, "logs/does-not-exist.log") is None


def test_inspect_missing_bundle_errors(tmp_path: Path):
    with pytest.raises(SystemExit):
        db.inspect(tmp_path / "nope.tgz")


def test_collect_rejects_missing_run(tmp_path: Path):
    with pytest.raises(SystemExit):
        db.collect(tmp_path / "nonexistent", tmp_path, None)


# ── CLI ────────────────────────────────────────────────────────────────────


def test_cli_collect_then_inspect(tmp_path: Path, capsys):
    run = tmp_path / "run"
    run.mkdir()
    _synthetic_run(run)
    rc = db.main(["collect", "--run", str(run), "--into", str(tmp_path), "--repo-root", REPO_ROOT])
    assert rc == 0
    tgz = next(tmp_path.glob("appsec-diag-*.tgz"))
    rc = db.main(["inspect", "--bundle", str(tgz)])
    assert rc == 0
