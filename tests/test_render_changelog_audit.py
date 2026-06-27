"""Tests for the full change-log audit export (`render_changelog_audit.py`).

The module renders the COMPLETE, uncapped change history beside the report from
`threat-model.yaml`'s `changelog[]`. Unlike the report's own `## Changelog`
section (capped at five IDs per bucket), this export must show every ID, every
run, and capture removals/changes — and must archive (not delete) on --rebuild.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import render_changelog_audit as rca
import yaml


def _entry(**over) -> dict:
    base = {
        "version": 1,
        "date": "2026-06-27",
        "time_local": "14:32 CEST",
        "mode": "full",
        "assessment_depth": "standard",
        "reasoning_model": "sonnet-economy",
        "current_sha": "08fc2760aff995ac735c9a83f6ef24a1fb52f53c",
        "baseline_sha": None,
        "threat_count": 3,
        "previous_threat_count": None,
        "delta_basis": "initial",
        "fingerprints": ["comp|CWE-89|x"],  # bulky internal state — dropped from jsonl
        "match_keys": ["a.ts|CWE-89"],
        "mitigation_fingerprints": ["mit-fp"],
        "instance_fingerprints": ["inst-fp"],
        "added": {
            "threats": [],
            "mitigations": [],
            "abuse_cases": [],
            "instances": [],
            "components": [],
            "attack_surface": [],
        },
        "changed": {"threats": []},
        "resolved": {"threats": [], "fingerprints": [], "reason_by_id": {}, "instances": []},
        "reanalyzed_components": [],
        "carried_forward_components": [],
        "note": "",
    }
    base.update(over)
    return base


def _threats_by_id() -> dict:
    return {f"T-{i:03d}": f"Finding {i}" for i in range(1, 9)}


# ─── markdown ────────────────────────────────────────────────────────────────


def test_markdown_is_uncapped():
    """Seven added findings must all appear — no '+N more' truncation."""
    seven = [f"T-{i:03d}" for i in range(1, 8)]
    entry = _entry(added={**_entry()["added"], "threats": seven})
    md = rca.render_markdown([entry], _threats_by_id(), {})
    for tid in seven:
        assert tid in md
    assert "more" not in md.lower()
    # titles are resolved for readability
    assert "Finding 7" in md


def test_markdown_renders_changed_and_removed():
    entry = _entry(
        changed={"threats": ["T-002"], "notes_by_id": {"T-002": "severity raised"}},
        resolved={
            "threats": [],
            "fingerprints": ["auth|CWE-89|sql injection in login"],
            "reason_by_id": {},
            "instances": ["express|CWE-639|/api/x"],
        },
    )
    md = rca.render_markdown([entry], _threats_by_id(), {})
    assert "### Changed" in md
    assert "severity raised" in md
    assert "### Removed / Resolved" in md
    assert "sql injection in login" in md
    assert "/api/x" in md


def test_markdown_version_numbering_newest_first():
    """Two entries: newest (index 0) gets the highest vN."""
    newest = _entry(date="2026-06-27")
    oldest = _entry(date="2026-06-20")
    md = rca.render_markdown([newest, oldest], {}, {})
    assert "## v2 — 2026-06-27" in md
    assert "## v1 — 2026-06-20" in md
    assert md.index("## v2") < md.index("## v1")


def test_markdown_mitigations_use_titles():
    entry = _entry(added={**_entry()["added"], "mitigations": ["M-003"]})
    md = rca.render_markdown([entry], {}, {"M-003": "Parameterize the query"})
    assert "M-003 — Parameterize the query" in md


# ─── jsonl ───────────────────────────────────────────────────────────────────


def test_jsonl_one_line_per_entry_with_seq():
    cl = [_entry(date="2026-06-27"), _entry(date="2026-06-20")]
    out = rca.render_jsonl(cl)
    rows = [json.loads(line) for line in out.splitlines()]
    assert len(rows) == 2
    assert rows[0]["seq"] == 2  # newest first
    assert rows[1]["seq"] == 1


def test_jsonl_drops_bulky_fingerprint_state():
    out = rca.render_jsonl([_entry()])
    rec = json.loads(out.splitlines()[0])
    for k in ("fingerprints", "match_keys", "mitigation_fingerprints", "instance_fingerprints"):
        assert k not in rec
    # delta buckets and identity are retained — this IS the audit
    for k in ("version", "date", "mode", "added", "changed", "resolved"):
        assert k in rec


# ─── write_audit / archive_audit ─────────────────────────────────────────────


def _write_yaml(output_dir: Path, changelog: list[dict]) -> None:
    data = {
        "changelog": changelog,
        "threats": [{"id": "T-001", "title": "SQL Injection"}],
        "mitigations": [{"id": "M-001", "title": "Use parameterized queries"}],
    }
    (output_dir / "threat-model.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")


def test_write_audit_emits_both_files(tmp_path):
    _write_yaml(tmp_path, [_entry(added={**_entry()["added"], "threats": ["T-001"]})])
    assert rca.write_audit(tmp_path) is True
    md = (tmp_path / "threat-model-changelog.md").read_text(encoding="utf-8")
    jsonl = (tmp_path / "threat-model-changelog.jsonl").read_text(encoding="utf-8")
    assert "T-001 — SQL Injection" in md
    assert json.loads(jsonl.splitlines()[0])["mode"] == "full"


def test_write_audit_noop_without_yaml(tmp_path):
    assert rca.write_audit(tmp_path) is False
    assert not (tmp_path / "threat-model-changelog.md").exists()


def test_write_audit_is_deterministic(tmp_path):
    _write_yaml(tmp_path, [_entry()])
    rca.write_audit(tmp_path)
    first = (tmp_path / "threat-model-changelog.md").read_text(encoding="utf-8")
    rca.write_audit(tmp_path)
    second = (tmp_path / "threat-model-changelog.md").read_text(encoding="utf-8")
    assert first == second


def test_archive_moves_live_files_into_history(tmp_path):
    (tmp_path / "threat-model-changelog.md").write_text("old md", encoding="utf-8")
    (tmp_path / "threat-model-changelog.jsonl").write_text("old jsonl", encoding="utf-8")
    moved = rca.archive_audit(tmp_path, stamp="20260627-143200")
    assert len(moved) == 2
    hist = tmp_path / "changelog-history"
    assert (hist / "threat-model-changelog-20260627-143200.md").read_text() == "old md"
    assert (hist / "threat-model-changelog-20260627-143200.jsonl").read_text() == "old jsonl"
    # live files were moved, not copied
    assert not (tmp_path / "threat-model-changelog.md").exists()


def test_archive_noop_when_absent(tmp_path):
    assert rca.archive_audit(tmp_path) == []
    assert not (tmp_path / "changelog-history").exists()


def test_cli_archive_then_render(tmp_path):
    # Seed a prior live pair, archive it (rebuild pre-flight), then render fresh.
    (tmp_path / "threat-model-changelog.md").write_text("prior", encoding="utf-8")
    assert rca.main(["--output-dir", str(tmp_path), "--archive"]) == 0
    assert list((tmp_path / "changelog-history").iterdir())
    _write_yaml(tmp_path, [_entry()])
    assert rca.main(["--output-dir", str(tmp_path)]) == 0
    assert (tmp_path / "threat-model-changelog.md").read_text().startswith("# Threat Model")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
