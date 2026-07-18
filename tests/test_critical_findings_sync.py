"""Tests for scripts/_critical_findings_sync.py.

`critical_findings[].mitigation_id` is derived from `threats[].mitigation_ids[0]`
by the yaml builder. The auto-emitter pass then runs AFTER the builder and
relinks `threats[]`, which left the curated list pointing at the pre-emitter
M-IDs. Two real models had every entry wrong (30/30 and 12/12): F-003 "Insecure
JWT Verification" cited "Apply least-privilege permissions".
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from _critical_findings_sync import resync_critical_findings  # noqa: E402


def _model(threat_mids: dict, curated: dict) -> dict:
    return {
        "threats": [{"id": tid, "mitigation_ids": mids} for tid, mids in threat_mids.items()],
        "critical_findings": [{"threat_id": tid, "summary": tid, "mitigation_id": mid} for tid, mid in curated.items()],
    }


def test_stale_ids_are_corrected():
    """The observed production failure: positional pairing left behind."""
    data = _model({"T-001": ["M-010"], "T-002": ["M-011"]}, {"T-001": "M-001", "T-002": "M-002"})
    assert resync_critical_findings(data) == 2
    assert [c["mitigation_id"] for c in data["critical_findings"]] == ["M-010", "M-011"]


def test_already_consistent_is_a_no_op():
    data = _model({"T-001": ["M-010"]}, {"T-001": "M-010"})
    assert resync_critical_findings(data) == 0
    assert data["critical_findings"][0]["mitigation_id"] == "M-010"


def test_threat_without_mitigation_yields_none():
    """A finding with no proposed fix must not keep a phantom id."""
    data = _model({"T-001": []}, {"T-001": "M-001"})
    assert resync_critical_findings(data) == 1
    assert data["critical_findings"][0]["mitigation_id"] is None


def test_first_mitigation_wins_when_several():
    data = _model({"T-001": ["M-020", "M-021"]}, {"T-001": "M-001"})
    resync_critical_findings(data)
    assert data["critical_findings"][0]["mitigation_id"] == "M-020"


def test_entry_for_unknown_threat_is_left_alone():
    """A dangling reference is the link checker's problem, not something to
    silently rewrite here."""
    data = _model({"T-001": ["M-010"]}, {"T-999": "M-001"})
    assert resync_critical_findings(data) == 0
    assert data["critical_findings"][0]["mitigation_id"] == "M-001"


def test_membership_is_never_changed():
    """The emitter has no business adding or dropping a curated worst case."""
    data = _model({"T-001": ["M-010"], "T-002": ["M-011"]}, {"T-001": "M-001"})
    resync_critical_findings(data)
    assert [c["threat_id"] for c in data["critical_findings"]] == ["T-001"]


def test_missing_or_malformed_sections_are_tolerated():
    assert resync_critical_findings({}) == 0
    assert resync_critical_findings({"critical_findings": "nope"}) == 0
    assert resync_critical_findings({"critical_findings": [None], "threats": [None]}) == 0


def test_every_emitter_resyncs_before_persisting():
    """Guard the wiring: each script that relinks threats[].mitigation_ids must
    call the resync on its write path, or the bug silently returns."""
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    for name in (
        "emit_finding_fix_mitigations.py",
        "emit_config_scan_mitigations.py",
        "emit_review_mitigations.py",
    ):
        text = (scripts / name).read_text(encoding="utf-8")
        assert "resync_critical_findings(data)" in text, f"{name} persists without resyncing critical_findings"
