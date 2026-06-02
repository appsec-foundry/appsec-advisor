"""Unit tests for scripts/build_threat_model_yaml.py field normalizers
(2026-06-02): title/affected_parameter clamps + cvss_v4 shape coercion, so the
deterministic Phase-11-Substep-2 builder always yields a schema-valid yaml even
when STRIDE analyzers emit verbose titles or a non-canonical cvss_v4."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_threat_model_yaml.py"


def _load():
    spec = importlib.util.spec_from_file_location("build_threat_model_yaml", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


b = _load()


def test_clamp_title_short_passthrough():
    t = "SQL Injection — routes/login.ts:34"
    assert b._clamp_title(t) == t


def test_clamp_title_enforces_maxlen_preserving_locator():
    long = "CPU Exhaustion via MarsDB $where JavaScript Injection blocking the event loop routes/showProductReviews.ts:31"
    out = b._clamp_title(long)
    assert len(out) <= 80
    assert out.endswith("routes/showProductReviews.ts:31")  # locator preserved
    assert "…" in out


def test_clamp_title_no_locator_truncates_with_ellipsis():
    long = "x" * 120
    out = b._clamp_title(long)
    assert len(out) <= 80 and out.endswith("…")


def test_normalize_cvss_v4_coerces_score_and_source():
    raw = {"vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
           "score": 9.4, "severity": "Critical"}
    out = b._normalize_cvss_v4(raw)
    assert out == {
        "vector": raw["vector"], "base_score": 9.4,
        "severity": "Critical", "source": "stride-analyzer",
    }


def test_normalize_cvss_v4_drops_invalid():
    assert b._normalize_cvss_v4(None) is None
    assert b._normalize_cvss_v4({"vector": "not-cvss", "score": 5}) is None
    assert b._normalize_cvss_v4({"vector": "CVSS:4.0/AV:N", "severity": "Bogus", "score": 5}) is None


def test_normalize_cvss_v4_keeps_valid_source():
    raw = {"vector": "CVSS:4.0/AV:N/AC:L", "base_score": 7.0, "severity": "High", "source": "nvd"}
    assert b._normalize_cvss_v4(raw)["source"] == "nvd"
