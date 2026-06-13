"""Unit tests for scripts/requirements_state.py — shared source-state helpers."""

from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "requirements_state.py"


def _load():
    if "requirements_state" in sys.modules:
        return sys.modules["requirements_state"]
    spec = importlib.util.spec_from_file_location("requirements_state", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["requirements_state"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rs = _load()

_CATALOG = (
    b"generated: '2026-04-09T07:51:52Z'\n"
    b"url: https://asr.example/x\n"
    b"description: Example Catalog\n"
    b"categories:\n"
    b"  - id: C1\n"
    b"    requirements:\n"
    b"      - id: SEC-A\n"
    b"      - id: SEC-B\n"
    b"  - id: C2\n"
    b"    requirements:\n"
    b"      - id: SEC-C\n"
)


def test_catalog_meta_counts_requirements():
    meta = rs.catalog_meta(_CATALOG)
    assert meta["count"] == 3
    assert meta["url"] == "https://asr.example/x"
    assert meta["generated"] == "2026-04-09T07:51:52Z"
    assert meta["description"] == "Example Catalog"


def test_catalog_meta_handles_garbage():
    meta = rs.catalog_meta(b"\x00not yaml: [unbalanced")
    assert meta["count"] is None


def test_freshness_fresh_and_stale():
    now = datetime(2026, 6, 13, tzinfo=timezone.utc)
    recent = (now - timedelta(days=5)).isoformat().replace("+00:00", "Z")
    old = (now - timedelta(days=90)).isoformat().replace("+00:00", "Z")
    assert rs.freshness(recent, now=now)["fresh"] is True
    assert rs.freshness(recent, now=now)["age_days"] == 5
    assert rs.freshness(old, now=now)["stale"] is True


def test_freshness_unknown_forces_stale():
    v = rs.freshness(None)
    assert v["known"] is False
    assert v["stale"] is True


def test_local_repo_source_ignores_dotfile(tmp_path):
    # The generated dotfile must NOT be picked up as a local source.
    (tmp_path / ".requirements.yaml").write_text("x", encoding="utf-8")
    assert rs.local_repo_source(tmp_path) is None
    (tmp_path / "requirements.yaml").write_text("categories: []\n", encoding="utf-8")
    assert rs.local_repo_source(tmp_path) == str(tmp_path / "requirements.yaml")


def test_sidecar_roundtrip_and_clear(tmp_path):
    cache = tmp_path / "requirements.yaml"
    cache.write_bytes(_CATALOG)
    sidecar = rs.sidecar_path_for_cache(cache)
    data = rs.build_sidecar("https://asr.example/x", "org-profile", _CATALOG, rs.now_iso())
    rs.write_sidecar(sidecar, data)
    back = rs.read_sidecar(sidecar)
    assert back["url"] == "https://asr.example/x"
    assert back["count"] == 3
    assert back["sha256"] == rs.sha256(_CATALOG)
    removed = rs.clear_state(cache)
    assert str(cache) in removed and str(sidecar) in removed
    assert not cache.exists() and not sidecar.exists()


def test_backfill_uses_cache_mtime_and_internal_url(tmp_path):
    cache = tmp_path / "requirements.yaml"
    cache.write_bytes(_CATALOG)
    data = rs.backfill_sidecar_from_cache(cache)
    assert data["url"] == "https://asr.example/x"
    assert data["source_kind"] == "backfilled"
    assert data["fetched_at"]  # derived from mtime
    # A second call must not overwrite an existing sidecar.
    again = rs.backfill_sidecar_from_cache(cache)
    assert again["source_kind"] == "backfilled"


def test_backfill_returns_none_without_cache(tmp_path):
    assert rs.backfill_sidecar_from_cache(tmp_path / "absent.yaml") is None


# ---------------------------------------------------------------------------
# validate_catalog
# ---------------------------------------------------------------------------
def test_validate_catalog_accepts_well_formed():
    body = (
        b"generated: '2026-06-13T00:00:00Z'\n"
        b"categories:\n  - id: C\n    title: Cat\n    requirements:\n"
        b"      - id: SEC-A\n        text: Do the thing\n        priority: MUST\n"
        b"      - id: SEC-B\n        text: Do another thing\n        priority: SHOULD\n"
    )
    errors, warnings = rs.validate_catalog(body)
    assert errors == []
    assert warnings == []


def test_validate_catalog_rejects_html_garbage():
    errors, _ = rs.validate_catalog(b"<!DOCTYPE html><html><body>404 Not Found</body></html>")
    assert errors  # not a mapping / wrong shape


def test_validate_catalog_rejects_missing_category_id():
    body = b"categories:\n  - requirements:\n      - id: SEC-A\n"
    errors, _ = rs.validate_catalog(body)
    assert any("id" in e for e in errors)


def test_validate_catalog_rejects_requirement_without_id():
    body = b"categories:\n  - id: C\n    requirements:\n      - text: no id here\n"
    errors, _ = rs.validate_catalog(body)
    assert any("id" in e for e in errors)


def test_validate_catalog_warns_zero_requirements():
    errors, warnings = rs.validate_catalog(b"categories:\n  - id: C\n")
    assert errors == []
    assert any("0 requirements" in w for w in warnings)


def test_validate_catalog_warns_bad_priority_and_missing_text():
    body = (
        b"categories:\n  - id: C\n    requirements:\n"
        b"      - id: A\n        priority: CRITICAL\n"
        b"      - id: B\n        text: ''\n        priority: MUST\n"
    )
    errors, warnings = rs.validate_catalog(body)
    assert errors == []
    assert any("priority" in w for w in warnings)
    assert any("no text" in w for w in warnings)


def test_validate_catalog_warns_duplicate_ids():
    body = b"categories:\n  - id: C\n    requirements:\n      - id: DUP\n        text: x\n      - id: DUP\n        text: y\n"
    errors, warnings = rs.validate_catalog(body)
    assert errors == []
    assert any("duplicate" in w.lower() for w in warnings)


@pytest.mark.parametrize(
    "rel",
    [
        "examples/appsec-requirements-example.yaml",
        "data/appsec-requirements-fallback.yaml",
        "data/appsec-bestpractices-baseline.yaml",
    ],
)
def test_shipped_catalogs_validate_clean(rel):
    body = (REPO_ROOT / rel).read_bytes()
    errors, _ = rs.validate_catalog(body)
    assert errors == [], f"{rel} structural errors: {errors}"
