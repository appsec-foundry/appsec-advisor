"""Unit tests for scripts/requirements_state.py — shared source-state helpers."""

from __future__ import annotations

import builtins
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requirements_state as rs

REPO_ROOT = Path(__file__).parent.parent

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


def test_catalog_meta_without_yaml_returns_empty(monkeypatch):
    monkeypatch.setattr(rs, "yaml", None)

    meta = rs.catalog_meta(_CATALOG)

    assert meta == {"generated": None, "url": None, "description": None, "label": None, "count": None}


def test_catalog_meta_non_mapping_yaml_returns_empty():
    meta = rs.catalog_meta(b"- one\n- two\n")

    assert meta["count"] is None
    assert meta["url"] is None


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


def test_freshness_naive_and_invalid_timestamps():
    now = datetime(2026, 6, 13, tzinfo=timezone.utc)

    naive = rs.freshness("2026-06-10T12:00:00", now=now)
    invalid = rs.freshness("not-a-date", now=now)

    assert naive["known"] is True
    assert naive["age_days"] == 2
    assert invalid["known"] is False


def test_local_repo_source_ignores_dotfile(tmp_path):
    # The generated dotfile must NOT be picked up as a local source.
    (tmp_path / ".requirements.yaml").write_text("x", encoding="utf-8")
    assert rs.local_repo_source(tmp_path) is None
    (tmp_path / "requirements.yaml").write_text("categories: []\n", encoding="utf-8")
    assert rs.local_repo_source(tmp_path) == str(tmp_path / "requirements.yaml")


def test_local_repo_source_uses_yml_and_skips_os_errors(tmp_path, monkeypatch):
    req_yaml = tmp_path / "requirements.yaml"
    req_yml = tmp_path / "requirements.yml"
    req_yaml.write_text("categories: []\n", encoding="utf-8")
    req_yml.write_text("categories:\n  - id: YML\n", encoding="utf-8")

    original_is_file = Path.is_file

    def flaky_is_file(self):
        if self == req_yaml:
            raise OSError("cannot stat")
        return original_is_file(self)

    monkeypatch.setattr(Path, "is_file", flaky_is_file)

    assert rs.local_repo_source(tmp_path) == str(req_yml)


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


def test_read_sidecar_missing_invalid_and_non_mapping(tmp_path):
    missing = tmp_path / "missing.json"
    invalid = tmp_path / "invalid.json"
    array = tmp_path / "array.json"
    invalid.write_text("{", encoding="utf-8")
    array.write_text("[]", encoding="utf-8")

    assert rs.read_sidecar(missing) is None
    assert rs.read_sidecar(invalid) is None
    assert rs.read_sidecar(array) is None


def test_clear_state_ignores_unlink_errors(tmp_path, monkeypatch):
    cache = tmp_path / "requirements.yaml"
    sidecar = rs.sidecar_path_for_cache(cache)
    cache.write_text("categories: []\n", encoding="utf-8")
    sidecar.write_text("{}", encoding="utf-8")

    def fail_unlink(self):
        if self == cache:
            raise OSError("cannot remove")
        return original_unlink(self)

    original_unlink = Path.unlink
    monkeypatch.setattr(Path, "unlink", fail_unlink)

    removed = rs.clear_state(cache)

    assert str(cache) not in removed
    assert str(sidecar) in removed
    assert cache.exists()
    assert not sidecar.exists()


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


def test_backfill_returns_none_for_empty_or_unreadable_cache(tmp_path, monkeypatch):
    empty = tmp_path / "empty.yaml"
    empty.write_bytes(b"")
    assert rs.backfill_sidecar_from_cache(empty) is None

    cache = tmp_path / "requirements.yaml"
    cache.write_bytes(_CATALOG)

    def fail_read_bytes(self):
        if self == cache:
            raise OSError("cannot read")
        return original_read_bytes(self)

    original_read_bytes = Path.read_bytes
    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)

    assert rs.backfill_sidecar_from_cache(cache) is None


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


def test_validate_catalog_without_yaml_errors(monkeypatch):
    monkeypatch.setattr(rs, "yaml", None)

    errors, warnings = rs.validate_catalog(b"categories: []\n")

    assert errors == ["PyYAML unavailable — cannot validate catalog"]
    assert warnings == []


def test_validate_catalog_invalid_yaml_errors():
    errors, warnings = rs.validate_catalog(b"categories: [\n")

    assert errors
    assert "not valid YAML" in errors[0]
    assert warnings == []


def test_validate_catalog_falls_back_without_jsonschema(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    errors, warnings = rs.validate_catalog(b"categories:\n  - id: C\n")

    assert errors == []
    assert any("0 requirements" in w for w in warnings)


def test_validate_catalog_falls_back_when_schema_unreadable(tmp_path):
    missing_schema = tmp_path / "missing.schema.yaml"

    errors, warnings = rs.validate_catalog(b"categories:\n  - id: C\n", schema_path=missing_schema)

    assert errors == []
    assert any("0 requirements" in w for w in warnings)


def test_structural_fallback_reports_nested_shape_errors():
    doc = {
        "categories": [
            "not-a-category",
            {"requirements": ["not-a-requirement", {"text": "missing id"}]},
        ]
    }

    errors = rs._structural_errors_without_jsonschema(doc)

    assert "categories[0] is not a mapping" in errors
    assert "categories[1] missing required key: id" in errors
    assert "categories[1].requirements[0] is not a mapping" in errors
    assert "categories[1].requirements[1] missing required key: id" in errors


def test_structural_fallback_reports_top_level_category_errors():
    assert rs._structural_errors_without_jsonschema(["not-a-mapping"]) == ["top level is not a mapping (got list)"]
    assert rs._structural_errors_without_jsonschema({}) == ["missing required key: categories"]
    assert rs._structural_errors_without_jsonschema({"categories": "not-a-list"}) == ["categories must be a list"]


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


def test_validate_catalog_skips_non_mapping_rows_in_warning_pass(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(rs, "_structural_errors_without_jsonschema", lambda _doc: [])
    body = b"categories:\n  - not-a-mapping\n  - id: C\n    requirements:\n      - not-a-mapping\n"

    errors, warnings = rs.validate_catalog(body)

    assert errors == []
    assert any("0 requirements" in w for w in warnings)


def test_cli_validate_missing_invalid_strict_and_valid(tmp_path, capsys):
    missing = tmp_path / "missing.yaml"
    assert rs._main(["--validate", str(missing)]) == 2
    assert "cannot read" in capsys.readouterr().out

    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("<html>404</html>\n", encoding="utf-8")
    assert rs._main(["--validate", str(invalid)]) == 1
    assert "INVALID catalog" in capsys.readouterr().out

    warn = tmp_path / "warn.yaml"
    warn.write_text("categories:\n  - id: C\n", encoding="utf-8")
    assert rs._main(["--validate", str(warn), "--strict"]) == 1
    assert "warning(s) under --strict" in capsys.readouterr().out

    valid = tmp_path / "valid.yaml"
    valid.write_text(
        "categories:\n  - id: C\n    requirements:\n      - id: SEC-A\n        text: Do it\n        priority: MUST\n",
        encoding="utf-8",
    )
    assert rs._main(["--validate", str(valid)]) == 0
    assert "valid catalog" in capsys.readouterr().out


@pytest.mark.parametrize(
    "rel",
    [
        "examples/appsec-requirements-example.yaml",
        "data/appsec-bestpractices-baseline.yaml",
    ],
)
def test_shipped_catalogs_validate_clean(rel):
    body = (REPO_ROOT / rel).read_bytes()
    errors, _ = rs.validate_catalog(body)
    assert errors == [], f"{rel} structural errors: {errors}"
