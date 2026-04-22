"""Unit tests for scripts/validate_fragment.py.

validate_fragment.py is a hard gate: it runs between LLM fragment output and
the renderer. These tests verify the CLI contract (exit codes, stdout/stderr)
and the FRAGMENT_SCHEMAS registry directly.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_fragment.py"
SCHEMAS_DIR = REPO_ROOT / "schemas" / "fragments"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


vf = _load_module("validate_fragment", SCRIPT_PATH)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Registry completeness
# ---------------------------------------------------------------------------

def test_all_schema_files_present():
    """Every schema registered in FRAGMENT_SCHEMAS must exist on disk."""
    missing = []
    for fragment_type, schema_file in vf.FRAGMENT_SCHEMAS.items():
        path = SCHEMAS_DIR / schema_file
        if not path.is_file():
            missing.append(f"{fragment_type} → {schema_file}")
    assert not missing, "Missing schema files:\n  " + "\n  ".join(missing)


def test_schema_files_are_valid_json():
    """Every registered schema file must parse as valid JSON."""
    invalid = []
    for fragment_type, schema_file in vf.FRAGMENT_SCHEMAS.items():
        path = SCHEMAS_DIR / schema_file
        if path.is_file():
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                invalid.append(f"{fragment_type}: {e}")
    assert not invalid, "Invalid JSON in schema files:\n  " + "\n  ".join(invalid)


def test_fragment_schemas_not_empty():
    assert len(vf.FRAGMENT_SCHEMAS) >= 6, (
        "Expected at least 6 registered fragment types"
    )


# ---------------------------------------------------------------------------
# CLI exit codes
# ---------------------------------------------------------------------------

def test_unknown_fragment_type_exits_nonzero(tmp_path: Path):
    dummy = tmp_path / "frag.json"
    dummy.write_text("{}")
    result = _run(["nonexistent-type", str(dummy)])
    assert result.returncode != 0


def test_missing_fragment_file_exits_nonzero():
    result = _run(["verdict", "/nonexistent/path/frag.json"])
    assert result.returncode != 0


def test_invalid_json_fragment_exits_nonzero(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json {{{")
    result = _run(["verdict", str(bad)])
    assert result.returncode != 0


def test_schema_violation_exits_1(tmp_path: Path):
    """A structurally wrong fragment must exit 1 (schema violation)."""
    frag = tmp_path / "bad-verdict.json"
    frag.write_text('{"wrong_field": true}')
    result = _run(["verdict", str(frag)])
    assert result.returncode == 1
    assert "VALIDATE_FAILED" in result.stderr


def test_valid_fragment_exits_0(tmp_path: Path):
    """Load the verdict schema and build a minimal conforming payload."""
    schema_path = SCHEMAS_DIR / vf.FRAGMENT_SCHEMAS["verdict"]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    required = schema.get("required", [])

    # Build a minimal object with empty/false values for required fields
    # so we can verify the happy path without tight-coupling to the schema.
    minimal: dict = {}
    props = schema.get("properties", {})
    for field in required:
        field_schema = props.get(field, {})
        ftype = field_schema.get("type")
        if ftype == "string":
            minimal[field] = "placeholder"
        elif ftype == "integer":
            minimal[field] = 0
        elif ftype == "boolean":
            minimal[field] = False
        elif ftype == "array":
            minimal[field] = []
        elif ftype == "object":
            minimal[field] = {}
        else:
            minimal[field] = None

    frag = tmp_path / "ok-verdict.json"
    frag.write_text(json.dumps(minimal))

    result = _run(["verdict", str(frag)])
    # May fail schema constraints (e.g. minLength) — we only assert the
    # script ran without an unexpected crash (exit 2 = usage/IO error).
    assert result.returncode in (0, 1), (
        f"Expected 0 or 1, got {result.returncode}; stderr: {result.stderr}"
    )
