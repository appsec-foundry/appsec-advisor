"""Unit tests for scripts/validate_intermediate.py.

validate_intermediate.py is the schema + invariant gate for all intermediate
JSON artifacts (stride, threats_merged, triage_flags, …). These tests
exercise the public API and CLI contract directly. The dep_scan validator
was removed in 2026-05 alongside the in-tree SCA producer.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "validate_intermediate.py"
SCHEMAS_DIR = REPO_ROOT / "schemas"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


vi = _load_module("validate_intermediate", SCRIPT_PATH)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Schema file registry completeness
# ---------------------------------------------------------------------------


def test_all_registered_schema_files_exist():
    """Every schema referenced in _SCHEMA_FILES must be present on disk."""
    missing = []
    for kind, schema_file in vi._SCHEMA_FILES.items():
        path = SCHEMAS_DIR / schema_file
        if not path.is_file():
            missing.append(f"{kind} → {schema_file}")
    assert not missing, "Missing schema files:\n  " + "\n  ".join(missing)


def test_schema_files_are_valid_yaml():
    """Every registered schema file must parse as valid YAML."""
    invalid = []
    for kind, schema_file in vi._SCHEMA_FILES.items():
        path = SCHEMAS_DIR / schema_file
        if path.is_file():
            try:
                yaml.safe_load(path.read_text())
            except yaml.YAMLError as e:
                invalid.append(f"{kind}: {e}")
    assert not invalid, "Invalid YAML in schema files:\n  " + "\n  ".join(invalid)


# ---------------------------------------------------------------------------
# CLI: unknown artifact type
# ---------------------------------------------------------------------------


def test_unknown_kind_exits_2(tmp_path: Path):
    dummy = tmp_path / "x.json"
    dummy.write_text("{}")
    result = _run(["unknown_kind", str(dummy)])
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# stride validation
# ---------------------------------------------------------------------------


def test_stride_empty_object_fails():
    ok, errors = vi.validate_stride({})
    assert not ok
    assert errors


def test_stride_minimal_valid():
    minimal = {
        "component_id": "auth-svc",
        "component_name": "Auth Service",
        "analyzed_at": "2026-04-22T10:00:00Z",
        "threats": [],
    }
    ok, errors = vi.validate_stride(minimal)
    assert ok, f"Expected valid stride, got errors: {errors}"


# ---------------------------------------------------------------------------
# CLI file-not-found
# ---------------------------------------------------------------------------


def test_missing_file_exits_nonzero():
    result = _run(["stride", "/nonexistent/path.json"])
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# Python post-check invariants
# ---------------------------------------------------------------------------


def _make_threat(t_id: str, cwe: str = "CWE-89") -> dict:
    return {
        "t_id": t_id,
        "component_id": "svc",
        "component_name": "Service",
        "stride": "Tampering",
        "risk": "High",
        "likelihood": "High",
        "impact": "High",
        "title": f"Threat {t_id}",
        "cwe": [cwe],
        "evidence": {"file": "app.py", "line": 1},
        "source": "stride",
        "architectural_violation": False,
    }


def test_t_id_must_be_sequential():
    """T-IDs in threats_merged must be sequential — a gap should fail the invariant check."""
    data = {
        "version": 1,
        "generated_at": "2026-04-22T10:00:00Z",
        "threats": [
            _make_threat("T-001"),
            _make_threat("T-003"),  # gap — should be T-002
        ],
    }
    ok, errors = vi.validate_threats_merged(data)
    assert not ok, "Expected validation to fail due to non-sequential T-IDs"
