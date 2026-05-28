"""
Tests for validate_intermediate.py — JSON schema validation of appsec-advisor
intermediate files (.stride-*.json). The dep_scan validator and its fixtures
were removed in 2026-05 alongside the in-tree SCA producer.
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

# Resolve the module under test without installing the package
PLUGIN_SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
from validate_intermediate import validate_stride  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load(name: str) -> dict:
    with (FIXTURES / name).open() as f:
        return json.load(f)


def stride_without(field: str) -> dict:
    d = load("valid_stride.json")
    d.pop(field, None)
    return d


# ===========================================================================
# validate_dep_scan tests removed 2026-05 — the in-tree SCA producer and its
# schema were removed. Supply-chain posture is now produced by
# emit_sca_practice.py / emit_known_bad_libs.py / emit_dep_update_activity.py
# (Phase 10); their sidecars follow simpler shapes covered by their own tests.
# ===========================================================================


# ===========================================================================
# validate_stride
# ===========================================================================


class TestValidStride:
    def test_valid_fixture_passes(self):
        ok, errors = validate_stride(load("valid_stride.json"))
        assert ok, errors

    def test_not_a_dict_fails(self):
        ok, errors = validate_stride("not a dict")
        assert not ok

    @pytest.mark.parametrize("field", ["component_id", "component_name", "analyzed_at", "threats"])
    def test_missing_top_level_field_fails(self, field):
        ok, errors = validate_stride(stride_without(field))
        assert not ok
        assert any(field in e for e in errors)

    def test_threats_not_array_fails(self):
        d = load("valid_stride.json")
        d["threats"] = {"bad": "value"}
        ok, errors = validate_stride(d)
        assert not ok
        assert any("array" in e for e in errors)

    def test_empty_threats_array_is_valid(self):
        d = load("valid_stride.json")
        d["threats"] = []
        ok, errors = validate_stride(d)
        assert ok, errors

    @pytest.mark.parametrize("field", ["local_id", "stride", "scenario", "likelihood", "impact", "risk"])
    def test_threat_missing_required_field_fails(self, field):
        d = load("valid_stride.json")
        d["threats"][0].pop(field)
        ok, errors = validate_stride(d)
        assert not ok
        assert any(field in e for e in errors)

    def test_invalid_stride_category_fails(self):
        d = load("valid_stride.json")
        d["threats"][0]["stride"] = "Hacking"
        ok, errors = validate_stride(d)
        assert not ok
        assert any("stride" in e.lower() for e in errors)

    @pytest.mark.parametrize(
        "valid_cat",
        [
            "Spoofing",
            "Tampering",
            "Repudiation",
            "Information Disclosure",
            "Denial of Service",
            "Elevation of Privilege",
        ],
    )
    def test_all_valid_stride_categories_accepted(self, valid_cat):
        d = load("valid_stride.json")
        d["threats"][0]["stride"] = valid_cat
        ok, errors = validate_stride(d)
        assert ok, errors

    def test_invalid_likelihood_fails(self):
        d = load("valid_stride.json")
        d["threats"][0]["likelihood"] = "Extreme"
        ok, errors = validate_stride(d)
        assert not ok

    def test_invalid_impact_fails(self):
        d = load("valid_stride.json")
        d["threats"][0]["impact"] = "Catastrophic"
        ok, errors = validate_stride(d)
        assert not ok

    def test_invalid_risk_fails(self):
        d = load("valid_stride.json")
        d["threats"][0]["risk"] = "Unknown"
        ok, errors = validate_stride(d)
        assert not ok

    def test_error_stub_is_valid(self):
        """Error stubs (written by agent on failure) must be accepted as valid."""
        ok, errors = validate_stride(load("stride_error_stub.json"))
        assert ok, errors

    def test_error_stub_with_non_empty_threats_array_is_valid(self):
        """parse_error stubs with populated threats are also valid (edge case)."""
        d = load("stride_error_stub.json")
        # even if threats list is non-empty, stub is accepted
        d["threats"] = []
        ok, errors = validate_stride(d)
        assert ok, errors

    def test_multiple_threats_validated_independently(self):
        """A second bad threat doesn't hide behind the first valid one."""
        d = load("valid_stride.json")
        bad_threat = copy.deepcopy(d["threats"][0])
        bad_threat.pop("scenario")
        bad_threat["local_id"] = "rest-api-002"
        d["threats"].append(bad_threat)
        ok, errors = validate_stride(d)
        assert not ok
        # Error must reference the second threat (index 1)
        assert any("threats[1]" in e for e in errors)


# ===========================================================================
# CLI interface
# ===========================================================================

VALIDATE_CLI = PLUGIN_SCRIPTS / "validate_intermediate.py"


class TestCLI:
    def _run(self, schema_type: str, fixture_name: str) -> subprocess.CompletedProcess:
        path = FIXTURES / fixture_name
        return subprocess.run(
            [sys.executable, str(VALIDATE_CLI), schema_type, str(path)],
            capture_output=True,
            text=True,
        )

    def test_cli_valid_stride_exits_0(self):
        result = self._run("stride", "valid_stride.json")
        assert result.returncode == 0
        assert result.stdout.startswith("VALID")

    def test_cli_stride_exit_code_reports_threat_count(self):
        result = self._run("stride", "valid_stride.json")
        assert "1 threats" in result.stdout

    def test_cli_invalid_json_exits_1(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        result = subprocess.run(
            [sys.executable, str(VALIDATE_CLI), "stride", str(bad)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "INVALID JSON" in result.stdout

    def test_cli_missing_file_exits_1(self, tmp_path):
        result = subprocess.run(
            [sys.executable, str(VALIDATE_CLI), "stride", str(tmp_path / "nonexistent.json")],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "INVALID" in result.stdout

    def test_cli_unknown_schema_type_exits_2(self, tmp_path):
        result = subprocess.run(
            [sys.executable, str(VALIDATE_CLI), "bogus_type", str(FIXTURES / "valid_stride.json")],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_cli_too_few_args_exits_2(self):
        result = subprocess.run(
            [sys.executable, str(VALIDATE_CLI)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_cli_stride_error_stub_exits_0(self):
        result = self._run("stride", "stride_error_stub.json")
        assert result.returncode == 0
        assert result.stdout.startswith("VALID")
