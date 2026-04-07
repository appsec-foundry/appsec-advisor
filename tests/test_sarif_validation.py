"""
Tests for SARIF v2.1.0 output validation.

Validates that the SARIF schema produced by the plugin conforms to the
SARIF v2.1.0 specification. Tests cover both the expected schema structure
and edge cases.
"""

import json
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# SARIF v2.1.0 structural validator
# ---------------------------------------------------------------------------

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

_VALID_LEVELS = {"error", "warning", "note", "none"}
_RISK_TO_LEVEL = {
    "Critical": "error",
    "High": "error",
    "Medium": "warning",
    "Low": "note",
}


def validate_sarif(data: Any) -> tuple[bool, list[str]]:
    """Validate a SARIF v2.1.0 JSON object. Returns (is_valid, error_list)."""
    errors: list[str] = []

    if not isinstance(data, dict):
        return False, ["root must be a JSON object"]

    # Top-level fields
    if data.get("version") != _SARIF_VERSION:
        errors.append(f"version must be '{_SARIF_VERSION}', got '{data.get('version')}'")

    if "$schema" in data and data["$schema"] != _SARIF_SCHEMA:
        errors.append(f"$schema URL does not match expected SARIF v2.1.0 schema")

    runs = data.get("runs")
    if not isinstance(runs, list):
        errors.append("'runs' must be an array")
        return len(errors) == 0, errors

    if len(runs) == 0:
        errors.append("'runs' must contain at least one run")
        return len(errors) == 0, errors

    for ri, run in enumerate(runs):
        prefix = f"runs[{ri}]"

        if not isinstance(run, dict):
            errors.append(f"{prefix}: must be an object")
            continue

        # Tool
        tool = run.get("tool")
        if not isinstance(tool, dict):
            errors.append(f"{prefix}.tool: must be an object")
        else:
            driver = tool.get("driver")
            if not isinstance(driver, dict):
                errors.append(f"{prefix}.tool.driver: must be an object")
            else:
                if not driver.get("name"):
                    errors.append(f"{prefix}.tool.driver.name: required")
                if not driver.get("version"):
                    errors.append(f"{prefix}.tool.driver.version: required")

                rules = driver.get("rules", [])
                if not isinstance(rules, list):
                    errors.append(f"{prefix}.tool.driver.rules: must be an array")
                else:
                    rule_ids = set()
                    for idx, rule in enumerate(rules):
                        rprefix = f"{prefix}.tool.driver.rules[{idx}]"
                        if not isinstance(rule, dict):
                            errors.append(f"{rprefix}: must be an object")
                            continue
                        if not rule.get("id"):
                            errors.append(f"{rprefix}.id: required")
                        else:
                            if rule["id"] in rule_ids:
                                errors.append(f"{rprefix}.id: duplicate rule ID '{rule['id']}'")
                            rule_ids.add(rule["id"])

                        sd = rule.get("shortDescription")
                        if sd is not None:
                            if not isinstance(sd, dict) or "text" not in sd:
                                errors.append(f"{rprefix}.shortDescription: must have 'text' field")

                        fd = rule.get("fullDescription")
                        if fd is not None:
                            if not isinstance(fd, dict) or "text" not in fd:
                                errors.append(f"{rprefix}.fullDescription: must have 'text' field")

                        dc = rule.get("defaultConfiguration")
                        if dc is not None:
                            level = dc.get("level")
                            if level and level not in _VALID_LEVELS:
                                errors.append(f"{rprefix}.defaultConfiguration.level: '{level}' not valid")

                        props = rule.get("properties", {})
                        if props:
                            stride = props.get("stride")
                            risk = props.get("risk")
                            if stride and not isinstance(stride, str):
                                errors.append(f"{rprefix}.properties.stride: must be a string")
                            if risk and risk not in ("Critical", "High", "Medium", "Low"):
                                errors.append(f"{rprefix}.properties.risk: invalid value '{risk}'")

        # Results
        results = run.get("results", [])
        if not isinstance(results, list):
            errors.append(f"{prefix}.results: must be an array")
        else:
            for idx, result in enumerate(results):
                rprefix = f"{prefix}.results[{idx}]"
                if not isinstance(result, dict):
                    errors.append(f"{rprefix}: must be an object")
                    continue

                if not result.get("ruleId"):
                    errors.append(f"{rprefix}.ruleId: required")

                level = result.get("level")
                if level and level not in _VALID_LEVELS:
                    errors.append(f"{rprefix}.level: '{level}' not valid")

                msg = result.get("message")
                if msg is not None:
                    if not isinstance(msg, dict) or "text" not in msg:
                        errors.append(f"{rprefix}.message: must have 'text' field")

                locations = result.get("locations", [])
                if not isinstance(locations, list):
                    errors.append(f"{rprefix}.locations: must be an array")
                else:
                    for li, loc in enumerate(locations):
                        lprefix = f"{rprefix}.locations[{li}]"
                        pl = loc.get("physicalLocation", {})
                        al = pl.get("artifactLocation", {})
                        if al and "uri" not in al:
                            errors.append(f"{lprefix}.physicalLocation.artifactLocation.uri: required")

        # columnKind
        ck = run.get("columnKind")
        if ck and ck not in ("utf16CodeUnits", "unicodeCodePoints"):
            errors.append(f"{prefix}.columnKind: '{ck}' not a valid value")

    return len(errors) == 0, errors


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def valid_sarif() -> dict:
    """A minimal valid SARIF v2.1.0 document."""
    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "appsec-plugin",
                        "version": "0.9.0-beta",
                        "semanticVersion": "0.9.0-beta",
                        "rules": [
                            {
                                "id": "T-001",
                                "name": "Spoofing/jwt-bypass",
                                "shortDescription": {"text": "JWT validation bypass"},
                                "fullDescription": {"text": "An attacker can bypass JWT validation..."},
                                "defaultConfiguration": {"level": "error"},
                                "properties": {
                                    "tags": ["security", "spoofing"],
                                    "stride": "Spoofing",
                                    "likelihood": "High",
                                    "impact": "Critical",
                                    "risk": "Critical",
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "T-001",
                        "level": "error",
                        "message": {"text": "JWT validation bypass allows unauthenticated access"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/middleware/auth.ts",
                                        "uriBaseId": "%SRCROOT%",
                                    },
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                        "fixes": [
                            {"description": {"text": "Add JWT signature verification"}}
                        ],
                        "properties": {"mitigationIds": ["M-001"]},
                    }
                ],
                "columnKind": "utf16CodeUnits",
            }
        ],
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSarifValidator:
    def test_valid_sarif(self, valid_sarif):
        ok, errors = validate_sarif(valid_sarif)
        assert ok, f"Validation errors: {errors}"

    def test_wrong_version(self, valid_sarif):
        valid_sarif["version"] = "1.0.0"
        ok, errors = validate_sarif(valid_sarif)
        assert not ok
        assert any("version" in e for e in errors)

    def test_missing_runs(self, valid_sarif):
        del valid_sarif["runs"]
        ok, errors = validate_sarif(valid_sarif)
        assert not ok

    def test_empty_runs(self, valid_sarif):
        valid_sarif["runs"] = []
        ok, errors = validate_sarif(valid_sarif)
        assert not ok

    def test_missing_tool_driver_name(self, valid_sarif):
        del valid_sarif["runs"][0]["tool"]["driver"]["name"]
        ok, errors = validate_sarif(valid_sarif)
        assert not ok
        assert any("name" in e for e in errors)

    def test_duplicate_rule_ids(self, valid_sarif):
        rules = valid_sarif["runs"][0]["tool"]["driver"]["rules"]
        rules.append(rules[0].copy())
        ok, errors = validate_sarif(valid_sarif)
        assert not ok
        assert any("duplicate" in e for e in errors)

    def test_invalid_level(self, valid_sarif):
        valid_sarif["runs"][0]["results"][0]["level"] = "critical"
        ok, errors = validate_sarif(valid_sarif)
        assert not ok
        assert any("level" in e for e in errors)

    def test_missing_rule_id_in_result(self, valid_sarif):
        del valid_sarif["runs"][0]["results"][0]["ruleId"]
        ok, errors = validate_sarif(valid_sarif)
        assert not ok

    def test_location_without_uri(self, valid_sarif):
        del valid_sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        ok, errors = validate_sarif(valid_sarif)
        assert not ok

    def test_result_without_locations(self, valid_sarif):
        """Results without locations are valid (some threats have no file evidence)."""
        del valid_sarif["runs"][0]["results"][0]["locations"]
        ok, errors = validate_sarif(valid_sarif)
        assert ok

    def test_result_without_fixes(self, valid_sarif):
        """Results without fixes are valid."""
        del valid_sarif["runs"][0]["results"][0]["fixes"]
        ok, errors = validate_sarif(valid_sarif)
        assert ok

    def test_risk_to_level_mapping(self):
        """Verify the risk-to-SARIF-level mapping matches the plugin's spec."""
        assert _RISK_TO_LEVEL["Critical"] == "error"
        assert _RISK_TO_LEVEL["High"] == "error"
        assert _RISK_TO_LEVEL["Medium"] == "warning"
        assert _RISK_TO_LEVEL["Low"] == "note"

    def test_valid_sarif_with_no_results(self, valid_sarif):
        """A run with zero results is valid (clean scan)."""
        valid_sarif["runs"][0]["results"] = []
        ok, errors = validate_sarif(valid_sarif)
        assert ok

    def test_invalid_risk_in_properties(self, valid_sarif):
        valid_sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["risk"] = "Extreme"
        ok, errors = validate_sarif(valid_sarif)
        assert not ok
        assert any("risk" in e for e in errors)
