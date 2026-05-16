"""
Tests for `scripts/export_sarif.py` — deterministic SARIF v2.1.0 generation
from a `threat-model.yaml` export.

Reuses the structural validator from `tests/test_sarif_validation.py` and the
existing fixtures under `tests/fixtures/`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# Import the module under test via path injection so the tests run from the
# repo root without installing the package.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import export_sarif  # noqa: E402
from test_sarif_validation import _RISK_TO_LEVEL, validate_sarif  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
FROZEN_RUN_YAML = FIXTURES / "e2e" / "frozen-run" / "threat-model.yaml"
COMPOSE_YAML = FIXTURES / "compose" / "threat-model.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def _make_threat(**overrides) -> dict:
    base = {
        "id": "T-001",
        "component": "REST API",
        "stride": "Tampering",
        "title": "SQL injection in product search",
        "scenario": "Product search builds raw SQL via template literal, enabling UNION dump.",
        "likelihood": "High",
        "impact": "Critical",
        "risk": "Critical",
        "cwe": "CWE-89",
        "evidence": [{"file": "routes/search.ts", "line": 42}],
        "mitigation_ids": ["M-001"],
        "source": "stride",
    }
    base.update(overrides)
    return base


def _make_mitigation(**overrides) -> dict:
    base = {
        "id": "M-001",
        "title": "Parameterize SQL queries",
        "threat_ids": ["T-001"],
        "priority": "P1",
        "reference": "https://cwe.mitre.org/data/definitions/89.html",
    }
    base.update(overrides)
    return base


def _make_doc(threats: list[dict], mitigations: list[dict] | None = None) -> dict:
    return {
        "meta": {
            "schema_version": 1,
            "plugin_version": "0.9.0-beta",
            "generated": "2026-05-12T00:00:00Z",
            "project": "test",
            "mode": "full",
            "model": "claude-opus-4-7",
        },
        "threats": threats,
        "mitigations": mitigations or [],
    }


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_slugify_basic(self):
        assert export_sarif._slugify("Hardcoded RSA private key") == "hardcoded-rsa-private-key"

    def test_slugify_caps_length(self):
        s = export_sarif._slugify("a" * 100, max_len=10)
        assert len(s) == 10

    def test_first_sentence(self):
        text = "First sentence. Second sentence. Third."
        assert export_sarif._first_sentence(text) == "First sentence."

    def test_first_sentence_no_break(self):
        assert export_sarif._first_sentence("no break") == "no break"

    def test_first_sentence_empty(self):
        assert export_sarif._first_sentence("") == ""

    def test_evidence_array(self):
        t = {"evidence": [{"file": "a.ts", "line": 1}, {"file": "b.ts"}]}
        out = export_sarif._evidence_entries(t)
        assert [e["file"] for e in out] == ["a.ts", "b.ts"]

    def test_evidence_dict_legacy(self):
        t = {"evidence": {"file": "a.ts", "line": 9}}
        out = export_sarif._evidence_entries(t)
        assert out == [{"file": "a.ts", "line": 9}]

    def test_evidence_empty(self):
        assert export_sarif._evidence_entries({}) == []
        assert export_sarif._evidence_entries({"evidence": []}) == []
        assert export_sarif._evidence_entries({"evidence": {}}) == []

    def test_mitigation_ids_canonical_and_legacy(self):
        assert export_sarif._mitigation_ids({"mitigation_ids": ["M-001"]}) == ["M-001"]
        assert export_sarif._mitigation_ids({"mitigations": ["M-002"]}) == ["M-002"]

    def test_threat_id_canonical_and_legacy(self):
        assert export_sarif._threat_id({"id": "T-001"}) == "T-001"
        assert export_sarif._threat_id({"t_id": "T-002"}) == "T-002"
        assert export_sarif._threat_id({}) is None


# ---------------------------------------------------------------------------
# build_sarif structural tests
# ---------------------------------------------------------------------------


class TestBuildSarif:
    def test_minimal_doc_validates(self):
        doc = _make_doc([_make_threat()], [_make_mitigation()])
        sarif = export_sarif.build_sarif(doc)
        ok, errors = validate_sarif(sarif)
        assert ok, f"SARIF validation failed: {errors}"

    def test_version_and_schema(self):
        sarif = export_sarif.build_sarif(_make_doc([_make_threat()]))
        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")

    def test_tool_driver(self):
        sarif = export_sarif.build_sarif(_make_doc([_make_threat()]))
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "appsec-advisor"
        assert driver["version"]  # non-empty

    def test_rule_per_threat(self):
        threats = [_make_threat(id=f"T-00{n}") for n in range(1, 4)]
        sarif = export_sarif.build_sarif(_make_doc(threats))
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids == ["T-001", "T-002", "T-003"]

    def test_risk_to_level_mapping(self):
        for risk, expected in _RISK_TO_LEVEL.items():
            sarif = export_sarif.build_sarif(_make_doc([_make_threat(risk=risk)]))
            rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
            result = sarif["runs"][0]["results"][0]
            assert rule["defaultConfiguration"]["level"] == expected
            assert result["level"] == expected

    def test_location_from_evidence_array(self):
        t = _make_threat(evidence=[{"file": "routes/login.ts", "line": 17}])
        sarif = export_sarif.build_sarif(_make_doc([t]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "routes/login.ts"
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert loc["region"]["startLine"] == 17

    def test_location_missing_line_defaults_to_one(self):
        t = _make_threat(evidence=[{"file": "x.ts"}])
        sarif = export_sarif.build_sarif(_make_doc([t]))
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] == 1

    def test_no_evidence_omits_locations(self):
        t = _make_threat(evidence=[])
        sarif = export_sarif.build_sarif(_make_doc([t]))
        assert "locations" not in sarif["runs"][0]["results"][0]

    def test_fixes_from_mitigations(self):
        t = _make_threat(mitigation_ids=["M-001", "M-002"])
        mits = [
            _make_mitigation(id="M-001", title="Parameterize SQL queries"),
            _make_mitigation(id="M-002", title="Sanitize template literals"),
        ]
        sarif = export_sarif.build_sarif(_make_doc([t], mits))
        fixes = sarif["runs"][0]["results"][0]["fixes"]
        assert [f["description"]["text"] for f in fixes] == [
            "Parameterize SQL queries",
            "Sanitize template literals",
        ]

    def test_no_mitigations_omits_fixes(self):
        t = _make_threat(mitigation_ids=[])
        sarif = export_sarif.build_sarif(_make_doc([t]))
        assert "fixes" not in sarif["runs"][0]["results"][0]

    def test_help_uri_direct(self):
        t = _make_threat(remediation_reference="https://internal/blueprint")
        sarif = export_sarif.build_sarif(_make_doc([t], [_make_mitigation()]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://internal/blueprint"

    def test_help_uri_falls_back_to_mitigation_reference(self):
        t = _make_threat()  # no remediation_reference
        mit = _make_mitigation(reference="https://owasp.org/cheat/sqli")
        sarif = export_sarif.build_sarif(_make_doc([t], [mit]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://owasp.org/cheat/sqli"

    def test_help_uri_absent_when_no_source(self):
        t = _make_threat()
        mit = _make_mitigation(reference=None)
        sarif = export_sarif.build_sarif(_make_doc([t], [mit]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "helpUri" not in rule

    def test_cvss_propagation(self):
        t = _make_threat(
            cvss_v4={
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                "base_score": 9.3,
                "severity": "Critical",
                "source": "stride-analyzer",
            }
        )
        sarif = export_sarif.build_sarif(_make_doc([t]))
        props = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        assert props["security-severity"] == "9.3"
        assert props["cvss-v4-vector"].startswith("CVSS:4.0/")
        assert props["cvss-version"] == "4.0"

    def test_cvss_v3_fallback(self):
        t = _make_threat(
            cvss_v4={
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "base_score": 8.8,
                "severity": "High",
                "source": "dep-scan",
                "version_fallback": "3.1",
            }
        )
        sarif = export_sarif.build_sarif(_make_doc([t]))
        props = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        assert props["security-severity"] == "8.8"
        assert props["cvss-version"] == "3.1"

    def test_no_cvss_omits_severity_keys(self):
        t = _make_threat(cvss_v4=None)
        sarif = export_sarif.build_sarif(_make_doc([t]))
        props = sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]
        assert "security-severity" not in props
        assert "cvss-v4-vector" not in props
        assert "cvss-version" not in props

    def test_stride_in_tags_and_properties(self):
        t = _make_threat(stride="Spoofing")
        sarif = export_sarif.build_sarif(_make_doc([t]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["stride"] == "Spoofing"
        assert "spoofing" in rule["properties"]["tags"]

    def test_short_description_is_first_sentence(self):
        t = _make_threat(
            scenario="One. Two. Three.",
        )
        sarif = export_sarif.build_sarif(_make_doc([t]))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["shortDescription"]["text"] == "One."
        assert rule["fullDescription"]["text"] == "One. Two. Three."

    def test_threat_with_no_id_is_skipped(self):
        threats = [_make_threat(id="T-001"), {"title": "no id"}, _make_threat(id="T-002")]
        sarif = export_sarif.build_sarif(_make_doc(threats))
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert rule_ids == ["T-001", "T-002"]

    def test_duplicate_threat_ids_emit_one_rule(self):
        threats = [_make_threat(id="T-001"), _make_threat(id="T-001")]
        sarif = export_sarif.build_sarif(_make_doc(threats))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        results = sarif["runs"][0]["results"]
        assert len(rules) == 1  # rule de-duplicated
        assert len(results) == 2  # but both result rows kept

    def test_empty_threats_produces_empty_run(self):
        sarif = export_sarif.build_sarif(_make_doc([]))
        ok, errors = validate_sarif(sarif)
        assert ok, errors
        assert sarif["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# Fixture-driven integration tests
# ---------------------------------------------------------------------------


class TestFixtures:
    @pytest.mark.parametrize("path", [COMPOSE_YAML, FROZEN_RUN_YAML])
    def test_fixture_yaml_produces_valid_sarif(self, path):
        if not path.is_file():
            pytest.skip(f"fixture missing: {path}")
        data = _load(path)
        sarif = export_sarif.build_sarif(data)
        ok, errors = validate_sarif(sarif)
        assert ok, f"SARIF from {path.name} failed validation: {errors}"

    def test_compose_fixture_legacy_fields_handled(self):
        if not COMPOSE_YAML.is_file():
            pytest.skip("compose fixture missing")
        data = _load(COMPOSE_YAML)
        sarif = export_sarif.build_sarif(data)
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        # The compose fixture uses `t_id` instead of `id` — the exporter must
        # still produce rules for each threat.
        assert "T-001" in rule_ids
        assert len(rule_ids) >= 1


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------


class TestCli:
    def test_cli_writes_sarif(self, tmp_path):
        yaml_path = tmp_path / "threat-model.yaml"
        out_path = tmp_path / "threat-model.sarif.json"
        with yaml_path.open("w") as f:
            yaml.safe_dump(_make_doc([_make_threat()], [_make_mitigation()]), f)

        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "export_sarif.py"),
                "--threat-model",
                str(yaml_path),
                "--output",
                str(out_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert out_path.is_file()
        with out_path.open() as f:
            sarif = json.load(f)
        ok, errors = validate_sarif(sarif)
        assert ok, errors

    def test_cli_missing_yaml_exits_one(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "export_sarif.py"),
                "--threat-model",
                str(tmp_path / "nope.yaml"),
                "--output",
                str(tmp_path / "out.sarif.json"),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 1
