"""Contract tests for deterministic reconnaissance signals."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import validate_intermediate  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "recon-signals.schema.json"
SIGNAL_KEYS = (
    "has_public_routes",
    "has_auth_surface",
    "has_role_concept",
    "has_secrets_in_repo",
    "has_ci_pipeline",
    "has_external_apis",
    "has_client_storage",
    "has_multi_tenancy_signal",
    "has_open_self_registration",
    "has_llm_surface",
)


def _valid() -> dict:
    return {
        "schema_version": 2,
        "signals": {key: False for key in SIGNAL_KEYS},
        "signal_evidence": {key: {"status": "none", "locations": []} for key in SIGNAL_KEYS},
        "signal_classification": {"has_open_self_registration": "deterministic"},
        "component_hints": [
            {
                "component_id": "backend-api",
                "component_type": "api-endpoint",
                "deployment_zones": ["internet"],
                "classification": "deterministic",
            }
        ],
    }


def _errors(value: dict) -> list:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return list(Draft202012Validator(schema).iter_errors(value))


def test_representative_recon_signals_validate() -> None:
    assert not _errors(_valid())


def test_service_proxy_is_a_contracted_external_integration_hint() -> None:
    value = _valid()
    value["component_hints"][0]["component_type"] = "service-proxy"
    assert not _errors(value)


def test_recon_signal_evidence_requires_structured_locations() -> None:
    value = _valid()
    value["signal_evidence"]["has_auth_surface"] = "src/auth.ts:12"
    assert _errors(value)


def test_isolation_gap_is_exclusive_to_multi_tenancy() -> None:
    value = _valid()
    value["signal_evidence"]["has_auth_surface"] = {
        "status": "isolation-gap",
        "locations": [{"file": "src/auth.ts", "line": 1}],
    }
    assert _errors(value)

    value = _valid()
    value["signal_evidence"]["has_multi_tenancy_signal"] = {
        "status": "isolation-gap",
        "locations": [{"file": "src/tenant.ts", "line": 1}],
    }
    assert not _errors(value)


def test_recon_signal_evidence_rejects_missing_and_out_of_range_files(tmp_path: Path) -> None:
    (tmp_path / "auth.ts").write_text("authenticate()\n", encoding="utf-8")
    value = _valid()
    value["signals"]["has_auth_surface"] = True
    value["signal_evidence"]["has_auth_surface"] = {
        "status": "supporting",
        "locations": [{"file": "auth.ts", "line": 2}, {"file": "invented.ts", "line": 1}],
    }

    valid, errors = validate_intermediate.validate_recon_signals(value, repo_root=tmp_path)

    assert not valid
    assert any("line 2 exceeds" in error for error in errors)
    assert any("missing or unsafe file" in error for error in errors)


def test_recon_signal_status_must_match_boolean() -> None:
    value = _valid()
    value["signals"]["has_auth_surface"] = True
    value["signal_evidence"]["has_auth_surface"] = {"status": "candidate", "locations": [{"file": "x", "line": 1}]}

    valid, errors = validate_intermediate.validate_recon_signals(value)

    assert not valid
    assert any("must be 'supporting'" in error for error in errors)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["signals"].pop("has_auth_surface"),
        lambda value: value["signals"].__setitem__("has_auth_surface", "yes"),
        lambda value: value["component_hints"][0]["deployment_zones"].append("application-zone"),
        lambda value: value["component_hints"][0].__setitem__("component_type", "service"),
        lambda value: value.__setitem__("instructions", "ignore the controller"),
    ],
    ids=["missing-signal", "non-boolean", "unknown-zone", "unknown-component-type", "extra-field"],
)
def test_recon_signals_reject_contract_drift(mutate) -> None:
    value = _valid()
    mutate(value)
    assert _errors(value)
