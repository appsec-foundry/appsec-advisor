"""Contract tests for deterministic reconnaissance signals."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

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
)


def _valid() -> dict:
    return {
        "schema_version": 1,
        "signals": {key: False for key in SIGNAL_KEYS},
        "signal_evidence": {key: "none" for key in SIGNAL_KEYS},
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
