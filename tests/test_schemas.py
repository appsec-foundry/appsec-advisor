"""
Smoke tests for plugin/schemas/*.schema.yaml.

Guards the invariant that every schema is loadable, valid under the
JSONSchema Draft 2020-12 meta-schema, and that the canonical example
`docs/security/threat-model.yaml` satisfies `threat-model.output.schema.yaml`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).parent.parent
SCHEMAS_DIR = ROOT / "plugin" / "schemas"

ALL_SCHEMAS = sorted(SCHEMAS_DIR.glob("*.schema.yaml"))


@pytest.mark.parametrize("schema_path", ALL_SCHEMAS, ids=lambda p: p.name)
def test_schema_is_valid_jsonschema(schema_path: Path) -> None:
    schema = yaml.safe_load(schema_path.read_text())
    # Raises SchemaError if the schema itself is malformed against the
    # Draft 2020-12 meta-schema.
    Draft202012Validator.check_schema(schema)


def test_schemas_directory_not_empty() -> None:
    assert ALL_SCHEMAS, "plugin/schemas/ must contain at least one *.schema.yaml"


def test_threat_model_output_example_validates() -> None:
    schema_path = SCHEMAS_DIR / "threat-model.output.schema.yaml"
    example_path = ROOT / "docs" / "security" / "threat-model.yaml"
    if not example_path.exists():
        pytest.skip(f"example {example_path} not present")

    schema = yaml.safe_load(schema_path.read_text())
    data = yaml.safe_load(example_path.read_text())
    errors = sorted(
        Draft202012Validator(schema).iter_errors(data),
        key=lambda e: list(e.absolute_path),
    )
    assert not errors, "\n".join(
        f"{'.'.join(str(p) for p in e.absolute_path) or 'root'}: {e.message}"
        for e in errors
    )
