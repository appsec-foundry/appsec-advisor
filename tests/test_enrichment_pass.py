"""Completion receipts survive approved writes but never conceal a rebuild."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from enrichment_pass import EnrichmentContinuation, model_hash, stamp, valid_receipt


@pytest.mark.parametrize("project", ["service-alpha", "document-store"])
def test_receipt_detects_changed_or_rebuilt_model(project):
    document = {"meta": {"project": project}, "threats": [{"id": "T-001", "vektor": "internet-anon"}]}
    stamp(document)
    assert valid_receipt(document)
    document["threats"][0].pop("vektor")
    assert not valid_receipt(document)
    document["meta"] = {"project": project}
    assert not valid_receipt(document)


def test_serialization_and_mapping_order_do_not_invalidate_receipt():
    document = {"meta": {"project": "service"}, "threats": []}
    stamp(document)
    reordered = yaml.safe_load(yaml.safe_dump(document, sort_keys=True, width=4096))
    assert valid_receipt(reordered)
    assert model_hash(reordered) == model_hash(document)


@pytest.mark.parametrize("initial", ["valid", "missing", "stale", "malformed"])
def test_continuation_never_heals_an_unverified_receipt(initial):
    document = {"meta": {}, "threats": []}
    if initial != "missing":
        stamp(document)
    if initial == "stale":
        document["assets"] = []
    if initial == "malformed":
        document["meta"]["enrichment_pass"]["completed_at"] = "not-a-date"
    receipt = copy.deepcopy(document["meta"].get("enrichment_pass"))
    continuation = EnrichmentContinuation(document)
    document["verdict"] = {"opening": "A bounded assessment."}
    continuation.refresh(document)
    assert valid_receipt(document) is (initial == "valid")
    if initial == "valid":
        assert document["meta"]["enrichment_pass"]["completed_at"] == receipt["completed_at"]
    else:
        assert document["meta"].get("enrichment_pass") == receipt


def test_continuation_does_not_restore_a_removed_marker():
    document = {"meta": {}, "threats": []}
    stamp(document)
    continuation = EnrichmentContinuation(document)
    document["meta"].pop("enrichment_pass")
    continuation.refresh(document)
    assert not valid_receipt(document)


@pytest.mark.parametrize("initial", ["valid", "missing", "stale"])
def test_verdict_writer_preserves_only_a_verified_receipt(tmp_path, monkeypatch, initial):
    import emit_verdict_to_model as emitter

    document = {"meta": {}, "threats": []}
    if initial != "missing":
        stamp(document)
    if initial == "stale":
        document["threats"] = [{"id": "T-009"}]
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(document))
    monkeypatch.setattr(emitter, "build_verdict", lambda _: {"opening": "A concrete conclusion."})
    assert emitter.emit(tmp_path).startswith("written")
    assert valid_receipt(yaml.safe_load(path.read_text())) is (initial == "valid")


def test_editorial_change_preserves_receipt_without_loosening_structural_guard(tmp_path):
    from apply_editorial_plan import _apply_structured
    from check_editorial_diff import verify

    document = {"meta": {}, "threats": [{"id": "T-001", "scenario": "Original prose.", "risk": "High"}]}
    stamp(document)
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(document))
    snapshot = {"files": {path.name: path.read_text()}}
    action = {"path": "threats[0].scenario", "find": "Original prose.", "replace": "Clearer prose."}
    assert _apply_structured(path.name, path, [action])[0] == 1
    changed = yaml.safe_load(path.read_text())
    assert valid_receipt(changed)
    assert verify(snapshot, tmp_path) == []
    continuation = EnrichmentContinuation(changed)
    changed["threats"][0]["risk"] = "Low"
    continuation.refresh(changed)
    path.write_text(yaml.safe_dump(changed))
    assert verify(snapshot, tmp_path)


def test_receipt_has_a_closed_schema():
    import jsonschema

    root = Path(__file__).resolve().parents[1]
    schema = yaml.safe_load((root / "schemas/threat-model.output.schema.yaml").read_text())
    receipt_schema = schema["properties"]["meta"]["properties"]["enrichment_pass"]
    document = {"meta": {}}
    stamp(document)
    receipt = document["meta"]["enrichment_pass"]
    jsonschema.validate(receipt, receipt_schema)
    for changed in (
        {**receipt, "extra": True},
        {"completed_at": receipt["completed_at"]},
        {**receipt, "yaml_sha256": "bad"},
    ):
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(changed, receipt_schema)


def test_redaction_preserves_receipt(tmp_path):
    from redact_known_secrets import redact_artifacts

    document = {"meta": {}, "description": "password: 'Example-long-secret-42!'"}
    stamp(document)
    path = tmp_path / "threat-model.yaml"
    path.write_text(yaml.safe_dump(document))
    redact_artifacts(tmp_path, {"Example-long-secret-42!": "[REDACTED]"})
    changed = yaml.safe_load(path.read_text())
    assert valid_receipt(changed)
    assert "Example-long-secret-42!" not in json.dumps(changed)


@pytest.mark.parametrize("content", [None, "[broken", "[]", "meta: wrong"])
def test_cli_rejects_missing_or_malformed_model_without_traceback(tmp_path, content):
    path = tmp_path / "threat-model.yaml"
    if content is not None:
        path.write_text(content)
    script = Path(__file__).resolve().parents[1] / "scripts/enrichment_pass.py"
    result = subprocess.run([sys.executable, str(script), str(tmp_path)], capture_output=True, text=True)
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert (path.read_text() if path.exists() else None) == content


def test_empty_cli_path_does_not_stamp_an_existing_model_in_cwd(tmp_path):
    path = tmp_path / "threat-model.yaml"
    path.write_text("meta: {}\n")
    script = Path(__file__).resolve().parents[1] / "scripts/enrichment_pass.py"
    result = subprocess.run([sys.executable, str(script), ""], cwd=tmp_path, capture_output=True, text=True)
    assert result.returncode != 0
    assert path.read_text() == "meta: {}\n"


def test_cli_refuses_an_escaping_model_symlink(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    source = tmp_path / "foreign.yaml"
    source.write_text("meta: {}\n")
    (run / "threat-model.yaml").symlink_to(source)
    script = Path(__file__).resolve().parents[1] / "scripts/enrichment_pass.py"
    result = subprocess.run([sys.executable, str(script), str(run)], capture_output=True, text=True)
    assert result.returncode != 0
    assert source.read_text() == "meta: {}\n"
