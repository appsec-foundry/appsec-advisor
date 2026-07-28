"""Tests for scripts/emit_verdict_to_model.py.

The emitter exists because the assessment's own verdict lived only in the
rendered Markdown and in `.fragments/ms-verdict.json`, which cleanup deletes —
so no consumer of `threat-model.yaml` could state it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import emit_verdict_to_model as emitter  # noqa: E402,I001

FRAGMENT = {
    "severity": "red",
    "opening": "Not production-ready. The application leaves sensitive operations open to anyone.",
    "bullets_intro": "The scenarios behind this rating:",
    "bullets": [
        {
            "title": "Server takeover",
            "body": "A crafted order runs commands on the server.",
            "refs": ["T-003", "F-003"],
        },
        {
            "title": "Weak password policy",
            "body": "Short passwords are accepted at signup.",
            "refs": ["F-050"],
        },
    ],
    "closing": "Address authentication and authorization before any production use.",
}


def _setup(tmp_path: Path, fragment: dict | None = FRAGMENT, model: dict | None = None) -> Path:
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir(parents=True, exist_ok=True)
    if fragment is not None:
        (frag_dir / "ms-verdict.json").write_text(json.dumps(fragment), encoding="utf-8")
    (frag_dir / "abuse-cases.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "abuse_cases": [
                    {"id": "AC-T-002", "chain_verdict": "fully_viable", "matched_finding_ids": ["F-003"]},
                ],
            }
        ),
        encoding="utf-8",
    )
    doc = model if model is not None else {"meta": {"project": "Demo"}, "threats": [], "weaknesses": []}
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(doc), encoding="utf-8")
    return tmp_path


def _persisted(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8"))


def test_writes_verdict_with_reader_facing_ids(tmp_path):
    out = _setup(tmp_path)
    assert emitter.emit(out).startswith("written")

    verdict = _persisted(out)["verdict"]
    assert verdict["severity"] == "red"
    assert verdict["opening"].startswith("Not production-ready")
    assert verdict["closing"].startswith("Address authentication")
    assert verdict["bullets_intro"] == "The scenarios behind this rating:"
    # T-003 and F-003 are the same finding — cited once, in the form the report shows.
    assert verdict["bullets"][0]["findings"] == ["F-003"]
    assert verdict["bullets"][0]["verified_attack_path"] is True
    assert verdict["bullets"][1]["findings"] == ["F-050"]
    assert verdict["bullets"][1]["verified_attack_path"] is False


def test_preserves_the_rest_of_the_model(tmp_path):
    out = _setup(tmp_path, model={"meta": {"project": "Demo"}, "threats": [{"id": "T-001", "risk": "High"}]})
    emitter.emit(out)
    doc = _persisted(out)
    assert doc["meta"] == {"project": "Demo"}
    assert doc["threats"] == [{"id": "T-001", "risk": "High"}]


def test_idempotent(tmp_path):
    out = _setup(tmp_path)
    emitter.emit(out)
    before = (out / "threat-model.yaml").read_bytes()
    assert emitter.emit(out) == "unchanged"
    assert (out / "threat-model.yaml").read_bytes() == before


def test_no_fragment_is_a_no_op(tmp_path):
    """Architecture-only documents and runs that never reached Stage 2."""
    out = _setup(tmp_path, fragment=None)
    before = (out / "threat-model.yaml").read_bytes()
    assert emitter.emit(out) == "no verdict fragment — nothing to do"
    assert (out / "threat-model.yaml").read_bytes() == before


def test_empty_opening_is_a_no_op(tmp_path):
    out = _setup(tmp_path, fragment={**FRAGMENT, "opening": "   "})
    assert emitter.emit(out) == "no verdict fragment — nothing to do"
    assert "verdict" not in _persisted(out)


def test_missing_model_never_raises(tmp_path):
    """A report that already rendered must not be invalidated by this write."""
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir(parents=True)
    (frag_dir / "ms-verdict.json").write_text(json.dumps(FRAGMENT), encoding="utf-8")
    assert "nothing to do" in emitter.emit(tmp_path)
    assert not (tmp_path / "threat-model.yaml").exists()


def test_persisted_block_validates_against_the_output_schema(tmp_path):
    import jsonschema

    out = _setup(tmp_path)
    emitter.emit(out)
    schema = yaml.safe_load(
        (Path(__file__).resolve().parent.parent / "schemas" / "threat-model.output.schema.yaml").read_text(
            encoding="utf-8"
        )
    )
    validator = jsonschema.Draft202012Validator(schema["properties"]["verdict"])
    validator.validate(_persisted(out)["verdict"])


def test_cli(tmp_path, capsys):
    out = _setup(tmp_path)
    assert emitter.main([str(out)]) == 0
    assert "emit_verdict_to_model: written" in capsys.readouterr().out
    assert emitter.main([]) == 2
