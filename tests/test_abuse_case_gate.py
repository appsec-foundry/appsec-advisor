"""Tests for the opt-in deterministic abuse-case release gate."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "abuse_case_gate.py"


def _load():
    spec = importlib.util.spec_from_file_location("abuse_case_gate", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["abuse_case_gate"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


gate = _load()


def _write(output_dir: Path, matches: list[dict], verdicts: list[dict], preset: str | None = None) -> None:
    (output_dir / ".abuse-case-matches.json").write_text(json.dumps({"matches": matches}), encoding="utf-8")
    (output_dir / ".abuse-case-verdicts.json").write_text(json.dumps({"verdicts": verdicts}), encoding="utf-8")
    if preset:
        (output_dir / ".skill-config.json").write_text(json.dumps({"preset": {"name": preset}}), encoding="utf-8")


def _case(fail_on: list[str], applies: list[str] | None = None) -> dict:
    gate_cfg = {"fail_on": fail_on}
    if applies is not None:
        gate_cfg["applies_to_presets"] = applies
    return {"id": "REPO-AC-001", "title": "Replay", "release_gate": gate_cfg}


def test_gate_blocks_explicit_final_verdict(tmp_path: Path):
    _write(tmp_path, [{"abuse_case_id": "REPO-AC-001", "case": _case(["fully_viable"])}], [{"abuse_case_id": "REPO-AC-001", "chain_verdict": "fully_viable"}])
    assert gate.evaluate(tmp_path) == [{"abuse_case_id": "REPO-AC-001", "title": "Replay", "chain_verdict": "fully_viable", "preset": None}]
    assert gate.main(["--output-dir", str(tmp_path)]) == 2


def test_gate_ignores_unlisted_or_missing_verdict(tmp_path: Path):
    _write(tmp_path, [{"abuse_case_id": "REPO-AC-001", "case": _case(["fully_viable"])}], [{"abuse_case_id": "REPO-AC-001", "chain_verdict": "inconclusive"}])
    assert gate.main(["--output-dir", str(tmp_path)]) == 0


def test_gate_honours_preset_filter(tmp_path: Path):
    _write(tmp_path, [{"abuse_case_id": "REPO-AC-001", "case": _case(["fully_viable"], ["release"])}], [{"abuse_case_id": "REPO-AC-001", "chain_verdict": "fully_viable"}], preset="ci")
    assert gate.main(["--output-dir", str(tmp_path)]) == 0
    assert gate.main(["--output-dir", str(tmp_path), "--preset", "release"]) == 2
