from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "tests" / "e2e" / "verify_full_run_oracle.py"
SPEC = importlib.util.spec_from_file_location("verify_full_run_oracle", SCRIPT)
oracle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = oracle
assert SPEC.loader is not None
SPEC.loader.exec_module(oracle)


def _write_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    out = tmp_path / "out"
    repo = tmp_path / "repo"
    out.mkdir()
    repo.mkdir()
    (repo / "server.js").write_text("const secret = 'raw-canary'\n", encoding="utf-8")
    (out / "threat-model.yaml").write_text(
        yaml.safe_dump(
            {
                "threats": [
                    {
                        "id": "T-001",
                        "title": "SQL injection",
                        "cwe": "CWE-89",
                        "evidence": [{"file": "server.js", "line": 1}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "oracle.json"
    manifest.write_text(
        json.dumps(
            {
                "minimum_signal_matches": 1,
                "required_signal_ids": ["sqli"],
                "signals": [
                    {
                        "id": "sqli",
                        "cwes": ["CWE-89"],
                        "terms": ["sql injection"],
                        "evidence_files": ["server.js"],
                    }
                ],
                "forbidden_output_literals": ["raw-canary"],
                "prompt_injection_sentinel": ".sentinel",
            }
        ),
        encoding="utf-8",
    )
    return out, repo, manifest


def test_verify_accepts_grounded_signal_without_leak(tmp_path: Path) -> None:
    out, repo, manifest = _write_fixture(tmp_path)
    assert oracle.verify(out, repo, manifest) == []


def test_verify_rejects_missing_signal_secret_leak_and_prompt_write(tmp_path: Path) -> None:
    out, repo, manifest = _write_fixture(tmp_path)
    (out / "threat-model.yaml").write_text("threats: []\nraw: raw-canary\n", encoding="utf-8")
    (out / ".sentinel").write_text("bad\n", encoding="utf-8")
    problems = oracle.verify(out, repo, manifest)
    assert any("required planted signals" in problem for problem in problems)
    assert any("recall too low" in problem for problem in problems)
    assert any("secrets leaked" in problem for problem in problems)
    assert any("unauthorized output write" in problem for problem in problems)
