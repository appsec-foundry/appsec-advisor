"""Test for scripts/check_fragment_registry.py — fragment-registry drift gate."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_fragment_registry.py"


def _import_module():
    spec = importlib.util.spec_from_file_location("check_fragment_registry", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["check_fragment_registry"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_registry_clean_against_head():
    """The fragment registry MUST stay consistent across all 5 maps + schemas."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert proc.returncode == 0, (
        "Fragment-registry drift detected. The maps in compose_threat_model.py, "
        "validate_fragment.py, qa_checks.py must stay aligned with "
        "data/sections-contract.yaml and schemas/fragments/. "
        f"Linter output:\n{proc.stderr}"
    )


def test_check_returns_empty_on_clean_repo():
    mod = _import_module()
    errors = mod.check()
    assert errors == [], f"Unexpected drift: {errors}"


def test_check_detects_missing_section_in_map(monkeypatch, tmp_path):
    """Synthetic-drift test: remove an entry from _SECTION_FRAGMENT_MAP, expect a drift."""
    mod = _import_module()
    real_extract = mod._extract_dict_literal

    def broken_extract(source, name):
        result = real_extract(source, name)
        if name == "_SECTION_FRAGMENT_MAP":
            result = {k: v for k, v in result.items() if k != "verdict"}
        return result

    monkeypatch.setattr(mod, "_extract_dict_literal", broken_extract)
    errors = mod.check()
    assert any("verdict" in e for e in errors), errors
