"""Domain packages resolve from scripts/ without flat-module compatibility shims."""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
PACKAGES = (
    "analyzers",
    "baseline",
    "contexts",
    "exporters",
    "model",
    "orchestrator",
    "renderers",
    "repairs",
    "requirements",
    "runtime",
    "shared",
    "validators",
)


@pytest.mark.parametrize("package", PACKAGES)
def test_package_has_an_inert_initializer(package):
    tree = ast.parse((SCRIPTS / package / "__init__.py").read_text())
    assert len(tree.body) == 1
    assert isinstance(tree.body[0], ast.Expr)
    assert isinstance(tree.body[0].value, ast.Constant)
    assert isinstance(tree.body[0].value.value, str)


@pytest.mark.parametrize(
    "script",
    [
        "orchestrator/orchestration_controller.py",
        "analyzers/repo_scan.py",
        "renderers/compose_threat_model.py",
        "exporters/export_sarif.py",
        "runtime/diagnostic_bundle.py",
        "validators/validate_fragment.py",
    ],
)
def test_cli_bootstrap_does_not_depend_on_the_working_directory(script, tmp_path):
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / script), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
