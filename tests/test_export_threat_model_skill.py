"""
Integration tests for the `export-threat-model` skill.

The skill is a Bash wrapper over three Python helpers (export_sarif.py,
render_pentest_tasks.py, export_pdf.py). These tests exercise the helpers
end-to-end on a synthetic threat-model.yaml + .md pair to confirm the three
exports are produced and validate cleanly. The Bash skill body itself is not
shell-executed here — it is straightforward delegation with no logic the
helpers don't already cover.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(ROOT / "tests"))

from test_sarif_validation import validate_sarif  # noqa: E402


def _make_threat_model_yaml() -> dict:
    return {
        "meta": {
            "schema_version": 1,
            "plugin_version": "0.9.0-beta",
            "project":        "skill-test",
            "generated":      "2026-05-12T00:00:00Z",
            "mode":           "full",
            "model":          "claude-opus-4-7",
        },
        "components": [
            {"id": "C-01", "name": "API", "paths": ["routes/"]},
        ],
        "assets": [
            {"name": "user-credentials", "classification": "Confidential"},
        ],
        "attack_surface": [
            {"entry_point": "POST /login", "protocol": "HTTPS",
             "auth_required": False, "file": "routes/login.ts", "line": 12},
        ],
        "trust_boundaries": [{"name": "internet→api"}],
        "security_controls": [
            {"domain": "input_validation", "control": "Input Validation",
             "effectiveness": "Weak", "gap": "Raw SQL"},
        ],
        "threats": [
            {
                "id":         "T-001",
                "component":  "API",
                "stride":     "Tampering",
                "title":      "SQL injection in login endpoint",
                "scenario":   "Login concatenates email into raw SQL.",
                "likelihood": "High",
                "impact":     "Critical",
                "risk":       "Critical",
                "cwe":        "CWE-89",
                "evidence":   [{"file": "routes/login.ts", "line": 12}],
                "source":     "stride",
                "mitigation_ids": ["M-001"],
            },
        ],
        "mitigations": [
            {
                "id":         "M-001",
                "title":      "Parameterize SQL",
                "threat_ids": ["T-001"],
                "priority":   "P1",
                "reference":  "https://cwe.mitre.org/data/definitions/89.html",
            },
        ],
    }


def _setup_output_dir(tmp_path: Path) -> Path:
    output_dir = tmp_path / "docs" / "security"
    output_dir.mkdir(parents=True)
    yaml_path = output_dir / "threat-model.yaml"
    yaml_path.write_text(yaml.safe_dump(_make_threat_model_yaml()))
    # Markdown isn't validated by the helpers we test here; the PDF helper is
    # exercised separately in test_export_pdf.py. Write a tiny placeholder so
    # the skill's preflight is satisfied if someone invokes --formats pdf in
    # an integration environment.
    md_path = output_dir / "threat-model.md"
    md_path.write_text("# Threat Model — skill-test\n\n_test fixture_\n")
    return output_dir


def test_sarif_helper_runs_standalone(tmp_path: Path):
    output_dir = _setup_output_dir(tmp_path)
    sarif_out = output_dir / "threat-model.sarif.json"
    result = subprocess.run(
        [
            sys.executable, str(SCRIPTS / "export_sarif.py"),
            "--threat-model", str(output_dir / "threat-model.yaml"),
            "--output",       str(sarif_out),
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    with sarif_out.open() as f:
        sarif = json.load(f)
    ok, errors = validate_sarif(sarif)
    assert ok, errors
    rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert "T-001" in rule_ids


def test_pentest_helper_runs_yaml_only(tmp_path: Path):
    output_dir = _setup_output_dir(tmp_path)
    pentest_out = output_dir / "pentest-tasks.yaml"
    result = subprocess.run(
        [
            sys.executable, str(SCRIPTS / "render_pentest_tasks.py"),
            "--threat-model", str(output_dir / "threat-model.yaml"),
            "--output",       str(pentest_out),
            "--dialect",      "generic",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    doc = yaml.safe_load(pentest_out.read_text())
    finding = [t for t in doc["tasks"] if t["task_type"] == "finding-verification"]
    assert len(finding) == 1
    assert finding[0]["threat_id"] == "T-001"
    assert finding[0]["cwe"] == "CWE-89"


def test_pentest_helper_with_target_url(tmp_path: Path):
    output_dir = _setup_output_dir(tmp_path)
    pentest_out = output_dir / "pentest-tasks.yaml"
    result = subprocess.run(
        [
            sys.executable, str(SCRIPTS / "render_pentest_tasks.py"),
            "--threat-model", str(output_dir / "threat-model.yaml"),
            "--output",       str(pentest_out),
            "--dialect",      "strix",
            "--target-url",   "https://staging.example.com",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    doc = yaml.safe_load(pentest_out.read_text())
    assert doc["meta"]["target"]["base_url"] == "https://staging.example.com"
    assert doc["meta"]["dialect"] == "strix"


def test_skill_file_exists():
    skill = ROOT / "skills" / "export-threat-model" / "SKILL.md"
    assert skill.is_file(), "SKILL.md must exist"
    content = skill.read_text()
    # Sanity-check: every documented format must appear in the body so the
    # routing tables stay in sync with the help block.
    for keyword in ("--formats", "pdf", "html", "sarif", "pentest",
                    "export_sarif.py", "render_pentest_tasks.py",
                    "export_pdf.py", "export_html.py"):
        assert keyword in content, f"SKILL.md missing keyword: {keyword}"


def test_html_helper_cli_present():
    """export_html.py exposes --check-only and propagates exit codes
    consistent with the skill's preflight contract."""
    script = SCRIPTS / "export_html.py"
    assert script.is_file()
    # --help should print without invoking pandoc.
    result = subprocess.run(
        [sys.executable, str(script), "--help"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "--input" in result.stdout
    assert "--output" in result.stdout
    assert "--no-mermaid" in result.stdout
    assert "--check-only" in result.stdout


def test_html_helper_reuses_pdf_helpers():
    """The HTML exporter must import the shared helpers from export_pdf to
    avoid drift in Mermaid/vscode/pandoc handling."""
    sys.path.insert(0, str(SCRIPTS))
    import importlib
    if "export_html" in sys.modules:
        importlib.reload(sys.modules["export_html"])
    import export_html  # noqa: E402
    # Functions imported from export_pdf should be reachable.
    assert export_html.md_to_html.__module__ == "export_pdf"
    assert export_html.render_mermaid_blocks.__module__ == "export_pdf"
    assert export_html.rewrite_vscode_links.__module__ == "export_pdf"


def test_html_helper_missing_input_exits_two(tmp_path: Path):
    """When pandoc is present but input md is missing, exit 2."""
    import shutil
    if not shutil.which("pandoc"):
        pytest.skip("pandoc not installed — preflight would fail first")
    result = subprocess.run(
        [
            sys.executable, str(SCRIPTS / "export_html.py"),
            "--input",  str(tmp_path / "nope.md"),
            "--output", str(tmp_path / "out.html"),
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 2
