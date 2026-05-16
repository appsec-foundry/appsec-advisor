"""
Tests for scripts/render_threat_model.py (Step 1 of the template migration).

Covers:
  - marker parsing (required and optional forms, whitespace tolerance)
  - strict mode aborts on missing required fragment
  - lenient mode inserts a visible stub and continues
  - optional marker is silently dropped when the fragment is absent
  - malformed markers raise TemplateError (exit 2 via CLI)
  - nested-include warning
  - basic fixture roundtrip (template + fragments → rendered report)
  - CLI exit codes for success, missing fragment, template error, IO error
  - template skeleton under templates/ is well-formed
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
SCRIPT_PATH = SCRIPTS_DIR / "render_threat_model.py"
SCHEMA_PATH = SCRIPTS_DIR / "render_threat_model_schema.py"
TEMPLATE_PATH = REPO_ROOT / "templates" / "threat-model.template.md"
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "render"


def _load_module(name: str, path: Path):
    """Load a standalone .py file as a module (scripts/ is not a package)."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


renderer = _load_module("render_threat_model", SCRIPT_PATH)
schema = _load_module("render_threat_model_schema", SCHEMA_PATH)


# ---------------------------------------------------------------------------
# Unit tests — marker parsing & substitution
# ---------------------------------------------------------------------------


def test_basic_required_include(tmp_path: Path) -> None:
    (tmp_path / "one.md").write_text("ONE\n")
    rendered, warnings = renderer.render("A\n{{include: one.md}}\nB\n", tmp_path)
    assert rendered == "A\nONE\n\nB\n"
    assert warnings == []


def test_whitespace_tolerance_in_marker(tmp_path: Path) -> None:
    (tmp_path / "one.md").write_text("ONE\n")
    # whitespace around the colon and inside the braces is allowed
    rendered, _ = renderer.render("{{  include :   one.md  }}\n", tmp_path)
    assert "ONE" in rendered


def test_optional_marker_missing_is_dropped(tmp_path: Path) -> None:
    # fragment does not exist; optional marker must be silently removed
    rendered, warnings = renderer.render("X\n{{include?: missing.md}}\nY\n", tmp_path)
    assert rendered == "X\n\nY\n"
    assert warnings == []


def test_optional_marker_present_is_included(tmp_path: Path) -> None:
    (tmp_path / "opt.md").write_text("OPTIONAL\n")
    rendered, _ = renderer.render("{{include?: opt.md}}\n", tmp_path)
    assert "OPTIONAL" in rendered


def test_required_missing_strict_raises(tmp_path: Path) -> None:
    with pytest.raises(renderer.MissingFragmentError) as exc:
        renderer.render("{{include: nope.md}}\n", tmp_path, strict=True)
    assert "nope.md" in exc.value.missing


def test_required_missing_lenient_inserts_stub(tmp_path: Path) -> None:
    rendered, warnings = renderer.render("{{include: nope.md}}\n", tmp_path, strict=False)
    assert "nope.md" in rendered
    assert "Renderer" in rendered  # stub mentions the renderer
    assert any("nope.md" in w for w in warnings)


def test_malformed_marker_raises_template_error(tmp_path: Path) -> None:
    # missing closing brace on the inner expression — {{foo}} is not a valid include marker
    with pytest.raises(renderer.TemplateError):
        renderer.render("hello {{foo}} world\n", tmp_path)


def test_unknown_marker_keyword_raises(tmp_path: Path) -> None:
    # {{var: x}} is not yet supported; it should be rejected, not silently passed through
    with pytest.raises(renderer.TemplateError):
        renderer.render("{{var: project_name}}\n", tmp_path)


def test_nested_include_warns(tmp_path: Path) -> None:
    (tmp_path / "outer.md").write_text("outer\n{{include: inner.md}}\n")
    (tmp_path / "inner.md").write_text("inner\n")
    rendered, warnings = renderer.render("{{include: outer.md}}\n", tmp_path)
    assert "outer" in rendered
    # nested marker must be left as literal text
    assert "{{include: inner.md}}" in rendered
    # and a warning must be emitted
    assert any("nested include" in w for w in warnings)


def test_multiple_markers_in_one_line(tmp_path: Path) -> None:
    (tmp_path / "a.md").write_text("A")
    (tmp_path / "b.md").write_text("B")
    rendered, _ = renderer.render("{{include: a.md}} and {{include: b.md}}\n", tmp_path)
    assert rendered == "A and B\n"


# ---------------------------------------------------------------------------
# Fixture roundtrip
# ---------------------------------------------------------------------------


def test_fixture_roundtrip() -> None:
    template_text = (FIXTURES_DIR / "template-basic.md").read_text()
    rendered, warnings = renderer.render(template_text, FIXTURES_DIR / "fragments-basic")

    # required fragments are inlined in order
    assert "# Threat Model — Fixture" in rendered
    assert "## Header" in rendered
    assert "Generated at: 2026-04-10" in rendered
    assert "## 1. Overview" in rendered
    assert "This is the overview" in rendered

    # ordering: header before overview
    assert rendered.index("## Header") < rendered.index("## 1. Overview")

    # optional fragment is absent from the fixtures dir → must be dropped,
    # and no warnings should fire for it
    assert "99-optional" not in rendered
    assert warnings == []


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


def _run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


def test_cli_success(tmp_path: Path) -> None:
    fragments = tmp_path / "fragments"
    fragments.mkdir()
    (fragments / "body.md").write_text("BODY\n")

    template = tmp_path / "tpl.md"
    template.write_text("{{include: body.md}}\n")

    output = tmp_path / "out.md"

    result = _run_cli(
        [
            "--template",
            str(template),
            "--fragments-dir",
            str(fragments),
            "--output",
            str(output),
        ]
    )
    assert result.returncode == 0, result.stderr
    assert "RENDERED" in result.stdout
    assert output.read_text().startswith("BODY")


def test_cli_exit_1_on_missing_required(tmp_path: Path) -> None:
    fragments = tmp_path / "fragments"
    fragments.mkdir()

    template = tmp_path / "tpl.md"
    template.write_text("{{include: missing.md}}\n")

    result = _run_cli(
        [
            "--template",
            str(template),
            "--fragments-dir",
            str(fragments),
            "--output",
            str(tmp_path / "out.md"),
        ]
    )
    assert result.returncode == 1
    assert "missing.md" in result.stderr


def test_cli_exit_2_on_template_error(tmp_path: Path) -> None:
    fragments = tmp_path / "fragments"
    fragments.mkdir()

    template = tmp_path / "tpl.md"
    template.write_text("{{garbage}}\n")

    result = _run_cli(
        [
            "--template",
            str(template),
            "--fragments-dir",
            str(fragments),
            "--output",
            str(tmp_path / "out.md"),
        ]
    )
    assert result.returncode == 2


def test_cli_exit_3_on_missing_fragments_dir(tmp_path: Path) -> None:
    template = tmp_path / "tpl.md"
    template.write_text("hello\n")

    result = _run_cli(
        [
            "--template",
            str(template),
            "--fragments-dir",
            str(tmp_path / "does-not-exist"),
            "--output",
            str(tmp_path / "out.md"),
        ]
    )
    assert result.returncode == 3


def test_cli_lenient_flag(tmp_path: Path) -> None:
    fragments = tmp_path / "fragments"
    fragments.mkdir()

    template = tmp_path / "tpl.md"
    template.write_text("{{include: missing.md}}\n")

    output = tmp_path / "out.md"
    result = _run_cli(
        [
            "--template",
            str(template),
            "--fragments-dir",
            str(fragments),
            "--output",
            str(output),
            "--lenient",
        ]
    )
    assert result.returncode == 0
    assert "Renderer" in output.read_text()


# ---------------------------------------------------------------------------
# Plugin template skeleton self-check
# ---------------------------------------------------------------------------


def test_plugin_template_parses(tmp_path: Path) -> None:
    """The committed plugin template must be well-formed and must render
    successfully against a fragments directory containing its declared
    required fragments."""
    assert TEMPLATE_PATH.is_file(), f"template missing at {TEMPLATE_PATH}"
    template_text = TEMPLATE_PATH.read_text()

    fragments_dir = tmp_path / "fragments"
    fragments_dir.mkdir()
    for rel in schema.REQUIRED_FRAGMENTS:
        (fragments_dir / rel).write_text(f"STUB: {rel}\n")

    rendered, warnings = renderer.render(template_text, fragments_dir, strict=True)
    for rel in schema.REQUIRED_FRAGMENTS:
        assert f"STUB: {rel}" in rendered, f"{rel} was not inlined"
    assert warnings == []


def test_plugin_template_declares_known_schema() -> None:
    """Every fragment ID declared in REQUIRED_FRAGMENTS must be referenced in
    the template. OPTIONAL_FRAGMENTS may or may not appear during the
    migration (only Section 7b is optional by design)."""
    template_text = TEMPLATE_PATH.read_text()
    for rel in schema.REQUIRED_FRAGMENTS:
        assert f"{{{{include: {rel}}}}}" in template_text, f"REQUIRED fragment {rel} is not referenced in the template"
