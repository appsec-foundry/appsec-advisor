"""Tests for scripts/check_target_specificity.py.

The gate is only useful if it stays quiet on a healthy repository, so the
exemptions carry as many tests as the violations.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import check_target_specificity as cts  # noqa: E402

VOCABULARY = """
targets:
  demo-target:
    names:
      - demo-shop
      - demoshop
    artifacts:
      - "/secretkeys"
      - "loot.md"
"""


@pytest.fixture
def project(tmp_path: Path) -> Path:
    for name in cts.SCAN_ROOTS:
        (tmp_path / name).mkdir()
    (tmp_path / "vocabulary.yaml").write_text(VOCABULARY, encoding="utf-8")
    return tmp_path


def run(project: Path) -> tuple[int, str]:
    import io
    from contextlib import redirect_stderr

    buffer = io.StringIO()
    with redirect_stderr(buffer):
        code = cts.main(["--root", str(project), "--vocabulary", str(project / "vocabulary.yaml")])
    return code, buffer.getvalue()


def test_clean_project_passes(project: Path) -> None:
    (project / "scripts" / "clean.py").write_text('MESSAGE = "generic text"\n', encoding="utf-8")
    assert run(project) == (0, "")


def test_name_in_python_string_literal_is_reported(project: Path) -> None:
    (project / "scripts" / "report.py").write_text('DETAIL = "the demo-shop run lost $51"\n', encoding="utf-8")
    code, output = run(project)
    assert code == 1
    assert "R1-name" in output
    assert "scripts/report.py:1" in output


def test_name_in_python_comment_or_docstring_is_provenance(project: Path) -> None:
    source = '"""Calibrated on the demo-shop run of 2026-06-13."""\n\n# demo-shop showed 8 components\nX = 1\n'
    (project / "scripts" / "calibrated.py").write_text(source, encoding="utf-8")
    assert run(project) == (0, "")


def test_name_in_markdown_code_span_is_reported(project: Path) -> None:
    (project / "agents" / "prompt.md").write_text("Good: `participant DB as demoshop.sqlite`\n", encoding="utf-8")
    code, output = run(project)
    assert code == 1
    assert "R1-name" in output


def test_name_in_markdown_prose_is_provenance(project: Path) -> None:
    body = "The 2026-05-25 demo-shop run shipped a thin callout, so author the fragment.\n"
    (project / "agents" / "prompt.md").write_text(body, encoding="utf-8")
    assert run(project) == (0, "")


def test_name_in_fenced_block_comment_is_provenance(project: Path) -> None:
    body = "Example:\n\n```bash\n# demo-shop 2026-06-27 needed this\nrun --flag\n```\n"
    (project / "agents" / "prompt.md").write_text(body, encoding="utf-8")
    assert run(project) == (0, "")


def test_name_in_yaml_value_is_reported_but_comment_is_not(project: Path) -> None:
    (project / "data" / "rules.yaml").write_text("# demo-shop needed this\nhint: plain\n", encoding="utf-8")
    assert run(project) == (0, "")

    (project / "data" / "rules.yaml").write_text("hint: demo-shop-route\n", encoding="utf-8")
    code, output = run(project)
    assert code == 1
    assert "R1-name" in output


def test_name_in_help_text_is_reported(project: Path) -> None:
    (project / "skills" / "HELP.txt").write_text("  --slug <value>   e.g. demo-shop-quick\n", encoding="utf-8")
    code, _ = run(project)
    assert code == 1


def test_reference_to_an_existing_repository_file_is_allowed(project: Path) -> None:
    (project / "examples").mkdir()
    (project / "examples" / "threat-model-demo-shop.md").write_text("published example\n", encoding="utf-8")
    body = "The reference output at `examples/threat-model-demo-shop.md` uses the rounded form.\n"
    (project / "agents" / "prompt.md").write_text(body, encoding="utf-8")
    assert run(project) == (0, "")


def test_artifact_is_reported_in_code_and_in_markdown_prose(project: Path) -> None:
    (project / "scripts" / "rules.py").write_text('HINTS = ("/secretkeys", "key material")\n', encoding="utf-8")
    code, output = run(project)
    assert code == 1
    assert "R2-artifact" in output

    (project / "scripts" / "rules.py").unlink()
    (project / "agents" / "sample.md").write_text("> 1. Download the key at /secretkeys.\n", encoding="utf-8")
    code, output = run(project)
    assert code == 1
    assert "R2-artifact" in output


def test_artifact_in_a_comment_documents_the_rule(project: Path) -> None:
    source = '# The LLM prose often mentions loot.md as a bare token.\nSUFFIXES = ("bak",)\n'
    (project / "scripts" / "prose.py").write_text(source, encoding="utf-8")
    assert run(project) == (0, "")


def test_generic_paths_outside_the_vocabulary_never_fire(project: Path) -> None:
    """Guards the FP budget: only unmistakable artifacts belong in the vocabulary."""
    source = 'HINTS = ("/ftp", "routes/login", "app.use(\'/metrics\'", "/.well-known/jwks.json")\n'
    (project / "scripts" / "generic.py").write_text(source, encoding="utf-8")
    assert run(project) == (0, "")


def test_unparseable_python_still_gets_scanned(project: Path) -> None:
    (project / "scripts" / "broken.py").write_text('def f(:\n    "demo-shop"\n', encoding="utf-8")
    code, _ = run(project)
    assert code == 1


def test_missing_vocabulary_exits_two(project: Path) -> None:
    import io
    from contextlib import redirect_stderr

    buffer = io.StringIO()
    with redirect_stderr(buffer):
        code = cts.main(["--root", str(project), "--vocabulary", str(project / "absent.yaml")])
    assert code == 2


def test_repository_itself_is_clean() -> None:
    """Drift guard: production code carries no test-target specifics."""
    assert cts.main([]) == 0
