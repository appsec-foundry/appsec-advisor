"""Regression tests for the two-layer Mermaid QA check.

Layer A (pure-Python regex in qa_checks.check_mermaid_syntax) catches a narrow
set of known-bad patterns. Layer B (scripts/mermaid_validate.mjs) embeds the
real Mermaid parser and catches grammar violations Layer A can't see.

These tests verify:
  * Layer A still flags the patterns it is supposed to flag.
  * Layer B catches at least one grammar violation Layer A misses — proving the
    extra dependency is actually earning its keep.
  * When Node isn't available, Layer B degrades to a non-blocking warning
    rather than flagging diagrams as broken.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPTS = REPO / "scripts"


def _qa() -> object:
    # Import lazily — the module is at scripts/qa_checks.py. We must register
    # the loaded module in sys.modules before executing it, otherwise
    # dataclasses (`@dataclass class Report`) fail with AttributeError when
    # resolving forward-ref annotations because sys.modules[cls.__module__]
    # is None.
    import importlib.util
    import sys

    if "qa_checks" in sys.modules:
        return sys.modules["qa_checks"]
    spec = importlib.util.spec_from_file_location("qa_checks", SCRIPTS / "qa_checks.py")
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["qa_checks"] = mod
    spec.loader.exec_module(mod)
    return mod


def _run_check(tmp_path: Path, md_body: str):
    md = tmp_path / "threat-model.md"
    md.write_text(md_body)
    return _qa().check_mermaid_syntax(md)


# ---------------------------------------------------------------------------
# Layer A — regex patterns we own directly
# ---------------------------------------------------------------------------


def test_layer_a_catches_semicolon_in_sequence_payload(tmp_path: Path):
    """Semicolons derail the sequenceDiagram parser — the autofix (Rule D) now
    repairs them before detection, so the issue is drained into report.fixes
    and the rewritten file no longer carries the ';'."""
    md = "# t\n\n```mermaid\nsequenceDiagram\n    A->>B: SELECT * FROM x; DROP\n```\n"
    report = _run_check(tmp_path, md)
    assert any("seqdiagram_semicolon" in f for f in report.fixes), report.fixes
    assert not any("literal ';'" in i for i in report.issues), report.issues


def test_layer_a_catches_unbalanced_quote(tmp_path: Path):
    md = '# t\n\n```mermaid\nsequenceDiagram\n    A->>B: say "hi there\n```\n'
    report = _run_check(tmp_path, md)
    assert any("unbalanced double-quote" in i for i in report.issues), report.issues


def test_layer_a_catches_unquoted_paren_in_participant(tmp_path: Path):
    md = "# t\n\n```mermaid\nsequenceDiagram\n    participant OS as Host OS (sh)\n    A->>OS: hi\n```\n"
    report = _run_check(tmp_path, md)
    assert any("unquoted '('" in i for i in report.issues), report.issues


def test_layer_c_autofixes_html_tag_in_sequence_payload(tmp_path: Path):
    """`Bearer <token>` / `<br/>` in a sequenceDiagram arrow payload crash
    Mermaid. Layer C strips them to plain text in place and — because the
    auto-fix runs before detection — the issue is NOT re-reported, so the
    Re-Render Loop never dispatches an agent for it (the 2026-06-05 juice-shop
    §7 render defect)."""
    md = tmp_path / "threat-model.md"
    md.write_text(
        "# t\n\n```mermaid\nsequenceDiagram\n"
        "    Client->>MW: GET /api/Users Authorization: Bearer <token>\n"
        "    MW-->>Client: 200 OK<br/>body\n"
        "```\n"
    )
    report = _qa().check_mermaid_syntax(md)
    after = md.read_text()
    assert not any("HTML tag" in i for i in report.issues), report.issues
    assert any("seqdiagram_html_strip" in f for f in report.fixes), report.fixes
    assert "<token>" not in after and "<br" not in after
    assert "Bearer token" in after
    # Idempotent — a second pass makes no further change.
    report2 = _qa().check_mermaid_syntax(md)
    assert report2.fixes == [], report2.fixes


def test_layer_a_passes_valid_sequence(tmp_path: Path):
    md = "# t\n\n```mermaid\nsequenceDiagram\n    participant A\n    participant B\n    A->>B: hello\n```\n"
    report = _run_check(tmp_path, md)
    assert report.issues == [], report.issues


# ---------------------------------------------------------------------------
# Layer B — authoritative parser. Skipped when Node or the validator's
# dependencies are missing.
# ---------------------------------------------------------------------------


def _layer_b_ready() -> bool:
    if shutil.which("node") is None:
        return False
    validator = SCRIPTS / "mermaid_validate.mjs"
    if not validator.exists():
        return False
    # Probe the validator with a minimal valid diagram. If it exits with code
    # 2 (environment error) or its output reports `skipped: true`, we know
    # mermaid/jsdom aren't reachable and Layer B can't run.
    probe = "sequenceDiagram\n    A->>B: hi\n"
    r = subprocess.run(
        ["node", str(validator)],
        input=probe,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if r.returncode == 2:
        return False
    try:
        payload = json.loads((r.stdout or "").strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return False
    return bool(payload.get("ok")) and not payload.get("skipped")


@pytest.mark.skipif(not _layer_b_ready(), reason="Node / mermaid / jsdom not available")
def test_layer_b_batch_mode_reports_per_block_results():
    validator = SCRIPTS / "mermaid_validate.mjs"
    payload = [
        {"idx": 1, "body": "sequenceDiagram\n    A->>B: hi\n"},
        {"idx": 2, "body": "sequenceDiagram\n    alt Missing close\n        A->>B: attack\n"},
    ]
    r = subprocess.run(
        ["node", str(validator), "--batch-json"],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r.returncode == 1
    result = json.loads((r.stdout or "").strip().splitlines()[-1])
    assert result["ok"] is False
    assert result["results"][0]["idx"] == 1
    assert result["results"][0]["ok"] is True
    assert result["results"][1]["idx"] == 2
    assert result["results"][1]["ok"] is False


@pytest.mark.skipif(not _layer_b_ready(), reason="Node / mermaid / jsdom not available")
def test_layer_b_catches_unclosed_alt_block(tmp_path: Path):
    """Missing `end` on an `alt` block — invisible to Layer A, fatal to mermaid."""
    md = (
        "# t\n\n"
        "```mermaid\n"
        "sequenceDiagram\n"
        "    participant A\n"
        "    participant B\n"
        "    alt Current state — T-001\n"
        "        A->>B: attack\n"
        "```\n"
    )
    report = _run_check(tmp_path, md)
    # Layer A finds nothing here.
    layer_a_misses = not any("literal ';'" in i or "unbalanced" in i or "unquoted '('" in i for i in report.issues)
    # Layer B finds the missing `end`.
    layer_b_catches = any("authoritative parse failed" in i for i in report.issues)
    assert layer_a_misses and layer_b_catches, report.issues


@pytest.mark.skipif(not _layer_b_ready(), reason="Node / mermaid / jsdom not available")
def test_layer_b_catches_bracket_label_in_flowchart(tmp_path: Path):
    """Bare `[` inside a flowchart node label — Layer A has no flowchart
    label rules, but mermaid rejects the diagram."""
    md = "# t\n\n```mermaid\ngraph TD\n    A[raw [unescaped] bracket] --> B\n```\n"
    report = _run_check(tmp_path, md)
    assert any("authoritative parse failed" in i for i in report.issues), report.issues


@pytest.mark.skipif(not _layer_b_ready(), reason="Node / mermaid / jsdom not available")
def test_layer_b_passes_valid_diagrams(tmp_path: Path):
    md = (
        "# t\n\n"
        "```mermaid\n"
        "sequenceDiagram\n"
        "    participant A\n"
        "    participant B\n"
        "    A->>B: hi\n"
        "```\n\n"
        "```mermaid\n"
        "graph TD\n"
        "    A --> B\n"
        "```\n"
    )
    report = _run_check(tmp_path, md)
    assert report.issues == [], report.issues
    assert report.warnings == [], report.warnings


# ---------------------------------------------------------------------------
# Layer B skip path — simulate missing deps and verify we emit a warning
# rather than flagging every diagram as broken.
# ---------------------------------------------------------------------------


def test_layer_b_skip_path_is_non_blocking(monkeypatch, tmp_path: Path):
    """If the validator script is missing, Layer B must record a single
    informational warning and let Layer A drive the check."""
    qa = _qa()
    # Point the module's validator path at a path that doesn't exist.
    missing = tmp_path / "not-there.mjs"
    monkeypatch.setattr(qa, "_MERMAID_VALIDATOR_JS", missing)
    md = tmp_path / "tm.md"
    md.write_text("# t\n\n```mermaid\nsequenceDiagram\n    A->>B: valid\n```\n")
    report = qa.check_mermaid_syntax(md)
    # Issues must stay empty (diagram IS valid by Layer A).
    assert report.issues == [], report.issues
    # Exactly one informational warning about the skip.
    assert len(report.warnings) == 1, report.warnings
    assert "skipped" in report.warnings[0].lower()


def test_layer_b_uses_single_batch_invocation(monkeypatch, tmp_path: Path):
    qa = _qa()
    validator = tmp_path / "validator.mjs"
    validator.write_text("// fake validator\n")
    monkeypatch.setattr(qa, "_MERMAID_VALIDATOR_JS", validator)
    monkeypatch.setattr(qa.shutil, "which", lambda name: "/usr/bin/node" if name == "node" else None)

    calls = []

    class Result:
        returncode = 1
        stdout = json.dumps(
            {
                "ok": False,
                "results": [
                    {"idx": 1, "ok": True},
                    {"idx": 2, "ok": False, "error": "Parse error on line 2"},
                ],
            }
        )

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return Result()

    monkeypatch.setattr(qa.subprocess, "run", fake_run)

    md = tmp_path / "tm.md"
    md.write_text(
        "# t\n\n```mermaid\nsequenceDiagram\n    A->>B: valid\n```\n\n```mermaid\ngraph TD\n    A --> B\n```\n"
    )
    report = qa.check_mermaid_syntax(md)

    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args == ["/usr/bin/node", str(validator), "--batch-json"]
    batch = json.loads(kwargs["input"])
    assert [item["idx"] for item in batch] == [1, 2]
    assert len(report.issues) == 1
    assert "mermaid block #2" in report.issues[0]


def test_layer_b_batch_skip_path_is_non_blocking(monkeypatch, tmp_path: Path):
    qa = _qa()
    validator = tmp_path / "validator.mjs"
    validator.write_text("// fake validator\n")
    monkeypatch.setattr(qa, "_MERMAID_VALIDATOR_JS", validator)
    monkeypatch.setattr(qa.shutil, "which", lambda name: "/usr/bin/node" if name == "node" else None)

    class Result:
        returncode = 2
        stdout = json.dumps(
            {
                "ok": False,
                "skipped": True,
                "error": "missing: jsdom",
            }
        )

    monkeypatch.setattr(qa.subprocess, "run", lambda *args, **kwargs: Result())

    md = tmp_path / "tm.md"
    md.write_text("# t\n\n```mermaid\nsequenceDiagram\n    A->>B: valid\n```\n")
    report = qa.check_mermaid_syntax(md)

    assert report.issues == [], report.issues
    assert len(report.warnings) == 1
    assert "missing: jsdom" in report.warnings[0]
