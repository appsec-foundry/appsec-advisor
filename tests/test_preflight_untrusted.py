"""Tests for scripts/preflight_untrusted.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "preflight_untrusted.py"
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import preflight_untrusted as pre  # noqa: E402


def _run(repo_root: Path, *extra: str) -> tuple[int, str]:
    env = dict(os.environ)
    env.pop("APPSEC_URL_ALLOWLIST", None)
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(repo_root), "--format", "json", *extra],
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode, proc.stdout


def test_clean_repo_passes(tmp_path):
    (tmp_path / "README.md").write_text("clean", encoding="utf-8")
    code, out = _run(tmp_path)
    assert code == 0
    report = json.loads(out)
    assert report["finding_count"] == 0


def test_repo_owned_claude_settings_flagged(tmp_path):
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text("{}", encoding="utf-8")
    code, out = _run(tmp_path, "--strict")
    assert code == 2
    report = json.loads(out)
    kinds = {f["kind"] for f in report["findings"]}
    assert "repo-owned-hook" in kinds


def test_escaping_symlink_flagged(tmp_path):
    outside = tmp_path.parent / "x_leak.txt"
    outside.write_text("x", encoding="utf-8")
    try:
        os.symlink(outside, tmp_path / "leak.txt")
        code, out = _run(tmp_path, "--strict")
        assert code == 2
        report = json.loads(out)
        assert any(f["kind"] == "escaping-symlink" for f in report["findings"])
    finally:
        outside.unlink(missing_ok=True)


def test_related_repos_url_rejected_in_strict_mode(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "related-repos.yaml").write_text(
        "related:\n  - name: bad\n    threat_model: http://127.0.0.1/threat-model.yaml\n",
        encoding="utf-8",
    )
    code, out = _run(tmp_path, "--strict", "--strict-urls")
    assert code == 2
    report = json.loads(out)
    assert any(f["kind"] == "related-repos-url-rejected" for f in report["findings"])


def test_run_function_returns_structured_report(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    report = pre.run(tmp_path, strict=True, strict_urls=False)
    assert report["finding_count"] >= 1
    assert isinstance(report["findings"], list)


def test_hook_severity_variants(tmp_path):
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "hooks").mkdir()
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "tasks.json").write_text("{}", encoding="utf-8")

    findings = pre._scan_repo_owned_hooks(tmp_path)
    by_path = {f["path"]: f for f in findings}
    assert by_path[".claude/hooks"]["severity"] == "High"
    assert by_path[".vscode/tasks.json"]["severity"] == "Critical"


def test_related_repos_parse_error_and_ignored_entries(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    related = docs / "related-repos.yaml"

    related.write_text("related: [\n", encoding="utf-8")
    findings = pre._scan_related_repos(tmp_path, strict_urls=False)
    assert findings[0]["kind"] == "related-repos-parse-error"

    related.write_text(
        "related:\n"
        "  - local-string\n"
        "  - name: no threat model\n"
        "  - name: local\n    threat_model: docs/local.md\n",
        encoding="utf-8",
    )
    assert pre._scan_related_repos(tmp_path, strict_urls=False) == []


def test_related_repos_url_validation_accepts_ok_and_records_rejection(tmp_path, monkeypatch):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "related-repos.yaml").write_text(
        "related:\n"
        "  - name: ok\n    threat_model: https://example.com/ok.yaml\n"
        "  - name: bad\n    threat_model: https://example.com/bad.yaml\n",
        encoding="utf-8",
    )

    def fake_validate(url: str, *, strict: bool):
        if url.endswith("ok.yaml"):
            return SimpleNamespace(ok=True, reason="")
        return SimpleNamespace(ok=False, reason=f"blocked strict={strict}")

    monkeypatch.setattr(pre, "validate_target_url", fake_validate)

    findings = pre._scan_related_repos(tmp_path, strict_urls=True)
    assert len(findings) == 1
    assert findings[0]["entry_name"] == "bad"
    assert findings[0]["note"] == "blocked strict=True"


def test_render_human_no_findings_and_url_target_bits(tmp_path):
    clean = pre.run(tmp_path, strict=False, strict_urls=False)
    assert "no findings" in pre._render_human(clean)

    report = {
        "repo_root": str(tmp_path),
        "finding_count": 2,
        "findings": [
            {"severity": "High", "kind": "url", "path": "docs/x.yaml", "url": "https://bad", "note": "blocked"},
            {"severity": "High", "kind": "symlink", "path": "leak", "target": "/tmp/leak", "note": "escape"},
        ],
    }
    rendered = pre._render_human(report)
    assert "<https://bad>" in rendered
    assert "-> /tmp/leak" in rendered


def test_main_invalid_repo_text_output_and_json_file(tmp_path, capsys):
    assert pre.main(["--repo-root", str(tmp_path / "missing")]) == 3
    assert "repo root not found" in capsys.readouterr().err

    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    out = tmp_path / "report.json"
    code = pre.main(["--repo-root", str(tmp_path), "--format", "both", "--output", str(out)])
    captured = capsys.readouterr()

    assert code == 1
    assert "repo-owned-hook" in captured.err
    assert json.loads(out.read_text(encoding="utf-8"))["finding_count"] == 1


def test_main_text_only_clean_repo(tmp_path, capsys):
    assert pre.main(["--repo-root", str(tmp_path), "--format", "text"]) == 0
    captured = capsys.readouterr()
    assert "no findings" in captured.err
    assert captured.out == ""
