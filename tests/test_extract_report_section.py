"""Contract for scripts/extract_report_section.py.

The extractor feeds the GitHub Actions job summary, so a silent truncation
would show a plausible-looking but incomplete report to whoever reads the run
page -- the worst failure mode for a security report. These tests pin the
boundary rules, above all fence-awareness: against the real fixture report a
naive `startswith("## ")` scan returned 3 006 of 33 043 bytes for the
Mitigation Register, dropping 91% at the first `# Before (insecure):` comment
inside an embedded code block.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
SCRIPT = ROOT / "scripts" / "extract_report_section.py"

sys.path.insert(0, str(ROOT / "scripts"))
from extract_report_section import extract_section  # noqa: E402

REPORT = """\
# Threat Model - demo

## Management Summary

Two critical findings.

## 10. Mitigation Register

Fix it like this:

```bash
# Before (insecure):
q = "SELECT " + name
## not a heading either
```

Still inside the Mitigation Register.

## 11. Out of Scope

Nothing.
"""


class TestSectionBoundaries:
    def test_extracts_only_the_requested_section(self):
        out = extract_section(REPORT, "Management Summary")
        assert out.startswith("## Management Summary")
        assert "Two critical findings." in out
        assert "Mitigation Register" not in out

    def test_heading_line_is_included(self):
        assert extract_section(REPORT, "Management Summary").splitlines()[0] == "## Management Summary"

    def test_last_section_runs_to_eof(self):
        out = extract_section(REPORT, "11. Out of Scope")
        assert "Nothing." in out

    def test_missing_section_returns_none(self):
        assert extract_section(REPORT, "Nope") is None

    def test_heading_match_is_case_insensitive(self):
        assert extract_section(REPORT, "management summary") is not None


class TestFenceAwareness:
    """The load-bearing rule. Without it the Mitigation Register -- the section
    that embeds before/after code blocks -- gets cut at its first code comment."""

    def test_hash_comments_inside_a_fence_do_not_end_the_section(self):
        out = extract_section(REPORT, "10. Mitigation Register")
        assert "# Before (insecure):" in out, "fence-aware scan lost the code block"
        assert "Still inside the Mitigation Register." in out, (
            "section ended early at a '#' comment inside a code fence"
        )
        assert "Out of Scope" not in out, "section ran past its real end"

    def test_double_hash_inside_a_fence_does_not_end_the_section(self):
        out = extract_section(REPORT, "10. Mitigation Register")
        assert "## not a heading either" in out

    def test_tilde_fence_is_honoured(self):
        text = "## A\n\n~~~\n## inside tilde fence\n~~~\n\nafter\n\n## B\n\nb\n"
        out = extract_section(text, "A")
        assert "## inside tilde fence" in out
        assert "after" in out
        assert "\n## B" not in out

    def test_shorter_run_does_not_close_a_longer_fence(self):
        """CommonMark: a closing fence needs at least the opening length."""
        text = "## A\n\n````\n```\n## still inside\n````\n\nafter\n\n## B\n\nb\n"
        out = extract_section(text, "A")
        assert "## still inside" in out
        assert "after" in out
        assert "\n## B" not in out


class TestCli:
    def _run(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)

    @pytest.fixture()
    def report(self, tmp_path):
        p = tmp_path / "threat-model.md"
        p.write_text(REPORT, encoding="utf-8")
        return p

    def test_default_section_is_management_summary(self, report):
        r = self._run(str(report))
        assert r.returncode == 0
        assert r.stdout.startswith("## Management Summary")

    def test_multiple_sections_keep_request_order(self, report):
        r = self._run(str(report), "--section", "11. Out of Scope", "--section", "Management Summary")
        assert r.returncode == 0
        assert r.stdout.index("Out of Scope") < r.stdout.index("Management Summary")

    def test_missing_file_exits_2(self, tmp_path):
        r = self._run(str(tmp_path / "absent.md"))
        assert r.returncode == 2

    def test_missing_section_exits_3(self, report):
        r = self._run(str(report), "--section", "Nope")
        assert r.returncode == 3

    def test_skip_missing_tolerates_absent_optional_section(self, report):
        r = self._run(str(report), "--section", "Management Summary", "--section", "Nope", "--skip-missing")
        assert r.returncode == 0
        assert r.stdout.startswith("## Management Summary")

    def test_skip_missing_still_fails_when_nothing_matched(self, report):
        r = self._run(str(report), "--section", "Nope", "--skip-missing")
        assert r.returncode == 3
