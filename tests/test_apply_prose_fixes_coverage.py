"""Coverage extension for scripts/apply_prose_fixes.py.

Targets wrap-line guard branches, controls-covered/anchor/title/relevant-findings
post-processors, blockquote handling, apply_code_formatting fences and main().
Pins current behavior (test-files-only campaign). No producer edits.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "apply_prose_fixes.py"


def _load():
    if "apply_prose_fixes" in sys.modules:
        return sys.modules["apply_prose_fixes"]
    spec = importlib.util.spec_from_file_location("apply_prose_fixes", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_prose_fixes"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


prose = _load()


# --- _wrap_line http-method-path trailing punctuation / wildcard (426,433-437)


def test_http_method_path_wildcard_route_skipped():
    line = "Call GET /api/* to fetch."
    out, _ = prose._wrap_line(line)
    # Wildcard route must NOT be backticked.
    assert "`/api/*`" not in out


def test_http_method_path_trailing_punct_outside_backtick():
    line = "Use POST /users/login."
    out, n = prose._wrap_line(line)
    assert "`/users/login`." in out
    assert n >= 1


# --- _wrap_line generic branches: glob, before ._, quotes, after (464,489,491,493,495,506)


def test_wrap_line_glob_token_skipped():
    line = "The pattern routes/** matches everything."
    out, _ = prose._wrap_line(line)
    assert "`routes/**`" not in out


def test_wrap_line_member_access_prefix_skipped():
    # token preceded by '.' -> mid-expression, skip (before in "._").
    line = "result is foo.bar.ts here"
    out, _ = prose._wrap_line(line)
    # bare member-chain fragment should not produce partial backticking
    assert "`" not in out or "foo" in out


def test_wrap_line_quoted_literal_skipped():
    line = "the value 'config.ts' stays a string"
    out, _ = prose._wrap_line(line)
    assert "`config.ts`" not in out


# --- _apply_label_as_code_unwrap callback (586-590) ------------------------


def test_label_as_code_unwrap_removes_allowlisted_tokens():
    # Pick a token from the unwrap allowlist dynamically so the test pins
    # current behavior regardless of allowlist contents.
    tokens = sorted(prose._LABEL_TOKENS_TO_UNWRAP)
    assert tokens, "expected a non-empty unwrap allowlist"
    tok = tokens[0]
    out, n = prose._apply_label_as_code_unwrap(f"see `{tok}` here")
    assert out == f"see {tok} here"
    assert n == 1


def test_label_as_code_unwrap_keeps_non_allowlisted():
    out, n = prose._apply_label_as_code_unwrap("keep `zzqqx` backticked")
    assert out == "keep `zzqqx` backticked"
    assert n == 0


# --- _rewrite_controls_covered_anchors: empty sections continue (660) ------


def test_controls_covered_section_with_no_subsections_left_alone():
    text = "### 6.1 Identity\n**Controls covered:** [Old](#old)\n"
    out, n = prose._rewrite_controls_covered_anchors(text)
    # No #### subsections in the section -> sections[sec] empty -> skipped.
    assert n == 0
    assert out == text


# --- _rewrite_controls_covered_anchors: bullet rename drift (687-688) ------


def test_controls_covered_bullet_anchor_rename_refreshed():
    text = "### 6.2 Access\n#### Role checks\nBody.\n**Controls covered:**\n- [Stale label](#stale-anchor)\n"
    out, n = prose._rewrite_controls_covered_anchors(text)
    assert "- [Role checks](#role-checks)" in out
    assert n >= 1


# --- _bulletize_relevant_findings: single finding left alone (754-756) -----


def test_relevant_findings_single_left_alone():
    text = "**Relevant findings:** [F-001](#f-001) — only one"
    out, n = prose._bulletize_relevant_findings(text)
    assert out == text
    assert n == 0


# --- _bulletize_relevant_findings: no rationale bullet (763) ---------------


def test_relevant_findings_multiple_without_rationale():
    text = "**Relevant findings:** [F-001](#f-001) [F-002](#f-002)"
    out, n = prose._bulletize_relevant_findings(text)
    assert "**Relevant findings**" in out
    assert "- [F-001](#f-001)" in out
    assert "- [F-002](#f-002)" in out
    assert n == 1


# --- _normalize_title_path_tail (790-795) ---------------------------------


def test_normalize_title_path_tail_rewrites_table_row():
    text = "| T-001 | Hardcoded key — lib/insecurity.ts:23 |\n"
    out, n = prose._normalize_title_path_tail(text)
    assert "(lib/insecurity.ts:23)" in out
    assert n == 1


def test_normalize_title_path_tail_skips_backticked_cell():
    text = "| T-001 | Issue with `lib/x.ts` — lib/insecurity.ts:23 |\n"
    out, n = prose._normalize_title_path_tail(text)
    # Cell contains a backtick -> left untouched.
    assert out == text
    assert n == 0


def test_normalize_title_path_tail_no_path_tail_unchanged():
    text = "| T-001 | Plain title with no path |\n"
    out, n = prose._normalize_title_path_tail(text)
    assert out == text
    assert n == 0


# --- _collapse_consecutive_anchors (822-829) ------------------------------


def test_collapse_consecutive_anchors_joins_run():
    text = '<a id="a"></a>\n<a id="b"></a>\n## Heading\n'
    out, n = prose._collapse_consecutive_anchors(text)
    assert '<a id="a"></a><a id="b"></a>' in out
    assert n == 1


def test_collapse_consecutive_anchors_skips_fences():
    text = '```\n<a id="x"></a>\n<a id="y"></a>\n```\n'
    out, n = prose._collapse_consecutive_anchors(text)
    assert out == text
    assert n == 0


# --- apply_fixes: blockquote block skipped (897, 899-902) -----------------


def test_apply_fixes_blockquote_block_left_untouched():
    text = "<blockquote>\nPath server.ts:12 inside blockquote stays bare\n</blockquote>\nOutside server.ts:12 prose\n"
    out, _ = prose.apply_fixes(text)
    # Inside-blockquote path NOT backticked; outside prose IS.
    assert "Path server.ts:12 inside blockquote stays bare" in out
    assert "`server.ts:12`" in out  # the outside occurrence


# --- apply_code_formatting fence + blockquote + heading (973-988) ---------


def test_apply_code_formatting_skips_fence_and_blockquote_and_heading():
    text = (
        "```\n"
        "code server.ts:1\n"
        "```\n"
        "<blockquote>\n"
        "bq server.ts:2\n"
        "</blockquote>\n"
        "# Heading server.ts:3\n"
        "prose server.ts:4\n"
    )
    out, _ = prose.apply_code_formatting(text)
    assert "code server.ts:1" in out  # fence untouched
    assert "bq server.ts:2" in out  # blockquote untouched
    assert "# Heading server.ts:3" in out  # heading untouched
    assert "`server.ts:4`" in out  # prose backticked


# --- main() CLI (1013-1040) -----------------------------------------------


def test_main_usage_error_wrong_argc(capsys):
    rc = prose.main([])
    assert rc == 2
    assert "Usage:" in capsys.readouterr().err


def test_main_missing_file(tmp_path: Path, capsys):
    rc = prose.main([str(tmp_path / "nope.md")])
    assert rc == 1
    assert "no md at" in capsys.readouterr().err


def test_main_applies_fixes_and_writes(tmp_path: Path, capsys):
    md = tmp_path / "tm.md"
    md.write_text("Prose referencing server.ts:12 here.\n", encoding="utf-8")
    rc = prose.main([str(md)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "applied" in out
    assert "`server.ts:12`" in md.read_text()


def test_main_no_fixable_violations(tmp_path: Path, capsys):
    md = tmp_path / "clean.md"
    md.write_text("Just plain prose with nothing to fix.\n", encoding="utf-8")
    rc = prose.main([str(md)])
    assert rc == 0
    assert "no fixable prose-style violations found" in capsys.readouterr().out


# --- __main__ guard (line 1044) -------------------------------------------


def test_module_runpy_main_guard(tmp_path: Path):
    import runpy

    md = tmp_path / "tm.md"
    md.write_text("plain text\n", encoding="utf-8")
    argv = sys.argv
    sys.argv = ["apply_prose_fixes.py", str(md)]
    sys.modules.pop("apply_prose_fixes", None)
    try:
        with pytest.raises(SystemExit) as ei:
            runpy.run_path(str(SCRIPT_PATH), run_name="__main__")
        assert ei.value.code == 0
    finally:
        sys.argv = argv
        _load()
