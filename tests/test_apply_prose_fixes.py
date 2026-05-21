"""Unit tests for scripts/apply_prose_fixes.py."""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "apply_prose_fixes.py"


def _load_apply_prose_fixes():
    if "apply_prose_fixes" in sys.modules:
        return sys.modules["apply_prose_fixes"]
    spec = importlib.util.spec_from_file_location("apply_prose_fixes", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["apply_prose_fixes"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


prose = _load_apply_prose_fixes()


def test_apply_fixes_is_idempotent_for_core_rewrites():
    md = textwrap.dedent("""\
        ## 7. Security Architecture

        ### 7.2 Identity and Authentication Controls

        **Controls covered:** [Stale](#stale).

        #### Password Login

        routes/login.ts:34 reaches the SQL query. Additionally, the password hash is trivially crackable. No DDoS protection is configured. Keep this sentence.

        **Relevant findings:** [F-001](#f-001) - SQL injection, [F-002](#f-002) - MD5 hashing.
    """)

    once, n_fixes = prose.apply_fixes(md)
    twice, n_fixes_again = prose.apply_fixes(once)

    assert n_fixes > 0
    assert once == twice
    assert n_fixes_again == 0
    assert "`routes/login.ts:34` reaches the SQL query." in once
    assert "Additionally," not in once
    assert "recoverable by GPU dictionary attack within seconds" in once
    assert "No DDoS protection" not in once
    assert "**Controls covered:** [Password Login](#password-login)" in once
    assert "**Relevant findings**\n\n- [F-001](#f-001) — SQL injection" in once
    assert "- [F-002](#f-002) — MD5 hashing" in once


def test_legacy_title_path_tail_uses_canonical_paren_form():
    md = "| ID | Finding |\n|----|---------|\n| F-001 | Hardcoded key — lib/insecurity.ts:23 |\n"

    fixed, n_fixes = prose.apply_fixes(md)

    assert n_fixes == 1
    assert "| F-001 | Hardcoded key (lib/insecurity.ts:23) |" in fixed


def test_path_wrapping_skips_code_fences_and_markdown_urls():
    md = textwrap.dedent("""\
        ```text
        routes/login.ts:34
        ```

        See [login](routes/login.ts) and routes/admin.ts:12.
    """)

    fixed, n_fixes = prose.apply_fixes(md)

    assert n_fixes == 1
    assert "```text\nroutes/login.ts:34\n```" in fixed
    assert "[login](routes/login.ts)" in fixed
    assert "`routes/admin.ts:12`" in fixed
