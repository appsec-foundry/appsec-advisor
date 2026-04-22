"""Unit tests for scripts/qa_checks.py.

qa_checks.py runs 11 deterministic checks on threat-model.md. These tests
exercise the CLI subcommands and the key check logic directly using minimal
fixtures — they do not run the full pipeline.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT   = Path(__file__).parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "qa_checks.py"


def _load_qa_checks():
    # Must register in sys.modules before exec so @dataclass forward-ref
    # resolution via sys.modules[cls.__module__] does not get None.
    if "qa_checks" in sys.modules:
        return sys.modules["qa_checks"]
    spec = importlib.util.spec_from_file_location("qa_checks", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["qa_checks"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


qa = _load_qa_checks()


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
    )


def _write_minimal_model(path: Path, content: str) -> Path:
    f = path / "threat-model.md"
    f.write_text(content)
    return f


# ---------------------------------------------------------------------------
# CLI: missing arguments
# ---------------------------------------------------------------------------

def test_no_args_exits_nonzero():
    result = _run([])
    assert result.returncode != 0


def test_unknown_subcommand_exits_nonzero(tmp_path: Path):
    md = _write_minimal_model(tmp_path, "# Threat Model\n")
    result = _run(["unknown_subcommand", str(md)])
    assert result.returncode != 0


# ---------------------------------------------------------------------------
# CLI: xrefs subcommand on a clean file
# ---------------------------------------------------------------------------

_CLEAN_XREF_CONTENT = textwrap.dedent("""\
    ## Management Summary

    ## 8. Threat Register

    <a id="t-001"></a>
    | T-001 | Title | High | ... |

    ## 9. Mitigation Register

    <a id="m-001"></a>
    ### M-001 Fix the thing

    **Addresses:** [T-001](#t-001)
""")


def test_xrefs_exits_0_on_clean_file(tmp_path: Path):
    md = _write_minimal_model(tmp_path, _CLEAN_XREF_CONTENT)
    result = _run(["xrefs", str(md)])
    assert result.returncode == 0, f"stderr: {result.stderr}\nstdout: {result.stdout}"


# ---------------------------------------------------------------------------
# CLI: invariants subcommand — Risk Distribution present
# ---------------------------------------------------------------------------

_RISK_DIST_CONTENT = textwrap.dedent("""\
    ## 8. Threat Register

    **Risk Distribution:** Critical: 1 · High: 2 · Medium: 3 · Low: 4 · **Total: 10**
    **STRIDE Coverage:** Spoofing: 1 · Tampering: 2 · Repudiation: 0 · Information Disclosure: 3 · Denial of Service: 2 · Elevation of Privilege: 2
""")


def test_invariants_exits_0_with_risk_distribution(tmp_path: Path):
    md = _write_minimal_model(tmp_path, _RISK_DIST_CONTENT)
    result = _run(["invariants", str(md)])
    assert result.returncode == 0, f"stderr: {result.stderr}"


# ---------------------------------------------------------------------------
# VSCODE_LINK_RE regex sanity
# ---------------------------------------------------------------------------

def test_vscode_link_re_matches_valid_link():
    link = "vscode://file//home/user/repo/src/app.py:42"
    m = qa.VSCODE_LINK_RE.search(link + ")")
    assert m is not None
    assert m.group(1) == "/home/user/repo/src/app.py"
    assert m.group(2) == "42"


def test_vscode_link_re_no_match_on_plain_text():
    assert qa.VSCODE_LINK_RE.search("just plain text") is None


# ---------------------------------------------------------------------------
# T_ID_RE / M_ID_RE sanity
# ---------------------------------------------------------------------------

def test_t_id_re_matches():
    assert qa.T_ID_RE.search("See T-001 for details") is not None
    assert qa.T_ID_RE.search("T-1234") is not None


def test_m_id_re_matches():
    assert qa.M_ID_RE.search("Fix via M-042") is not None


def test_t_id_re_no_false_positive():
    assert qa.T_ID_RE.search("AT-001") is None  # prefix — must be word boundary


# ---------------------------------------------------------------------------
# Risk distribution regex
# ---------------------------------------------------------------------------

def test_risk_dist_re_parses_counts():
    line = "**Risk Distribution:** Critical: 2 · High: 5 · Medium: 3 · Low: 1 · **Total: 11**"
    m = qa.RISK_DIST_RE.search(line)
    assert m is not None
    assert m.group(1) == "2"   # Critical
    assert m.group(2) == "5"   # High
    assert m.group(5) == "11"  # Total


def test_risk_dist_re_no_match_on_empty():
    assert qa.RISK_DIST_RE.search("nothing here") is None
