"""
Tests for annotate_architecture.py — post-Phase-9 Mermaid diagram annotator.

The annotator reads a Markdown file with C4 diagrams and a .threats-merged.json,
and rewrites every ``graph`` block to attach severity badges, classes, and click
links to nodes preceded by ``%% component: <id>`` comments. The script is
idempotent: running it twice produces byte-identical output.
"""

import json
import sys
from pathlib import Path

import pytest

PLUGIN_SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
from annotate_architecture import (  # noqa: E402
    annotate_markdown,
    _aggregate,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _threats(*rows: dict) -> dict:
    return _aggregate(list(rows))


def _threat(
    t_id: str,
    component_id: str,
    risk: str,
    title: str = "X",
    stride: str = "Tampering",
    cwe: str = "CWE-00",
) -> dict:
    return {
        "t_id": t_id,
        "component_id": component_id,
        "risk": risk,
        "title": title,
        "stride": stride,
        "cwe": cwe,
    }


SIMPLE_MD = """\
## 2. Architecture

```mermaid
graph TD
    Attacker["Attacker"]
    %% component: rest-api
    RestApi["REST API<br/>Express 4"]
    %% component: auth
    Auth["Auth Service<br/>Passport"]
    Attacker --> RestApi
    RestApi --> Auth
```

**Key takeaway:** text here.
"""


# ---------------------------------------------------------------------------
# Basic annotation
# ---------------------------------------------------------------------------

def test_annotates_critical_component():
    aggs = _threats(
        _threat("T-001", "rest-api", "Critical", title="SQLi"),
        _threat("T-002", "rest-api", "High", title="XSS"),
    )
    out = annotate_markdown(SIMPLE_MD, aggs)

    assert '⚠ 1C·1H' in out
    assert ':::critical' in out
    assert 'classDef critical' in out
    assert 'click RestApi "#t-001" "T-001: SQLi"' in out


def test_class_reflects_max_severity_when_only_high():
    aggs = _threats(
        _threat("T-005", "auth", "High", title="JWT forge"),
        _threat("T-006", "auth", "Medium", title="Weak rate limit"),
    )
    out = annotate_markdown(SIMPLE_MD, aggs)
    # Auth should be :::high — not critical
    auth_line = [l for l in out.splitlines() if l.startswith("    Auth[")][0]
    assert ":::high" in auth_line
    assert "⚠ 1H·1M" in auth_line


def test_click_target_falls_back_to_high_then_medium():
    aggs = _threats(
        _threat("T-009", "auth", "Medium", title="Rate limit"),
    )
    out = annotate_markdown(SIMPLE_MD, aggs)
    assert 'click Auth "#t-009" "T-009: Rate limit"' in out
    assert ":::medium" in out


# ---------------------------------------------------------------------------
# Thresholds — when NOT to annotate
# ---------------------------------------------------------------------------

def test_component_with_only_low_is_not_annotated():
    aggs = _threats(
        _threat("T-020", "rest-api", "Low", title="Minor"),
    )
    out = annotate_markdown(SIMPLE_MD, aggs)
    assert "⚠" not in out
    assert "classDef critical" not in out
    assert "anno-legend" not in out


def test_component_without_threats_is_untouched():
    aggs = _threats(
        _threat("T-030", "auth", "Critical", title="Key"),
    )
    out = annotate_markdown(SIMPLE_MD, aggs)
    # Only auth is annotated; rest-api stays clean
    rest_line = [l for l in out.splitlines() if l.startswith("    RestApi[")][0]
    assert "⚠" not in rest_line
    assert ":::" not in rest_line


def test_unannotated_node_is_never_touched():
    aggs = _threats(
        _threat("T-040", "attacker", "Critical", title="something"),
    )
    out = annotate_markdown(SIMPLE_MD, aggs)
    # Attacker has no %% component: comment → script must not touch it
    assert 'Attacker["Attacker"]' in out
    assert "⚠" not in [l for l in out.splitlines() if "Attacker" in l][0]


def test_zero_threats_noop():
    out = annotate_markdown(SIMPLE_MD, {})
    assert out == SIMPLE_MD


# ---------------------------------------------------------------------------
# Legend
# ---------------------------------------------------------------------------

def test_legend_added_after_annotated_block():
    aggs = _threats(_threat("T-001", "rest-api", "Critical", title="RCE"))
    out = annotate_markdown(SIMPLE_MD, aggs)
    assert "<!-- anno-legend -->" in out
    assert "*Legend:" in out
    # Legend must come after the closing fence and before the Key takeaway
    legend_idx = out.index("<!-- anno-legend -->")
    takeaway_idx = out.index("**Key takeaway:")
    fence_close_idx = out.rindex("```")
    assert fence_close_idx < legend_idx < takeaway_idx


def test_legend_absent_when_no_annotations():
    aggs = _threats(_threat("T-001", "rest-api", "Low"))
    out = annotate_markdown(SIMPLE_MD, aggs)
    assert "<!-- anno-legend -->" not in out


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

def test_idempotent_rerun():
    aggs = _threats(
        _threat("T-001", "rest-api", "Critical", title="SQLi"),
        _threat("T-002", "auth", "High", title="JWT"),
    )
    first = annotate_markdown(SIMPLE_MD, aggs)
    second = annotate_markdown(first, aggs)
    assert first == second


def test_rerun_with_different_threats_replaces_annotations():
    aggs_a = _threats(_threat("T-001", "rest-api", "Critical", title="SQLi"))
    aggs_b = _threats(_threat("T-050", "rest-api", "Medium", title="Timing"))
    first = annotate_markdown(SIMPLE_MD, aggs_a)
    second = annotate_markdown(first, aggs_b)
    # Old annotations must be gone
    assert "T-001" not in second
    assert "SQLi" not in second
    assert "classDef critical" in second  # classdef is always the same 3 lines
    # Node shows new badge and class
    rest_line = [l for l in second.splitlines() if l.startswith("    RestApi[")][0]
    assert "⚠ 1M" in rest_line
    assert ":::medium" in rest_line
    assert "click RestApi" in second
    assert '"#t-050"' in second


def test_rerun_then_clear_removes_annotations():
    aggs = _threats(_threat("T-001", "rest-api", "Critical", title="SQLi"))
    annotated = annotate_markdown(SIMPLE_MD, aggs)
    cleared = annotate_markdown(annotated, {})
    assert cleared == SIMPLE_MD


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_multiple_mermaid_blocks_independent():
    md = """\
## 2.1

```mermaid
graph TD
    %% component: rest-api
    RestApi["REST API"]
```

**Key takeaway:** a.

## 2.2

```mermaid
graph TD
    %% component: auth
    Auth["Auth Service"]
```

**Key takeaway:** b.
"""
    aggs = _threats(
        _threat("T-001", "rest-api", "Critical", title="SQLi"),
        _threat("T-002", "auth", "Medium", title="Session"),
    )
    out = annotate_markdown(md, aggs)
    assert out.count("classDef critical") == 2
    assert out.count("<!-- anno-legend -->") == 2
    assert ":::critical" in out
    assert ":::medium" in out


def test_same_component_twice_in_one_block():
    md = """\
```mermaid
graph TD
    %% component: rest-api
    RestApi1["REST API v1"]
    %% component: rest-api
    RestApi2["REST API v2"]
```
"""
    aggs = _threats(_threat("T-001", "rest-api", "High", title="t"))
    out = annotate_markdown(md, aggs)
    # Both instances get annotated
    assert out.count(":::high") == 2
    assert out.count("⚠ 1H") == 2
    # Two click links
    assert out.count("click RestApi1") == 1
    assert out.count("click RestApi2") == 1


def test_unknown_component_id_silently_skipped():
    md = """\
```mermaid
graph TD
    %% component: does-not-exist
    Unknown["Unknown"]
```
"""
    aggs = _threats(_threat("T-001", "rest-api", "Critical"))
    out = annotate_markdown(md, aggs)
    # Unknown component was not in the threats JSON — leave node alone
    assert "⚠" not in out
    assert ":::" not in out


def test_preserves_non_mermaid_code_blocks():
    md = """\
```python
def foo():
    return "hi"
```

```mermaid
graph TD
    %% component: rest-api
    RestApi["REST API"]
```
"""
    aggs = _threats(_threat("T-001", "rest-api", "High", title="x"))
    out = annotate_markdown(md, aggs)
    assert 'def foo():' in out
    assert ':::high' in out


def test_preserves_label_with_br_separators():
    md = """\
```mermaid
graph TD
    %% component: rest-api
    RestApi["REST API<br/>Express 4<br/>Node 20"]
```
"""
    aggs = _threats(_threat("T-001", "rest-api", "Critical", title="RCE"))
    out = annotate_markdown(md, aggs)
    assert 'REST API<br/>Express 4<br/>Node 20<br/>⚠ 1C' in out


def test_title_with_double_quotes_is_sanitized():
    md = """\
```mermaid
graph TD
    %% component: rest-api
    RestApi["REST API"]
```
"""
    aggs = _threats(_threat("T-001", "rest-api", "Critical", title='He said "hi"'))
    out = annotate_markdown(md, aggs)
    # Click-link tooltip is wrapped in double quotes; inner quotes must be single
    click_line = [l for l in out.splitlines() if "click RestApi" in l][0]
    assert click_line.count('"') == 4  # exactly: href and tooltip, each in quotes
    assert "He said 'hi'" in click_line


def test_idempotent_file_write_noop(tmp_path: Path):
    """Running annotate_markdown twice produces no file-level churn."""
    aggs = _threats(_threat("T-001", "rest-api", "Critical", title="SQLi"))
    first = annotate_markdown(SIMPLE_MD, aggs)
    second = annotate_markdown(first, aggs)
    third = annotate_markdown(second, aggs)
    assert first == second == third


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

def test_cli_rewrites_file_in_place(tmp_path: Path):
    from annotate_architecture import main

    md_path = tmp_path / "threat-model.md"
    md_path.write_text(SIMPLE_MD, encoding="utf-8")

    threats_path = tmp_path / ".threats-merged.json"
    threats_path.write_text(
        json.dumps(
            {
                "version": 1,
                "generated_at": "2026-04-11T00:00:00Z",
                "threats": [
                    {
                        "t_id": "T-001",
                        "component_id": "rest-api",
                        "component_name": "REST API",
                        "stride": "Tampering",
                        "risk": "Critical",
                        "likelihood": "High",
                        "impact": "Critical",
                        "title": "SQLi",
                        "cwe": "CWE-89",
                        "evidence": {"file": "r.ts", "line": 1},
                        "source": "stride",
                        "architectural_violation": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc = main(["--markdown", str(md_path), "--threats", str(threats_path)])
    assert rc == 0
    rewritten = md_path.read_text(encoding="utf-8")
    assert ":::critical" in rewritten
    assert "<!-- anno-legend -->" in rewritten
