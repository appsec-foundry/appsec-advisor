"""
Tests for annotate_sequences.py — post-Phase-9 Mermaid sequence-diagram annotator.
"""

import json
import sys
from pathlib import Path

PLUGIN_SCRIPTS = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(PLUGIN_SCRIPTS))
from annotate_sequences import annotate_markdown, main  # noqa: E402


def _threat(
    t_id: str,
    component_id: str,
    stride: str,
    risk: str = "High",
    cwe: str = "CWE-89",
) -> dict:
    return {
        "t_id": t_id,
        "component_id": component_id,
        "stride": stride,
        "risk": risk,
        "cwe": cwe,
    }


SIMPLE_MD = """\
## 3.1 Login flow

```mermaid
sequenceDiagram
    %% components: auth-service, rest-api
    %% stride: S, T
    participant A as Attacker
    participant API as REST API
    participant DB as PostgreSQL
    A->>API: POST /login (payload)
    alt Current state — SQLi bypass %% attack-path
        API->>DB: raw query
        DB-->>API: admin row
        API-->>A: JWT
    else After mitigation — parameterized
        API->>DB: prepared stmt
        DB-->>API: no match
        API-->>A: 401
    end
```

**Key takeaway:** sentinel.
"""


# ---------------------------------------------------------------------------
# Basic injection
# ---------------------------------------------------------------------------


def test_note_injected_in_attack_branch():
    threats = [
        _threat("T-001", "auth-service", "Spoofing", "Critical", "CWE-89"),
        _threat("T-004", "rest-api", "Tampering", "High", "CWE-321"),
    ]
    out = annotate_markdown(SIMPLE_MD, threats)

    assert "Note over A,DB: T-001 (CWE-89), T-004 (CWE-321)" in out
    # Note comes AFTER the alt %% attack-path line and BEFORE the first arrow
    alt_idx = out.index("alt Current state")
    note_idx = out.index("Note over A,DB:")
    api_db_idx = out.index("API->>DB: raw query")
    assert alt_idx < note_idx < api_db_idx


def test_threats_sorted_by_severity():
    threats = [
        _threat("T-010", "rest-api", "Tampering", "Medium", "CWE-20"),
        _threat("T-020", "auth-service", "Spoofing", "Critical", "CWE-89"),
        _threat("T-030", "rest-api", "Tampering", "High", "CWE-200"),
    ]
    out = annotate_markdown(SIMPLE_MD, threats)
    # Expect order: Critical first, then High, then Medium
    note_line = [l for l in out.splitlines() if "Note over" in l][0]
    pos_crit = note_line.index("T-020")
    pos_high = note_line.index("T-030")
    pos_med = note_line.index("T-010")
    assert pos_crit < pos_high < pos_med


def test_component_filter_excludes_others():
    threats = [
        _threat("T-001", "auth-service", "Spoofing", "Critical"),
        _threat("T-999", "other-service", "Tampering", "Critical"),
    ]
    out = annotate_markdown(SIMPLE_MD, threats)
    assert "T-001" in out
    assert "T-999" not in out


def test_stride_filter_excludes_others():
    threats = [
        _threat("T-001", "auth-service", "Spoofing", "Critical", "CWE-287"),
        # Flow declares stride S, T — this Repudiation threat is excluded
        _threat("T-050", "auth-service", "Repudiation", "Critical", "CWE-778"),
    ]
    out = annotate_markdown(SIMPLE_MD, threats)
    assert "T-001" in out
    assert "T-050" not in out


# ---------------------------------------------------------------------------
# Top-3 cap and overflow
# ---------------------------------------------------------------------------


def test_top_three_cap_and_overflow_indicator():
    threats = [_threat(f"T-{i:03d}", "auth-service", "Spoofing", "High", f"CWE-{i}") for i in range(1, 7)]
    out = annotate_markdown(SIMPLE_MD, threats)
    note_line = [l for l in out.splitlines() if "Note over" in l][0]
    # Only 3 T-IDs
    for i in range(1, 4):
        assert f"T-{i:03d}" in note_line
    for i in range(4, 7):
        assert f"T-{i:03d}" not in note_line
    assert "+3 more → §8" in note_line


def test_exactly_three_no_overflow_marker():
    threats = [
        _threat("T-001", "auth-service", "Spoofing", "High"),
        _threat("T-002", "rest-api", "Tampering", "High"),
        _threat("T-003", "auth-service", "Spoofing", "High"),
    ]
    out = annotate_markdown(SIMPLE_MD, threats)
    note_line = [l for l in out.splitlines() if "Note over" in l][0]
    assert "more → §8" not in note_line


# ---------------------------------------------------------------------------
# Skipping scenarios
# ---------------------------------------------------------------------------


def test_missing_attack_path_marker_skips_diagram():
    md = SIMPLE_MD.replace("%% attack-path", "")
    threats = [_threat("T-001", "auth-service", "Spoofing", "Critical")]
    out = annotate_markdown(md, threats)
    assert "Note over" not in out


def test_missing_components_comment_skips_diagram():
    md = SIMPLE_MD.replace("    %% components: auth-service, rest-api\n", "")
    threats = [_threat("T-001", "auth-service", "Spoofing", "Critical")]
    out = annotate_markdown(md, threats)
    assert "Note over A,DB:" not in out


def test_missing_stride_comment_skips_diagram():
    md = SIMPLE_MD.replace("    %% stride: S, T\n", "")
    threats = [_threat("T-001", "auth-service", "Spoofing", "Critical")]
    out = annotate_markdown(md, threats)
    assert "Note over A,DB:" not in out


def test_non_sequence_mermaid_block_untouched():
    md = """\
```mermaid
graph TD
    %% components: rest-api
    %% stride: T
    A[X] --> B[Y]
```
"""
    threats = [_threat("T-001", "rest-api", "Tampering", "Critical")]
    out = annotate_markdown(md, threats)
    assert "Note over" not in out
    assert "anno-seq-start" not in out


def test_zero_matching_threats_no_injection():
    threats = [_threat("T-999", "unrelated", "Spoofing", "Critical")]
    out = annotate_markdown(SIMPLE_MD, threats)
    assert "Note over" not in out
    assert "anno-seq-start" not in out


def test_empty_threat_list_noop():
    out = annotate_markdown(SIMPLE_MD, [])
    assert out == SIMPLE_MD


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


def test_idempotent_rerun():
    threats = [
        _threat("T-001", "auth-service", "Spoofing", "Critical", "CWE-89"),
        _threat("T-004", "rest-api", "Tampering", "High", "CWE-321"),
    ]
    first = annotate_markdown(SIMPLE_MD, threats)
    second = annotate_markdown(first, threats)
    assert first == second


def test_rerun_with_different_threats_replaces():
    t1 = [_threat("T-001", "auth-service", "Spoofing", "Critical", "CWE-89")]
    t2 = [_threat("T-050", "rest-api", "Tampering", "Medium", "CWE-200")]
    first = annotate_markdown(SIMPLE_MD, t1)
    second = annotate_markdown(first, t2)
    assert "T-001" not in second
    assert "T-050" in second
    assert "(CWE-200)" in second


def test_rerun_then_clear_returns_to_original():
    threats = [_threat("T-001", "auth-service", "Spoofing", "Critical")]
    annotated = annotate_markdown(SIMPLE_MD, threats)
    cleared = annotate_markdown(annotated, [])
    assert cleared == SIMPLE_MD


# ---------------------------------------------------------------------------
# Multiple diagrams
# ---------------------------------------------------------------------------

MULTI_MD = """\
## 3.1

```mermaid
sequenceDiagram
    %% components: auth-service
    %% stride: S
    participant A as Attacker
    participant API as Auth
    A->>API: login
    alt bypass %% attack-path
        API-->>A: session
    else normal
        API-->>A: 401
    end
```

**Key takeaway:** a.

## 3.2

```mermaid
sequenceDiagram
    %% components: rest-api
    %% stride: I
    participant A as Attacker
    participant API as REST
    A->>API: /wallet/123
    alt normal
        API-->>A: 403
    else IDOR %% attack-path
        API-->>A: other user data
    end
```

**Key takeaway:** b.
"""


def test_multiple_sequence_diagrams_independent():
    threats = [
        _threat("T-001", "auth-service", "Spoofing", "Critical", "CWE-287"),
        _threat("T-020", "rest-api", "Information Disclosure", "High", "CWE-639"),
    ]
    out = annotate_markdown(MULTI_MD, threats)
    assert out.count("anno-seq-start") == 2
    assert "T-001 (CWE-287)" in out
    assert "T-020 (CWE-639)" in out
    # Each diagram only gets its own threat
    first_block = out[: out.index("## 3.2")]
    second_block = out[out.index("## 3.2") :]
    assert "T-001" in first_block and "T-001" not in second_block
    assert "T-020" in second_block and "T-020" not in first_block


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------


def test_cli_rewrites_file_in_place(tmp_path: Path):
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
                        "component_id": "auth-service",
                        "component_name": "Auth",
                        "stride": "Spoofing",
                        "risk": "Critical",
                        "likelihood": "High",
                        "impact": "Critical",
                        "title": "t",
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
    assert "Note over A,DB: T-001 (CWE-89)" in rewritten
    assert "anno-seq-start" in rewritten
