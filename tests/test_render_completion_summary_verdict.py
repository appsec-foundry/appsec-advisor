"""Console verdict: the persisted worst-case bullets render as one shared table."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest
import summarize_threat_model as stm
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_completion_summary.py"


def _load_module():
    if "render_completion_summary" in sys.modules:
        return sys.modules["render_completion_summary"]
    spec = importlib.util.spec_from_file_location("render_completion_summary", SCRIPT_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["render_completion_summary"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rcs = _load_module()

_TAXONOMY = {
    "cwes": {
        "CWE-1": {"title": "Improper Neutralization in a Query (Query Injection)"},
        "CWE-2": {"title": "Path Traversal"},
        "CWE-3": {"title": "Improper Output Encoding (XSS)"},
    }
}


def _plugin_root(tmp_path: Path) -> Path:
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "cwe-taxonomy.yaml").write_text(yaml.safe_dump(_TAXONOMY), encoding="utf-8")
    return tmp_path


def _bullet(title: str, classes: list[str] | None = None, verified: bool = False) -> dict:
    return {"title": title, "classes": classes or [], "verified_attack_path": verified}


def test_labels_follow_the_cwe_short_name_rule(tmp_path):
    labels = stm.verdict_class_labels(
        [
            {"id": "T-011", "cwe": "CWE-1"},
            {"id": "T-012", "cwe": "CWE-2"},
            {"id": "T-013", "cwe": ["CWE-3", "CWE-3"]},
            {"t_id": "T-014", "cwe": "CWE-1"},
            {"id": "T-015", "cwe": "CWE-999"},
            {"id": "T-016"},
            "not-a-threat",
        ],
        _plugin_root(tmp_path),
    )
    assert labels == {
        "F-011": ["Query Injection"],
        "F-012": ["Path Traversal"],
        "F-013": ["XSS"],
        "F-014": ["Query Injection"],
    }


def test_missing_taxonomy_yields_no_labels(tmp_path):
    assert stm.verdict_class_labels([{"id": "T-011", "cwe": "CWE-1"}], tmp_path) == {}


def test_bullet_classes_follow_finding_order_without_repeats(tmp_path):
    data = {
        "threats": [
            {"id": "T-011", "cwe": "CWE-1"},
            {"id": "T-012", "cwe": ["CWE-1", "CWE-2"]},
            {"id": "T-013", "cwe": "CWE-3"},
        ],
        "verdict": {
            "opening": "Not production-ready.",
            "bullets": [{"title": "Customer data exposed", "findings": ["F-012", "T-011", "F-013"]}],
        },
    }
    bullet = stm.persisted_verdict(data, _plugin_root(tmp_path))["bullets"][0]
    assert bullet["classes"] == ["Query Injection", "Path Traversal", "XSS"]


def test_rows_carry_rank_mark_outcome_and_first_class_in_one_column():
    rows = stm.render_worst_case_table(
        [
            _bullet("Admin takeover", ["SQL Injection"]),
            _bullet("Token forgery", ["Hard-coded Key", "Signature Bypass"], verified=True),
            _bullet("Unclassified outcome"),
        ],
        indent="",
    )
    assert [row[:5] for row in rows[:3]] == ["1    ", "2 ✓  ", "3    "]
    assert rows[0][5:].startswith("Admin takeover") and rows[1][5:].startswith("Token forgery")
    assert rows[0].index("SQL Injection") == rows[1].index("Hard-coded Key +1")
    assert rows[2] == "3    Unclassified outcome"
    assert rows[3:] == ["", stm.WORST_CASE_LEGEND]


def test_legend_only_when_a_path_is_verified():
    assert stm.render_worst_case_table([_bullet("Admin takeover", ["SQL Injection"])]) == [
        "  1    Admin takeover  SQL Injection"
    ]
    assert stm.render_worst_case_table([]) == []


def test_ranks_stay_aligned_past_nine():
    rows = stm.render_worst_case_table([_bullet(f"Outcome {n}", ["XSS"]) for n in range(1, 11)], indent="")
    assert len({row.index("XSS") for row in rows}) == 1
    assert rows[0].startswith("1 ") and rows[9].startswith("10 ")


def test_no_line_opens_a_markdown_block():
    # The completion summary is relayed as Markdown, which strips leading blanks
    # and reads `#`, `-`, `>`, `1.` at a line start as block syntax.
    bullets = [_bullet(f"Outcome {n}", ["XSS"], verified=n % 2 == 0) for n in range(1, 12)]
    for row in stm.render_worst_case_table(bullets, indent=""):
        assert not re.match(r"(#|[-*+>=]|\d+[.)])(\s|$)", row), row


def test_completion_summary_swaps_the_bullets_for_the_table(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    (out / "threat-model.md").write_text(
        "# Threat Model\n\n## Management Summary\n\n### Verdict\n\n🔴 Not production-ready.\n\n\n\n"
        "**What an attacker can do today, worst first:**\n\n\n"
        "- **Customer data exposed** — Anyone can dump every record. "
        "*(🔴 [F-011](#f-011) — Query built from input (`src/db/search.ts:23`) → [W-003](#w-003))*"
        " — ✓ verified attack path\n\n\n\n"
        "Fix the query layer first.\n\n### Security Posture & Top Threats\n\nNot part of the verdict.\n",
        encoding="utf-8",
    )
    threats = [{"id": "T-011", "cwe": "CWE-89", "title": "Query built from input", "risk": "Critical"}]
    verdict = {
        "severity": "red",
        "opening": "Not production-ready.",
        "bullets": [
            {
                "title": "Customer data exposed",
                "body": "Anyone can dump every record.",
                "findings": ["F-011"],
                "verified_attack_path": True,
            }
        ],
        "closing": "Fix the query layer first.",
    }
    model = {"meta": {"schema_version": 1}, "threats": threats, "mitigations": [], "components": [], "verdict": verdict}
    (out / "threat-model.yaml").write_text(yaml.safe_dump(model), encoding="utf-8")
    label = stm.verdict_class_labels(threats)["F-011"][0]
    r = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--output-dir", str(out), "--repo-root", str(out), "--mode", "full"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    verdict_block = r.stdout.split("-- Verdict", 1)[1].split("Fix the query layer first.", 1)[0]
    assert "\n  What an attacker can do today, worst first\n" in verdict_block
    assert f"\n  1 ✓  Customer data exposed  {label}\n" in verdict_block
    assert stm.WORST_CASE_LEGEND in verdict_block
    # The sentence, the finding links and their locations stay in the report.
    assert "Anyone can dump every record" not in verdict_block
    assert "F-011" not in verdict_block and "W-003" not in verdict_block and "search.ts" not in verdict_block
    assert "**" not in verdict_block
    assert "\n\n\n" not in verdict_block


@pytest.mark.parametrize(
    "refs",
    [
        "🔴 [F-011](#f-011) — Query built from input (`src/db/search.ts:23`) → [W-003](#w-003)",
        "🟠 [T-204](#t-204), 🔴 [F-107](#f-107) — Unsigned upload (`services/files/upload.go:88`)",
    ],
    ids=["finding-and-weakness", "other-ids-and-paths"],
)
def test_without_persisted_bullets_the_console_drops_the_reference_clauses(refs):
    bullet = f"- **Customer data exposed** — Anyone can dump every record. *({refs})* — ✓ verified attack path"
    lines = rcs._verdict_console_lines(f"🔴 Not production-ready.\n\n{bullet}", [])
    assert lines == [
        "🔴 Not production-ready.",
        "",
        "- **Customer data exposed** — Anyone can dump every record. — ✓ verified attack path",
    ]


def test_an_italic_aside_without_a_finding_link_stays():
    bullet = "- **Customer data exposed** — Anyone can dump every record. *(internal network only)*"
    assert rcs._verdict_console_lines(bullet, []) == [bullet]
