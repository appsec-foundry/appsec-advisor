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

def _bullet(
    title: str,
    cwes: list[str] | None = None,
    verified: bool = False,
    findings: list[str] | None = None,
) -> dict:
    return {"title": title, "cwes": cwes or [], "findings": findings or [], "verified_attack_path": verified}


def test_cwe_ids_per_finding_keep_order_and_drop_non_ids():
    ids = stm.verdict_cwe_ids(
        [
            {"id": "T-011", "cwe": "CWE-89"},
            {"id": "T-012", "cwe": ["cwe-306", "CWE-306", "CWE-400"]},
            {"t_id": "T-013", "cwe": "CWE-74"},
            {"id": "T-014", "cwe": "SQL Injection"},
            {"id": "T-015"},
            "not-a-threat",
        ]
    )
    assert ids == {"F-011": ["CWE-89"], "F-012": ["CWE-306", "CWE-400"], "F-013": ["CWE-74"]}


def test_bullet_carries_findings_and_cwes_in_finding_order_without_repeats():
    data = {
        "threats": [
            {"id": "T-011", "cwe": "CWE-89"},
            {"id": "T-012", "cwe": ["CWE-89", "CWE-22"]},
            {"id": "T-013", "cwe": "CWE-79"},
        ],
        "verdict": {
            "opening": "Not production-ready.",
            "bullets": [{"title": "Customer data exposed", "findings": ["F-012", "T-011", "F-013", "F-012"]}],
        },
    }
    bullet = stm.persisted_verdict(data)["bullets"][0]
    assert bullet["findings"] == ["F-012", "F-011", "F-013"]
    assert bullet["cwes"] == ["CWE-89", "CWE-22", "CWE-79"]


def test_rows_carry_mark_outcome_cwes_and_findings():
    rows = stm.render_worst_case_table(
        [
            _bullet("Admin takeover", ["CWE-89"], findings=["F-001"]),
            _bullet("Token forgery", ["CWE-798", "CWE-347", "CWE-321"], verified=True, findings=["F-002", "F-003"]),
            _bullet("Unclassified outcome"),
        ],
        indent="",
    )
    assert rows[:3] == [
        "•  Admin takeover (CWE-89)  → F-001",
        "✓  Token forgery (CWE-798, CWE-347 +1)  → F-002, F-003",
        "•  Unclassified outcome",
    ]
    assert rows[3:] == ["", stm.WORST_CASE_LEGEND]


def test_rows_never_repeat_the_weakness_after_the_title():
    # The title already names the attack; the row adds only the CWE id.
    row = stm.render_worst_case_table([_bullet("Login bypass via SQL injection", ["CWE-89"], findings=["F-001"])])[0]
    assert row.count("via") == 1


def test_rows_leave_mitigations_to_fix_first():
    rows = stm.render_worst_case_table([_bullet("Admin takeover", ["CWE-89"], findings=["F-001"])], indent="")
    assert not any("M-" in row or "Fix" in row for row in rows)


def test_long_rows_move_the_findings_to_their_own_line():
    title = "Language model service open to any internet caller without credentials"
    rows = stm.render_worst_case_table(
        [_bullet(title, ["CWE-306"], findings=["F-006", "F-013", "F-027", "F-030", "F-031"])]
    )
    assert rows[0] == f"  •  {title} (CWE-306)"
    assert rows[1] == "     → F-006, F-013, F-027, F-030 +1"
    assert all(len(row) <= 92 for row in rows)


def test_legend_only_when_a_path_is_verified():
    assert stm.render_worst_case_table([_bullet("Admin takeover", ["CWE-89"])]) == ["  •  Admin takeover (CWE-89)"]
    assert stm.render_worst_case_table([]) == []


def test_rows_claim_no_rank():
    # RA-14: the verdict's bullets carry no severity order, so no row shows a rank.
    rows = stm.render_worst_case_table([_bullet(f"Outcome {n}", ["CWE-79"]) for n in range(1, 11)], indent="")
    assert all(row[0] in "✓•" for row in rows)
    assert not any(re.search(r"#\d|\b(rank|worst first)\b", row) for row in rows)


def test_no_line_opens_a_markdown_block():
    # The completion summary is relayed as Markdown, which strips leading blanks
    # and reads `#`, `-`, `>`, `1.` at a line start as block syntax.
    bullets = [
        _bullet(f"Outcome {n} " + "x" * 80, ["CWE-79"], verified=n % 2 == 0, findings=["F-001"])
        for n in range(1, 12)
    ]
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
    r = subprocess.run(
        [sys.executable, str(SCRIPT_PATH), "--output-dir", str(out), "--repo-root", str(out), "--mode", "full"],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr
    verdict_block = r.stdout.split("-- Verdict", 1)[1].split("Fix the query layer first.", 1)[0]
    assert "\n  What an attacker can do today, worst first\n" in verdict_block
    assert "\n  ✓  Customer data exposed (CWE-89)  → F-011\n" in verdict_block
    assert stm.WORST_CASE_LEGEND in verdict_block
    # The sentence survives; the report's reference clause (weakness, location) does not.
    assert "Anyone can dump every record" in verdict_block
    assert "W-003" not in verdict_block and "search.ts" not in verdict_block
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


# ---------------------------------------------------------------------------
# Fix first — the model's P1 mitigations, never the verdict's closing prose
# ---------------------------------------------------------------------------


def _fix_first_model(mitigations: list[dict]) -> dict:
    return {
        "threats": [
            {"id": "T-001", "risk": "High", "effective_severity": "Critical"},
            {"id": "T-002", "risk": "Critical"},
            {"id": "T-003", "risk": "Medium"},
        ],
        "mitigations": mitigations,
    }


def test_fix_first_lists_p1_mitigations_most_severe_finding_first():
    lines = rcs.render_fix_first(
        _fix_first_model(
            [
                {"id": "M-003", "title": "Harden logging", "priority": "P1", "threat_ids": ["T-003"]},
                {"id": "M-002", "title": "Check ownership", "priority": 1, "threat_ids": ["T-002"]},
                {"id": "M-001", "title": "Verify tokens", "priority": "P1", "threat_ids": ["T-001"]},
                {"id": "M-004", "title": "Later work", "priority": "P2", "threat_ids": ["T-002"]},
            ]
        ),
        {},
    )
    rows = [line.split()[0] for line in lines[2:]]
    assert rows == ["M-001", "M-002", "M-003"]
    assert lines[2].endswith("→ F-001")


def test_fix_first_puts_declared_business_context_first_within_a_severity():
    model = _fix_first_model(
        [
            {"id": "M-001", "title": "Verify tokens", "priority": "P1", "threat_ids": ["T-001"]},
            {"id": "M-002", "title": "Check ownership", "priority": "P1", "threat_ids": ["T-002"]},
            {"id": "M-003", "title": "Harden logging", "priority": "P1", "threat_ids": ["T-003"]},
        ]
    )
    model["business_context_trace"] = {"status": "applied", "declared_asset_names": ["Order History"]}
    model["assets"] = [{"name": "Order History", "linked_threats": ["T-002", "T-003"]}]

    lines = rcs.render_fix_first(model, {})

    # Business context reorders within Critical; it never lifts the Medium M-003.
    assert [line.split()[0] for line in lines[2:]] == ["M-002", "M-001", "M-003"]
    assert lines[2].endswith("[Business-critical: Order History]")
    assert "[" not in lines[3]


def test_fix_first_rows_are_not_padded_to_the_longest_title():
    lines = rcs.render_fix_first(
        _fix_first_model(
            [
                {"id": "M-001", "title": "Short", "priority": "P1", "threat_ids": ["T-001"]},
                {"id": "M-002", "title": "A much longer mitigation title", "priority": "P1", "threat_ids": ["T-002"]},
            ]
        ),
        {},
    )
    assert "    M-001  Short  → F-001" in lines


def test_fix_first_orders_by_unnamed_context_but_does_not_print_it():
    model = _fix_first_model(
        [
            {"id": "M-001", "title": "Verify tokens", "priority": "P1", "threat_ids": ["T-001"]},
            {"id": "M-002", "title": "Check ownership", "priority": "P1", "threat_ids": ["T-002"]},
        ]
    )
    model["business_context_trace"] = {"status": "applied"}
    model["threats"][1]["business_context_basis"] = "declared use case"

    lines = rcs.render_fix_first(model, {})

    assert [line.split()[0] for line in lines[2:]] == ["M-002", "M-001"]
    assert not any("[" in line for line in lines)


def test_fix_first_caps_the_list_and_names_the_rest():
    mitigations = [{"id": f"M-{n:03d}", "title": "t", "priority": "P1", "threat_ids": ["T-002"]} for n in range(1, 11)]
    lines = rcs.render_fix_first(_fix_first_model(mitigations), {})
    assert len(lines) == 2 + rcs._FIX_FIRST_LIMIT + 1
    assert lines[-1].strip().startswith("+2 more P1")


@pytest.mark.parametrize("cfg", [{"quiet": True}, {}])
def test_fix_first_is_absent_when_quiet_or_without_p1(cfg):
    model = _fix_first_model([{"id": "M-001", "title": "t", "priority": "P2", "threat_ids": ["T-002"]}])
    assert rcs.render_fix_first(model, cfg) == []


@pytest.mark.parametrize(
    "body",
    [
        "A signed-in customer can change another customer record.",
        "An operator with deployment access can read archived messages.",
    ],
)
def test_console_preserves_scenario_access_requirements(body):
    bullet = {"title": "Records exposed", "body": body, "cwes": ["CWE-862"]}
    report = f"- **Records exposed** — {body}"
    rendered = " ".join(" ".join(rcs._verdict_console_lines(report, [bullet])).split())
    assert body in rendered
    assert "✓" not in rendered


def test_verification_legend_limits_the_claim_to_finding_participation():
    rendered = "\n".join(stm.render_worst_case_table([_bullet("Records exposed", verified=True)]))
    assert "a cited finding participates" in rendered
    assert "does not verify the entire scenario" in rendered
    assert "attack was executed" in rendered


@pytest.mark.parametrize("ids", [("M-071", "M-092"), ("M-315", "M-208")])
def test_fix_first_uses_existing_triage_order(ids):
    model = _fix_first_model(
        [{"id": mid, "title": "Check access", "priority": "P1", "threat_ids": ["T-002"]} for mid in ids]
    )
    triage = {
        "ranking": {
            "views": {"prioritized_mitigations": {"mitigations_ranked": [{"id": mid} for mid in reversed(ids)]}}
        }
    }
    rows = rcs.render_fix_first(model, {}, triage)[2:]
    assert [row.split()[0] for row in rows] == list(reversed(ids))


@pytest.mark.parametrize(
    "triage",
    [
        None,
        {},
        {"ranking": []},
        {"ranking": {"views": "invalid"}},
        {"ranking": {"views": {"prioritized_mitigations": {"mitigations_ranked": [{"id": "M-001"}]}}}},
    ],
)
def test_fix_first_fallback_uses_effort_without_losing_unranked_p1(triage):
    model = _fix_first_model(
        [
            {"id": "M-001", "title": "Broad change", "effort": "High", "priority": "P1", "threat_ids": ["T-002"]},
            {"id": "M-002", "title": "Small change", "effort": "Low", "priority": "P1", "threat_ids": ["T-002"]},
            {"id": "M-003", "title": "Later work", "effort": "Low", "priority": "P2", "threat_ids": ["T-002"]},
        ]
    )
    assert [row.split()[0] for row in rcs.render_fix_first(model, {}, triage)[2:]] == ["M-002", "M-001"]


def test_completion_summary_reads_persisted_mitigation_order(tmp_path):
    model = _fix_first_model(
        [
            {"id": mid, "title": title, "priority": "P1", "threat_ids": ["T-002"]}
            for mid, title in [("M-071", "First numbered fix"), ("M-092", "First ranked fix")]
        ]
    )
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(model))
    (tmp_path / ".triage-flags.json").write_text(
        '{"ranking":{"views":{"prioritized_mitigations":{"mitigations_ranked":[{"id":"M-092"},{"id":"M-071"}]}}}}'
    )
    rendered = rcs.render_summary(tmp_path, tmp_path, {}, REPO_ROOT)
    fixes = rendered.split("Fix first (P1 mitigations)", 1)[1]
    assert fixes.index("M-092") < fixes.index("M-071")
