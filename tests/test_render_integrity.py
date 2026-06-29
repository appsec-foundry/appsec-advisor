"""Report-integrity manifest — .render-integrity.json end-to-end.

compose.render() records a per-section render outcome and writes a
``.render-integrity.json`` sidecar certifying which sections rendered and which
fragments were wired. The completion summary surfaces it as a "Report
integrity: N%" console line; aggregate_run_issues turns a degraded report into a
run issue the QA agent reacts to. These tests pin:

  * the integrity math (_compute_integrity)
  * the live render writes a well-formed sidecar, with outcomes driven by what
    reached the report (a yaml-computed section is `rendered` even when an
    OPTIONAL enrichment fragment is absent) and a gated-in section with no
    content flagged `empty`
  * the console readout (render_report_integrity)
  * the run-issue surfacing (_extract_render_integrity / aggregate)
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS = REPO_ROOT / "scripts"
CONTRACT = REPO_ROOT / "data" / "sections-contract.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "compose"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


compose = _load("compose_threat_model")
rcs = _load("render_completion_summary")
ari = _load("aggregate_run_issues")
qa = _load("qa_checks")


def _entry(sid, in_scope, outcome, expected=None, present=None):
    return {
        "id": sid,
        "in_scope": in_scope,
        "outcome": outcome,
        "expected_fragments": expected or [],
        "present_fragments": present or [],
    }


# ---------------------------------------------------------------------------
# _compute_integrity — the math
# ---------------------------------------------------------------------------


def test_compute_integrity_all_clean():
    manifest = [
        _entry("a", True, "rendered", ["x.json"], ["x.json"]),
        _entry("b", True, "fallback", ["sp.json"], []),
        _entry("c", False, "skipped_conditional"),
        _entry("d", True, "rendered"),
    ]
    integ = compose._compute_integrity(manifest)
    assert integ["report_integrity_ok"] is True
    assert integ["integrity_pct"] == 100  # rendered(2) + fallback(1) of 3 in-scope
    assert integ["sections_in_scope"] == 3
    assert integ["sections_fallback"] == 1
    assert integ["sections_skipped_conditional"] == 1
    assert integ["fragments_expected"] == 2
    assert integ["fragments_wired"] == 1
    assert integ["broken_sections"] == []
    assert integ["schema_version"] == compose.RENDER_INTEGRITY_SCHEMA_VERSION


def test_compute_integrity_degraded_and_empty_are_broken():
    manifest = [
        _entry("a", True, "rendered"),
        _entry("e", True, "degraded", ["y.json"], []),
        _entry("f", True, "empty"),
    ]
    integ = compose._compute_integrity(manifest)
    assert integ["report_integrity_ok"] is False
    assert integ["integrity_pct"] == 33  # 1 ok of 3
    assert integ["sections_degraded"] == 1
    assert integ["sections_empty"] == 1
    assert set(integ["broken_sections"]) == {"e", "f"}


def test_compute_integrity_empty_manifest_is_100():
    integ = compose._compute_integrity([])
    assert integ["integrity_pct"] == 100
    assert integ["report_integrity_ok"] is True


# ---------------------------------------------------------------------------
# §9 Abuse Cases — silent-drop detection guard (juice-shop 2026-06-29 RC)
#
# Before this guard, §9 rendering its placeholder while viable verdicts sat on
# disk scored 100% integrity — the verified chains were silently dropped and
# nothing flagged it. These lock in that the placeholder-with-verdicts state is
# now classified as a real content gap, while the legitimately-empty case is
# not falsely flagged.
# ---------------------------------------------------------------------------

_PLACEHOLDER_9 = "## 9. Abuse Cases\n\n_No abuse cases were identified or mandated for this assessment._\n"
_POPULATED_9 = '## 9. Abuse Cases\n\n### <a id="ac-t-001"></a>AC-T-001 — Account Takeover\n'


def _ctx(tmp_path: Path):
    return compose.RenderContext(
        output_dir=tmp_path,
        contract={},
        yaml_data={},
        triage={},
        fragments_dir=tmp_path / ".fragments",
    )


def _write_verdicts(tmp_path: Path, *chain_verdicts):
    (tmp_path / ".abuse-case-verdicts.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "verdicts": [
                    {"abuse_case_id": f"AC-T-{i:03d}", **({"chain_verdict": cv} if cv is not None else {})}
                    for i, cv in enumerate(chain_verdicts, start=1)
                ],
            }
        ),
        encoding="utf-8",
    )


def test_has_viable_abuse_verdicts_absent_file():
    assert compose._has_viable_abuse_verdicts(Path("/nonexistent-dir-xyz")) is False


def test_has_viable_abuse_verdicts_only_not_applicable(tmp_path: Path):
    _write_verdicts(tmp_path, "not_applicable", "not_applicable")
    assert compose._has_viable_abuse_verdicts(tmp_path) is False


def test_has_viable_abuse_verdicts_one_viable(tmp_path: Path):
    _write_verdicts(tmp_path, "not_applicable", "fully_viable")
    assert compose._has_viable_abuse_verdicts(tmp_path) is True


def test_has_viable_abuse_verdicts_missing_chain_verdict_is_viable(tmp_path: Path):
    # No chain_verdict yet — renderer self-heals the fold; treat as viable.
    _write_verdicts(tmp_path, None)
    assert compose._has_viable_abuse_verdicts(tmp_path) is True


def test_has_viable_abuse_verdicts_bad_json_is_false(tmp_path: Path):
    (tmp_path / ".abuse-case-verdicts.json").write_text("{not json", encoding="utf-8")
    assert compose._has_viable_abuse_verdicts(tmp_path) is False


def test_substance_abuse_cases_placeholder_with_verdicts_is_gap(tmp_path: Path):
    # The exact regression: verdicts on disk, §9 still only the placeholder.
    _write_verdicts(tmp_path, "fully_viable")
    assert compose._section_substance_ok(_ctx(tmp_path), "abuse_cases", _PLACEHOLDER_9) is False


def test_substance_abuse_cases_populated_with_verdicts_is_ok(tmp_path: Path):
    _write_verdicts(tmp_path, "fully_viable")
    assert compose._section_substance_ok(_ctx(tmp_path), "abuse_cases", _POPULATED_9) is True


def test_substance_abuse_cases_placeholder_without_verdicts_not_flagged(tmp_path: Path):
    # Legitimately empty (no evaluation on disk) — must NOT be flagged.
    assert compose._section_substance_ok(_ctx(tmp_path), "abuse_cases", _PLACEHOLDER_9) is True


def test_render_flags_abuse_gap_when_verdicts_unrecoverable(tmp_path: Path):
    # Full-loop proof of the silent-drop guard. A viable verdict sits on disk
    # but its AC-id resolves to NO case definition, so even the compose
    # self-heal cannot rebuild the fragment — §9 falls to its placeholder. The
    # integrity pass must now classify that as a real gap (report_integrity_ok
    # False, abuse_cases in broken_sections) so the QA repair loop fires, rather
    # than shipping the old silent 100%.
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    (out / ".abuse-case-verdicts.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "verdicts": [
                    {
                        "abuse_case_id": "AC-UNRESOLVABLE-999",
                        "chain_verdict": "fully_viable",
                        "step_verdicts": [{"step": 1, "verdict": "confirmed"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    compose.render(CONTRACT, out)
    data = json.loads((out / ".render-integrity.json").read_text(encoding="utf-8"))
    assert data["report_integrity_ok"] is False
    assert "abuse_cases" in data["broken_sections"]


# ---------------------------------------------------------------------------
# Live render writes a well-formed sidecar
# ---------------------------------------------------------------------------


def test_render_writes_integrity_sidecar(tmp_path: Path):
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    compose.render(CONTRACT, out)

    data = json.loads((out / ".render-integrity.json").read_text(encoding="utf-8"))
    assert data["schema_version"] == compose.RENDER_INTEGRITY_SCHEMA_VERSION
    assert isinstance(data["integrity_pct"], int) and 0 <= data["integrity_pct"] <= 100
    assert data["generated"]

    by_id = {s["id"]: s for s in data["sections"]}

    # Regression: a yaml-computed section whose optional enrichment fragment
    # (compound-chains.json) is absent must still be `rendered`, not degraded.
    assert by_id["threat_register"]["outcome"] == "rendered"
    for sid in ("system_overview", "assets", "management_summary"):
        assert by_id[sid]["outcome"] == "rendered", sid

    # Skipped (condition-false) sections are out-of-scope, never counted.
    assert by_id["requirements_compliance"]["in_scope"] is False
    assert by_id["requirements_compliance"]["outcome"] == "skipped_conditional"

    # Empty-detection works end-to-end: the fixture gates critical_attack_tree
    # in (>=2 Criticals) but ships no fragment, so it renders empty and is flagged.
    assert by_id["critical_attack_tree"]["outcome"] == "empty"
    assert "critical_attack_tree" in data["broken_sections"]
    assert data["report_integrity_ok"] is False

    # Self-consistency: broken == in-scope degraded/empty; wired == present count.
    in_scope = [s for s in data["sections"] if s["in_scope"]]
    assert set(data["broken_sections"]) == {s["id"] for s in in_scope if s["outcome"] in ("degraded", "empty")}
    assert data["fragments_wired"] == sum(len(s["present_fragments"]) for s in in_scope)


# ---------------------------------------------------------------------------
# render_completion_summary.render_report_integrity — console line
# ---------------------------------------------------------------------------


def _write_sidecar(d: Path, **over):
    payload = {
        "schema_version": 1,
        "report_integrity_ok": True,
        "integrity_pct": 100,
        "sections_in_scope": 18,
        "sections_rendered": 18,
        "sections_fallback": 0,
        "sections_degraded": 0,
        "sections_empty": 0,
        "fragments_wired": 9,
        "broken_sections": [],
    }
    payload.update(over)
    (d / ".render-integrity.json").write_text(json.dumps(payload), encoding="utf-8")


def test_console_line_clean(tmp_path: Path):
    _write_sidecar(tmp_path)
    lines = rcs.render_report_integrity(tmp_path)
    assert len(lines) == 1
    assert "Report integrity" in lines[0]
    assert "100%" in lines[0]
    assert "⚠" not in lines[0]
    assert "9 fragments wired" in lines[0]


def test_console_line_degraded(tmp_path: Path):
    _write_sidecar(
        tmp_path,
        report_integrity_ok=False,
        integrity_pct=83,
        sections_rendered=15,
        broken_sections=["security_architecture", "abuse_cases"],
    )
    lines = rcs.render_report_integrity(tmp_path)
    assert "83%" in lines[0]
    assert "⚠" in lines[0]
    assert any("broken:" in l and "security_architecture" in l for l in lines)


def test_console_line_absent_sidecar(tmp_path: Path):
    assert rcs.render_report_integrity(tmp_path) == []


# ---------------------------------------------------------------------------
# aggregate_run_issues._extract_render_integrity — run-issue surfacing
# ---------------------------------------------------------------------------


def test_run_issue_absent_when_ok(tmp_path: Path):
    _write_sidecar(tmp_path)
    assert ari._extract_render_integrity(tmp_path) == []


def test_run_issue_raised_when_broken(tmp_path: Path):
    _write_sidecar(
        tmp_path,
        report_integrity_ok=False,
        integrity_pct=88,
        broken_sections=["critical_attack_tree"],
    )
    issues = ari._extract_render_integrity(tmp_path)
    assert len(issues) == 1
    iss = issues[0]
    assert iss["category"] == "report_integrity"
    assert iss["severity"] == "warning"
    assert "critical_attack_tree" in iss["title"]
    assert iss["evidence"]["broken_sections"] == ["critical_attack_tree"]


def test_aggregate_flips_run_status_on_broken_report(tmp_path: Path):
    _write_sidecar(tmp_path, report_integrity_ok=False, integrity_pct=88, broken_sections=["critical_attack_tree"])
    result = ari.aggregate(tmp_path, depth="standard", repo_root=tmp_path)
    assert result["run_status"] == "issues"
    assert any(i["category"] == "report_integrity" for i in result["issues"])


# ---------------------------------------------------------------------------
# qa_checks: a broken report feeds the Re-Render Loop (blocking repair action)
# ---------------------------------------------------------------------------


def test_integrity_actions_helper(tmp_path: Path):
    # ok / missing → no actions; broken → one blocking action targeting the fragment.
    assert qa._render_integrity_actions(tmp_path) == ([], [])  # no sidecar
    _write_sidecar(tmp_path)
    assert qa._render_integrity_actions(tmp_path) == ([], [])  # ok sidecar
    (tmp_path / ".render-integrity.json").write_text(
        json.dumps(
            {
                "report_integrity_ok": False,
                "broken_sections": ["critical_attack_tree"],
                "sections": [
                    {
                        "id": "critical_attack_tree",
                        "in_scope": True,
                        "outcome": "empty",
                        "expected_fragments": ["ms-critical-attack-tree.json"],
                        "present_fragments": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    issues, actions = qa._render_integrity_actions(tmp_path)
    assert len(actions) == 1
    assert actions[0]["type"] == "report_integrity"
    assert actions[0]["fragments_to_rewrite"] == [".fragments/ms-critical-attack-tree.json"]
    assert qa._action_severity(actions[0]["type"]) == "blocking"


def test_build_repair_plan_folds_in_broken_report(tmp_path: Path):
    # The compose fixture gates critical_attack_tree in (>=2 Criticals) but ships
    # no fragment → it renders empty → the repair plan must carry a blocking
    # report_integrity action that points the Re-Render Loop at the fragment.
    out = tmp_path / "output"
    shutil.copytree(FIXTURE, out)
    rendered, _ = compose.render(CONTRACT, out)
    # render() returns the markdown + writes .render-integrity.json; the CLI
    # main() is what persists threat-model.md — do the same so build_repair_plan
    # (which reads the md) sees the same on-disk state as the real pipeline.
    (out / "threat-model.md").write_text(rendered, encoding="utf-8")

    plan, _report = qa.build_repair_plan(out / "threat-model.md", out, CONTRACT)
    integrity = [a for a in plan["actions"] if a["type"] == "report_integrity"]
    assert integrity, "broken report did not produce a report_integrity repair action"
    assert any(".fragments/ms-critical-attack-tree.json" in a["fragments_to_rewrite"] for a in integrity)
    assert all(a["severity"] == "blocking" for a in integrity)
    # A blocking action with a writable fragment → the loop is expected to run.
    assert plan["status"] == "fail"
    assert plan["actionable"] is True
