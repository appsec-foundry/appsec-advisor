"""Tests for scripts/render_abuse_cases.py — the deterministic §9 renderer.

Verifies the fragment structure (summary table, per-case blocks, 5-column
chain table with verdict-derived status icons, blocking-mitigation links) and
the no-applicable-case fallback. The rendered links must target anchors the
report actually emits (#f-nnn in §8, #m-nnn in §10, self #ac-... anchors).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "render_abuse_cases.py"

# The sidecar (.fragments/abuse-cases.json) is an internal machine-readable
# artefact — not a compose-loaded fragment — so its shape is pinned here rather
# than via a schemas/fragments/*.json (which would couple it to the composer's
# fragment registry). These keys are what downstream consumers rely on.
_SIDECAR_REQUIRED_CASE_KEYS = {
    "id",
    "title",
    "source",
    "combined_risk",
    "chain_verdict",
    "rows",
}


def _load():
    if "render_abuse_cases" in sys.modules:
        return sys.modules["render_abuse_cases"]
    spec = importlib.util.spec_from_file_location("render_abuse_cases", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["render_abuse_cases"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rac = _load()

_THREAT_MODEL = {
    "threats": [
        {"t_id": "T-010", "title": "Persistent XSS via bypassSecurityTrustHtml", "risk": "High"},
        {"t_id": "T-046", "title": "Refresh token in localStorage", "risk": "Medium"},
        {"t_id": "T-001", "title": "SQL injection in search", "risk": "Critical"},
        {"t_id": "T-002", "title": "Mass assignment on role", "risk": "High"},
    ],
    "mitigations": [
        {"m_id": "M-007", "title": "Replace bypassSecurityTrustHtml", "priority": "P1", "threat_ids": ["T-010"]},
        {"m_id": "M-009", "title": "HttpOnly session cookie", "priority": "P1", "threat_ids": ["T-046"]},
    ],
}


def _setup(tmp_path: Path, verdicts: dict) -> Path:
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(_THREAT_MODEL))
    (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps(verdicts))
    return tmp_path


_FULLY_VIABLE = {
    "schema_version": 1,
    "verdicts": [
        {
            "abuse_case_id": "AC-T-001",
            "chain_verdict": "fully_viable",
            "step_verdicts": [
                {
                    "step": 1,
                    "verdict": "confirmed",
                    "matched_finding_id": "T-010",
                    "evidence": {"file": "about.component.ts", "line": 119},
                    "controls_found": [],
                },
                {
                    "step": 2,
                    "verdict": "confirmed",
                    "matched_finding_id": "T-046",
                    "evidence": {"file": "interceptor.ts", "line": 13},
                    "controls_found": [],
                },
                {
                    "step": 3,
                    "verdict": "inconclusive",
                    "matched_finding_id": None,
                    "evidence": {},
                    "controls_found": [],
                },
            ],
        }
    ],
}


def test_no_verdicts_file_yields_no_models(tmp_path: Path):
    assert rac.build_models(tmp_path, None) == []


def test_fully_viable_case_model(tmp_path: Path):
    _setup(tmp_path, _FULLY_VIABLE)
    models = rac.build_models(tmp_path, None)
    assert len(models) == 1
    m = models[0]
    assert m["id"] == "AC-T-001"
    assert m["chain_verdict"] == "fully_viable"
    # max matched severity High → escalated to Critical because fully viable
    assert m["combined_risk"] == "Critical"
    # step 1 confirmed, no controls → ⚠; step 3 inconclusive/unmatched → ?
    icons = [r["status_icon"] for r in m["rows"]]
    assert icons == ["⚠", "⚠", "?"]
    # T-010 normalised to F-010 for the visible label/anchor
    assert m["rows"][0]["fid"] == "F-010"
    # blocking mitigation M-007 addresses F-010 → breaks at step 1
    bm = {b["id"]: b["breaks_at_step"] for b in m["blocking_mitigations"]}
    assert bm.get("M-007") == 1


def test_fragment_markdown_structure(tmp_path: Path):
    _setup(tmp_path, _FULLY_VIABLE)
    models = rac.build_models(tmp_path, None)
    md = rac.render_fragment(models)
    assert md.startswith("## 9. Abuse Cases")
    assert "| # | Scenario | Actor | Combined Risk | Verdict |" in md
    assert '<a id="ac-t-001"></a>' in md
    assert "### AC-T-001 —" in md
    # 3-column chain table: Evidence folded into Finding (`<br/>`), Status dropped.
    assert "| Step | Finding | Outcome |" in md
    assert "| Step | Finding | Evidence | Outcome | Status |" not in md
    assert "[F-010](#f-010)" in md  # chain step links to §8 dual anchor
    assert "[M-007](#m-007)" in md  # blocking mitigation links to §10
    # Blocking mitigations render as an explained bullet list, not a table.
    assert "Implementing any single mitigation below severs the chain" in md
    assert "| Mitigation | Addresses | Breaks chain at |" not in md
    assert "breaks the chain at **Step 1**" in md
    assert "[§8 Findings Register](#8-findings-register)" in md
    # summary table verdict cell
    assert "⚠ Fully viable" in md


def test_partially_blocked_icon_and_verdict(tmp_path: Path):
    verdicts = {
        "schema_version": 1,
        "verdicts": [
            {
                "abuse_case_id": "AC-T-002",
                "chain_verdict": "partially_blocked",
                "step_verdicts": [
                    {
                        "step": 1,
                        "verdict": "confirmed",
                        "matched_finding_id": "T-001",
                        "evidence": {"file": "user.ts", "line": 44},
                        "controls_found": [],
                    },
                    {
                        "step": 2,
                        "verdict": "confirmed",
                        "matched_finding_id": "T-002",
                        "evidence": {"file": "user.ts", "line": 88},
                        "controls_found": ["allowlist"],
                    },
                ],
            }
        ],
    }
    _setup(tmp_path, verdicts)
    m = rac.build_models(tmp_path, None)[0]
    icons = [r["status_icon"] for r in m["rows"]]
    assert icons == ["⚠", "◐"]  # second step has a control → ◐
    # partially_blocked → no escalation; max matched severity is Critical (T-001)
    assert m["combined_risk"] == "Critical"


def test_unverified_step_adds_provisional_caveat(tmp_path: Path):
    # Step 1 confirmed, step 2 an untouched write-first pre-seed (inconclusive,
    # no reason, empty excerpt = verifier hit its turn ceiling before examining
    # it). The chain still carries a viable verdict but must render the
    # provisional caveat so it is not read as fully verified (juice-shop AC-T-001).
    verdicts = {
        "schema_version": 1,
        "verdicts": [
            {
                "abuse_case_id": "AC-T-001",
                "chain_verdict": "fully_viable",
                "step_verdicts": [
                    {
                        "step": 1,
                        "verdict": "confirmed",
                        "matched_finding_id": "T-010",
                        "evidence": {"file": "x.ts", "line": 5},
                        "controls_found": [],
                    },
                    {
                        "step": 2,
                        "verdict": "inconclusive",
                        "matched_finding_id": "T-046",
                        "evidence": {"excerpt": ""},
                        "controls_found": [],
                    },
                ],
            }
        ],
    }
    _setup(tmp_path, verdicts)
    models = rac.build_models(tmp_path, None)
    assert models[0]["unverified_steps"] == [2]
    md = rac.render_fragment(models)
    assert "Not verified end-to-end" in md and "step 2" in md
    assert "provisional" in md


def test_reasoned_inconclusive_step_has_no_caveat(tmp_path: Path):
    # An inconclusive step WITH a reason is a genuine "examined but couldn't
    # decide" — not an untouched pre-seed. No provisional caveat.
    verdicts = {
        "schema_version": 1,
        "verdicts": [
            {
                "abuse_case_id": "AC-T-001",
                "chain_verdict": "fully_viable",
                "step_verdicts": [
                    {
                        "step": 1,
                        "verdict": "confirmed",
                        "matched_finding_id": "T-010",
                        "evidence": {"file": "x.ts", "line": 5},
                        "controls_found": [],
                    },
                    {
                        "step": 2,
                        "verdict": "inconclusive",
                        "matched_finding_id": "T-046",
                        "reason": "handler precedence unresolved within budget",
                        "evidence": {},
                        "controls_found": [],
                    },
                ],
            }
        ],
    }
    _setup(tmp_path, verdicts)
    models = rac.build_models(tmp_path, None)
    assert models[0]["unverified_steps"] == []
    assert "Not verified end-to-end" not in rac.render_fragment(models)


def test_not_applicable_case_excluded(tmp_path: Path):
    verdicts = {
        "schema_version": 1,
        "verdicts": [{"abuse_case_id": "AC-T-001", "chain_verdict": "not_applicable", "step_verdicts": []}],
    }
    _setup(tmp_path, verdicts)
    assert rac.build_models(tmp_path, None) == []


# Regression: the deterministic fold (match_abuse_cases.finalize_verdict) runs
# in a separate pipeline step that can be skipped (a Stage-1c orchestration
# gap), leaving .abuse-case-verdicts.json with step_verdicts but NO
# chain_verdict. Without the renderer self-heal every chain silently rendered
# "Inconclusive" even when all steps were confirmed (juice-shop 2026-06-24).
_NO_CHAIN_VERDICT = {
    "schema_version": 1,
    "verdicts": [
        {
            "abuse_case_id": "AC-T-001",
            # NOTE: no "chain_verdict" key — finalize never ran.
            "step_verdicts": [
                {"step": 1, "verdict": "confirmed", "matched_finding_id": "T-010", "controls_found": []},
                {"step": 2, "verdict": "confirmed", "matched_finding_id": "T-046", "controls_found": []},
                {"step": 3, "verdict": "confirmed", "matched_finding_id": "T-001", "controls_found": []},
            ],
        }
    ],
}

_MATCHES_HEAL = {
    "schema_version": 1,
    "matches": [
        {
            "abuse_case_id": "AC-T-001",
            "step_matches": [
                {"step": 1, "required": True},
                {"step": 2, "required": True},
                {"step": 3, "required": True},
            ],
        }
    ],
}


def test_missing_chain_verdict_is_self_healed_from_step_verdicts(tmp_path: Path):
    _setup(tmp_path, _NO_CHAIN_VERDICT)
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(_MATCHES_HEAL))
    models = rac.build_models(tmp_path, None)
    assert len(models) == 1
    # All required steps confirmed, no controls → folds to fully_viable,
    # NOT the bare "inconclusive" default.
    assert models[0]["chain_verdict"] == "fully_viable"


def test_missing_chain_verdict_without_matches_stays_inconclusive(tmp_path: Path):
    # No .abuse-case-matches.json → no case_match to fold against → graceful
    # fallback to the historical "inconclusive" default (never crashes).
    _setup(tmp_path, _NO_CHAIN_VERDICT)
    models = rac.build_models(tmp_path, None)
    assert len(models) == 1
    assert models[0]["chain_verdict"] == "inconclusive"


_MATCHES_NA = {
    "schema_version": 1,
    "matches": [
        {
            "abuse_case_id": "AC-T-002",
            "title": "Bulk Data Exfiltration via BOLA",
            "source": "mandatory",
            "structural_verdict": "not_applicable",
            "reason": "no finding matched the required chain step(s) for this scenario",
        },
        {
            "abuse_case_id": "AC-T-001",
            "title": "Account Takeover via XSS",
            "source": "mandatory",
            "structural_verdict": "candidate",
            "reason": None,
        },
    ],
}


def test_catalog_evaluation_lists_only_not_applicable(tmp_path: Path):
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(_MATCHES_NA))
    rows = rac.build_catalog_evaluation(tmp_path)
    assert [r["id"] for r in rows] == ["AC-T-002"]  # candidate excluded
    assert "no finding matched" in rows[0]["reason"]


def test_fragment_renders_catalog_table_when_no_viable_cases(tmp_path: Path):
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(_MATCHES_NA))
    rows = rac.build_catalog_evaluation(tmp_path)
    md = rac.render_fragment([], rows)
    assert md.startswith("## 9. Abuse Cases")
    assert "### Generic catalog — evaluated, not applicable" in md
    assert "| Scenario | Source | Why not applicable |" in md
    assert "Bulk Data Exfiltration via BOLA" in md
    # honest 'nothing verified' line instead of the bare empty placeholder
    assert "No abuse-case chain was verified end-to-end" in md


def test_main_renders_catalog_even_without_verdicts(tmp_path: Path):
    (tmp_path / ".abuse-case-matches.json").write_text(json.dumps(_MATCHES_NA))
    rc = rac.main(["--output-dir", str(tmp_path)])
    assert rc == 0
    frag = (tmp_path / ".fragments" / "abuse-cases.md").read_text()
    assert "Generic catalog" in frag


def test_main_writes_fragment_and_sidecar_validates(tmp_path: Path):
    _setup(tmp_path, _FULLY_VIABLE)
    rc = rac.main(["--output-dir", str(tmp_path)])
    assert rc == 0
    md = (tmp_path / ".fragments" / "abuse-cases.md").read_text()
    assert md.startswith("## 9. Abuse Cases")
    sidecar = json.loads((tmp_path / ".fragments" / "abuse-cases.json").read_text())
    assert sidecar["schema_version"] == 1
    assert sidecar["abuse_cases"], "sidecar must carry at least one case"
    for case in sidecar["abuse_cases"]:
        missing = _SIDECAR_REQUIRED_CASE_KEYS - set(case)
        assert not missing, f"sidecar case missing keys: {missing}"
        assert case["chain_verdict"] in {
            "fully_viable",
            "partially_blocked",
            "mitigated",
            "inconclusive",
        }
        assert case["combined_risk"] in {"Critical", "High", "Medium", "Low", "Informational"}


def test_main_no_models_removes_stale_fragment(tmp_path: Path):
    # Pre-seed a stale fragment, then run with no verdicts → it must be removed
    frag = tmp_path / ".fragments"
    frag.mkdir()
    (frag / "abuse-cases.md").write_text("## 9. Abuse Cases\n\nstale\n")
    rc = rac.main(["--output-dir", str(tmp_path)])
    assert rc == 0
    assert not (frag / "abuse-cases.md").exists()


def test_main_preserves_fragment_when_verdicts_exist_but_all_not_applicable(tmp_path: Path):
    # Regression: when .abuse-case-verdicts.json exists but every verdict has
    # chain_verdict="not_applicable" (build_models → []) AND no matches have
    # structural_verdict="not_applicable" (build_catalog_evaluation → []),
    # main() must NOT delete an existing fragment — the sidecars prove that
    # Stage 1c ran. Deleting would replace a §9 written by Stage 1c with an
    # empty placeholder, silently dropping abuse-case coverage from the report.
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    prior_frag = "## 9. Abuse Cases\n\n_No abuse-case chain was verified._\n"
    (frag_dir / "abuse-cases.md").write_text(prior_frag)

    # .abuse-case-verdicts.json exists (Stage 1c ran) but all chains are not_applicable
    (tmp_path / ".abuse-case-verdicts.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "verdicts": [
                    {"abuse_case_id": "AC-T-001", "chain_verdict": "not_applicable", "step_verdicts": []},
                ],
            }
        )
    )
    # .abuse-case-matches.json with only candidate entries (no not_applicable rows
    # for build_catalog_evaluation to pick up)
    (tmp_path / ".abuse-case-matches.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "matches": [
                    {"abuse_case_id": "AC-T-001", "structural_verdict": "candidate", "step_matches": []},
                ],
            }
        )
    )
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(_THREAT_MODEL))

    rc = rac.main(["--output-dir", str(tmp_path)])
    assert rc == 0
    assert (frag_dir / "abuse-cases.md").exists(), (
        "main() must not delete abuse-cases.md when .abuse-case-verdicts.json is present"
    )


# ─── changelog enrichment with abuse cases (added 2026-06-13) ───────────────
# Abuse cases (AC-T-NNN / AC-NNN / ORG-AC-NNN / REPO-AC-NNN) are produced by this script AFTER build_threat_model_yaml
# wrote the changelog, so they cannot be recorded by the builder. enrich_*
# patches the newest changelog entry with `added.abuse_cases` (diffed against
# the prior entry's `abuse_case_fingerprints`) plus this run's fingerprints.


def _write_tm(tmp_path: Path, changelog: list) -> Path:
    p = tmp_path / "threat-model.yaml"
    p.write_text(yaml.safe_dump({"changelog": changelog}, sort_keys=False), encoding="utf-8")
    return p


def test_enrich_changelog_first_run_all_added(tmp_path: Path):
    _write_tm(tmp_path, [{"version": 1, "date": "2026-06-13", "mode": "full", "added": {"threats": []}}])
    models = [{"id": "AC-T-001", "title": "Forge admin JWT"}, {"id": "AC-T-002", "title": "Exfiltrate user table"}]
    rac.enrich_changelog_with_abuse_cases(tmp_path, models)
    tm = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    e = tm["changelog"][0]
    assert e["added"]["abuse_cases"] == ["AC-T-001", "AC-T-002"]
    assert e["abuse_case_fingerprints"] == ["forge admin jwt", "exfiltrate user table"]


def test_enrich_changelog_diffs_against_prior_entry(tmp_path: Path):
    # changelog[1] = prior run (stored fps); changelog[0] = current (to enrich).
    prior = {"version": 1, "date": "2026-06-12", "mode": "full", "abuse_case_fingerprints": ["forge admin jwt"]}
    current = {"version": 1, "date": "2026-06-13", "mode": "incremental", "added": {"threats": ["T-009"]}}
    _write_tm(tmp_path, [current, prior])
    # AC-T-005 carries the prior title (id renumbered); AC-T-006 is genuinely new.
    models = [{"id": "AC-T-005", "title": "Forge admin JWT"}, {"id": "AC-T-006", "title": "Chain SSRF to RCE"}]
    rac.enrich_changelog_with_abuse_cases(tmp_path, models)
    tm = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    e = tm["changelog"][0]
    assert e["added"]["abuse_cases"] == ["AC-T-006"]
    assert e["added"]["threats"] == ["T-009"]  # builder-written threats preserved


def test_enrich_changelog_no_yaml_is_noop(tmp_path: Path):
    # Missing threat-model.yaml must not raise (non-fatal contract).
    rac.enrich_changelog_with_abuse_cases(tmp_path, [{"id": "AC-T-001", "title": "x"}])
    assert not (tmp_path / "threat-model.yaml").exists()
