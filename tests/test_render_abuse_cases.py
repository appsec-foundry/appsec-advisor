"""Tests for scripts/renderers/render_abuse_cases.py — the deterministic §9 renderer.

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

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "renderers/render_abuse_cases.py"
VALID_MODEL = REPO_ROOT / "tests" / "fixtures" / "schema" / "threat-model.valid.yaml"

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
    if "renderers.render_abuse_cases" in sys.modules:
        return sys.modules["renderers.render_abuse_cases"]
    spec = importlib.util.spec_from_file_location("renderers.render_abuse_cases", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["renderers.render_abuse_cases"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


rac = _load()


def test_stale_matcher_identity_does_not_render_dead_finding_link():
    case = {
        "id": "AC-T-999",
        "title": "Stale chain",
        "source": "mandatory",
        "goal": "change privileged state",
        "attacker": {"actor_id": "anonymous", "initial_access": "unauthenticated"},
        "chain": [{"step": 1, "description": "Submit a privileged field"}],
    }
    verdict = {
        "chain_verdict": "inconclusive",
        "step_verdicts": [
            {
                "step": 1,
                "verdict": "inconclusive",
                "matched_finding_id": "T-007",
                "evidence": {"file": "routes/verify.ts", "line": 53},
            }
        ],
    }
    model = rac.render_case(
        case,
        verdict,
        findings_idx={},
        mitigations=[],
        match_steps={1: {"matched_finding_id": "T-007", "evidence": {"file": "routes/verify.ts", "line": 53}}},
    )

    assert model["rows"][0]["fid"] == ""
    assert model["rows"][0]["evidence"] == "routes/verify.ts:53"
    assert model["matched_finding_ids"] == []


_THREAT_MODEL = {
    "threats": [
        {"id": "T-010", "title": "Persistent Cross-Site Scripting", "risk": "High"},
        {"id": "T-046", "title": "Refresh Token in Browser Storage", "risk": "Medium"},
        {"id": "T-001", "title": "SQL Injection in Search", "risk": "Critical"},
        {"id": "T-002", "title": "Mass Assignment on Role", "risk": "High"},
    ],
    "mitigations": [
        {"id": "M-007", "title": "Replace unsafe HTML rendering", "priority": "P1", "threat_ids": ["T-010"]},
        {"id": "M-009", "title": "Use an HttpOnly session cookie", "priority": "P1", "threat_ids": ["T-046"]},
    ],
}


def _write_valid_threat_model(path: Path) -> None:
    model = yaml.safe_load(VALID_MODEL.read_text(encoding="utf-8"))
    model["threats"] = []
    stride_by_id = {
        "T-010": "Tampering",
        "T-046": "Information Disclosure",
        "T-001": "Tampering",
        "T-002": "Elevation of Privilege",
    }
    for threat in _THREAT_MODEL["threats"]:
        model["threats"].append(
            {
                **threat,
                "component": "C-01",
                "stride": stride_by_id[threat["id"]],
                "scenario": f"Repository evidence confirms {threat['title'].lower()} in the profile flow.",
                "likelihood": threat["risk"],
                "impact": threat["risk"],
                "evidence": [{"file": "src/profile/handler.ts", "line": 10}],
                "mitigation_ids": [
                    mitigation["id"]
                    for mitigation in _THREAT_MODEL["mitigations"]
                    if threat["id"] in mitigation["threat_ids"]
                ],
            }
        )
    model["mitigations"] = _THREAT_MODEL["mitigations"]
    model["components"][0]["threat_ids"] = [threat["id"] for threat in model["threats"]]
    model["security_controls"][0]["linked_threats"] = [threat["id"] for threat in model["threats"]]
    model["trust_boundaries"][0]["adjacent_finding_ids"] = [threat["id"] for threat in model["threats"]]
    path.write_text(yaml.safe_dump(model, sort_keys=False), encoding="utf-8")


def _setup(tmp_path: Path, verdicts: dict) -> Path:
    _write_valid_threat_model(tmp_path / "threat-model.yaml")
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
    # Verification establishes the path without increasing its assessed risk.
    assert m["combined_risk"] == "High"
    # step 1 confirmed, no controls → ⚠; step 3 inconclusive/unmatched → ?
    icons = [r["status_icon"] for r in m["rows"]]
    assert icons == ["⚠", "⚠", "?"]
    # T-010 normalised to F-010 for the visible label/anchor
    assert m["rows"][0]["fid"] == "F-010"
    # blocking mitigation M-007 addresses F-010 → breaks at step 1
    bm = {b["id"]: b["breaks_at_step"] for b in m["blocking_mitigations"]}
    assert bm.get("M-007") == 1


def test_refuted_step_keeps_its_own_icon(tmp_path: Path):
    # AC-6: a settled mismatch renders as ✗, distinct from an open "?" step;
    # an unknown verdict still normalises to inconclusive.
    verdicts = json.loads(json.dumps(_FULLY_VIABLE))
    verdicts["verdicts"][0]["chain_verdict"] = "inconclusive"
    verdicts["verdicts"][0]["step_verdicts"][1]["verdict"] = "refuted"
    verdicts["verdicts"][0]["step_verdicts"][2]["verdict"] = "not-a-verdict"
    _setup(tmp_path, verdicts)
    m = rac.build_models(tmp_path, None)[0]
    assert [r["status_icon"] for r in m["rows"]] == ["⚠", "✗", "?"]
    assert [r["verdict"] for r in m["rows"]] == ["confirmed", "refuted", "inconclusive"]
    assert "✗ Refuted" in rac._LEGEND


@pytest.mark.parametrize(
    "title,filename", [("Alter project records", "src/records.py"), ("Run queued work", "jobs/run.go")]
)
@pytest.mark.parametrize("risks", [("High",), ("High", "Medium"), ("High", "High"), ("Critical", "Medium")])
def test_verified_case_retains_highest_assessed_risk(title, filename, risks):
    case = {
        "id": "ORG-AC-901",
        "title": title,
        "source": "mandatory",
        "goal": title,
        "attacker": {"actor_id": "external-attacker", "initial_access": "unauthenticated"},
        "chain": [{"step": n, "description": f"Reach operation {n}"} for n in range(1, len(risks) + 1)],
    }
    verdict = {
        "chain_verdict": "fully_viable",
        "step_verdicts": [
            {"step": n, "verdict": "confirmed", "matched_finding_id": f"F-{n:03d}", "controls_found": []}
            for n in range(1, len(risks) + 1)
        ],
    }
    findings = {
        f"F-{n:03d}": {"risk": risk, "title": title, "evidence": {"file": filename, "line": n}}
        for n, risk in enumerate(risks, 1)
    }
    model = rac.render_case(case, verdict, findings, [])
    assert model["combined_risk"] == ("Critical" if "Critical" in risks else "High")
    assert "Why combined risk exceeds individual ratings" not in rac.render_fragment([model])


@pytest.mark.parametrize("ids", [(11, 900, 80, 1, 2, 3), (950, 40, 700, 30, 20, 10)])
def test_report_orders_cases_by_verified_risk_and_preserves_export_order(tmp_path, ids):
    definitions, verdicts = [], []
    rows = [
        ("Read project records", "T-010", "fully_viable"),
        ("Execute a server operation", "T-001", "fully_viable"),
        ("Change a protected role", "T-002", "fully_viable"),
        ("Reach a guarded operation", "T-001", "partially_blocked"),
        ("Investigate an operation", "T-001", "inconclusive"),
        ("Attempt a denied operation", "T-001", "mitigated"),
    ]
    for number, (title, fid, status) in zip(ids, rows):
        cid = f"ORG-AC-{number:03d}"
        definitions.append(
            {
                "id": cid,
                "title": title,
                "source": "mandatory",
                "goal": title,
                "attacker": {"actor_id": "external-attacker", "initial_access": "unauthenticated"},
                "chain": [
                    {"step": 1, "label": title, "grants": "operation_access", "probe": {"sink_patterns": ["operation"]}}
                ],
            }
        )
        verdicts.append(
            {
                "abuse_case_id": cid,
                "chain_verdict": status,
                "step_verdicts": [{"step": 1, "verdict": "confirmed", "matched_finding_id": fid}],
            }
        )
    profile = tmp_path / "profile"
    (profile / "abuse-cases").mkdir(parents=True)
    (profile / "abuse-cases" / "cases.yaml").write_text(yaml.safe_dump({"abuse_cases": definitions}))
    profile_path = profile / "org-profile.yaml"
    profile_path.write_text(yaml.safe_dump({"abuse_cases": {"inherit_defaults": False}}))
    _setup(tmp_path, {"schema_version": 1, "verdicts": verdicts})
    path = tmp_path / "threat-model.yaml"
    model = yaml.safe_load(path.read_text())
    for finding in model["threats"]:
        finding["breach_distance"] = 2 if finding["id"] == "T-010" else 1
    path.write_text(yaml.safe_dump(model))
    expected = [f"ORG-AC-{ids[index]:03d}" for index in (1, 2, 0, 3, 4, 5)]

    for ordered_verdicts in (verdicts, list(reversed(verdicts))):
        (tmp_path / ".abuse-case-verdicts.json").write_text(json.dumps({"verdicts": ordered_verdicts}))
        assert rac.main(["--output-dir", str(tmp_path), "--org-profile", str(profile_path)]) == 0
        sidecar = json.loads((tmp_path / ".fragments" / "abuse-cases.json").read_text())
        assert [case["id"] for case in sidecar["abuse_cases"]] == expected
        exported = yaml.safe_load(path.read_text())["abuse_case_analysis"]["cases"]
        assert [case["id"] for case in exported] == expected
        assert [case["combined_risk"] for case in exported[:3]] == ["Critical", "High", "High"]
        md = (tmp_path / ".fragments" / "abuse-cases.md").read_text()
        assert [md.index(f"### {cid}") for cid in expected] == sorted(md.index(f"### {cid}") for cid in expected)
        assert md.index("**Confirmed attack paths**") < md.index("**Unresolved scenarios**")
        assert md.index("**Unresolved scenarios**") < md.index("**Mitigated scenarios**")


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
    assert md.count("implementing any single mitigation listed under a case severs the chain") == 1
    assert "Implementing any single mitigation below" not in md
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
    # Stage 1d ran. Deleting would replace a §9 written by Stage 1d with an
    # empty placeholder, silently dropping abuse-case coverage from the report.
    frag_dir = tmp_path / ".fragments"
    frag_dir.mkdir()
    prior_frag = "## 9. Abuse Cases\n\n_No abuse-case chain was verified._\n"
    (frag_dir / "abuse-cases.md").write_text(prior_frag)

    # .abuse-case-verdicts.json exists (Stage 1d ran) but all chains are not_applicable
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
    _write_valid_threat_model(tmp_path / "threat-model.yaml")

    rc = rac.main(["--output-dir", str(tmp_path)])
    assert rc == 0
    assert (frag_dir / "abuse-cases.md").exists(), (
        "main() must not delete abuse-cases.md when .abuse-case-verdicts.json is present"
    )


def test_main_persists_canonical_analysis_to_yaml(tmp_path: Path):
    _setup(tmp_path, _FULLY_VIABLE)

    assert rac.main(["--output-dir", str(tmp_path)]) == 0

    analysis = yaml.safe_load((tmp_path / "threat-model.yaml").read_text(encoding="utf-8"))["abuse_case_analysis"]
    assert analysis["status"] == "completed"
    case = analysis["cases"][0]
    assert case["id"] == "AC-T-001"
    assert case["chain_verdict"] == "fully_viable"
    assert case["verification_complete"] is False
    assert case["unverified_steps"] == [3]
    assert case["matched_finding_ids"] == ["F-010", "F-046"]
    assert case["blocking_mitigation_ids"] == ["M-007", "M-009"]
    assert case["steps"][0] == {
        "step": 1,
        "outcome": case["steps"][0]["outcome"],
        "verdict": "confirmed",
        "finding_id": "F-010",
        "evidence": {"file": "about.component.ts", "line": 119},
        "controls_found": [],
        "unverified": False,
    }
    assert "rows" not in case and "status_icon" not in json.dumps(case)


def test_canonical_persistence_does_not_follow_pending_symlink(tmp_path: Path):
    _setup(tmp_path, _FULLY_VIABLE)
    victim = tmp_path / "unrelated.txt"
    victim.write_text("preserve me", encoding="utf-8")
    pending = tmp_path / ".threat-model.yaml.abuse.pending"
    pending.symlink_to(victim)

    assert rac.main(["--output-dir", str(tmp_path)]) == 0

    assert victim.read_text(encoding="utf-8") == "preserve me"
    assert not pending.exists()


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


@pytest.mark.parametrize(
    ("access", "meta", "name"),
    [
        ("unauthenticated", {}, "Anonymous Internet Attacker"),
        ("authenticated_low_priv", {"open_user_registration": True}, "Internet Attacker"),
        ("authenticated_low_priv", {}, "Authenticated Internet Attacker"),
        ("physical", {}, "device-holder"),
    ],
)
def test_case_actor_carries_the_figure_name_of_its_access_group(access, meta, name):
    """Library actor IDs such as external-attacker never reach the report."""
    case = {
        "id": "AC-T-900",
        "title": "Chain",
        "attacker": {
            "actor_id": "external-attacker" if access != "physical" else "device-holder",
            "initial_access": access,
        },
        "chain": [],
    }
    model = rac.render_case(case, {"chain_verdict": "inconclusive"}, findings_idx={}, mitigations=[], meta=meta)

    assert model["actor_label"].split(" — ")[0] == name
    assert "external-attacker" not in model["actor_label"]


@pytest.mark.parametrize(
    ("verdict", "case", "expected"),
    [
        ("fully_viable", {"goal_impact": "Critical"}, "Critical"),
        ("fully_viable", {}, "High"),
        ("partially_blocked", {"goal_impact": "Critical"}, "High"),
    ],
)
def test_section_nine_risk_uses_the_triage_chain_rule(verdict, case, expected):
    matched = [{"risk": "High"}, {"risk": "Medium"}]
    assert rac._combined_risk(matched, verdict, case) == expected


# ─── descriptive (business) cases ───────────────────────────────────────────

_DESCRIPTIVE_CASE = {
    "id": "REPO-AC-020",
    "kind": "descriptive",
    "title": "Delegated administrator grants themselves a role",
    "actor": "Delegated administrator",
    "initial_access": "authenticated_high_priv",
    "goal": "Obtain a role outside the delegation.",
    "boundary": "Roles the delegation permits.",
    "steps": ["Assign a role to themselves.", "Choose a role outside the delegation."],
    "expected_controls": ["The assignment checks the delegation."],
    "scope_qualifier": {"path_patterns": ["src/roles/*"]},
}


def _descriptive_setup(tmp_path: Path, chain_verdict: str = "fully_viable") -> Path:
    repo = tmp_path / "repo"
    case_dir = repo / ".appsec" / "abuse-cases"
    case_dir.mkdir(parents=True)
    (case_dir / "business.yaml").write_text(
        yaml.safe_dump({"schema_version": 2, "abuse_cases": [_DESCRIPTIVE_CASE]}), encoding="utf-8"
    )
    out = tmp_path / "out"
    out.mkdir()
    steps = [
        {
            "step": n,
            "verdict": "confirmed",
            "state": "decided",
            "matched_finding_id": None,
            "reason": "no delegation check",
            "evidence": {"file": "src/roles/assign.ts", "line": 3},
            "controls_found": [],
        }
        for n in (1, 2)
    ]
    _setup(
        out,
        {
            "schema_version": 1,
            "verdicts": [{"abuse_case_id": "REPO-AC-020", "chain_verdict": chain_verdict, "step_verdicts": steps}],
        },
    )
    matches = {
        "schema_version": 1,
        "matches": [
            {
                "abuse_case_id": "REPO-AC-020",
                "kind": "descriptive",
                "title": _DESCRIPTIVE_CASE["title"],
                "structural_verdict": "candidate",
                "step_matches": [{"step": 1, "required": True}, {"step": 2, "required": True}],
            },
            {
                "abuse_case_id": "REPO-AC-021",
                "kind": "descriptive",
                "title": "Self-approval",
                "source": "descriptive",
                "structural_verdict": "not_applicable",
                "reason": "no runtime source path matched: **/approv*",
            },
            {
                "abuse_case_id": "REPO-AC-022",
                "kind": "descriptive",
                "title": "Approval reuse",
                "requested": True,
                "structural_verdict": "not_performed",
                "reason": "exceeds the limit of 16 explicitly requested business cases per run",
            },
            {
                "abuse_case_id": "REPO-AC-023",
                "kind": "descriptive",
                "title": "Export bypass",
                "requested": False,
                "structural_verdict": "not_performed",
                "reason": "exceeds the limit of 3 business cases at standard depth",
            },
        ],
        "rejected_case_files": [
            {"path": ".appsec/abuse-cases/bad.yaml", "reason": "bad.yaml: schema_version 7 is not supported"}
        ],
    }
    (out / ".abuse-case-matches.json").write_text(json.dumps(matches))
    return repo


def test_unlinked_descriptive_case_is_not_rated(tmp_path: Path):
    """A confirmed business chain without a linked finding gets no fallback severity."""
    repo = _descriptive_setup(tmp_path)
    out = tmp_path / "out"
    assert rac.main(["--output-dir", str(out), "--repo-root", str(repo)]) == 0
    analysis = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["abuse_case_analysis"]
    case = next(c for c in analysis["cases"] if c["id"] == "REPO-AC-020")
    assert case["combined_risk"] is None
    assert case["source"] == "descriptive"
    assert case["actor"] == "Delegated administrator"
    assert [s["outcome"] for s in case["steps"]] == _DESCRIPTIVE_CASE["steps"]
    md = (out / ".fragments" / "abuse-cases.md").read_text(encoding="utf-8")
    assert "not rated (no linked finding)" in md
    assert "**Source:** business case" in md


def test_an_open_business_case_carries_its_bounded_questions_to_the_model(tmp_path: Path, monkeypatch):
    questions = [f"Which roles may administrator tier {n} assign?" for n in range(1, 6)]
    monkeypatch.setitem(_DESCRIPTIVE_CASE, "open_questions", questions)
    repo = _descriptive_setup(tmp_path, chain_verdict="inconclusive")
    out = tmp_path / "out"
    assert rac.main(["--output-dir", str(out), "--repo-root", str(repo)]) == 0
    analysis = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["abuse_case_analysis"]
    case = next(c for c in analysis["cases"] if c["id"] == "REPO-AC-020")
    assert case["open_questions"] == questions[:3]


def test_a_business_case_without_questions_adds_no_question_field(tmp_path: Path):
    repo = _descriptive_setup(tmp_path, chain_verdict="inconclusive")
    out = tmp_path / "out"
    assert rac.main(["--output-dir", str(out), "--repo-root", str(repo)]) == 0
    analysis = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["abuse_case_analysis"]
    assert all("open_questions" not in case for case in analysis["cases"])


@pytest.mark.parametrize("flag", [True, False, None])
def test_a_verified_case_is_marked_requested_only_by_the_matcher(tmp_path: Path, flag):
    repo = _descriptive_setup(tmp_path)
    out = tmp_path / "out"
    matches_path = out / ".abuse-case-matches.json"
    matches = json.loads(matches_path.read_text(encoding="utf-8"))
    if flag is not None:
        next(m for m in matches["matches"] if m["abuse_case_id"] == "REPO-AC-020")["requested"] = flag
    matches_path.write_text(json.dumps(matches), encoding="utf-8")
    assert rac.main(["--output-dir", str(out), "--repo-root", str(repo)]) == 0
    analysis = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["abuse_case_analysis"]
    case = next(c for c in analysis["cases"] if c["id"] == "REPO-AC-020")
    md = (out / ".fragments" / "abuse-cases.md").read_text(encoding="utf-8")
    if flag:
        assert case["requested"] is True
        assert "**Source:** business case, requested" in md
    else:
        assert "requested" not in case
        assert "business case, requested" not in md


def test_business_coverage_is_summarized_and_requests_answered_individually(tmp_path: Path):
    repo = _descriptive_setup(tmp_path)
    out = tmp_path / "out"
    assert rac.main(["--output-dir", str(out), "--repo-root", str(repo)]) == 0
    md = (out / ".fragments" / "abuse-cases.md").read_text(encoding="utf-8")
    assert "### Business-case coverage" in md
    assert "1 business case(s) did not apply" in md
    assert "Self-approval" not in md  # templates are counted, not listed
    assert "Requested case REPO-AC-022 — Approval reuse: not performed" in md
    assert "1 business case(s) were not performed: exceeds the limit of 3" in md
    assert "`.appsec/abuse-cases/bad.yaml` was rejected" in md
    analysis = yaml.safe_load((out / "threat-model.yaml").read_text(encoding="utf-8"))["abuse_case_analysis"]
    assert {r["id"]: r["requested"] for r in analysis["not_performed"]} == {"REPO-AC-022": True, "REPO-AC-023": False}
    assert any(r["id"] == "REPO-AC-021" for r in analysis["catalog_evaluated"])


def test_matched_candidates_without_a_verdict_are_reported_as_not_verified(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir()
    rows = [
        {"abuse_case_id": "AC-T-001", "title": "Script to token theft", "structural_verdict": "candidate"},
        {"abuse_case_id": "AC-T-006", "title": "Server-side injection", "structural_verdict": "candidate"},
        {"abuse_case_id": "AC-T-002", "title": "Bulk export", "structural_verdict": "not_applicable", "reason": "x"},
    ]
    (out / ".abuse-case-matches.json").write_text(json.dumps({"matches": rows}), encoding="utf-8")
    unverified = rac.build_unverified_candidates(out)
    assert [r["id"] for r in unverified] == ["AC-T-001", "AC-T-006"]
    md = rac.render_fragment([], rac.build_catalog_evaluation(out), [], [], unverified)
    assert "2 matched candidate(s) were never checked" in md
    assert "No abuse-case chain was verified" not in md
    analysis = rac.build_canonical_analysis(out, [], [], [], unverified)
    assert analysis["status"] == "not_run"
    assert {r["id"] for r in analysis["not_performed"]} == {"AC-T-001", "AC-T-006"}
    # A candidate that received a verdict is a result, not a gap.
    (out / ".abuse-case-verdicts.json").write_text(
        json.dumps({"verdicts": [{"abuse_case_id": "AC-T-001", "step_verdicts": []}]}), encoding="utf-8"
    )
    assert [r["id"] for r in rac.build_unverified_candidates(out)] == ["AC-T-006"]
    assert rac.build_canonical_analysis(out, [], [], [], rac.build_unverified_candidates(out))["status"] == "completed"


def test_unrated_risk_is_reserved_for_unlinked_descriptive_cases():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    from validators.validate_intermediate import _check_export_trace_invariants as semantic  # noqa: PLC0415

    base = {
        "id": "AC-T-001",
        "source": "mandatory",
        "combined_risk": None,
        "steps": [],
        "matched_finding_ids": [],
        "unverified_steps": [],
        "verification_complete": True,
    }
    errors = semantic({"abuse_case_analysis": {"status": "completed", "cases": [base]}})
    assert any("only an unlinked descriptive case may be unrated" in e for e in errors)
    errors = semantic({"abuse_case_analysis": {"status": "completed", "cases": [dict(base, source="descriptive")]}})
    assert not any("unrated" in e for e in errors)
