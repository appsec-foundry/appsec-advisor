"""Guards for data/abuse-cases/business-cases.yaml — the generic business cases.

The file is part of the default library; these tests keep it valid, open,
distinct from the technical cases, and preselectable without
application-specific names.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import contexts.build_abuse_case_contexts as contexts  # noqa: E402
import model.match_abuse_cases as matcher  # noqa: E402
import model.resolve_abuse_cases as resolver  # noqa: E402

CATALOG = ROOT / "data" / "abuse-cases" / "business-cases.yaml"


def _cases() -> list[dict]:
    cases, errors = resolver._load_case_file(CATALOG, resolver._load_schema())
    assert errors == [], errors
    return cases


def test_business_catalog_holds_a_short_list_of_open_checks():
    cases = _cases()
    assert 1 <= len(cases) <= 10
    assert all(case["kind"] == "descriptive" and case.get("check") and not case.get("steps") for case in cases)


def test_business_catalog_is_loaded_with_the_technical_library_unless_defaults_are_off():
    library, errors = resolver.resolve_abuse_cases(None, None)
    assert errors == []
    ids = [case["id"] for case in library]
    business_ids = {case["id"] for case in _cases()}
    assert len(set(ids)) == len(ids)
    assert business_ids <= set(ids) and set(ids) - business_ids
    without, errors = resolver.resolve_abuse_cases({"abuse_cases": {"inherit_defaults": False}}, None)
    assert errors == [] and without == []


def test_descriptive_signal_vocabulary_matches_recon_signals():
    recon = json.loads((ROOT / "schemas" / "recon-signals.schema.json").read_text(encoding="utf-8"))
    schema = yaml.safe_load((ROOT / "schemas" / "abuse-cases.schema.yaml").read_text(encoding="utf-8"))
    allowed = schema["$defs"]["descriptive_case"]["properties"]["scope_qualifier"]["allOf"][2]
    enum = allowed["properties"]["required_signals"]["items"]["enum"]
    assert sorted(enum) == sorted(recon["properties"]["signals"]["properties"])


def test_case_is_preselected_by_capability_not_by_application_name(tmp_path: Path):
    """The same capability under unrelated names and frameworks preselects the
    rights-escalation case; a repository without it does not."""
    case = next(c for c in _cases() if c["id"] == "AC-T-102")
    for layout in (("src", "roleAssignment.ts"), ("app", "Permissions", "GrantController.java")):
        repo = tmp_path / "-".join(layout)
        target = repo.joinpath(*layout)
        target.parent.mkdir(parents=True)
        target.write_text("code\n")
        match = matcher.match_case(case, [], {"has_role_concept"}, repo_root=repo)
        assert match["structural_verdict"] == "candidate", layout
    plain = tmp_path / "plain"
    (plain / "src").mkdir(parents=True)
    (plain / "src" / "index.ts").write_text("code\n")
    assert matcher.match_case(case, [], {"has_role_concept"}, repo_root=plain)["structural_verdict"] == "not_applicable"
    # "share" selects sharing code, not a generic "shared" helper directory.
    export_case = next(c for c in _cases() if c["id"] == "AC-T-101")
    for rel, expected in (("app/shared/theme.ts", "not_applicable"), ("app/share/link.ts", "candidate")):
        repo = tmp_path / ("share-" + expected)
        (repo / rel).parent.mkdir(parents=True)
        (repo / rel).write_text("code\n")
        assert (
            matcher.match_case(export_case, [], {"has_auth_surface"}, repo_root=repo)["structural_verdict"] == expected
        )
    # Without the recon signal the case does not apply even when a path matches.
    assert (
        matcher.match_case(case, [], set(), repo_root=tmp_path / "src-roleAssignment.ts")["structural_verdict"]
        == "not_applicable"
    )


# ---------------------------------------------------------------------------
# Pilot: delegated-administrator self-escalation end to end (verifier doubled)
# ---------------------------------------------------------------------------

_VULNERABLE = """export async function grant(req, res) {
  if (!req.user.isAdmin) return res.status(403).end();
  await Users.addRole(req.body.userId, req.body.role);
  return res.status(204).end();
}
"""
_PROTECTED = """export async function grant(req, res) {
  if (!req.user.delegatedRoles.includes(req.body.role)) return res.status(403).end();
  await Users.addRole(req.body.userId, req.body.role);
  return res.status(204).end();
}
"""


def _pilot(tmp_path: Path, layout: tuple[str, ...], source: str, steps: list[dict]) -> dict:
    repo = tmp_path / "repo"
    target = repo.joinpath(*layout)
    target.parent.mkdir(parents=True)
    target.write_text(source)
    case = dict(next(c for c in _cases() if c["id"] == "AC-T-102"), id="REPO-AC-101")
    (repo / ".appsec" / "abuse-cases").mkdir(parents=True)
    (repo / ".appsec" / "abuse-cases" / "business.yaml").write_text(
        yaml.safe_dump({"schema_version": 2, "abuse_cases": [case]})
    )
    out = tmp_path / "out"
    out.mkdir()
    (out / ".threats-merged.json").write_text(json.dumps({"threats": []}))
    (out / ".skill-config.json").write_text(json.dumps({"repo_root": str(repo), "assessment_depth": "standard"}))
    signals = out / "signals.json"
    signals.write_text(json.dumps({"signals": ["has_role_concept"]}))
    assert matcher.main(["match", "--output-dir", str(out), "--repo-root", str(repo), "--signals", str(signals)]) == 0
    match = next(
        m
        for m in json.loads((out / ".abuse-case-matches.json").read_text())["matches"]
        if m["abuse_case_id"] == "REPO-AC-101"
    )
    assert match["structural_verdict"] == "candidate"
    context = contexts.write_candidate(out, "REPO-AC-101", repo_root=repo)
    assert "/".join(layout) in json.loads(context.read_text())["candidate"]["preselected_sources"]
    # The verifier double writes what the agent would; finalize admits or rejects it.
    verdict = {"abuse_case_id": "REPO-AC-101", "step_verdicts": steps}
    (out / ".abuse-case-verdicts.json").write_text(json.dumps({"verdicts": [verdict]}))
    assert matcher.main(["finalize", "--output-dir", str(out)]) == 0
    return json.loads((out / ".abuse-case-verdicts.json").read_text())["verdicts"][0]


def _ev(file: str, line: int, excerpt: str) -> dict:
    return {"file": file, "line": line, "excerpt": excerpt}


@pytest.mark.parametrize("layout", [("src", "roles", "grant.ts"), ("app", "Permissions", "GrantController.ts")])
def test_pilot_violating_variant_is_fully_viable_under_any_name(tmp_path: Path, layout):
    file = "/".join(layout)
    steps = [
        {
            "step": 1,
            "verdict": "confirmed",
            "state": "decided",
            "reason": "only isAdmin is checked",
            "evidence": _ev(file, 2, "if (!req.user.isAdmin) return res.status(403).end();"),
        },
        {
            "step": 2,
            "verdict": "confirmed",
            "state": "decided",
            "reason": "any role is accepted",
            "evidence": _ev(file, 3, "await Users.addRole(req.body.userId, req.body.role);"),
        },
    ]
    assert _pilot(tmp_path, layout, _VULNERABLE, steps)["chain_verdict"] == "fully_viable"


def test_pilot_protected_variant_is_mitigated(tmp_path: Path):
    file = "src/roles/grant.ts"
    blocked = {
        "verdict": "blocked",
        "state": "decided",
        "reason": "delegated set is enforced",
        "evidence": _ev(file, 2, "if (!req.user.delegatedRoles.includes(req.body.role)) return res.status(403).end();"),
    }
    steps = [dict(blocked, step=1), dict(blocked, step=2)]
    assert _pilot(tmp_path, ("src", "roles", "grant.ts"), _PROTECTED, steps)["chain_verdict"] == "mitigated"


def test_pilot_unresolved_variant_stays_inconclusive(tmp_path: Path):
    steps = [
        {
            "step": n,
            "verdict": "inconclusive",
            "state": "decided",
            "reason": "delegation is defined by an external policy service",
            "evidence": None,
        }
        for n in (1, 2)
    ]
    assert _pilot(tmp_path, ("src", "roles", "grant.ts"), _VULNERABLE, steps)["chain_verdict"] == "inconclusive"


def test_pilot_forged_confirmation_on_protected_code_is_not_admitted(tmp_path: Path):
    """A model that claims a missing check the code does contain cannot
    produce a viable chain: the cited excerpt is not in the file."""
    file = "src/roles/grant.ts"
    steps = [
        {
            "step": n,
            "verdict": "confirmed",
            "state": "decided",
            "reason": "only isAdmin is checked",
            "evidence": _ev(file, 2, "if (!req.user.isAdmin) return res.status(403).end();"),
        }
        for n in (1, 2)
    ]
    verdict = _pilot(tmp_path, ("src", "roles", "grant.ts"), _PROTECTED, steps)
    assert verdict["chain_verdict"] == "inconclusive"
    assert all(s["reason"].startswith("evidence not admitted") for s in verdict["step_verdicts"])


def test_documented_business_case_example_validates(tmp_path: Path):
    doc = (ROOT / "docs" / "org-profiles.md").read_text(encoding="utf-8")
    section = doc.split("### Business abuse cases\n", 1)[1]
    block = section.split("```yaml\n", 1)[1].split("```", 1)[0]
    target = tmp_path / "example.yaml"
    target.write_text(block, encoding="utf-8")
    cases, errors = resolver._load_case_file(target, resolver._load_schema())
    assert errors == [] and cases[0]["kind"] == "descriptive"


@pytest.mark.parametrize(
    ("excerpt", "kept"),
    [("await Users.addRole(req.body.userId, req.body.role);", True), ("Users.grantAll()", False)],
    ids=["found-in-code", "not-in-code"],
)
def test_an_inconclusive_step_keeps_only_a_citation_found_in_the_code(tmp_path: Path, excerpt: str, kept: bool):
    """An inconclusive step that cites code becomes an indication, so its
    citation passes the same gate as a deciding verdict."""
    file = "src/roles/grant.ts"
    step = {
        "step": 1,
        "verdict": "inconclusive",
        "state": "decided",
        "reason": "whether admins may grant every role is a policy question",
        "evidence": _ev(file, 3, excerpt),
    }
    verdict = _pilot(tmp_path, ("src", "roles", "grant.ts"), _VULNERABLE, [step])
    admitted = verdict["step_verdicts"][0]
    assert admitted["verdict"] == "inconclusive"
    assert (admitted["evidence"] is not None) is kept
    assert ("rejected_evidence" in admitted) is not kept


def test_withdrawn_rights_case_is_located_by_session_code_or_a_token_lifetime_finding(tmp_path: Path):
    """The case reaches the verifier where sessions or tokens live, not only
    when no other case competes for the per-depth limit."""
    case = next(c for c in _cases() if c["id"] == "AC-T-106")
    signals = {"has_role_concept", "has_auth_surface"}
    layouts = {
        "path": ("lib/auth/SessionStore.py", []),
        "finding": (
            "src/server/auth.js",
            [{"id": "F-001", "source_check_id": "AUTHZ-009", "evidence": {"file": "src/server/auth.js", "line": 3}}],
        ),
        "none": ("src/index.ts", []),
    }
    for label, (rel, findings) in layouts.items():
        repo = tmp_path / label
        (repo / rel).parent.mkdir(parents=True)
        (repo / rel).write_text("code\n")
        verdict = matcher.match_case(case, findings, signals, repo_root=repo)["structural_verdict"]
        assert verdict == ("not_applicable" if label == "none" else "candidate"), label
