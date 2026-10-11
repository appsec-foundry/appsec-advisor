"""Combined-assessment Stage 2 publishes only renderer output that passes the fragment gates."""

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import model.emit_requirement_trace_to_model as emit_trace
import yaml
from model.build_threat_model_yaml import build_requirements_compliance
from orchestrator import assessment_stage2 as stage2
from runtime.assessment_host import ExchangeError

MODEL = """\
components:
  - {id: web-api, name: Web API, tier: application, framework: Express}
threats:
  - {id: T-001, title: SQL injection in login, risk: Critical, stride: Tampering, cwe: CWE-89,
     component: web-api, evidence_summary: "server.js:12 interpolates the email into SQL.",
     violated_requirements: [SEC-001]}
  - {id: T-002, title: Missing content security policy, risk: High, stride: Tampering, cwe: CWE-1021,
     component: web-api}
security_controls:
  - {domain: Identity and Authentication Controls, control: Password-Based Authentication,
     effectiveness: Unsafe, status_note: raw SQL login lookup, linked_threats: [T-001], implementation: "server.js:12"}
  - {domain: Browser and Cross-Origin Controls, control: Content Security Policy, effectiveness: Missing,
     status_note: no CSP header is set, linked_threats: [T-002]}
"""
TRIAGE = {"ranking": {"views": {"top_findings": {"findings_ranked": [{"id": "T-001"}, {"id": "T-002"}]}}}}

VERDICT = {
    "severity": "red",
    "opening": "This web application lets an anonymous attacker sign in as any customer, including administrators. "
    "It must not hold real customer data until the login lookup is fixed.",
    "bullets": [
        {
            "title": "Account takeover at login",
            "body": "Anyone on the internet can use SQL injection at login to sign in as any customer.",
            "refs": ["F-001"],
        },
        {
            "title": "Customer pages can be framed",
            "body": "A missing framing policy lets another site trick signed-in customers into unwanted actions.",
            "refs": ["F-002"],
        },
    ],
    "closing": "Until these gaps close, treat every account and its stored data as exposed to outside parties.",
}
ATTACK_PATHS = {
    "schema_version": 1,
    "actors": ["internet-anon"],
    "attack_paths": [
        {
            "class": "injection",
            "actor": "internet-anon",
            "target": "data",
            "scenario_title": "SQL injection bypasses login",
            "description": "Injection lets an attacker change database queries the application builds from input.",
            "findings": ["F-001"],
            "impact": ["full-admin-takeover"],
        }
    ],
}
MERMAID = (
    "The diagram shows the intended login flow:\n```mermaid\nsequenceDiagram\n"
    "  Client->>API: submit credentials\n  API-->>Client: session issued\n```"
)


class FakeJobs:
    """Accept like AssessmentJobs: schema first, then the caller's deterministic validation."""

    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def execute(self, *, role, selector, instructions, context, schema, allowed_sources, validate):
        self.calls.append({"role": role, "selector": selector, "allowed_sources": allowed_sources, "context": context})
        assert isinstance(instructions, str) and instructions
        json.dumps(context)
        artifact = copy.deepcopy(self.replies[selector])
        Draft202012Validator.check_schema(schema)
        if not Draft202012Validator(schema).is_valid(artifact):
            raise ExchangeError("artifact violates its output contract")
        validate(artifact, [])
        return artifact


def _script(*args):
    subprocess.run([sys.executable, *args], cwd=SCRIPTS, check=True, capture_output=True)


@pytest.fixture(scope="module")
def prepared(tmp_path_factory):
    ws = tmp_path_factory.mktemp("prepared")
    (ws / "threat-model.yaml").write_text(MODEL, encoding="utf-8")
    (ws / ".triage-flags.json").write_text(json.dumps(TRIAGE), encoding="utf-8")
    _script("renderers/pregenerate_fragments.py", str(ws), "--only", "security-architecture.md")
    _script("renderers/ms_input_digest.py", str(ws))
    return ws


@pytest.fixture
def workspace(prepared, tmp_path):
    ws = tmp_path / "ws"
    shutil.copytree(prepared, ws)
    return ws


def _fill(row):
    if row["optional"]:
        return ""
    if row["mermaid"]:
        return MERMAID
    if row["inline"]:
        return "🔴 Unsafe — the login lookup trusts caller input ([F-001](#f-001))."
    return "The login handler checks credentials against the user store.\n- Query built from input ([F-001](#f-001))."


def _fills(ws):
    scaffold = (ws / ".fragments" / "security-architecture.md").read_text(encoding="utf-8")
    return {"fills": [{"id": row["id"], "text": _fill(row)} for row in stage2.placeholders(scaffold)]}


def _replies(ws, verdict=VERDICT, fills=None):
    return {
        "stage2:management-summary": {"verdict": verdict, "attack_paths": ATTACK_PATHS, "anti_patterns": None},
        "stage2:security-architecture": fills if fills is not None else _fills(ws),
    }


def _gate(*args):
    return subprocess.run([sys.executable, *args], cwd=SCRIPTS, capture_output=True, text=True).returncode


def test_valid_replies_publish_gated_fragments_without_source_access(workspace):
    jobs = FakeJobs(_replies(workspace))

    receipts = stage2.render(jobs, workspace)

    fragments = workspace / ".fragments"
    assert _gate("validators/validate_fragment.py", "verdict", str(fragments / "ms-verdict.json")) == 0
    assert (
        _gate(
            "validators/validate_fragment.py",
            "security-posture-attack-paths",
            str(fragments / "security-posture-attack-paths.json"),
        )
        == 0
    )
    assert _gate("validators/validate_ms_compactness.py", str(workspace)) == 0
    assert not (fragments / "ms-anti-patterns.json").exists()
    section6 = (fragments / "security-architecture.md").read_text(encoding="utf-8")
    assert "NARRATIVE_PLACEHOLDER" not in section6 and "```mermaid" in section6
    assert [c["role"] for c in jobs.calls] == ["ms_renderer", "secarch_renderer"]
    assert all(c["allowed_sources"] == frozenset() for c in jobs.calls)
    assert len(receipts) == 3 and "skipped (no catalog)" in receipts[1]


@pytest.mark.parametrize(
    "change",
    [
        {"severity": "green"},
        {"bullets": [{**VERDICT["bullets"][1], "refs": ["F-002"]}]},
        {"bullets": [{**VERDICT["bullets"][0], "refs": ["F-001", "F-099"]}]},
        {"closing": "Until the SQL injection is fixed, every account and its stored data remain exposed."},
    ],
    ids=["wrong-colour", "uncited-critical", "unknown-ref", "attack-in-closing"],
)
def test_invalid_verdict_is_rejected_and_nothing_is_written(workspace, change):
    before = sorted(p.name for p in (workspace / ".fragments").iterdir())
    jobs = FakeJobs(_replies(workspace, verdict={**VERDICT, **change}))

    with pytest.raises(ExchangeError):
        stage2.render(jobs, workspace)

    assert sorted(p.name for p in (workspace / ".fragments").iterdir()) == before
    assert [c["role"] for c in jobs.calls] == ["ms_renderer"]


@pytest.mark.parametrize("defect", ["unknown", "missing", "duplicate"])
def test_secarch_fills_must_cover_exactly_the_scaffold_placeholders(workspace, defect):
    scaffold_path = workspace / ".fragments" / "security-architecture.md"
    scaffold = scaffold_path.read_text(encoding="utf-8")
    rows = stage2.placeholders(scaffold)
    fills = _fills(workspace)
    if defect == "unknown":
        fills["fills"][0]["id"] = "P-999"
    elif defect == "missing":
        fills["fills"].pop()
    else:
        fills["fills"][-1]["id"] = fills["fills"][0]["id"]

    with pytest.raises(ExchangeError):
        stage2.apply_fills(scaffold, rows, fills)
    with pytest.raises(ExchangeError):
        stage2.render(FakeJobs(_replies(workspace, fills=fills)), workspace)
    assert scaffold_path.read_text(encoding="utf-8") == scaffold


@pytest.mark.parametrize(
    "text",
    [
        "## Injected heading",
        "See [details](https://example.invalid/x).",
        "<script>alert(1)</script>",
        "Cites an unpublished finding [F-077](#f-077).",
        "```ts\nconst q = input;\n```",
    ],
    ids=["heading", "url", "html", "unpublished-ref", "code-fence"],
)
def test_secarch_fill_content_is_held_to_the_section6_contract(workspace, text):
    scaffold_path = workspace / ".fragments" / "security-architecture.md"
    scaffold = scaffold_path.read_text(encoding="utf-8")
    fills = _fills(workspace)
    block = next(i for i, row in enumerate(stage2.placeholders(scaffold)) if not row["inline"] and not row["mermaid"])
    fills["fills"][block]["text"] = text

    with pytest.raises(ExchangeError):
        stage2.render(FakeJobs(_replies(workspace, fills=fills)), workspace)
    assert scaffold_path.read_text(encoding="utf-8") == scaffold


def test_filled_scaffold_needs_no_job(workspace):
    path = workspace / ".fragments" / "security-architecture.md"
    path.write_text("## 6. Security Architecture\n\nNo placeholders remain.\n", encoding="utf-8")
    jobs = FakeJobs(_replies(workspace, fills={"fills": []}))

    receipts = stage2.render(jobs, workspace)

    assert [c["role"] for c in jobs.calls] == ["ms_renderer"]
    assert receipts[-1] == "stage2: security architecture already filled"


CATALOG = """\
source: company
categories:
  - id: CAT-AUTH
    title: Authentication
    requirements:
      - {id: SEC-001, text: Database queries MUST bind user input as parameters., priority: MUST}
      - {id: SEC-002, text: Responses SHOULD send a content security policy., priority: SHOULD}
"""
COMPLIANCE = {
    "summary": "The login query violates the parameter-binding requirement; the browser policy cannot be confirmed.",
    "rows": [
        {
            "id": "SEC-001",
            "title": "Parameterized queries",
            "status": "FAIL",
            "evidence": "The login lookup builds its query from request input.",
            "finding_ids": ["F-001"],
        },
        {
            "id": "SEC-002",
            "title": "Content security policy",
            "status": "UNVERIFIABLE",
            "evidence": "No supplied control evidences a policy header.",
            "finding_ids": [],
        },
    ],
}


@pytest.fixture
def catalog_workspace(workspace):
    (workspace / ".requirements.yaml").write_text(CATALOG, encoding="utf-8")
    return workspace


def _with_compliance(ws, compliance):
    return {**_replies(ws), "stage2:requirements-compliance": compliance}


def test_catalog_yields_a_compliance_fragment_the_trace_emitter_accepts(catalog_workspace, tmp_path):
    jobs = FakeJobs(_with_compliance(catalog_workspace, COMPLIANCE))

    receipts = stage2.render(jobs, catalog_workspace)

    fragment = (catalog_workspace / ".fragments" / "requirements-compliance.md").read_text(encoding="utf-8")
    assert "| SEC-001: Parameterized queries | ❌ FAIL | MUST |" in fragment and "[F-001](#f-001)" in fragment
    assert [c["selector"] for c in jobs.calls] == [
        "stage2:management-summary",
        "stage2:requirements-compliance",
        "stage2:security-architecture",
    ]
    assert all(c["allowed_sources"] == frozenset() for c in jobs.calls)
    assert "requirements compliance assessed 2" in receipts[1]
    # The emitter's own parse; its final whole-model schema check needs a complete
    # model, which this minimal fixture deliberately is not.
    staging = tmp_path / "staging"
    shutil.copytree(catalog_workspace, staging)
    compliance = build_requirements_compliance(staging, strict=True)
    assert {r["id"]: r["status"] for r in compliance["requirements"]} == {"SEC-001": "FAIL", "SEC-002": "UNVERIFIABLE"}
    assert compliance["requirements"][0]["finding_ids"] == ["F-001"]
    emit_trace.build_trace(staging, yaml.safe_load((staging / "threat-model.yaml").read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    "row",
    [
        {"status": "MAYBE"},
        {"id": "SEC-999"},
        {"id": "SEC-001"},
        {"evidence": "The login lookup is broken, see F-001."},
        {"finding_ids": ["F-001"]},
        {"evidence": "Injected | column"},
    ],
    ids=["invalid-status", "unknown-id", "repeated-id", "inline-finding", "unlinked-finding", "pipe"],
)
def test_invalid_compliance_is_rejected_and_not_written(catalog_workspace, row):
    compliance = copy.deepcopy(COMPLIANCE)
    compliance["rows"][1].update(row)

    with pytest.raises(ExchangeError):
        stage2.render(FakeJobs(_with_compliance(catalog_workspace, compliance)), catalog_workspace)
    assert not (catalog_workspace / ".fragments" / "requirements-compliance.md").exists()


@pytest.mark.parametrize("catalog", [None, "source: skipped\ncategories: []\n"], ids=["absent", "skipped-stub"])
def test_no_configured_catalog_authors_no_compliance(workspace, catalog):
    if catalog is not None:
        (workspace / ".requirements.yaml").write_text(catalog, encoding="utf-8")
    jobs = FakeJobs(_replies(workspace))

    stage2.render(jobs, workspace)

    assert "stage2:requirements-compliance" not in [c["selector"] for c in jobs.calls]
    assert not (workspace / ".fragments" / "requirements-compliance.md").exists()


def test_the_management_summary_request_carries_no_volatile_model_hash(workspace):
    # A resumed run must send the same request so the accepted job is replayed.
    jobs = FakeJobs(_replies(workspace))
    stage2.render(jobs, workspace)
    digest = next(c for c in jobs.calls if c["selector"] == "stage2:management-summary")["context"]["digest"]
    assert "source_sha256" not in digest and digest


def test_a_diagram_placeholder_names_its_exact_format_in_context_and_rejection(workspace):
    rows = stage2.placeholders((workspace / ".fragments" / "security-architecture.md").read_text(encoding="utf-8"))
    diagram = next(row for row in rows if row["mermaid"] and not row["optional"])
    jobs = FakeJobs(_replies(workspace))
    stage2.render(jobs, workspace)
    context = next(c for c in jobs.calls if c["selector"] == "stage2:security-architecture")["context"]
    listed = next(row for row in context["placeholders"] if row["id"] == diagram["id"])
    assert listed["format"] == stage2.MERMAID_FORMAT
    with pytest.raises(ExchangeError, match="exact form"):
        stage2._check_fill(diagram, "The flow is shown below.")
