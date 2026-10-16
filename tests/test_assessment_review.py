"""Combined-assessment abuse-case verification and architect review run as scoped, validated jobs."""

import contextlib
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import analyzers.architect_review_runtime as runtime
import pytest
import yaml
from jsonschema import Draft202012Validator
from orchestrator import assessment_review as review
from orchestrator.assessment_workspace import Namespaces
from runtime.assessment_host import ExchangeError

from tests.test_architect_review import finding, merged
from tests.test_architect_review_runtime import answer, model_for

ROOT = Path(__file__).resolve().parents[1]
EDGE, SERVICE = "repo-" + "a" * 16, "repo-" + "b" * 16
SINK = "    return eval(request.args['expr'])"
EDGE_APP = "\n".join([f"# line {n}" for n in range(1, 17)] + [SINK, "# end"]) + "\n"


class Scope:
    """The admitted-scope surface the review stages use."""

    def __init__(self, files):
        self.repositories = [SimpleNamespace(repository_id=rid, files=rows) for rid, rows in files.items()]
        labels = {EDGE: "edge", SERVICE: "service"}
        self.rows = [{"repository_id": rid, "label": labels[rid]} for rid in files]

    def inventory(self):
        return {"repositories": self.rows, "scope_sha256": "f" * 64}

    @contextlib.contextmanager
    def scanner_snapshot(self, repository_id):
        repo = next(r for r in self.repositories if r.repository_id == repository_id)
        with tempfile.TemporaryDirectory() as root:
            for path, data in repo.files.items():
                target = Path(root, path)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            yield Path(root)


class Jobs:
    """Contract-checking job runner: validates the artifact, then the caller's source rules."""

    def __init__(self, respond):
        self.respond = respond
        self.calls = []

    def execute(self, *, role, selector, instructions, context, schema, allowed_sources, validate, on_failure=None):
        self.calls.append({"role": role, "selector": selector, "allowed": allowed_sources, "context": context})
        artifact, ranges = self.respond(role, context)
        if not Draft202012Validator(schema).is_valid(artifact):
            raise ExchangeError("Assessment job artifact violates its output contract")
        validate(artifact, ranges)
        return artifact


def served(rid, path, start, end, text=""):
    return {
        "repository_id": rid,
        "path": path,
        "start_line": start,
        "end_line": end,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


def instructions(role, adaptation):
    return f"{role}: {adaptation}"


# --------------------------------------------------------------------------- abuse cases

CASE = "AC-T-901"


def _matches(workspace: Path) -> None:
    step = {
        "step": 1,
        "label": "Expression input reaches evaluation",
        "grants": "code_execution",
        "description": "Attacker input reaches an evaluation sink.",
        "probe": {"sink_patterns": ["eval\\("]},
        "finding": {
            "title": "Untrusted expression reaches dynamic evaluation",
            "cwe": "CWE-95",
            "stride": "Elevation of Privilege",
            "severity": "High",
            "mitigation_title": "Remove dynamic expression evaluation",
            "remediation": "Parse expressions with a fixed grammar instead of evaluating them.",
        },
    }
    match = {
        "abuse_case_id": CASE,
        "title": "Expression evaluation leads to code execution",
        "structural_verdict": "candidate",
        "case": {
            "id": CASE,
            "source": "library",
            "attacker": {"actor_id": "external-user", "initial_access": "unauthenticated"},
            "goal": "Execute code on the server",
            "chain": [step],
        },
        "step_matches": [
            {
                "step": 1,
                "label": step["label"],
                "grants": step["grants"],
                "matched": False,
                "matched_finding_id": None,
                "match_basis": "source_probe",
                "evidence": {"file": "edge/app.py", "line": 17, "excerpt": SINK.strip()},
            }
        ],
        "matched_finding_ids": [],
    }
    (workspace / ".abuse-case-matches.json").write_text(json.dumps({"schema_version": 1, "matches": [match]}))


@pytest.fixture
def abuse(tmp_path):
    scope = Scope({EDGE: {"app.py": EDGE_APP.encode()}, SERVICE: {"main.py": b"print('ok')\n"}})
    root, workspace = tmp_path / "root", tmp_path / "workspace"
    (root / "edge").mkdir(parents=True)
    (root / "edge/app.py").write_text(EDGE_APP)
    (root / "service").mkdir()
    (root / "service/main.py").write_text("print('ok')\n")
    workspace.mkdir()
    cfg = {"repo_root": str(root), "output_dir": str(workspace), "mode": "full", "assessment_depth": "standard"}
    (workspace / ".skill-config.json").write_text(json.dumps(cfg))
    (workspace / ".threats-merged.json").write_text(
        json.dumps(
            {
                "version": 1,
                "generated_at": "2026-10-10T00:00:00Z",
                "threats": [{"t_id": "T-001", "title": "Existing finding"}],
            }
        )
    )
    sources = [{"label": "edge", "head": "0" * 40, "dirty": False}]
    (workspace / "threat-model.yaml").write_text(yaml.safe_dump({"meta": {"source_repositories": sources}}))
    return SimpleNamespace(scope=scope, names=Namespaces(scope), root=root, workspace=workspace, cfg=cfg, calls=[])


def _run_script(ctx, candidates=(CASE,)):
    """Real deterministic Stage-1d scripts; the matcher and model build are replaced by fixtures."""
    real = {
        "contexts/build_abuse_case_contexts.py",
        "validators/verify_abuse_cases.py",
        "model/promote_verified_abuse_cases.py",
        "validators/abuse_case_gate.py",
    }

    def run(name, args, acceptable=(0,)):
        ctx.calls.append((name, args[0]))
        if name == "model/match_abuse_cases.py" and args[0] == "match":
            _matches(ctx.workspace)
        elif name == "model/match_abuse_cases.py" and args[0] == "list-candidates":
            return subprocess.CompletedProcess(args, 0, "\n".join(candidates) + "\n", "")
        elif name == "model/build_threat_model_yaml.py":
            (ctx.workspace / "threat-model.yaml").write_text(yaml.safe_dump({"meta": {}, "threats": []}))
        elif name in real or (name == "model/match_abuse_cases.py" and args[0] == "finalize"):
            done = subprocess.run([sys.executable, str(ROOT / "scripts" / name), *args], text=True, capture_output=True)
            assert done.returncode in acceptable, done.stderr
            return done
        return subprocess.CompletedProcess(args, 0, "", "")

    return run


def _verifier(evidence_line=17, read=(10, 20)):
    def respond(role, context):
        assert role == "abuse_case_verifier"
        verdict = {
            "abuse_case_id": CASE,
            "step_verdicts": [
                {
                    "step": 1,
                    "verdict": "confirmed",
                    "state": "decided",
                    "matched_finding_id": None,
                    "reason": "the expression parameter reaches eval without validation",
                    "evidence": {
                        "repository_id": EDGE,
                        "file": "app.py",
                        "line": evidence_line,
                        "excerpt": SINK.strip(),
                    },
                    "controls_found": [],
                }
            ],
        }
        return verdict, [served(EDGE, "app.py", *read, EDGE_APP)]

    return respond


def _abuse(ctx, jobs, **kwargs):
    return review.run_abuse_cases(
        ctx.scope,
        jobs,
        ctx.names,
        ctx.workspace,
        ctx.root,
        {**ctx.cfg, **kwargs.pop("cfg", {})},
        instructions=instructions,
        run_script=kwargs.pop("run_script", None) or _run_script(ctx),
        rebuild=lambda: ctx.calls.append(("rebuild", "")),
        progress=lambda text: None,
    )


def test_a_verified_case_is_promoted_with_its_namespaced_evidence_and_the_gate_passes(abuse):
    jobs = Jobs(_verifier())
    receipts = _abuse(abuse, jobs)

    assert jobs.calls[0]["allowed"] == frozenset({(EDGE, "app.py")})
    assert {"repository_id": EDGE, "path": "app.py", "workspace_path": "edge/app.py"} in jobs.calls[0]["context"][
        "sources"
    ]
    verdict = json.loads((abuse.workspace / f".abuse-case-verdict-{CASE}.json").read_text())
    assert verdict["step_verdicts"][0]["evidence"] == {"file": "edge/app.py", "line": 17, "excerpt": SINK.strip()}
    promoted = json.loads((abuse.workspace / ".threats-merged.json").read_text())["threats"][-1]
    assert promoted["abuse_case_id"] == CASE
    assert promoted["evidence_check"] == "verified"
    names = [name for name, _ in abuse.calls]
    order = [
        "rebuild",
        "model/triage_compute_ranking.py",
        "renderers/render_abuse_cases.py",
        "validators/abuse_case_gate.py",
    ]
    assert [names.index(name) for name in order] == sorted(names.index(name) for name in order)
    # The controller's own build is the rebuild; a second builder here dropped its meta (RB-6).
    assert "model/build_threat_model_yaml.py" not in names and names.count("rebuild") == 1
    model = yaml.safe_load((abuse.workspace / "threat-model.yaml").read_text())
    assert model["meta"]["source_repositories"][0]["label"] == "edge"
    assert "Canonical abuse-case analysis persisted" in receipts


def test_each_verified_case_is_reported_with_its_title_and_position(abuse):
    shown = []
    review.run_abuse_cases(
        abuse.scope,
        Jobs(_verifier()),
        abuse.names,
        abuse.workspace,
        abuse.root,
        abuse.cfg,
        instructions=instructions,
        run_script=_run_script(abuse),
        rebuild=lambda: None,
        progress=shown.append,
    )
    assert f"Verifying abuse case: {CASE} — Expression evaluation leads to code execution (1/1)" in shown
    # The numbered steps count the checked cases; no second count as a phase result.
    assert not any(text.startswith("Phase result: Abuse cases") for text in shown)


@pytest.mark.parametrize("read", [(1, 5), (17, 17)], ids=["unread-line", "read-line"])
def test_a_verdict_must_cite_a_line_its_job_read(abuse, read):
    jobs = Jobs(_verifier(read=read))
    if read == (1, 5):
        with pytest.raises(ExchangeError, match="not retrieved"):
            _abuse(abuse, jobs)
        assert not (abuse.workspace / f".abuse-case-verdict-{CASE}.json").exists()
    else:
        _abuse(abuse, jobs)
        assert (abuse.workspace / f".abuse-case-verdict-{CASE}.json").is_file()


def test_a_verdict_reading_another_repository_is_rejected(abuse):
    def respond(role, context):
        verdict, _ = _verifier()(role, context)
        return verdict, [served(EDGE, "app.py", 10, 20), served(SERVICE, "main.py", 1, 1)]

    with pytest.raises(ExchangeError, match="outside its authorization"):
        _abuse(abuse, Jobs(respond))


def test_more_candidates_than_the_fan_out_bound_stop_before_any_job(abuse):
    jobs = Jobs(_verifier())
    many = [f"AC-T-{n:03d}" for n in range(1, review.MAX_CANDIDATES + 2)]
    with pytest.raises(review.AssessmentReviewError, match="maximum is 64"):
        _abuse(abuse, jobs, run_script=_run_script(abuse, many))
    assert jobs.calls == []


def test_thorough_depth_derives_cases_once_without_source_access(abuse):
    verifier = _verifier()

    def respond(role, context):
        if role == "abuse_case_deriver":
            return {
                "cases": [
                    {
                        "title": "Refund an order twice",
                        "check": "Check whether an order can be refunded twice.",
                        "path_patterns": ["**/refund*"],
                    }
                ]
            }, []
        return verifier(role, context)

    jobs = Jobs(respond)
    receipts = _abuse(abuse, jobs, cfg={"assessment_depth": "thorough"})

    assert jobs.calls[0]["role"] == "abuse_case_deriver" and jobs.calls[0]["allowed"] == frozenset()
    record = json.loads((abuse.workspace / ".abuse-case-derivation.json").read_text())
    assert record["admitted"] == ["MODEL-AC-001"]
    assert receipts[0].startswith("derived business cases admitted: 1")


def test_disabled_verification_runs_nothing(abuse):
    def forbidden(*args, **kwargs):
        raise AssertionError("no Stage-1d script runs when verification is disabled")

    receipts = _abuse(abuse, Jobs(_verifier()), cfg={"skip_abuse_case_verification": True}, run_script=forbidden)
    assert receipts == ["Abuse verification disabled"]


@pytest.mark.parametrize(
    "label_path",
    [(SERVICE, "docs/security/abuse-cases/refunds.yaml"), (SERVICE, ".appsec/abuse-cases/refunds.yml")],
)
def test_repository_case_files_are_rejected_rather_than_misattributed(abuse, label_path):
    rid, path = label_path
    abuse.scope.repositories[1].files[path] = b"cases: []\n"
    with pytest.raises(review.AssessmentReviewError, match=f"service:{path}"):
        _abuse(abuse, Jobs(_verifier()))


@pytest.mark.parametrize("path", ["docs/security/abuse-cases/refunds.yaml", ".appsec/abuse-cases/refunds.yml"])
def test_a_sole_repository_keeps_its_case_files_as_a_single_scan_does(path):
    """Its files sit at the combined root itself, so the resolver attributes them correctly."""
    sole = Scope({SERVICE: {path: b"cases: []\n"}})
    review.reject_repository_case_files(sole, Namespaces(sole), {})
    review.reject_repository_case_files(sole, Namespaces(sole), {"abuse_case_files": [path]})
    pair = Scope({EDGE: {"app.py": b"x\n"}, SERVICE: {path: b"cases: []\n"}})
    with pytest.raises(review.AssessmentReviewError, match="per-scan"):
        review.reject_repository_case_files(pair, Namespaces(pair), {"abuse_case_files": [path]})
    with pytest.raises(review.AssessmentReviewError, match=f"service:{path}"):
        review.reject_repository_case_files(pair, Namespaces(pair), {})


def test_a_repository_labelled_docs_cannot_inject_combined_root_cases():
    scope = Scope({EDGE: {"security/abuse-cases/x.yaml": b""}, SERVICE: {"security/abuse-cases/notes.md": b""}})
    scope.rows[0]["label"] = "docs"
    with pytest.raises(review.AssessmentReviewError, match="docs:security/abuse-cases/x.yaml"):
        review.reject_repository_case_files(scope, Namespaces(scope), {})
    # The same file under any other label is neither loaded nor rejected.
    other = Scope({SERVICE: {"security/abuse-cases/x.yaml": b""}})
    review.reject_repository_case_files(other, Namespaces(other), {})


# --------------------------------------------------------------------------- architect review


@pytest.fixture
def architect(tmp_path):
    scope = Scope({EDGE: {"routes/orders.py": b"x\n"}, SERVICE: {"lib/records.rs": b"y\n"}})
    cfg = {"run_id": "combined-run", "architect_review": True, "architect_model": "sonnet", "mode": "full"}
    source = merged(finding("T-001", "gateway", "edge/routes/orders.py"))
    components = {
        "schema_version": 1,
        "components": [
            {"id": "gateway", "name": "Gateway [edge]", "paths": ["edge/routes/orders.py"]},
            {"id": "records", "name": "Records [service]", "paths": ["service/lib/records.rs"]},
        ],
    }
    for name, value in (
        (".skill-config.json", cfg),
        (".threats-merged.json", source),
        (".components.json", components),
    ):
        (tmp_path / name).write_text(json.dumps(value))
    return SimpleNamespace(scope=scope, names=Namespaces(scope), workspace=tmp_path, cfg=cfg, source=source)


def _reviewer(reads):
    def respond(role, context):
        assert role == "architect_reviewer"
        proposals = {packet["packet_id"]: answer(packet) for packet in context["packets"]}
        return {"schema_version": 1, "job_id": context["job_id"], "proposals": proposals}, reads

    return respond


def _architect(ctx, jobs, scripts=None):
    return review.run_architect_review(
        ctx.scope,
        jobs,
        ctx.names,
        ctx.workspace,
        ctx.cfg,
        instructions=instructions,
        run_script=lambda name, args, **kw: (scripts if scripts is not None else []).append(name),
        progress=lambda text: None,
    )


def test_an_architect_correction_is_applied_and_preserved_downstream(architect):
    jobs = Jobs(_reviewer([served(EDGE, "routes/orders.py", 1, 1)]))
    scripts = []
    receipts = _architect(architect, jobs, scripts)

    assert [call["allowed"] for call in jobs.calls] == [frozenset({(EDGE, "routes/orders.py")})]
    assert receipts[0].startswith("architect review")
    assert scripts == ["validators/validate_intermediate.py"]
    snapshot = json.loads((architect.workspace / ".threats-merged.json").read_text())
    assert snapshot["threats"][0]["risk"] == "High"
    assert architect.source["threats"][0]["risk"] == "Medium"
    saved = runtime.load_review(architect.workspace)
    model = runtime.project_model(architect.workspace, model_for(snapshot), snapshot)
    assert runtime.verify_model(architect.workspace, model) == saved
    # A repeated call replays the completed transaction without another job.
    _architect(architect, jobs)
    assert len(jobs.calls) == 1


def test_a_promoted_abuse_finding_is_reviewed_before_rebuild_and_ranking(abuse):
    from tests.test_architect_review_runtime import review as initial_review

    abuse.cfg.update(architect_review=True, run_id="promoted-case-review", architect_model="sonnet")
    workspace = abuse.workspace
    (workspace / ".skill-config.json").write_text(json.dumps(abuse.cfg))
    (workspace / ".stride-analyst-context.json").write_text("{}")
    (workspace / ".threats-merged.json").write_text(json.dumps(merged(finding(filename="edge/app.py"))))
    (workspace / ".components.json").write_text(
        json.dumps(
            {
                "components": [
                    {"id": "gateway", "name": "Gateway", "paths": ["edge/app.py"]},
                ]
            }
        )
    )
    initial = initial_review(workspace, abuse.cfg)
    model = yaml.safe_load((workspace / "threat-model.yaml").read_text())
    model["components"] = [{"id": "gateway", "name": "Gateway", "paths": ["edge/app.py"]}]
    (workspace / "threat-model.yaml").write_text(yaml.safe_dump(model))
    order = []

    def respond(role, context):
        order.append(role)
        if role == "abuse_case_verifier":
            return _verifier()(role, context)
        assert role == "architect_reviewer"
        packets = context["packets"]
        assert [row["finding"]["t_id"] for packet in packets for row in packet["findings"]] == ["T-002"]
        proposals = {}
        for packet in packets:
            proposal = answer(packet)
            for row in proposal["decisions"]:
                row.update(assessment="unchanged")
                row.pop("rating")
                row["fix"]["operation"] = "add"
                row["fix"]["value"].update(
                    title="Replace expression evaluation with a fixed grammar",
                    steps=[
                        "Parse expressions using the fixed grammar.",
                        "Reject unsupported operations before evaluation.",
                    ],
                    verification="Code-bearing expressions are rejected; supported arithmetic still succeeds.",
                )
            proposals[packet["packet_id"]] = proposal
        return {"schema_version": 1, "job_id": context["job_id"], "proposals": proposals}, []

    real = _run_script(abuse)

    def run(name, args, **kw):
        order.append(name)
        return real(name, args, **kw)

    _abuse(abuse, Jobs(respond), run_script=run)
    current = json.loads((workspace / ".threats-merged.json").read_text())
    assert current["threats"][0] == initial["snapshot"]["threats"][0]
    assert current["threats"][1]["remediation"]["steps"][0].startswith("Parse expressions")
    model = runtime.project_model(workspace, model_for(current), current)
    assert runtime.verify_model(workspace, model)
    expected = ["model/promote_verified_abuse_cases.py", "architect_reviewer", "model/triage_compute_ranking.py"]
    assert [order.index(name) for name in expected] == sorted(order.index(name) for name in expected)
    assert runtime.review_coverage(runtime.load_review(workspace))["reviewed"] == 2


def test_a_reviewer_reading_another_components_file_is_rejected(architect):
    jobs = Jobs(_reviewer([served(SERVICE, "lib/records.rs", 1, 1)]))
    with pytest.raises(ExchangeError, match="outside its component"):
        _architect(architect, jobs)
    assert not (architect.workspace / ".dispatch-context/architect/gateway.proposals.json").exists()


def test_disabled_architect_review_dispatches_nothing(architect):
    jobs = Jobs(_reviewer([]))
    architect.cfg["architect_review"] = False
    assert _architect(architect, jobs) == ["Architect review disabled"]
    assert jobs.calls == []
    assert not (architect.workspace / ".architect-review.json").exists()


@pytest.mark.parametrize("given", ["release/cases.yaml", "ABSOLUTE"])
def test_a_sole_repository_per_scan_case_file_is_read_below_the_assessment_root(tmp_path, given):
    """The matcher reads below the controller's copy, so the path becomes repository-relative."""
    checkout = tmp_path / "service"
    sole = Scope({SERVICE: {"release/cases.yaml": b"cases: []\n"}})
    sole.repositories[0].root = checkout
    raw = str(checkout / "release/cases.yaml") if given == "ABSOLUTE" else given
    assert review.scan_case_files(sole, Namespaces(sole), [raw]) == ["release/cases.yaml"]


@pytest.mark.parametrize("raw", ["../outside.yaml", "release/missing.yaml", "/etc/cases.yaml"])
def test_a_per_scan_case_file_outside_the_admitted_repository_is_refused(tmp_path, raw):
    sole = Scope({SERVICE: {"release/cases.yaml": b"cases: []\n"}})
    sole.repositories[0].root = tmp_path / "service"
    with pytest.raises(review.AssessmentReviewError, match="outside the selected repository|not an admitted file"):
        review.scan_case_files(sole, Namespaces(sole), [raw])


TEAM_CASES = """schema_version: 2
abuse_cases:
- id: REPO-AC-901
  kind: descriptive
  title: Customer refunds an order twice
  check: Check whether a customer can receive a refund for the same order more than once.
  scope_qualifier:
    path_patterns: ['*export*']
"""


def test_a_sole_repository_selects_shipped_business_and_per_scan_cases_with_the_real_matcher(tmp_path):
    """The controller's own matcher call: shipped business cases and the run's case file become candidates."""
    files = {
        "routes/export.js": b"module.exports = (req, res) => res.json(store.all(req.query.account))\n",
        "release/cases.yaml": TEAM_CASES.encode(),
    }
    scope = Scope({SERVICE: files})
    scope.repositories[0].root = tmp_path / "checkout"
    names = Namespaces(scope)
    root, workspace = tmp_path / "root", tmp_path / "workspace"
    for path, data in files.items():
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_bytes(data)
    workspace.mkdir()
    case_files = review.scan_case_files(scope, names, [str(scope.repositories[0].root / "release/cases.yaml")])
    cfg = {"repo_root": str(root), "output_dir": str(workspace), "mode": "full", "assessment_depth": "standard"}
    (workspace / ".skill-config.json").write_text(json.dumps({**cfg, "abuse_case_files": case_files}))
    components = [{"id": "api", "name": "API", "tier": "application", "paths": ["routes/export.js"]}]
    (workspace / ".components.json").write_text(json.dumps({"schema_version": 1, "components": components}))
    (workspace / ".threats-merged.json").write_text(json.dumps({"version": 1, "threats": []}))
    keys = ["has_auth_surface", "has_public_routes"]
    (workspace / ".recon-signals.json").write_text(
        json.dumps({"schema_version": 2, "signals": dict.fromkeys(keys, True), "component_hints": []})
    )
    listed = []

    class Stop(Exception):
        pass

    def run(name, args, acceptable=(0,)):
        if name != "model/match_abuse_cases.py":
            raise Stop(name)
        done = subprocess.run([sys.executable, str(ROOT / "scripts" / name), *args], text=True, capture_output=True)
        assert done.returncode in acceptable, done.stderr
        if args[0] == "list-candidates":
            listed.extend(done.stdout.split())
        return done

    with pytest.raises(Stop):
        review.run_abuse_cases(
            scope,
            None,
            names,
            workspace,
            root,
            {**cfg, "abuse_case_files": case_files},
            instructions=instructions,
            run_script=run,
            rebuild=lambda: None,
            progress=lambda text: None,
        )
    assert "AC-B-001" in listed and "REPO-AC-901" in listed


def test_a_matcher_configuration_error_stops_the_run_instead_of_matching_nothing(abuse):
    """An org-profile or catalog error writes no matches; it must not read as "none matched"."""
    real = _run_script(abuse)

    def run(name, args, acceptable=(0,)):
        if name == "model/match_abuse_cases.py" and args[0] == "match":
            return subprocess.CompletedProcess(args, 1, "", "org profile: abuse_cases must be a mapping")
        return real(name, args, acceptable)

    with pytest.raises(review.AssessmentReviewError, match="org profile"):
        _abuse(abuse, Jobs(_verifier()), run_script=run)
