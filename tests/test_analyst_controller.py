"""End-to-end controller behavior of the on-demand threat analysis.

Only the model transport is replaced by a test double; snapshot capture, path
guards, schemas, response validation, state, and publication run for real.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from contexts.resolve_analyst_catalog import Selection  # noqa: E402
from orchestrator import analyst_controller as ctl  # noqa: E402
from runtime import analyst_state as st  # noqa: E402
from runtime.analyst_host import HostCancelled, HostReply, TransportError  # noqa: E402

GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
BASE_CODE = "app.get('/export/:id', requireSupport, (req, res) => {\n  res.json(db.metadata(req.params.id));\n});\n"
CHANGED_CODE = "app.get('/export/:id', (req, res) => {\n  res.json(db.customer(req.params.id));\n});\n"


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env={**os.environ, **GIT_ENV})


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    (repo / "export.js").write_text(BASE_CODE)
    (repo / "auth.js").write_text("module.exports.requireSupport = (req, res, next) => next();\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    (repo / "export.js").write_text(CHANGED_CODE)
    return repo


@pytest.fixture
def state_root(tmp_path: Path) -> Path:
    return tmp_path / "state"


def envelope(prompt: str) -> dict:
    start = prompt.index("<<<UNTRUSTED_ANALYSIS_INPUT\n") + len("<<<UNTRUSTED_ANALYSIS_INPUT\n")
    return json.loads(prompt[start : prompt.index("\nUNTRUSTED_ANALYSIS_INPUT>>>")])


def response(prompt: str, **overrides) -> dict:
    data = envelope(prompt)
    reply = {
        "summary": "The export endpoint lost its support-role check.",
        "findings": [],
        "scenarios": [],
        "assumptions": [],
        "requirement_observations": [],
        "methodology_observations": [],
        "question_coverage": [
            {"question_ref": q["ref"], "status": "not_applicable", "note": "Not relevant."} for q in data["questions"]
        ],
        "questions": [],
        "evidence_requests": [],
        "limitations": [],
    }
    reply.update(overrides)
    if "question_coverage" not in overrides:
        asked = {q.get("question_ref") for q in reply["questions"]}
        for entry in reply["question_coverage"]:
            if entry["question_ref"] in asked:
                entry.update(status="needs_answer", note="The scope needs clarification.")
    return reply


def removed_check_finding(**overrides) -> dict:
    finding = {
        "title": "Export no longer requires the support role",
        "explanation": "The route dropped requireSupport and now returns full customer records.",
        "severity": "high",
        "change_relationship": "worsened",
        "evidence": [
            {
                "side": "proposed",
                "path": "export.js",
                "line_start": 1,
                "line_end": 1,
                "excerpt": "app.get('/export/:id', (req, res) => {",
            }
        ],
        "comparison": [
            {
                "side": "baseline",
                "path": "export.js",
                "line_start": 1,
                "line_end": 1,
                "excerpt": "app.get('/export/:id', requireSupport, (req, res) => {",
            },
            {
                "side": "proposed",
                "path": "export.js",
                "line_start": 2,
                "line_end": 2,
                "excerpt": "res.json(db.customer(req.params.id));",
            },
        ],
        "next_action": "Restore requireSupport and add a test that a non-support user is refused.",
    }
    finding.update(overrides)
    return finding


class Fake:
    """Transport double: each step maps the prompt to a payload or raises."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.prompts: list[str] = []

    def __call__(self, job, request):
        return self

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        self.prompts.append(prompt)
        assert "untrusted data" in prompt and system
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return HostReply(step(prompt, should_stop) if step.__code__.co_argcount == 2 else step(prompt), 0.01)


def review(repo: Path, state_root: Path, **kwargs) -> ctl.Invocation:
    kwargs.setdefault("env", {})
    return ctl.Invocation(mode="review", scope={"kind": "worktree"}, repo_root=repo, state_root=state_root, **kwargs)


def job_root(state_root: Path, repo: Path, job_id: str) -> Path:
    return st.job_path(job_id, repo, state_root)


def test_complete_review_publishes_a_validated_result(repo, state_root, tmp_path):
    fake = Fake(lambda p: response(p, findings=[removed_check_finding()]))
    out = tmp_path / "out"
    outcome = ctl.run(review(repo, state_root, output_dir=out), fake)
    assert (outcome.exit_code, outcome.state) == (0, "complete")
    result = json.loads((out / "analyst-result.json").read_text())
    assert result["findings"][0]["id"] == "f-001"
    assert result["findings"][0]["change_relationship"] == "worsened"
    assert "not a security approval" in (out / "analyst-result.md").read_text()
    root = job_root(state_root, repo, outcome.job_id)
    assert not (root / "source").exists()
    assert st.read_artifact(root, "state.json")["state"] == "complete"
    files = {f["path"] for f in envelope(fake.prompts[0])["files"]}
    assert files == {"export.js"}


@pytest.mark.parametrize(
    "bad",
    [
        removed_check_finding(
            evidence=[
                {"side": "proposed", "path": "export.js", "line_start": 1, "line_end": 1, "excerpt": "eval(req.body)"}
            ]
        ),
        removed_check_finding(
            evidence=[{"side": "proposed", "path": "auth.js", "line_start": 1, "line_end": 1, "excerpt": "next()"}]
        ),
        removed_check_finding(comparison=[]),
        removed_check_finding(
            change_relationship="introduced",
            evidence=[
                {"side": "baseline", "path": "export.js", "line_start": 1, "line_end": 1, "excerpt": "requireSupport"}
            ],
            comparison=[],
        ),
    ],
    ids=[
        "fabricated-excerpt",
        "unadmitted-file",
        "worsened-without-comparison",
        "introduced-without-proposed-evidence",
    ],
)
def test_unsupported_claims_fail_validation_and_publish_nothing_from_the_reply(repo, state_root, bad):
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, findings=[bad])))
    assert (outcome.exit_code, outcome.state) == (2, "failed")
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert result["terminal_reason"] == "invalid_model_output"
    assert result["findings"] == [] and result["summary"] == ""


def test_injected_authority_fields_are_rejected(repo, state_root):
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, run_command="rm -rf /", completed=True)))
    assert outcome.state == "failed"


def test_unknown_relationship_needs_no_comparison(repo, state_root):
    finding = removed_check_finding(change_relationship="unknown", comparison=[])
    assert ctl.run(review(repo, state_root), Fake(lambda p: response(p, findings=[finding]))).state == "complete"


def test_design_requests_never_produce_findings(repo, state_root):
    inv = ctl.Invocation(
        mode="design",
        scope={"kind": "design", "source": "text"},
        repo_root=repo,
        state_root=state_root,
        design_text="Let support staff export customer data.",
    )
    scenario = {
        "title": "Cross-customer export",
        "description": "A support user exports any customer's data.",
        "next_action": "Bind exports to assigned customers.",
    }
    ok = ctl.run(inv, Fake(lambda p: response(p, scenarios=[scenario])))
    assert ok.state == "complete" and r"Cross\-customer export" in ok.report
    assert ctl.run(inv, Fake(lambda p: response(p, findings=[removed_check_finding()]))).state == "failed"


@pytest.mark.parametrize("mode", ["design", "review", "hypothesis"])
@pytest.mark.parametrize("package_id", ["example/requests", "example/reservations"])
def test_question_applicability_reaches_each_mode_without_expanding_scope(repo, state_root, tmp_path, mode, package_id):
    question = {
        "id": "independent-approval",
        "topic": "authorization",
        "applies_when": ["business_operation", "changed_permission"],
        "asks": "Where policy requires separate identities, can the creator approve the same request?",
        "purpose": "Self-approval bypasses an evidenced independent-approval requirement.",
        "evidence": ["applicable approval policy", "creator and approver identity binding"],
        "negative_tests": ["The creator cannot approve the same request where separation is required."],
    }
    path = tmp_path / "workflow-questions.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "kind": "questions",
                "id": package_id,
                "version": "1.0.0",
                "title": "Conditional approval investigation",
                "provenance": {"source": "Synthetic integration case", "revision": "1"},
                "questions": [question],
            }
        )
    )
    selection = [Selection(str(path), "explicit")]
    if mode == "design":
        inv = ctl.Invocation(
            mode="design",
            scope={"kind": "design", "source": "text"},
            repo_root=repo,
            state_root=state_root,
            env={},
            design_text="Design a request approval operation.",
            packages=selection,
        )
    elif mode == "hypothesis":
        inv = hypothesis(repo, state_root, packages=selection)
    else:
        inv = review(repo, state_root, packages=selection)

    def observe(prompt):
        data = envelope(prompt)
        delivered = next(q for q in data["questions"] if q["ref"] == f"{package_id}:{question['id']}")
        assert delivered == {
            "ref": f"{package_id}:{question['id']}",
            **{k: v for k, v in question.items() if k != "id"},
        }
        assert {f["path"] for f in data["files"]} == (set() if mode == "design" else {"export.js"})
        return hypothesis_response(prompt, "not_confirmed") if mode == "hypothesis" else response(prompt)

    assert ctl.run(inv, Fake(observe)).state == "complete"


def test_context_applicability_preserves_catalog_constraints_and_legacy_contexts():
    from validators.validate_analyst import _schema, schema_errors

    catalog = json.loads((ROOT / "schemas" / "analyst-catalog.schema.json").read_text())
    package_signals = catalog["properties"]["questions"]["items"]["properties"]["applies_when"]
    context_signals = _schema("context")["properties"]["questions"]["items"]["properties"]["applies_when"]
    assert context_signals == {k: v for k, v in package_signals.items() if k != "description"}
    legacy = {
        "schema_version": 1,
        "job_id": "aj-" + "a" * 32,
        "sources": [],
        "requirements": [],
        "business_context": None,
        "threat_model": None,
        "questions": [{"ref": "example/workflow:approval", "asks": "Can the creator approve?"}],
        "criteria": [],
        "question_selection": {"omitted": [], "required_complete": True},
    }
    assert schema_errors("context", legacy) == []


def test_an_empty_scope_completes_without_a_model_call(repo, state_root):
    (repo / "export.js").write_text(BASE_CODE)
    fake = Fake()
    outcome = ctl.run(review(repo, state_root), fake)
    assert (outcome.exit_code, outcome.state) == (0, "complete")
    assert fake.prompts == []
    assert (
        st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")["terminal_reason"] == "empty_scope"
    )


def test_transport_failures_are_retried_within_the_limit_then_fail(repo, state_root):
    fake = Fake(TransportError("down"), TransportError("down"))
    outcome = ctl.run(review(repo, state_root), fake)
    assert (outcome.exit_code, outcome.state) == (2, "failed")
    assert len(fake.prompts) == 2
    assert (
        st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")["terminal_reason"]
        == "transport_failure"
    )


def test_cancellation_stops_the_call_and_records_it(repo, state_root):
    def cancel(prompt, should_stop):
        root = next((state_root).rglob("aj-*"))
        st.request_cancel(root)
        assert should_stop()
        raise HostCancelled("job cancelled")

    outcome = ctl.run(review(repo, state_root), Fake(cancel))
    assert (outcome.exit_code, outcome.state) == (130, "cancelled")
    root = job_root(state_root, repo, outcome.job_id)
    assert not (root / "source").exists()


def test_evidence_requests_are_served_from_the_frozen_view(repo, state_root):
    fake = Fake(
        lambda p: response(
            p,
            evidence_requests=[{"path": "auth.js", "reason": "middleware"}],
        ),
        lambda p: response(p),
    )
    outcome = ctl.run(review(repo, state_root), fake)
    assert outcome.state == "complete"
    second = {f["path"]: f["change"] for f in envelope(fake.prompts[1])["files"] if f["side"] == "proposed"}
    assert second["auth.js"] == "context" and "missing.js" not in second
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert result["coverage"]["evidence_requests"][0]["status"] == "admitted"


def test_an_escaping_evidence_request_invalidates_the_reply(repo, state_root):
    fake = Fake(lambda p: response(p, evidence_requests=[{"path": "../outside", "reason": "escape"}]))
    outcome = ctl.run(review(repo, state_root), fake)
    assert outcome.state == "failed" and len(fake.prompts) == 1


def test_required_questions_checkpoint_interactively_and_resume_with_answers(repo, state_root, tmp_path):
    question = {
        "question_ref": "appsec/core:authz-scope",
        "asks": "Which customers may support staff export?",
        "why": "Decides whether the export is a cross-customer leak.",
        "affects": "export.js",
        "required": True,
    }
    fake = Fake(lambda p: response(p, questions=[question]), lambda p: response(p))
    first = ctl.run(review(repo, state_root), fake, interactive=True)
    assert (first.exit_code, first.state) == (0, "awaiting_answers")
    root = job_root(state_root, repo, first.job_id)
    assert (root / "source").exists()
    q = first.questions[0]

    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "job_id": first.job_id,
                "answers": [{"question_id": q["id"], "fingerprint": "0" * 64, "answer": "Only assigned customers."}],
            }
        )
    )
    rejected = ctl.answer(first.job_id, repo, bad, fake, state_root)
    assert rejected.state == "awaiting_answers" and "changed since it was asked" in rejected.report

    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {
                "job_id": first.job_id,
                "answers": [
                    {"question_id": q["id"], "fingerprint": q["fingerprint"], "answer": "Only assigned customers."}
                ],
            }
        )
    )
    feature = tmp_path / "customer-export.yaml"
    done = ctl.answer(first.job_id, repo, good, fake, state_root, save_feature=feature, feature_id="customer-export")
    assert (done.exit_code, done.state) == (0, "complete")
    assert envelope(fake.prompts[1])["answers"] == [{"asks": question["asks"], "answer": "Only assigned customers."}]
    assert not (root / "source").exists()

    reuse = Fake(lambda p: response(p))
    ctl.run(review(repo, state_root, feature_path=feature), reuse)
    assert envelope(reuse.prompts[0])["feature"]["answers"] == [
        {"asks": question["asks"], "answer": "Only assigned customers."}
    ]


def test_required_questions_leave_a_noninteractive_run_incomplete(repo, state_root):
    question = {"asks": "Who may export?", "why": "Scope of access.", "affects": "export.js", "required": True}
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, questions=[question])), interactive=False)
    assert (outcome.exit_code, outcome.state) == (2, "incomplete")
    assert "q-001" in outcome.report


def test_a_secret_in_model_output_withholds_the_result(repo, state_root):
    leak = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, summary=leak)))
    assert outcome.state == "failed"
    assert "wJalrXUtnFEMI" not in outcome.report
    assert "wJalrXUtnFEMI" not in json.dumps(
        st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    )


def test_a_missing_required_catalog_stops_before_any_model_call(repo, state_root, tmp_path):
    fake = Fake()
    outcome = ctl.run(
        review(repo, state_root, requirements_path=tmp_path / "missing.yaml", requirements_required=True), fake
    )
    assert (outcome.exit_code, outcome.state) == (2, "incomplete")
    assert fake.prompts == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"packages": [Selection("vendor/unknown@1.0.0", "explicit")]},
        {"packages": [Selection("tmm/threat-modeling-manifesto@1.0.0", "explicit")], "ci": True},
    ],
    ids=["unknown-package", "explicit-package-in-ci"],
)
def test_admission_failures_create_no_job(repo, state_root, kwargs):
    inv = review(repo, state_root, **kwargs)
    if kwargs.get("ci"):
        inv.scope = {"kind": "commits", "base": "HEAD", "head": "HEAD", "comparison": "exact"}
    outcome = ctl.run(inv, Fake())
    assert (outcome.exit_code, outcome.state, outcome.job_id) == (2, "rejected", None)
    assert not state_root.exists() or not list(state_root.rglob("aj-*"))


def test_output_into_assessment_state_is_rejected_before_a_job_exists(repo, state_root):
    assessment = repo / "tm-out"
    assessment.mkdir()
    (assessment / "threat-model.yaml").write_text("meta: {}\n")
    outcome = ctl.run(review(repo, state_root, output_dir=assessment), Fake())
    assert outcome.state == "rejected" and outcome.job_id is None


def test_selected_manifesto_profile_is_delivered_and_recorded(repo, state_root):
    def observe(prompt):
        criteria = envelope(prompt)["criteria"]
        assert criteria and all(c["ref"].startswith("tmm/threat-modeling-manifesto:") for c in criteria)
        return response(
            prompt,
            methodology_observations=[
                {"criterion_ref": criteria[0]["ref"], "observation": "Scope and trust boundaries are stated."}
            ],
        )

    outcome = ctl.run(
        review(repo, state_root, packages=[Selection("tmm/threat-modeling-manifesto@1.0.0", "explicit")]), Fake(observe)
    )
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert [p["id"] for p in result["packages"]] == ["appsec/core", "tmm/threat-modeling-manifesto"]
    assert result["packages"][1]["provenance"]["license"] == "CC BY 4.0"
    assert result["methodology_observations"]


def test_without_a_selected_profile_no_methodology_is_delivered(repo, state_root):
    fake = Fake(lambda p: response(p))
    ctl.run(review(repo, state_root), fake)
    assert envelope(fake.prompts[0])["criteria"] == []


def org_profile(tmp_path: Path, analyst: dict) -> dict:
    target = tmp_path / "org"
    shutil.copytree(ROOT / "tests" / "fixtures" / "org-profiles" / "acme", target)
    profile = yaml.safe_load((target / "org-profile.yaml").read_text())
    profile["analyst"] = analyst
    (target / "org-profile.yaml").write_text(yaml.safe_dump(profile))
    return {"APPSEC_ADVISOR_ORG_PROFILE": str(target / "org-profile.yaml")}


def test_organization_required_packages_apply_to_every_invoked_analysis(repo, state_root, tmp_path):
    env = org_profile(tmp_path, {"required_packages": [{"ref": "tmm/threat-modeling-manifesto@1.0.0"}]})
    catalog = tmp_path / "org-requirements.yaml"
    catalog.write_text(
        yaml.safe_dump({"categories": [{"id": "AC", "requirements": [{"id": "ORG-1", "text": "Authorize exports."}]}]})
    )
    fake = Fake(lambda p: response(p))
    outcome = ctl.run(review(repo, state_root, env=env, requirements_path=catalog), fake)
    assert envelope(fake.prompts[0])["criteria"]
    assert [r["id"] for r in envelope(fake.prompts[0])["requirements"]] == ["ORG-1"]
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert {p["id"]: p["authority"] for p in result["packages"]}["tmm/threat-modeling-manifesto"] == "org_required"


def test_an_organization_required_catalog_never_falls_back(repo, state_root, tmp_path):
    env = org_profile(tmp_path, {})
    fake = Fake()
    outcome = ctl.run(review(repo, state_root, env=env), fake)
    assert (outcome.exit_code, outcome.state) == (2, "incomplete")
    assert fake.prompts == [] and r"\-\-requirements" in outcome.report


def test_an_invalid_organization_profile_rejects_the_analysis(repo, state_root, tmp_path):
    env = org_profile(tmp_path, {"required_packages": [{"file": "../outside.yaml", "sha256": "0" * 64}]})
    outcome = ctl.run(review(repo, state_root, env=env), Fake())
    assert (outcome.state, outcome.job_id) == ("rejected", None)
    assert "organization profile is invalid" in outcome.report


def test_configuring_the_organization_profile_starts_nothing(tmp_path):
    env = org_profile(tmp_path, {"default_packages": [{"ref": "tmm/threat-modeling-manifesto@1.0.0"}]})
    state = tmp_path / "xdg"
    subprocess.run(
        [sys.executable, "-c", "import orchestrator.analyst_controller"],
        cwd=ROOT / "scripts",
        env={**os.environ, **env, "XDG_STATE_HOME": str(state)},
        check=True,
    )
    assert not state.exists()


class Clock:
    """Monotonic clock the test can advance."""

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def pending_question_run(repo, state_root, fake, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(ctl.time, "monotonic", clock)
    question = {"asks": "Who may export?", "why": "Scope of access.", "affects": "export.js", "required": True}
    fake.steps.insert(0, lambda p: response(p, questions=[question]))
    first = ctl.run(review(repo, state_root), fake, interactive=True)
    assert first.state == "awaiting_answers"
    return first, clock


def test_answers_after_the_first_pass_budget_still_complete(repo, state_root, monkeypatch):
    fake = Fake(lambda p: response(p))
    first, clock = pending_question_run(repo, state_root, fake, monkeypatch)
    clock.now += 4 * 3600
    done = ctl.answer(first.job_id, repo, None, fake, state_root, inline_answers={"q-001": "Assigned customers only."})
    assert (done.exit_code, done.state) == (0, "complete")


def test_abandoned_jobs_are_closed_by_the_next_invocation(repo, state_root):
    crashed = st.create_job(repo.resolve(), state_root)
    st.transition(
        crashed,
        ctl._state(
            crashed,
            "prepared",
            "a" * 64,
            {"host_calls": 0, "evidence_rounds": 0, "question_rounds": 0, "transport_retries": 0},
        ),
    )
    (crashed.root / "source").mkdir()
    st.release(crashed)
    ctl.run(review(repo, state_root), Fake(lambda p: response(p)))
    closed = st.read_artifact(crashed.root, "state.json")
    assert (closed["state"], closed["terminal_reason"]) == ("cancelled", "terminated")
    assert not (crashed.root / "source").exists()


def test_cancel_closes_a_job_waiting_for_answers(repo, state_root, monkeypatch):
    first, _ = pending_question_run(repo, state_root, Fake(), monkeypatch)
    outcome = ctl.cancel(first.job_id, repo, state_root)
    assert (outcome.exit_code, outcome.state) == (130, "cancelled")
    root = job_root(state_root, repo, first.job_id)
    assert not (root / "source").exists()
    assert ctl.answer(first.job_id, repo, None, Fake(), state_root, inline_answers={"q-001": "x"}).state == "rejected"


@pytest.mark.parametrize(
    ("raised", "state", "code"),
    [
        (RuntimeError("boom"), "failed", 2),
        (ctl.Terminated(), "cancelled", 130),
        (KeyboardInterrupt(), "cancelled", 130),
    ],
    ids=["unexpected-error", "sigterm", "sigint"],
)
def test_errors_and_signals_always_end_in_a_terminal_state(repo, state_root, raised, state, code):
    def explode(prompt):
        raise raised

    outcome = ctl.run(review(repo, state_root), Fake(explode))
    assert (outcome.state, outcome.exit_code) == (state, code)
    root = job_root(state_root, repo, outcome.job_id)
    assert st.read_artifact(root, "state.json")["state"] == state
    assert not (root / "source").exists()
    st.release(st.acquire(root))


def test_an_unreadable_design_file_fails_without_a_traceback(repo, state_root, tmp_path):
    inv = ctl.Invocation(
        mode="design",
        scope={"kind": "design", "source": "file", "design_path": str(tmp_path / "missing.md")},
        repo_root=repo,
        state_root=state_root,
        env={},
    )
    outcome = ctl.run(inv, Fake())
    assert (outcome.exit_code, outcome.state) == (2, "failed")


def test_secrets_never_reach_the_model_or_the_question_output(repo, state_root, tmp_path, monkeypatch):
    leak = "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'"
    design = ctl.Invocation(
        mode="design",
        scope={"kind": "design", "source": "text"},
        repo_root=repo,
        state_root=state_root,
        design_text=leak,
        env={},
    )
    fake = Fake()
    assert ctl.run(design, fake).state == "rejected" and fake.prompts == []
    feature = tmp_path / "feature.yaml"
    doc = yaml.safe_load((ROOT / "examples" / "analyst" / "customer-export-feature.yaml").read_text())
    doc["declarations"] = [leak]
    feature.write_text(yaml.safe_dump(doc))
    assert ctl.run(review(repo, state_root, feature_path=feature), fake).state == "rejected" and fake.prompts == []
    question = {"asks": f"Is {leak} still valid?", "why": "Rotation.", "affects": "config", "required": True}
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, questions=[question])), interactive=True)
    assert outcome.state == "failed" and "wJalrXUtnFEMI" not in outcome.report


def test_introduced_needs_code_that_the_change_added(repo, state_root):
    old_line = {"side": "proposed", "path": "export.js", "line_start": 3, "line_end": 3, "excerpt": "});"}
    claim = removed_check_finding(change_relationship="introduced", evidence=[old_line], comparison=[])
    assert ctl.run(review(repo, state_root), Fake(lambda p: response(p, findings=[claim]))).state == "failed"
    new_line = {
        "side": "proposed",
        "path": "export.js",
        "line_start": 2,
        "line_end": 2,
        "excerpt": "res.json(db.customer(req.params.id));",
    }
    claim = removed_check_finding(change_relationship="introduced", evidence=[new_line], comparison=[])
    assert ctl.run(review(repo, state_root), Fake(lambda p: response(p, findings=[claim]))).state == "complete"


def test_saved_free_form_answers_are_reused_and_can_be_forgotten(repo, state_root, tmp_path, monkeypatch):
    fake = Fake(lambda p: response(p))
    first, _ = pending_question_run(repo, state_root, fake, monkeypatch)
    feature = tmp_path / "feature.yaml"
    ctl.answer(
        first.job_id,
        repo,
        None,
        fake,
        state_root,
        save_feature=feature,
        feature_id="customer-export",
        inline_answers={"q-001": "Assigned customers only."},
    )
    reuse = Fake(lambda p: response(p))
    ctl.run(review(repo, state_root, feature_path=feature), reuse)
    assert envelope(reuse.prompts[0])["feature"]["answers"] == [
        {"asks": "Who may export?", "answer": "Assigned customers only."}
    ]
    import hashlib

    saved = yaml.safe_load(feature.read_text())["answers"][0]["question_fingerprint"]
    sha = hashlib.sha256(feature.read_bytes()).hexdigest()
    assert ctl.forget_answer(feature, "0" * 64, saved).state == "rejected"
    assert ctl.forget_answer(feature, sha, saved).state == "complete"
    assert yaml.safe_load(feature.read_text())["answers"] == []


def test_an_output_directory_that_becomes_assessment_state_keeps_the_result_private(repo, state_root, tmp_path):
    out = tmp_path / "out"

    def poison(prompt):
        out.mkdir(exist_ok=True)
        (out / ".appsec-lock").write_text("1 1 run\n")
        return response(prompt)

    outcome = ctl.run(review(repo, state_root, output_dir=out), Fake(poison))
    assert outcome.state == "failed"
    assert not (out / "analyst-result.json").exists()


@pytest.mark.parametrize("limited", ["evidence_rounds", "host_calls"])
@pytest.mark.parametrize("path", ["policy.js", "access/rules.py"])
def test_unfulfilled_evidence_cannot_complete(repo, state_root, monkeypatch, limited, path):
    original = ctl.load_limits

    def bounded():
        limits = original()
        limits[limited] = 0 if limited == "evidence_rounds" else 1
        return limits

    monkeypatch.setattr(ctl, "load_limits", bounded)
    fake = Fake(lambda p: response(p, evidence_requests=[{"path": path, "reason": "Required policy evidence"}]))
    outcome = ctl.run(review(repo, state_root), fake)
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert (outcome.state, outcome.exit_code) == ("incomplete", 2)
    assert result["terminal_reason"] == "limit_exhausted"
    assert result["coverage"]["required_complete"] is False
    assert result["coverage"]["evidence_requests"][0]["status"] == "limit_exhausted"
    assert path in outcome.report and "Required policy evidence" in outcome.report


@pytest.mark.parametrize(
    "path,content", [("missing.js", None), ("large.js", "a" * 66000), ("binary.bin", "\x00binary")]
)
def test_rejected_evidence_is_reported_as_incomplete(repo, state_root, path, content):
    if content is not None:
        (repo / path).write_text(content)
        git(repo, "add", path)
        git(repo, "commit", "-q", "-m", "context")
    fake = Fake(lambda p: response(p, evidence_requests=[{"path": path, "reason": "Required context"}]))
    outcome = ctl.run(review(repo, state_root), fake)
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert outcome.state == "incomplete" and len(fake.prompts) == 1
    assert result["coverage"]["evidence_requests"][0]["status"] == "rejected"
    assert path in outcome.report


@pytest.mark.parametrize("question_index", [0, 2])
def test_needs_answer_without_a_question_is_rejected(repo, state_root, question_index):
    def inconsistent(p):
        reply = response(p)
        reply["question_coverage"][question_index]["status"] = "needs_answer"
        return reply

    outcome = ctl.run(review(repo, state_root), Fake(inconsistent))
    assert outcome.state == "failed" and outcome.exit_code == 2


def test_optional_question_does_not_block_complete_analysis(repo, state_root):
    question = {
        "question_ref": "appsec/core:authz-scope",
        "asks": "Which role name is intended?",
        "why": "Naming the proposed remediation.",
        "affects": "export.js",
        "required": False,
    }
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, questions=[question])))
    assert outcome.state == "complete" and len(outcome.questions) == 1
    assert "optional" in outcome.report


@pytest.mark.parametrize(
    "path,guard,operation",
    [
        ("handler.py", "require_owner()", "return records.read()"),
        ("jobs/send.py", "check_project_access()", "return reports.export()"),
    ],
)
def test_removed_control_can_introduce_a_finding(repo, state_root, path, guard, operation):
    target = repo / path
    target.parent.mkdir(exist_ok=True)
    target.write_text(f"def handle():\n    {guard}\n    {operation}\n")
    git(repo, "add", path)
    git(repo, "commit", "-q", "-m", "protected operation")
    target.write_text(f"def handle():\n    {operation}\n")
    proposed = {"side": "proposed", "path": path, "line_start": 2, "line_end": 2, "excerpt": operation}
    baseline = {"side": "baseline", "path": path, "line_start": 2, "line_end": 2, "excerpt": guard}
    finding = removed_check_finding(
        change_relationship="introduced", evidence=[proposed], comparison=[baseline, proposed]
    )
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, findings=[finding])))
    assert outcome.state == "complete" and "introduced by the change" in outcome.report
    # The same operation, cited in both versions without the removed guard, is not change evidence.
    unchanged = dict(baseline, line_start=3, line_end=3, excerpt=operation)
    finding["comparison"] = [unchanged, proposed]
    outcome = ctl.run(review(repo, state_root), Fake(lambda p: response(p, findings=[finding])))
    assert outcome.state == "failed"


def hypothesis(repo, state_root, paths=None, **kwargs):
    return ctl.Invocation(
        mode="hypothesis",
        scope={"kind": "hypothesis", "revision": "HEAD", "paths": paths or ["export.js"]},
        hypothesis="Can a caller read another customer record?",
        repo_root=repo,
        state_root=state_root,
        env={},
        **kwargs,
    )


def hypothesis_response(prompt, status="supported", **overrides):
    source = next(f for f in envelope(prompt)["files"] if f["path"] == "export.js")
    excerpt = source["numbered_lines"].splitlines()[0].split("| ", 1)[1]
    assessment = {
        "status": status,
        "explanation": "The inspected route establishes the bounded conclusion.",
        "evidence": [{"side": "proposed", "path": "export.js", "line_start": 1, "line_end": 1, "excerpt": excerpt}],
        "next_action": "Verify the authorization behavior with the system owner.",
    }
    return response(prompt, hypothesis_assessment=assessment, **overrides)


@pytest.mark.parametrize(
    "status,expected", [("supported", "complete"), ("not_confirmed", "complete"), ("unresolved", "incomplete")]
)
def test_hypothesis_check_reports_evidenced_conclusion(repo, state_root, status, expected):
    fake = Fake(lambda p: hypothesis_response(p, status))
    outcome = ctl.run(hypothesis(repo, state_root), fake)
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert outcome.state == expected
    assert result["hypothesis_assessment"]["status"] == status
    inputs = envelope(fake.prompts[0])
    assert len(inputs["files"]) == 1 and inputs["files"][0]["change"] == "context"
    assert "requireSupport" in inputs["files"][0]["numbered_lines"]  # committed version, not the dirty worktree
    assert inputs["hypothesis"] == result["hypothesis"]
    assert result["objects"]["head"] in outcome.report and "export.js" in outcome.report
    assert "does not mean disproved or safe" in outcome.report
    assert not (job_root(state_root, repo, outcome.job_id) / "source").exists()


@pytest.mark.parametrize(
    "malformed", ["missing", "no_evidence", "invented_quote", "blank_quote", "outside_scope", "change_claim"]
)
def test_hypothesis_claims_need_valid_scoped_evidence(repo, state_root, malformed):
    def reply(p):
        r = hypothesis_response(p)
        if malformed == "missing":
            r.pop("hypothesis_assessment")
        elif malformed == "no_evidence":
            r["hypothesis_assessment"]["evidence"] = []
        elif malformed == "invented_quote":
            r["hypothesis_assessment"]["evidence"][0]["excerpt"] = "invented_call()"
        elif malformed == "blank_quote":
            r["hypothesis_assessment"]["evidence"][0]["excerpt"] = "   "
        elif malformed == "outside_scope":
            r["hypothesis_assessment"]["evidence"][0]["path"] = "auth.js"
        else:
            r["findings"] = [removed_check_finding()]
        return r

    outcome = ctl.run(hypothesis(repo, state_root), Fake(reply))
    assert outcome.state == "failed"
    assert "Supported by code" not in outcome.report


def test_hypothesis_cannot_expand_authorized_paths(repo, state_root):
    fake = Fake(
        lambda p: hypothesis_response(
            p, "unresolved", evidence_requests=[{"path": "auth.js", "reason": "Check middleware"}]
        )
    )
    outcome = ctl.run(hypothesis(repo, state_root), fake)
    assert outcome.state == "incomplete" and len(fake.prompts) == 1
    assert "outside the captured view" in outcome.report
    assert all(f["path"] != "auth.js" for f in envelope(fake.prompts[0])["files"])


def _directory_reply(path: str):
    def reply(prompt):
        source = next(f for f in envelope(prompt)["files"] if f["path"] == path)
        excerpt = source["numbered_lines"].splitlines()[0].split("| ", 1)[1]
        assessment = {
            "status": "supported",
            "explanation": "The inspected route establishes the bounded conclusion.",
            "evidence": [{"side": "proposed", "path": path, "line_start": 1, "line_end": 1, "excerpt": excerpt}],
            "next_action": "Verify the authorization behavior with the system owner.",
        }
        return response(prompt, hypothesis_assessment=assessment)

    return reply


@pytest.mark.parametrize(
    ("folder", "unreadable", "content"),
    [("api", ".env", b"SESSION_SECRET=x\n"), ("server/routes", "logo.png", b"\x00\x01png")],
)
def test_an_exclusion_inside_a_selected_directory_narrows_but_does_not_stop_the_check(
    repo, state_root, folder, unreadable, content
):
    area = repo / folder
    area.mkdir(parents=True)
    (area / "records.js").write_text("app.get('/records/:id', (req, res) => res.json(db.find(req.params.id)))\n")
    (area / unreadable).write_bytes(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "area")
    fake = Fake(_directory_reply(f"{folder}/records.js"))
    outcome = ctl.run(hypothesis(repo, state_root, [folder]), fake)
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert outcome.state == "complete" and len(fake.prompts) == 1
    assert any("does not cover them" in note for note in result["limitations"])
    assert f"{folder}/{unreadable}" in outcome.report


def test_a_named_path_that_is_not_admitted_stops_the_check_before_the_model(repo, state_root):
    (repo / "api").mkdir()
    (repo / "api" / "records.js").write_text("module.exports = {}\n")
    (repo / "api" / ".env").write_text("SESSION_SECRET=x\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "area")
    fake = Fake()
    outcome = ctl.run(hypothesis(repo, state_root, ["api/records.js", "api/.env"]), fake)
    assert outcome.state == "incomplete" and fake.prompts == []
    assert "selected hypothesis path was not admitted" in outcome.report


@pytest.mark.parametrize("paths", [["absent"], ["."], ["../outside"], ["/tmp"], ["src//api"], ["export.js/"]])
def test_hypothesis_invalid_or_missing_scope_never_calls_the_model(repo, state_root, paths):
    fake = Fake()
    outcome = ctl.run(hypothesis(repo, state_root, paths), fake)
    assert outcome.state in ("rejected", "incomplete") and outcome.exit_code == 2
    assert fake.prompts == []


def test_hypothesis_required_question_resumes_the_same_snapshot(repo, state_root):
    q = {
        "question_ref": "appsec/core:authz-scope",
        "asks": "Which accounts may support access?",
        "why": "Determines the authorized scope.",
        "affects": "export.js",
        "required": True,
    }
    fake = Fake(
        lambda p: hypothesis_response(p, "unresolved", questions=[q]), lambda p: hypothesis_response(p, "not_confirmed")
    )
    first = ctl.run(hypothesis(repo, state_root), fake)
    assert first.state == "awaiting_answers"
    (repo / "export.js").write_text("changed after capture\n")
    done = ctl.answer(
        first.job_id, repo, None, fake, state_root, inline_answers={first.questions[0]["id"]: "Only assigned accounts."}
    )
    assert done.state == "complete"
    assert envelope(fake.prompts[0])["files"] == envelope(fake.prompts[1])["files"]


def test_last_evidence_round_reports_remaining_work(repo, state_root):
    for path in ("policy_a.py", "policy_b.py", "policy_c.py"):
        (repo / path).write_text("def check():\n    return True\n")
        git(repo, "add", path)
    git(repo, "commit", "-q", "-m", "three evidence sources")

    def first(p):
        return response(p, evidence_requests=[{"path": "policy_a.py", "reason": "Resolve the first policy"}])

    def second(p):
        return response(p, evidence_requests=[{"path": "policy_b.py", "reason": "Resolve its delegate"}])

    def third(p):
        return response(p, evidence_requests=[{"path": "policy_c.py", "reason": "Resolve the final decision"}])

    fake = Fake(first, second, third)
    outcome = ctl.run(review(repo, state_root), fake)
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert outcome.state == "incomplete" and len(fake.prompts) == 3
    assert [e["status"] for e in result["coverage"]["evidence_requests"]] == ["admitted", "admitted", "limit_exhausted"]
    assert "policy_c.py" in outcome.report


def test_partially_admitted_evidence_stays_incomplete(repo, state_root):
    fake = Fake(
        lambda p: response(
            p,
            evidence_requests=[
                {"path": "auth.js", "reason": "Check the middleware"},
                {"path": "missing.js", "reason": "Check its required policy"},
            ],
        )
    )
    outcome = ctl.run(review(repo, state_root), fake)
    result = st.read_artifact(job_root(state_root, repo, outcome.job_id), "result.json")
    assert outcome.state == "incomplete" and len(fake.prompts) == 1
    assert [e["status"] for e in result["coverage"]["evidence_requests"]] == ["admitted", "rejected"]
    assert "missing.js" in outcome.report


STEP_HYPOTHESIS = (
    "Abuse case AC-T-002 (technical attack chain, plugin): Export of another customer's records.\n"
    "- Step 1: Export route skips ownership. The handler returns any record.\n"
    "- Step 2: Support role is trusted. The role comes from the request."
)


def _step_reply(steps):
    def reply(prompt):
        r = hypothesis_response(prompt, "supported")
        loc = r["hypothesis_assessment"]["evidence"][0]
        r["hypothesis_assessment"]["steps"] = steps(loc)
        return r

    return reply


@pytest.mark.parametrize(
    ("steps", "state"),
    [
        (
            lambda loc: [
                {"step": 1, "status": "supported", "note": "No owner check.", "evidence": [loc]},
                {"step": 2, "status": "unresolved", "note": "Role source not in scope.", "evidence": []},
            ],
            "complete",
        ),
        (lambda loc: [{"step": 1, "status": "supported", "note": "No owner check.", "evidence": [loc]}], "failed"),
        (
            lambda loc: [
                {"step": 1, "status": "supported", "note": "x", "evidence": [dict(loc, excerpt="invented()")]},
                {"step": 2, "status": "unresolved", "note": "y", "evidence": []},
            ],
            "failed",
        ),
    ],
    ids=["every-step-answered", "a-listed-step-missing", "a-step-quote-invented"],
)
def test_a_chain_hypothesis_needs_one_evidenced_verdict_per_listed_step(repo, state_root, steps, state):
    invocation = ctl.Invocation(
        mode="hypothesis",
        scope={"kind": "hypothesis", "revision": "HEAD", "paths": ["export.js"]},
        hypothesis=STEP_HYPOTHESIS,
        repo_root=repo,
        state_root=state_root,
        env={},
    )
    outcome = ctl.run(invocation, Fake(_step_reply(steps)))
    assert outcome.state == state
    if state == "complete":
        assert "| 1 | SUPPORTED | Export route skips ownership |" in outcome.report
        assert (
            "| 2 | NOT SETTLED | Support role is trusted | no code cited | Role source not in scope\\. |"
            in outcome.report
        )
