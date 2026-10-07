#!/usr/bin/env python3
"""orchestrator/analyst_controller.py — the one controller of the on-demand threat analysis.

Owns admission, job state, snapshot capture, context admission, bounded model
dispatch, questions and answers, result validation, publication, retention,
and cleanup. The skill and the CI CLI both call ``run``, ``answer``,
``cancel``, and ``forget_answer``; neither adds logic.

Model output supplies analysis and bounded proposals for evidence or
questions. It never chooses commands, tools, paths, permissions, states, or
exit codes. Admission failures exit before a job exists. Limits, deadlines,
cancellation, and retries are enforced here. Invalid model output is never
retried silently and never published. Every job that started ends in a
terminal state or a question checkpoint, also on an unexpected error or a
termination signal.

Exit codes: 0 complete (or, interactively, waiting for answers); 2 rejected,
incomplete, or failed; 130 cancelled. Code 1 is reserved for a future gate.
This controller dispatches no assessment roles and shares no assessment state
(decision P-1).
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from contexts import analyst_questions as aq
from contexts.build_analyst_context import ContextContractError, ContextError
from contexts.build_analyst_context import build as build_context
from contexts.build_analyst_snapshot import SnapshotError, admit_context, capture
from contexts.resolve_analyst_catalog import CatalogError, Selection, load_limits, resolve, select_questions
from renderers.render_analyst_report import render
from runtime import analyst_state as st
from runtime.analyst_host import (
    INSTRUCTIONS,
    HostCancelled,
    Transport,
    TransportError,
    build_prompt,
    instructions,
    response_schema,
)
from runtime.resolve_org_profile import resolve as resolve_org_profile
from validators.secret_scan import scan_text
from validators.validate_analyst import validate_request, validate_response, validate_result

EXIT_OK = 0
EXIT_NOT_COMPLETE = 2
EXIT_CANCELLED = 130
PLUGIN_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_VERSION_FILE = PLUGIN_ROOT / ".claude-plugin" / "plugin.json"
REQUEST_LIMITS = (
    "job_seconds",
    "call_seconds",
    "host_calls",
    "evidence_rounds",
    "question_rounds",
    "transport_retries",
    "admitted_files",
    "file_kib",
    "job_kib",
    "response_kib",
    "selected_questions",
    "answer_hours",
)


class AdmissionError(Exception):
    """The invocation is rejected before any job state or model call."""


class Terminated(BaseException):  # noqa: N818 - mirrors KeyboardInterrupt
    """Raised by the CLI's signal handler so the job records its termination."""


@dataclass
class Invocation:
    mode: str
    scope: dict
    repo_root: Path
    output_dir: Path | None = None
    design_text: str | None = None
    hypothesis: str | None = None
    feature_path: Path | None = None
    packages: list[Selection] = field(default_factory=list)
    ci: bool = False
    requirements_path: Path | None = None
    requirements_required: bool = False
    threat_model_path: Path | None = None
    threat_model_required: bool = False
    state_root: Path | None = None
    env: dict | None = None
    model: str = "sonnet"


@dataclass
class Outcome:
    exit_code: int
    state: str
    job_id: str | None
    report: str
    questions: list[dict] = field(default_factory=list)


TransportFactory = Callable[[st.Job, dict], Transport]


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _plugin_version() -> str:
    try:
        return str(json.loads(PLUGIN_VERSION_FILE.read_text(encoding="utf-8")).get("version") or "unknown")[:64]
    except (OSError, json.JSONDecodeError):
        return "unknown"


def _org_inputs(repo: Path, env: dict | None) -> tuple[list[Selection], dict | None]:
    """Packages and requirements source the active organization profile requires.

    An active profile that fails validation rejects the analysis: its required
    inputs are unknown, so no analysis can claim to honor them.
    """
    effective, errors = resolve_org_profile(None, None, False, str(repo), PLUGIN_ROOT, env)
    if errors:
        raise AdmissionError("organization profile is invalid: " + "; ".join(errors))
    block = effective.get("analyst") or {}
    selections = [Selection(spec, "org_required") for spec in block.get("required", [])]
    selections += [Selection(spec, "org_default") for spec in block.get("default", [])]
    source = effective.get("requirements_source")
    return selections, source if source and source.get("enabled") else None


def _admit(inv: Invocation, limits: dict) -> tuple[dict, dict, dict, dict | None, dict | None]:
    """Validate an invocation; return (request, resolved, selection, feature, org requirements source)."""
    repo = inv.repo_root
    if not repo.is_absolute() or not repo.is_dir() or not (repo / ".git").exists():
        raise AdmissionError("--repo must be an absolute path to a Git working tree")
    repo = repo.resolve()
    if inv.output_dir is not None:
        errors = st.check_output_dir(inv.output_dir, repo, inv.state_root)
        if errors:
            raise AdmissionError("; ".join(errors))
    if inv.mode not in ("design", "review", "hypothesis") or (inv.mode == "design") != (
        inv.scope.get("kind") == "design"
    ):
        raise AdmissionError("mode and scope do not match")
    if (inv.mode == "hypothesis") != (inv.scope.get("kind") == "hypothesis"):
        raise AdmissionError("hypothesis mode and scope do not match")
    if inv.ci and inv.scope["kind"] in ("staged", "worktree"):
        raise AdmissionError("CI reviews require an explicit commit comparison")
    if inv.design_text is not None and scan_text(inv.design_text):
        raise AdmissionError("the design text contains a secret; describe the design without the value")
    if inv.hypothesis is not None and scan_text(inv.hypothesis):
        raise AdmissionError("the hypothesis contains a secret; describe it without the value")
    org_packages, org_requirements = _org_inputs(repo, inv.env)
    try:
        resolved = resolve([*org_packages, *inv.packages], limits, repo_root=repo, ci=inv.ci)
    except CatalogError as exc:
        raise AdmissionError(str(exc)) from None
    feature = None
    if inv.feature_path is not None:
        try:
            doc, sha = aq.load_feature(inv.feature_path)
        except aq.QuestionError as exc:
            raise AdmissionError(str(exc)) from None
        if scan_text(json.dumps(doc)):
            raise AdmissionError("the feature file contains a secret")
        feature = {"doc": doc, "sha256": sha, "label": inv.feature_path.name}
    request = {
        "schema_version": 1,
        "mode": inv.mode,
        "scope": inv.scope,
        "repository": {"root": str(repo)},
        "output_dir": str((inv.output_dir or repo).resolve()),
        "packages": resolved["packages"],
        "limits": {k: limits[k] for k in REQUEST_LIMITS},
        "host": {"model": inv.model, "instructions_sha256": hashlib.sha256(INSTRUCTIONS.read_bytes()).hexdigest()},
        "plugin_version": _plugin_version(),
    }
    if feature is not None:
        request["feature"] = {"path": str(inv.feature_path.resolve()), "sha256": feature["sha256"]}
    if inv.hypothesis is not None:
        request["hypothesis"] = inv.hypothesis
    if inv.mode == "hypothesis" or inv.hypothesis is not None:
        if validate_request(dict(request, job_id="aj-" + "0" * 32, requested_at=st.utc_now())):
            raise AdmissionError("invalid hypothesis, revision, or source paths")
    selection = select_questions(resolved, limits["selected_questions"])
    return request, resolved, selection, feature, org_requirements


def _state(job: st.Job, name: str, fingerprint: str, counters: dict, reason=None, pending=None) -> dict:
    return {
        "schema_version": 1,
        "job_id": job.job_id,
        "state": name,
        "input_fingerprint": fingerprint,
        "counters": dict(counters),
        "pending_questions": pending or [],
        "terminal_reason": reason,
        "updated_at": st.utc_now(),
    }


def _number(items: list[dict], prefix: str) -> list[dict]:
    return [dict(item, id=f"{prefix}-{i:03d}") for i, item in enumerate(items, start=1)]


@dataclass
class _Run:
    """Everything one pass of a job carries until it ends."""

    job: st.Job
    request: dict
    receipts: dict
    state_root: Path | None
    snapshot: dict | None = None
    context: dict | None = None
    counters: dict = field(
        default_factory=lambda: {"host_calls": 0, "evidence_rounds": 0, "question_rounds": 0, "transport_retries": 0}
    )
    fingerprint: str = ""
    evidence_requests: list[dict] = field(default_factory=list)
    usd: float = 0.0
    deadline: float = 0.0

    def start_clock(self) -> None:
        self.deadline = time.monotonic() + self.request["limits"]["job_seconds"]

    def out_of_time(self) -> bool:
        return time.monotonic() > self.deadline

    def ensure_started(self) -> None:
        if st.read_artifact(self.job.root, "state.json") is None:
            self.fingerprint = self.fingerprint or _sha(self.request)
            st.transition(self.job, _state(self.job, "prepared", self.fingerprint, self.counters))

    def finish(self, state: str, reason: str, notes=(), response=None, questions=None) -> Outcome:
        self.ensure_started()
        response = response or {}
        current = st.read_artifact(self.job.root, "state.json")
        fingerprint = current["input_fingerprint"]
        snapshot, context = self.snapshot or {}, self.context or {}
        result = {
            "schema_version": 1,
            "job_id": self.job.job_id,
            "input_fingerprint": fingerprint,
            "state": state,
            "terminal_reason": reason,
            "mode": self.request["mode"],
            "scope": self.request["scope"],
            "objects": snapshot.get("objects", {}),
            "packages": self.receipts["receipts"],
            "coverage": {
                "admitted_files": len(snapshot.get("admitted", [])),
                "excluded": snapshot.get("excluded", []),
                "sources": context.get("sources", []),
                "omitted_questions": context.get("question_selection", {}).get("omitted", []),
                "question_coverage": response.get("question_coverage", []),
                "evidence_requests": self.evidence_requests,
                "required_complete": bool(context and context["question_selection"]["required_complete"])
                and not any(e["status"] != "admitted" for e in self.evidence_requests)
                and not any(q["required"] for q in questions or [])
                and not (self.request["mode"] == "hypothesis" and state != "complete"),
            },
            "summary": response.get("summary", ""),
            "findings": _number(response.get("findings", []), "f"),
            "scenarios": _number(response.get("scenarios", []), "s"),
            "assumptions": _number(response.get("assumptions", []), "a"),
            "requirement_observations": response.get("requirement_observations", []),
            "methodology_observations": response.get("methodology_observations", []),
            "questions": questions or [],
            "limitations": [*response.get("limitations", []), *notes],
            "costs": {"host_calls": self.counters["host_calls"], **({"usd": round(self.usd, 4)} if self.usd else {})},
            "generated_at": st.utc_now(),
        }
        if self.request["mode"] == "hypothesis":
            result["hypothesis"] = self.request["hypothesis"]
            if "hypothesis_assessment" in response:
                result["hypothesis_assessment"] = dict(response["hypothesis_assessment"])
                if state != "complete":
                    result["hypothesis_assessment"]["status"] = "unresolved"
        output = Path(self.request["output_dir"])
        repo = Path(self.request["repository"]["root"])
        publish = output != repo
        withheld = None
        if validate_result(result):
            withheld = "The result failed validation and was withheld."
        else:
            report = render(result)
            if scan_text(json.dumps(result)) or scan_text(report):
                withheld = "The result contained a secret and was withheld."
            elif publish and st.check_output_dir(output, repo, self.state_root):
                withheld = "The output directory became unusable; the result stays in the job directory."
                publish = False
        if withheld:
            empty = {k: [] for k in ("findings", "scenarios", "assumptions", "questions")}
            result = dict(
                result,
                **empty,
                summary="",
                requirement_observations=[],
                methodology_observations=[],
                limitations=[withheld],
                state="failed",
                terminal_reason="validation_failure",
            )
            result.pop("hypothesis_assessment", None)
            result["coverage"] = dict(result["coverage"], question_coverage=[], required_complete=False)
            report = render(result)
        pending = [q["id"] for q in result["questions"] if q["required"]] if result["state"] == "incomplete" else []
        st.transition(
            self.job, _state(self.job, result["state"], fingerprint, self.counters, result["terminal_reason"], pending)
        )
        st.write_artifact(self.job, "result.json", result)
        st.write_artifact(self.job, "result.md", report)
        if publish:
            _publish(output, result, report)
        code = {"complete": EXIT_OK, "cancelled": EXIT_CANCELLED}.get(result["state"], EXIT_NOT_COMPLETE)
        return Outcome(code, result["state"], self.job.job_id, report, result["questions"])

    def abort(self, exc: BaseException) -> Outcome:
        """Record an interruption or an unexpected error as a terminal state."""
        current = st.read_artifact(self.job.root, "state.json")
        if current is not None and current["state"] in ("complete", "incomplete", "failed", "cancelled"):
            return Outcome(EXIT_NOT_COMPLETE, current["state"], self.job.job_id, "")
        if isinstance(exc, (KeyboardInterrupt, Terminated)):
            return self.finish("cancelled", "terminated", ["The analysis was interrupted."])
        return self.finish(
            "failed", "validation_failure", [f"The analysis stopped on an internal error ({type(exc).__name__})."]
        )


def _publish(output_dir: Path, result: dict, report: str) -> None:
    st.mark_output_dir(output_dir)
    for name, text in (("analyst-result.json", json.dumps(result, indent=2) + "\n"), ("analyst-result.md", report)):
        tmp = output_dir / f".{name}.tmp"
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(output_dir / name)


def _guarded(run: _Run, body: Callable[[], Outcome]) -> Outcome:
    """Run a job body so that every exit leaves a terminal state or a checkpoint."""
    keep_view = False
    try:
        outcome = body()
        keep_view = outcome.state == "awaiting_answers"
        return outcome
    except (Exception, KeyboardInterrupt, Terminated) as exc:
        try:
            return run.abort(exc)
        except Exception:
            return Outcome(
                EXIT_NOT_COMPLETE,
                "failed",
                run.job.job_id,
                "The analysis failed and its state could not be recorded.\n",
            )
    finally:
        if not keep_view:
            st.cleanup_temporaries(run.job)
        st.release(run.job)


def _maintain(repo: Path, state_root: Path | None, limits: dict) -> None:
    """Close abandoned jobs and expire old results of this repository."""
    st.recover_stale(repo, state_root, result_days=limits["result_days"])


def run(inv: Invocation, transport_factory: TransportFactory, interactive: bool = True) -> Outcome:
    """Run one analysis from admission to a published result or a question checkpoint."""
    limits = load_limits()
    try:
        request, resolved, selection, feature, org_requirements = _admit(inv, limits)
    except AdmissionError as exc:
        return Outcome(EXIT_NOT_COMPLETE, "rejected", None, f"Rejected before analysis: {exc}\n")
    repo = Path(request["repository"]["root"])
    _maintain(repo, inv.state_root, limits)
    job = st.create_job(repo, inv.state_root)
    request = {"job_id": job.job_id, **request, "requested_at": st.utc_now()}
    receipts = {"fingerprint": resolved["fingerprint"], "receipts": resolved["receipts"]}
    current = _Run(job, request, receipts, inv.state_root)
    current.start_clock()
    return _guarded(
        current,
        lambda: _prepare(current, inv, resolved, selection, feature, org_requirements, transport_factory, interactive),
    )


def _prepare(
    current: _Run, inv, resolved, selection, feature, org_requirements, transport_factory, interactive
) -> Outcome:
    job, request = current.job, current.request
    if inv.mode == "design":
        content = (inv.design_text or "").encode() if request["scope"]["source"] == "text" else None
        if content is None:
            try:
                content = Path(request["scope"]["design_path"]).read_bytes()
            except OSError:
                current.request = request = dict(request, scope=dict(request["scope"], content_sha256="0" * 64))
                st.write_artifact(job, "request.json", request)
                return current.finish("failed", "validation_failure", ["The design file could not be read."])
        request["scope"] = dict(request["scope"], content_sha256=hashlib.sha256(content).hexdigest())
    st.write_artifact(job, "request.json", request)
    st.write_artifact(job, "packages.json", current.receipts)
    try:
        current.snapshot = capture(request, job, inv.design_text)
    except SnapshotError as exc:
        return current.finish("failed", "validation_failure", [f"Source capture failed: {exc}."])
    st.write_artifact(job, "snapshot.json", current.snapshot)
    delivered_feature = None
    if feature is not None:
        delivered = [
            {"fingerprint": aq.question_fingerprint("", q["ref"], resolved["fingerprint"])}
            for q in selection["selected"]
        ]
        delivered += [
            {"fingerprint": aq.question_fingerprint(a["asks"], None, resolved["fingerprint"])}
            for a in feature["doc"]["answers"]
            if not a.get("question_ref")
        ]
        delivered_feature = aq.projection(feature["doc"], feature["sha256"], feature["label"], delivered)
    requirements_required = inv.requirements_required or org_requirements is not None
    if requirements_required and inv.requirements_path is None:
        label = (org_requirements or {}).get("label") or "the required requirements catalog"
        return current.finish(
            "incomplete",
            "required_input_missing",
            [f"No trusted copy of {label} was supplied; pass it with --requirements."],
        )
    try:
        current.context = build_context(
            request,
            resolved,
            selection,
            requirements_path=inv.requirements_path,
            requirements_required=requirements_required,
            threat_model_path=inv.threat_model_path,
            threat_model_required=inv.threat_model_required,
            feature=delivered_feature,
        )
    except ContextContractError:
        return current.finish("failed", "validation_failure", ["The analysis context violated its contract."])
    except ContextError as exc:
        return current.finish("incomplete", "required_input_missing", [f"{exc}."])
    st.write_artifact(job, "context.json", current.context)
    current.fingerprint = _sha([request, current.snapshot, current.context])
    current.ensure_started()
    snapshot = current.snapshot
    if inv.mode == "hypothesis" and (snapshot["excluded"] or not snapshot["admitted"]):
        return current.finish(
            "incomplete",
            "required_input_missing",
            [
                "The selected hypothesis scope was not fully admitted; inspect the exclusions and narrow or correct the paths."
            ],
        )
    changed = snapshot["admitted"] or any(e["reason"] != "ignored" for e in snapshot["excluded"])
    if inv.mode == "review" and not changed and feature is None:
        return current.finish(
            "complete", "empty_scope", ["The selected scope contains no changes; no model call was made."]
        )
    return _analyze(current, [], transport_factory, interactive)


def _analyze(current: _Run, answers: list[dict], transport_factory: TransportFactory, interactive: bool) -> Outcome:
    job, request = current.job, current.request
    st.transition(job, _state(job, "analyzing", current.fingerprint, current.counters))
    transport = transport_factory(job, request)
    limits = request["limits"]
    source_dir = job.root / "source"
    response = None
    while response is None:
        if st.cancel_requested(job.root):
            return current.finish("cancelled", "cancelled_by_user")
        if current.out_of_time() or current.counters["host_calls"] >= limits["host_calls"]:
            return current.finish("incomplete", "limit_exhausted", ["The analysis reached its time or call limit."])
        current.counters["host_calls"] += 1
        st.transition(job, _state(job, "analyzing", current.fingerprint, current.counters))
        prompt = build_prompt(request, current.snapshot, current.context, source_dir, answers)
        timeout = max(1, min(limits["call_seconds"], int(current.deadline - time.monotonic())))
        try:
            reply = transport.invoke(
                instructions(),
                prompt,
                response_schema(),
                timeout,
                lambda: st.cancel_requested(job.root) or current.out_of_time(),
            )
        except HostCancelled:
            if st.cancel_requested(job.root):
                return current.finish("cancelled", "cancelled_by_user")
            return current.finish("incomplete", "limit_exhausted", ["A model call reached its time limit."])
        except TransportError:
            if current.counters["transport_retries"] >= limits["transport_retries"]:
                return current.finish("failed", "transport_failure", ["The model could not be reached."])
            current.counters["transport_retries"] += 1
            continue
        current.usd += reply.usd or 0.0
        errors = validate_response(reply.payload, request, current.snapshot, current.context, source_dir)
        if errors:
            note = f"The model reply failed validation ({len(errors)} problem(s)); nothing from it was published."
            return current.finish("failed", "invalid_model_output", [note])
        wanted = reply.payload["evidence_requests"]
        rounds_left = current.counters["evidence_rounds"] < limits["evidence_rounds"]
        if wanted:
            can_read = rounds_left and current.counters["host_calls"] < limits["host_calls"]
            unresolved = False
            for item in wanted:
                receipt = dict(item, status="limit_exhausted", detail="No evidence round or model call remains.")
                if can_read:
                    try:
                        current.snapshot = admit_context(request, job, current.snapshot, item["path"])
                        admitted = any(
                            e["path"] == item["path"] and e["side"] == "proposed" for e in current.snapshot["admitted"]
                        )
                        receipt.update(
                            status="admitted" if admitted else "rejected",
                            detail="Read from the frozen source view."
                            if admitted
                            else "Source admission excluded the requested file.",
                        )
                    except SnapshotError as exc:
                        receipt.update(status="rejected", detail=str(exc))
                current.evidence_requests.append(receipt)
                unresolved |= receipt["status"] != "admitted"
            st.write_artifact(job, "snapshot.json", current.snapshot)
            if unresolved:
                return current.finish(
                    "incomplete",
                    "required_input_missing" if can_read else "limit_exhausted",
                    ["Requested evidence remains unavailable; the analysis is incomplete."],
                    response=reply.payload,
                    questions=aq.assign(reply.payload["questions"], current.receipts["fingerprint"]),
                )
            current.counters["evidence_rounds"] += 1
            continue
        response = reply.payload
    st.write_artifact(job, "response.json", response)
    questions = aq.assign(response["questions"], current.receipts["fingerprint"])
    st.write_artifact(
        job,
        "questions.json",
        {"questions": questions, "usd": current.usd, "evidence_requests": current.evidence_requests},
    )
    required = [q for q in questions if q["required"]]
    if required and interactive and current.counters["question_rounds"] < limits["question_rounds"]:
        report = _question_report(job.job_id, questions)
        if scan_text(report):
            return current.finish("failed", "validation_failure", ["A question contained a secret and was withheld."])
        pending = [q["id"] for q in required]
        st.transition(job, _state(job, "awaiting_answers", current.fingerprint, current.counters, pending=pending))
        return Outcome(EXIT_OK, "awaiting_answers", job.job_id, report, questions)
    if required:
        return current.finish("incomplete", "required_answers_missing", response=response, questions=questions)
    if not current.context["question_selection"]["required_complete"]:
        note = ["Required questions exceeded the question limit."]
        return current.finish("incomplete", "limit_exhausted", note, response=response, questions=questions)
    if request["mode"] == "hypothesis" and response["hypothesis_assessment"]["status"] == "unresolved":
        return current.finish("incomplete", "required_input_missing", response=response, questions=questions)
    return current.finish("complete", "analysis_complete", response=response, questions=questions)


def _question_report(job_id: str, questions: list[dict]) -> str:
    lines = [f"Analysis {job_id} needs answers before it can complete.", ""]
    for q in questions:
        need = "required" if q["required"] else "optional"
        lines.append(f"- {q['id']} ({need}): {' '.join(q['asks'].split())}")
        lines.append(f"  Why: {' '.join(q['why'].split())}")
        lines.append(f"  Fingerprint: {q['fingerprint']}")
    return "\n".join(lines) + "\n"


def answer(
    job_id: str,
    repo_root: Path,
    answers_path: Path | None,
    transport_factory: TransportFactory,
    state_root: Path | None = None,
    save_feature: Path | None = None,
    feature_sha256: str | None = None,
    feature_id: str | None = None,
    inline_answers: dict[str, str] | None = None,
) -> Outcome:
    """Resume a job waiting for answers.

    Answers come from a JSON answers file or, in an interactive session, as
    ``{question id: text}`` for questions of this job; both pass the same checks.
    The resumed pass gets a fresh wall-clock budget.
    """
    limits = load_limits()
    try:
        _maintain(repo_root.resolve(), state_root, limits)
        root = st.job_path(job_id, repo_root.resolve(), state_root)
        job = st.acquire(root)
    except st.AnalystStateError as exc:
        return Outcome(EXIT_NOT_COMPLETE, "rejected", None, f"Rejected: {exc}\n")
    state = st.read_artifact(root, "state.json")
    if state is None or state["state"] != "awaiting_answers":
        st.release(job)
        name = state["state"] if state else "unknown"
        return Outcome(EXIT_NOT_COMPLETE, "rejected", job_id, f"Rejected: job is {name}, not waiting for answers\n")
    current = _Run(job, st.read_artifact(root, "request.json"), st.read_artifact(root, "packages.json"), state_root)
    current.snapshot = st.read_artifact(root, "snapshot.json")
    current.context = st.read_artifact(root, "context.json")
    saved_questions = st.read_artifact(root, "questions.json")
    current.evidence_requests = saved_questions.get("evidence_requests", [])
    current.usd = saved_questions.get("usd", 0.0)
    current.counters = dict(state["counters"])
    current.fingerprint = state["input_fingerprint"]
    current.start_clock()
    pending = [
        q for q in st.read_artifact(root, "questions.json")["questions"] if q["id"] in state["pending_questions"]
    ]

    def body() -> Outcome:
        try:
            if inline_answers is not None:
                by_id = {q["id"]: q["fingerprint"] for q in pending}
                items = [
                    {"question_id": k, "fingerprint": by_id.get(k, ""), "answer": v} for k, v in inline_answers.items()
                ]
                accepted = aq.check_answers(items, pending)
            elif answers_path is not None:
                accepted = aq.load_answers(answers_path, job_id, pending)
            else:
                raise aq.QuestionError(["no answers given"])
            missing = [q["id"] for q in pending if q["id"] not in accepted]
            if missing:
                raise aq.QuestionError([f"missing {', '.join(missing)}"])
        except aq.QuestionError as exc:
            return Outcome(EXIT_NOT_COMPLETE, "awaiting_answers", job_id, f"Answers rejected: {exc}\n", pending)
        answered = [
            {
                "question_ref": q.get("question_ref"),
                "asks": q["asks"],
                "answer": accepted[q["id"]],
                "question_fingerprint": q["fingerprint"],
            }
            for q in pending
        ]
        if save_feature is not None:
            intent = (current.context.get("feature") or {}).get("intent") or "Answers saved from a threat analysis."
            try:
                aq.save(save_feature, feature_sha256, feature_id or "feature", intent, answered)
            except aq.QuestionError as exc:
                return Outcome(
                    EXIT_NOT_COMPLETE, "awaiting_answers", job_id, f"Feature file not saved: {exc}\n", pending
                )
        current.counters["question_rounds"] += 1
        current.fingerprint = _sha([state["input_fingerprint"], answered])
        delivered = [{"asks": a["asks"], "answer": a["answer"]} for a in answered]
        return _analyze(current, delivered, transport_factory, True)

    return _guarded(current, body)


def cancel(job_id: str, repo_root: Path, state_root: Path | None = None) -> Outcome:
    """Ask a running job to stop, or close a job waiting for answers."""
    try:
        root = st.job_path(job_id, repo_root.resolve(), state_root)
    except st.AnalystStateError as exc:
        return Outcome(EXIT_NOT_COMPLETE, "rejected", None, f"Rejected: {exc}\n")
    st.request_cancel(root)
    try:
        job = st.acquire(root)
    except st.AnalystStateError:
        return Outcome(
            EXIT_CANCELLED,
            "cancelling",
            job_id,
            "Cancellation requested; the running analysis stops at its next check.\n",
        )
    state = st.read_artifact(root, "state.json")
    if state is None or state["state"] in ("complete", "incomplete", "failed", "cancelled"):
        if state is None:
            st.discard_job(job)
            return Outcome(EXIT_CANCELLED, "cancelled", job_id, "The job had not started and was removed.\n")
        st.release(job)
        return Outcome(EXIT_NOT_COMPLETE, state["state"], job_id, f"Job is already {state['state']}.\n")
    current = _Run(job, st.read_artifact(root, "request.json"), st.read_artifact(root, "packages.json"), state_root)
    current.snapshot = st.read_artifact(root, "snapshot.json")
    current.context = st.read_artifact(root, "context.json")
    current.counters = dict(state["counters"])
    return _guarded(current, lambda: current.finish("cancelled", "cancelled_by_user"))


def forget_answer(feature_path: Path, feature_sha256: str, question_fingerprint: str) -> Outcome:
    """Remove one saved answer from a feature file; its reuse ends with the next analysis."""
    try:
        doc, _sha256 = aq.load_feature(feature_path)
        if not any(a["question_fingerprint"] == question_fingerprint for a in doc["answers"]):
            raise aq.QuestionError(["no saved answer has this question fingerprint"])
        aq.save(
            feature_path,
            feature_sha256,
            doc["feature_id"],
            doc["intent"],
            [],
            remove_fingerprints=frozenset({question_fingerprint}),
        )
    except aq.QuestionError as exc:
        return Outcome(EXIT_NOT_COMPLETE, "rejected", None, f"Not removed: {exc}\n")
    return Outcome(EXIT_OK, "complete", None, f"Removed the saved answer from {feature_path.name}.\n")
