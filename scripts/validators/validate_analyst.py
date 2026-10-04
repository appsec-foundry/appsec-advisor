#!/usr/bin/env python3
"""validators/validate_analyst.py — contracts of the on-demand threat analysis job.

Validates the controller-owned request, state, and snapshot artifacts and the
untrusted model response against ``schemas/analyst-*.schema.json`` and
enforces the rules JSON Schema cannot express: mode and scope agreement, limit
relationships, canonical paths, the state machine, terminal reasons, snapshot
bounds, source receipts (every cited excerpt must occur at the cited lines of
an admitted file), change attribution backed by comparison evidence, and
references to delivered questions, criteria, and requirements only. Schema
validity alone is never treated as evidence.

Every function returns a list of error strings; an empty list means valid.
Schema error text names the failing location and keyword, never the rejected
value, so a diagnostic cannot leak admitted content. A missing ``jsonschema``
package fails closed.
"""

from __future__ import annotations

import json
import posixpath
from collections import Counter
from functools import cache
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas"
SCHEMAS = {
    "request": "analyst-request.schema.json",
    "state": "analyst-state.schema.json",
    "snapshot": "analyst-snapshot.schema.json",
    "context": "analyst-context.schema.json",
    "response": "analyst-response.schema.json",
    "result": "analyst-result.schema.json",
    "feature": "analyst-feature.schema.json",
}

TERMINAL_REASONS = {
    "complete": frozenset({"analysis_complete", "empty_scope"}),
    "incomplete": frozenset({"required_answers_missing", "required_input_missing", "limit_exhausted"}),
    "failed": frozenset({"invalid_model_output", "transport_failure", "validation_failure"}),
    "cancelled": frozenset({"cancelled_by_user", "terminated"}),
}
TRANSITIONS = {
    "prepared": frozenset({"analyzing", "complete", "incomplete", "failed", "cancelled"}),
    "analyzing": frozenset({"awaiting_answers", "complete", "incomplete", "failed", "cancelled"}),
    "awaiting_answers": frozenset({"analyzing", "incomplete", "failed", "cancelled"}),
}
COUNTERS = ("host_calls", "evidence_rounds", "question_rounds", "transport_retries")
REQUIRED_OBJECTS = {
    "design": frozenset({"design_sha256"}),
    "commits": frozenset({"head", "base"}),
    "staged": frozenset({"head"}),
    "worktree": frozenset({"head"}),
}
_STRUCTURAL_KEYWORDS = frozenset({"required", "additionalProperties"})


@cache
def _schema(kind: str) -> dict:
    return json.loads((SCHEMA_DIR / SCHEMAS[kind]).read_text(encoding="utf-8"))


def schema_errors(kind: str, data: object) -> list[str]:
    """Return structural errors of ``data`` against the ``kind`` schema."""
    try:
        from jsonschema import Draft202012Validator
    except ModuleNotFoundError:
        return ["jsonschema not installed; analyst contracts fail closed"]
    errors = []
    for err in sorted(Draft202012Validator(_schema(kind)).iter_errors(data), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        detail = err.message if err.validator in _STRUCTURAL_KEYWORDS else f"violates {err.validator}"
        errors.append(f"{kind}: {loc}: {detail}")
    return errors


def _is_canonical(path: str) -> bool:
    return posixpath.isabs(path) and posixpath.normpath(path) == path and not path.startswith("//")


def validate_request(data: object) -> list[str]:
    """Validate an analyst request."""
    errors = schema_errors("request", data)
    if errors:
        return errors
    scope = data["scope"]
    if (data["mode"] == "design") != (scope["kind"] == "design"):
        errors.append(f"request: mode {data['mode']} does not match scope {scope['kind']}")
    paths = {"repository/root": data["repository"]["root"], "output_dir": data["output_dir"]}
    if "feature" in data:
        paths["feature/path"] = data["feature"]["path"]
    if "design_path" in scope:
        paths["scope/design_path"] = scope["design_path"]
    if scope["kind"] == "design" and (scope["source"] == "file") != ("design_path" in scope):
        errors.append("request: scope/design_path is required exactly for a design file")
    errors += [
        f"request: {name} is not a canonical absolute path" for name, path in paths.items() if not _is_canonical(path)
    ]
    limits = data["limits"]
    if limits["call_seconds"] > limits["job_seconds"]:
        errors.append("request: limits/call_seconds exceeds limits/job_seconds")
    if limits["file_kib"] > limits["job_kib"]:
        errors.append("request: limits/file_kib exceeds limits/job_kib")
    counts = Counter(package["id"] for package in data["packages"])
    errors += [f"request: package {pid} is selected more than once" for pid, n in sorted(counts.items()) if n > 1]
    return errors


def validate_state(data: object, limits: dict | None = None) -> list[str]:
    """Validate one state document, optionally against the request limits."""
    errors = schema_errors("state", data)
    if errors:
        return errors
    state, reason = data["state"], data["terminal_reason"]
    if state in TERMINAL_REASONS:
        if reason not in TERMINAL_REASONS[state]:
            errors.append(f"state: terminal state {state} requires a matching terminal_reason")
    elif reason is not None:
        errors.append(f"state: non-terminal state {state} carries a terminal_reason")
    if data["pending_questions"] and state not in ("awaiting_answers", "incomplete"):
        errors.append(f"state: pending questions are not allowed in state {state}")
    if state == "awaiting_answers" and not data["pending_questions"]:
        errors.append("state: awaiting_answers requires pending questions")
    if limits is not None:
        errors += [
            f"state: counters/{name} exceeds limits/{name}"
            for name in COUNTERS
            if data["counters"][name] > limits[name]
        ]
    return errors


def validate_transition(previous: dict, current: dict) -> list[str]:
    """Validate a state change of one job; both documents must already be valid."""
    if previous["job_id"] != current["job_id"]:
        return ["transition: job_id changed"]
    errors = []
    old, new = previous["state"], current["state"]
    if old in TERMINAL_REASONS:
        errors.append(f"transition: terminal state {old} cannot change")
    elif new != old and new not in TRANSITIONS[old]:
        errors.append(f"transition: {old} -> {new} is not allowed")
    errors += [
        f"transition: counters/{name} decreased"
        for name in COUNTERS
        if current["counters"][name] < previous["counters"][name]
    ]
    if previous["input_fingerprint"] != current["input_fingerprint"] and (old, new) != (
        "awaiting_answers",
        "analyzing",
    ):
        errors.append("transition: input_fingerprint may change only when answers resume analysis")
    return errors


def validate_snapshot(data: object, request: dict | None = None) -> list[str]:
    """Validate a snapshot, optionally against the request it serves."""
    errors = schema_errors("snapshot", data)
    if errors:
        return errors
    kind, objects = data["scope_kind"], data["objects"]
    missing = REQUIRED_OBJECTS[kind] - objects.keys()
    if missing:
        errors.append(f"snapshot: scope {kind} requires objects {sorted(missing)}")
    if kind == "design":
        if set(objects) != {"design_sha256"}:
            errors.append("snapshot: a design scope carries no source objects")
        if data["admitted"]:
            errors.append("snapshot: a design scope admits no source files")
    elif "design_sha256" in objects:
        errors.append("snapshot: a review scope carries no design hash")
    sides = Counter((entry["side"], entry["path"]) for entry in data["admitted"])
    if any(n > 1 for n in sides.values()):
        errors.append("snapshot: a path is admitted twice on the same side")
    if any((entry["change"] == "renamed") != ("previous_path" in entry) for entry in data["admitted"]):
        errors.append("snapshot: previous_path is required exactly for a renamed entry")
    if any("path" in entry and entry["count"] != 1 for entry in data["excluded"]):
        errors.append("snapshot: an excluded path entry must have count 1")
    if request is not None:
        errors += _snapshot_against_request(data, request)
    return errors


def _snapshot_against_request(data: dict, request: dict) -> list[str]:
    errors = []
    if data["job_id"] != request["job_id"]:
        errors.append("snapshot: job_id does not match the request")
    scope = request["scope"]
    if data["scope_kind"] != scope["kind"]:
        errors.append("snapshot: scope_kind does not match the request")
    if scope["kind"] == "commits" and scope["comparison"] == "merge_base" and "merge_base" not in data["objects"]:
        errors.append("snapshot: a merge-base comparison requires objects/merge_base")
    if scope["kind"] == "design" and data["objects"].get("design_sha256") != scope["content_sha256"]:
        errors.append("snapshot: design_sha256 does not match the request")
    limits, admitted = request["limits"], data["admitted"]
    if len(admitted) > limits["admitted_files"]:
        errors.append("snapshot: admitted files exceed limits/admitted_files")
    if any(entry["bytes"] > limits["file_kib"] * 1024 for entry in admitted):
        errors.append("snapshot: an admitted file exceeds limits/file_kib")
    if sum(entry["bytes"] for entry in admitted) > limits["job_kib"] * 1024:
        errors.append("snapshot: admitted bytes exceed limits/job_kib")
    return errors


_CHANGED = frozenset({"added", "modified", "renamed"})


def _normalize(text: str) -> str:
    return " ".join(text.split())


def _location_errors(location: dict, admitted: dict, source_dir: Path, label: str) -> list[str]:
    key = (location["side"], location["path"])
    if key not in admitted:
        return [f"{label}: cites a file that is not admitted on the {location['side']} side"]
    if location["line_start"] > location["line_end"]:
        return [f"{label}: line range is reversed"]
    try:
        lines = (
            (source_dir / location["side"] / location["path"])
            .read_text(encoding="utf-8", errors="replace")
            .splitlines()
        )
    except OSError:
        return [f"{label}: admitted source is unavailable"]
    if location["line_end"] > len(lines):
        return [f"{label}: line range exceeds the file"]
    cited = _normalize("\n".join(lines[location["line_start"] - 1 : location["line_end"]]))
    if _normalize(location["excerpt"]) not in cited:
        return [f"{label}: excerpt does not occur at the cited lines"]
    return []


def _is_new_code(location: dict, admitted: dict, source_dir: Path) -> bool:
    """Whether a proposed-state excerpt is absent from the file's baseline version."""
    entry = admitted.get(("proposed", location["path"]))
    if location["side"] != "proposed" or entry is None or entry["change"] not in _CHANGED:
        return False
    if ("baseline", location["path"]) not in admitted:
        return entry["change"] == "added"
    try:
        baseline = (source_dir / "baseline" / location["path"]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return _normalize(location["excerpt"]) not in _normalize(baseline)


def _relationship_errors(finding: dict, admitted: dict, source_dir: Path, label: str) -> list[str]:
    relationship = finding["change_relationship"]
    locations = finding["evidence"] + finding["comparison"]
    sides = {loc["side"] for loc in finding["comparison"]}
    if relationship == "introduced":
        if not any(_is_new_code(loc, admitted, source_dir) for loc in locations):
            return [f"{label}: 'introduced' needs evidence from code that the change added"]
    elif relationship in ("worsened", "mitigated"):
        if sides != {"baseline", "proposed"}:
            return [
                f"{label}: '{relationship}' needs comparison evidence from both the baseline and the proposed state"
            ]
    elif relationship == "unchanged_preexisting" and not finding["comparison"]:
        return [f"{label}: 'unchanged_preexisting' needs comparison evidence"]
    return []


def validate_response(response: object, request: dict, snapshot: dict, context: dict, source_dir: Path) -> list[str]:
    """Validate one untrusted model response against what the job delivered."""
    errors = schema_errors("response", response)
    if errors:
        return errors
    if len(json.dumps(response).encode("utf-8")) > request["limits"]["response_kib"] * 1024:
        return ["response: exceeds limits/response_kib"]
    admitted = {(e["side"], e["path"]): e for e in snapshot["admitted"]}
    requirement_ids = {r["id"] for r in context["requirements"]}
    criteria = {c["ref"] for c in context["criteria"]}
    delivered = [q["ref"] for q in context["questions"]]
    design = request["mode"] == "design"

    if design and response["findings"]:
        errors.append("response: a design analysis reports scenarios and assumptions, not findings")
    for i, finding in enumerate(response["findings"]):
        label = f"response: findings/{i}"
        for j, location in enumerate(finding["evidence"] + finding["comparison"]):
            errors += _location_errors(location, admitted, source_dir, f"{label}/location {j}")
        errors += _relationship_errors(finding, admitted, source_dir, label)
    for i, assumption in enumerate(response["assumptions"]):
        label = f"response: assumptions/{i}"
        evidence = assumption.get("evidence", [])
        if assumption["status"] in ("supported", "contradicted") and (design or not evidence):
            errors.append(f"{label}: '{assumption['status']}' needs evidence from a reviewed change")
        for j, location in enumerate(evidence):
            errors += _location_errors(location, admitted, source_dir, f"{label}/location {j}")
    for i, observation in enumerate(response["requirement_observations"]):
        for j, location in enumerate(observation.get("evidence", [])):
            errors += _location_errors(
                location, admitted, source_dir, f"response: requirement_observations/{i}/location {j}"
            )
    cited = [ref for item in response["findings"] + response["scenarios"] for ref in item.get("requirement_refs", [])]
    cited += [o["requirement_ref"] for o in response["requirement_observations"]]
    if set(cited) - requirement_ids:
        errors.append(f"response: {len(set(cited) - requirement_ids)} cited requirement(s) were not delivered")
    errors += [
        "response: a methodology observation names an undelivered criterion"
        for o in response["methodology_observations"]
        if o["criterion_ref"] not in criteria
    ][:1]
    covered = Counter(c["question_ref"] for c in response["question_coverage"])
    if set(covered) != set(delivered) or any(n > 1 for n in covered.values()):
        errors.append("response: question_coverage must list every delivered question exactly once")
    if any(q.get("question_ref") not in (None, *delivered) for q in response["questions"]):
        errors.append("response: a question names an undelivered catalog entry")
    return errors


def validate_result(result: object) -> list[str]:
    """Validate a result document before publication."""
    errors = schema_errors("result", result)
    if errors:
        return errors
    if result["state"] == "complete" and not result["coverage"]["required_complete"]:
        errors.append("result: a complete result requires complete required coverage")
    if result["state"] == "complete" and any(q["required"] for q in result["questions"]):
        errors.append("result: a complete result cannot leave required questions open")
    if result["mode"] == "design" and result["findings"]:
        errors.append("result: a design result carries no findings")
    return errors
