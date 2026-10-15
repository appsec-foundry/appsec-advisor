"""Abuse-case verification and architect review of a combined assessment.

Both stages run in the private legacy-shaped workspace of a qualified
multi-repository assessment, with the same deterministic scripts, order and
gates as the single-repository pipeline. Only the semantic dispatches differ:
each one is a tool-less job whose source reads the controller authorizes and
whose artifact is validated against a strict contract before it is written
into the workspace. Every workspace location is ``<label>/<relative path>``;
a model sees and cites qualified ``(repository_id, path)`` pairs instead.

This module sequences no other stage and publishes nothing. The controller
supplies the job runner, role instructions, script runner and enrichment.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from runtime.assessment_host import ExchangeError

from orchestrator.assessment_workspace import WorkspaceError, read_json, write_json

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
# Same bound and identifier rule as the single-repository verifier fan-out.
MAX_CANDIDATES = 64
_ABUSE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_ABUSE_GATE_EXIT = 2
# Repository-local case locations the resolver loads relative to its root.
_CASE_DIRECTORIES = ("docs/security/abuse-cases", ".appsec/abuse-cases")
_CASE_SUFFIXES = (".yaml", ".yml")
# One architect job holds up to 24 packets of 16 KiB; an exchange context is
# bounded at 256 KiB, so a large job is reviewed in several exchanges.
_ARCHITECT_EXCHANGE_BYTES = 196_608
# advance_review plans at most one job per packet (128 packets).
_MAX_ARCHITECT_WAVES = 130

_EVIDENCE = {
    "type": "object",
    "additionalProperties": False,
    "required": ["repository_id", "file", "line", "excerpt"],
    "properties": {
        "repository_id": {"type": "string", "pattern": "^repo-[a-f0-9]{16}$"},
        "file": {"type": "string", "minLength": 1, "maxLength": 512},
        "line": {"type": "integer", "minimum": 1},
        "excerpt": {"type": "string", "maxLength": 1000},
    },
}


class AssessmentReviewError(ValueError):
    """A combined review stage cannot run faithfully or its gate failed."""


def _verdict_schema(candidate: str, steps: list[int]) -> dict:
    """Strict step-verdict contract of one candidate (agents/appsec-abuse-case-verifier.md)."""
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["abuse_case_id", "step_verdicts"],
        "properties": {
            "abuse_case_id": {"const": candidate},
            "step_verdicts": {
                "type": "array",
                "minItems": len(steps),
                "maxItems": len(steps),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "step",
                        "verdict",
                        "state",
                        "matched_finding_id",
                        "reason",
                        "evidence",
                        "controls_found",
                    ],
                    "properties": {
                        "step": {"enum": steps},
                        "verdict": {"enum": ["confirmed", "blocked", "refuted", "inconclusive"]},
                        # A completed exchange has no interrupted step.
                        "state": {"const": "decided"},
                        "matched_finding_id": {"type": ["string", "null"], "maxLength": 100},
                        "reason": {"type": "string", "minLength": 1, "maxLength": 600},
                        "evidence": {"anyOf": [_EVIDENCE, {"type": "null"}]},
                        "controls_found": {
                            "type": "array",
                            "maxItems": 16,
                            "items": {"type": "string", "minLength": 1, "maxLength": 300},
                        },
                    },
                    "allOf": [
                        {
                            "if": {"properties": {"verdict": {"enum": ["confirmed", "blocked"]}}},
                            "then": {"properties": {"evidence": _EVIDENCE}},
                        }
                    ],
                },
            },
        },
    }


def scan_case_files(scope, names, files) -> list[str]:
    """Per-scan case files as paths below the assessment root, or a refusal.

    The matcher reads these files below the root it is given, which is the
    controller's copy of the admitted files, never the checkout. A sole
    repository's files sit at that root itself, so a file of that repository
    keeps its repository-relative path. Several repositories share one root
    without origin attribution, so the files are refused there.
    """
    if not files:
        return []
    if not names.single:
        raise AssessmentReviewError("per-scan abuse-case files are not supported for a multi-repository assessment yet")
    repo = scope.repositories[0]
    relative = []
    for raw in files:
        path = Path(raw)
        try:
            rel = path.resolve().relative_to(repo.root.resolve()) if path.is_absolute() else Path(raw)
        except ValueError:
            raise AssessmentReviewError(f"abuse-case file {raw} is outside the selected repository") from None
        if rel.as_posix() not in repo.files:
            raise AssessmentReviewError(f"abuse-case file {raw} is not an admitted file of the selected repository")
        relative.append(rel.as_posix())
    return relative


def reject_repository_case_files(scope, names, cfg: dict) -> None:
    """Refuse per-repository and per-scan case files the combined root cannot attribute.

    The resolver loads repository-local cases relative to one root and records
    no origin repository, so in the combined root they would be dropped or
    attributed to the wrong checkout. A sole repository's files sit at the
    combined root itself, so the resolver attributes them as a single scan does.
    """
    scan_case_files(scope, names, cfg.get("abuse_case_files"))
    if names.single:
        return
    found = []
    for repo in scope.repositories:
        label = names.prefix[repo.repository_id]
        for path in sorted(repo.files):
            for location in (path, f"{label}/{path}"):
                directory, _, name = location.rpartition("/")
                if directory in _CASE_DIRECTORIES and name.endswith(_CASE_SUFFIXES):
                    found.append(f"{label}:{path}")
                    break
    if found:
        raise AssessmentReviewError(
            "repository abuse-case files are not supported for a multi-repository assessment yet ("
            + ", ".join(found[:10])
            + "); pass --no-abuse-cases or assess that repository on its own"
        )


def _qualified_sources(names, values) -> frozenset:
    """Admitted ``(repository_id, path)`` pairs of namespaced workspace paths."""
    allowed = set()
    for value in values:
        try:
            rid, path = names.split(value)
        except WorkspaceError:
            continue
        if path in names.files.get(rid, {}):
            allowed.add((rid, path))
    return frozenset(allowed)


def _cited_paths(candidate: dict) -> list[str]:
    paths = list(candidate.get("preselected_sources") or [])
    for row in candidate.get("step_matches") or []:
        paths += [(row.get("evidence") or {}).get("file"), (row.get("source_window") or {}).get("file")]
    for step in candidate.get("chain") or []:
        paths += [anchor.get("file") for anchor in (step.get("probe") or {}).get("anchors") or []]
    for row in candidate.get("related_findings") or []:
        paths += [row.get("file"), (row.get("source_window") or {}).get("file")]
    return [path for path in paths if isinstance(path, str)]


def _validate_retrieved(artifact: dict, ranges: list[dict], allowed: frozenset) -> None:
    """Every read is authorized and every cited line was actually served."""
    for row in ranges:
        if (row["repository_id"], row["path"]) not in allowed:
            raise ExchangeError("Review job read a source outside its authorization")
    for step in artifact.get("step_verdicts") or []:
        evidence = step.get("evidence")
        if evidence is None:
            continue
        key = (evidence["repository_id"], evidence["file"])
        if key not in allowed or not any(
            (row["repository_id"], row["path"]) == key and row["start_line"] <= evidence["line"] <= row["end_line"]
            for row in ranges
        ):
            raise ExchangeError("Abuse-case evidence was not retrieved by its authorized job")


def _candidate_titles(workspace: Path) -> dict[str, str]:
    """``{AC-ID: title}`` from the matcher sidecar, for the console's progress lines.

    Best-effort: without a readable sidecar a case is shown by its ID alone.
    """
    try:
        matches = json.loads((workspace / ".abuse-case-matches.json").read_text(encoding="utf-8")).get("matches")
    except (OSError, ValueError, AttributeError):
        return {}
    return {
        str(match["abuse_case_id"]): str(match.get("title") or "").strip()
        for match in matches or []
        if isinstance(match, dict) and match.get("abuse_case_id")
    }


def _verify_candidate(scope, jobs, names, workspace: Path, candidate: str, *, instructions) -> None:
    context = read_json(workspace / ".dispatch-context/abuse-cases" / f"{candidate}.json")
    body = context["candidate"]
    steps = [row["step"] for row in body.get("chain") or body.get("steps") or []]
    if not steps:
        raise AssessmentReviewError(f"abuse-case candidate {candidate} has no steps")
    finding_ids = {row.get("matched_finding_id") for row in body.get("step_matches") or []}
    finding_ids |= {row.get("id") for row in body.get("related_findings") or []}
    finding_ids.discard(None)
    allowed = _qualified_sources(names, _cited_paths(body))

    def validate(artifact, ranges):
        _validate_retrieved(artifact, ranges, allowed)
        if sorted(row["step"] for row in artifact["step_verdicts"]) != sorted(steps):
            raise ExchangeError("Abuse-case verdict does not answer every step exactly once")
        if any(row["matched_finding_id"] not in finding_ids | {None} for row in artifact["step_verdicts"]):
            raise ExchangeError("Abuse-case verdict binds a finding outside its candidate")
        from contexts.multi_repo_analysis import validate_executable_evidence

        validate_executable_evidence(scope, artifact, "Abuse-case evidence does not cite an executable implementation")

    artifact = jobs.execute(
        role="abuse_case_verifier",
        selector="abuse:" + candidate,
        instructions=instructions(
            "abuse_case_verifier",
            "Return the step verdicts for the supplied candidate, one per step, each with state decided. "
            "File locations in the candidate are workspace paths; `sources` maps each one to the repository_id "
            "and path you may read. Only those sources are readable. Cite evidence as repository_id, file "
            "(repository-relative path), line and the verbatim excerpt of that line, and cite only lines you "
            "read in this job; a source window in the candidate is not a read. A confirmed or blocked step "
            "requires evidence. matched_finding_id is null or an id the candidate supplies.",
        ),
        context={
            "candidate_context": context,
            "sources": [
                {"repository_id": rid, "path": path, "workspace_path": names.qualify(rid, path)}
                for rid, path in sorted(allowed)
            ],
        },
        schema=_verdict_schema(candidate, steps),
        allowed_sources=allowed,
        validate=validate,
        # Without a verdict file the merge records the case as not checked (OR-39).
        on_failure=lambda reason: None,
    )
    if artifact is None:
        return
    verdict = {"abuse_case_id": candidate, "step_verdicts": []}
    for row in artifact["step_verdicts"]:
        evidence = row["evidence"]
        if evidence is not None:
            evidence = {
                "file": names.qualify(evidence["repository_id"], evidence["file"]),
                "line": evidence["line"],
                "excerpt": evidence["excerpt"],
            }
        verdict["step_verdicts"].append({**row, "evidence": evidence})
    write_json(workspace / f".abuse-case-verdict-{candidate}.json", verdict)


def _derive(jobs, workspace: Path, *, instructions) -> list[str]:
    """Thorough depth: admit model-derived business cases once, before matching (AC-12)."""
    import model.derive_abuse_cases as derive_abuse_cases

    context = read_json(derive_abuse_cases.write_context(workspace))
    schema = json.loads((PLUGIN_ROOT / "schemas/abuse-case-deriver-output.schema.json").read_text(encoding="utf-8"))

    def validate(artifact, ranges):
        if ranges:
            raise ExchangeError("The abuse-case deriver has no source authorization")

    artifact = jobs.execute(
        role="abuse_case_deriver",
        selector="abuse-derive",
        instructions=instructions(
            "abuse_case_deriver",
            "Return the proposals document for the supplied deriver context. No source files are available in "
            "this job; derive cases only from the supplied components, actors, assets and use case.",
        ),
        context=context,
        schema=schema,
        allowed_sources=frozenset(),
        validate=validate,
        # A failed derivation proposes no case; the catalog cases still run (OR-39).
        on_failure=lambda reason: {"cases": []},
    )
    write_json(workspace / derive_abuse_cases.OUTPUT_FILE, artifact)
    result = derive_abuse_cases.admit(workspace)
    write_json(workspace / ".abuse-case-derivation.json", {"schema_version": 1, **result})
    return [f"derived business cases admitted: {len(result['admitted'])}, dropped: {len(result['dropped'])}"]


def _rebuild_model(workspace: Path, root: Path, run_script, enrich) -> None:
    """Rebuild the model with verified chains; keep the controller-owned source rows."""
    from shared._atomic_io import atomic_write_text

    model_path = workspace / "threat-model.yaml"
    before = yaml.safe_load(model_path.read_text(encoding="utf-8")) or {}
    owned = {
        k: v
        for k, v in (before.get("meta") or {}).items()
        if k in ("source_repositories", "project_name", "business_context_source")
    }
    trace = before.get("business_context_trace") or {}
    attribution = {k: trace[k] for k in ("source", "source_kind") if trace.get("status") == "applied" and k in trace}
    run_script(
        "model/build_threat_model_yaml.py",
        [str(workspace), "--repo-root", str(root), "--plugin-root", str(PLUGIN_ROOT)],
    )
    if owned or attribution:
        # Repository ownership is controller-applied; a rebuild must not drop it.
        model = yaml.safe_load(model_path.read_text(encoding="utf-8"))
        model["meta"].update(owned)
        if attribution and (model.get("business_context_trace") or {}).get("status") == "applied":
            model["business_context_trace"].update(attribution)
        atomic_write_text(model_path, yaml.safe_dump(model, sort_keys=False, allow_unicode=True))
    run_script("validators/validate_intermediate.py", ["threat_model_output", str(model_path)])
    enrich()


def run_abuse_cases(
    scope, jobs, names, workspace, root, cfg, *, instructions, run_script, enrich, progress
) -> list[str]:
    """Stage 1d on the workspace: match, verify per candidate, finalize, render and gate."""
    if cfg.get("skip_abuse_case_verification"):
        return ["Abuse verification disabled"]
    reject_repository_case_files(scope, names, cfg)
    workspace, root = Path(workspace), Path(root)
    receipts: list[str] = []
    progress("Matching abuse cases")
    if cfg.get("assessment_depth") == "thorough" and not cfg.get("only_abuse_case_ids"):
        progress("Deriving application-specific business abuse cases")
        receipts += _derive(jobs, workspace, instructions=instructions)
    org = ["--org-profile", str(cfg["org_profile_path"])] if cfg.get("org_profile_path") else []
    match = run_script(
        "model/match_abuse_cases.py",
        [
            "match",
            "--output-dir",
            str(workspace),
            "--repo-root",
            str(root),
            "--signals",
            str(workspace / ".recon-signals.json"),
            # A confirmed step becomes a finding of the component listing its file.
            "--component-owned-only",
            *org,
        ],
        acceptable=(0, 1, 2),
    )
    # Cases this run was explicitly given must not degrade to a receipt.
    if match.returncode != 0 and (cfg.get("abuse_case_files") or cfg.get("only_abuse_case_ids")):
        detail = (match.stderr or match.stdout or "").strip()
        raise AssessmentReviewError(f"the abuse-case matcher rejected the selected cases: {detail[-500:]}")
    listed = run_script("model/match_abuse_cases.py", ["list-candidates", "--output-dir", str(workspace)])
    candidates = [item for item in (listed.stdout or "").split() if _ABUSE_ID_RE.fullmatch(item)]
    if len(candidates) > MAX_CANDIDATES:
        raise AssessmentReviewError(
            f"abuse verifier fan-out has {len(candidates)} candidates; maximum is {MAX_CANDIDATES}"
        )
    receipts.append(f"abuse candidates: {len(candidates)}")
    if not candidates:
        # The controller console's phase result step (`_phase_result`); the
        # numbered verification steps below count the checked cases.
        progress("Phase result: Abuse cases: none matched")
    if match.returncode != 0:
        receipts.append(f"matcher returned {match.returncode}; partial candidates retained")
    if candidates:
        run_script(
            "contexts/build_abuse_case_contexts.py",
            ["--output-dir", str(workspace), "--repo-root", str(root)]
            + [arg for candidate in candidates for arg in ("--candidate", candidate)],
        )
        titles = _candidate_titles(workspace)
        for position, candidate in enumerate(candidates, 1):
            title = f" — {titles[candidate]}" if titles.get(candidate) else ""
            progress(f"Verifying abuse case: {candidate}{title} ({position}/{len(candidates)})")
            _verify_candidate(scope, jobs, names, workspace, candidate, instructions=instructions)
    run_script("validators/verify_abuse_cases.py", ["merge", "--output-dir", str(workspace)])
    run_script("model/match_abuse_cases.py", ["finalize", "--output-dir", str(workspace)])
    run_script("model/promote_verified_abuse_cases.py", ["--output-dir", str(workspace)])
    if (workspace / ".abuse-case-verdicts.json").is_file():
        _rebuild_model(workspace, root, run_script, enrich)
        run_script("model/triage_compute_ranking.py", [str(workspace), "--if-deterministic-owner"])
    persist_abuse_cases(workspace, root, cfg, run_script)
    receipts.append("Canonical abuse-case analysis persisted")
    gate = run_script(
        "validators/abuse_case_gate.py", ["--output-dir", str(workspace)], acceptable=(0, _ABUSE_GATE_EXIT)
    )
    if gate.returncode == _ABUSE_GATE_EXIT:
        raise AssessmentReviewError("abuse-case release gate failed: " + (gate.stderr or gate.stdout).strip()[-500:])
    return receipts


def persist_abuse_cases(workspace, root, cfg, run_script) -> None:
    """Render the abuse-case section and write its canonical analysis into threat-model.yaml.

    Every model build starts the analysis at ``not_run``; a build after Stage 1d
    must call this again, or the published model loses the verified cases the
    report still shows.
    """
    org = ["--org-profile", str(cfg["org_profile_path"])] if cfg.get("org_profile_path") else []
    run_script("renderers/render_abuse_cases.py", ["--output-dir", str(workspace), "--repo-root", str(root), *org])


def _component_sources(components: dict, component_id: str, names) -> frozenset:
    component = components.get(component_id)
    if component is None:
        raise AssessmentReviewError(f"architect review names an unknown component {component_id}")
    return _qualified_sources(names, component.get("paths") or [])


def _packet_chunks(packets: list[dict]) -> list[list[dict]]:
    chunks: list[list[dict]] = [[]]
    size = 0
    for packet in packets:
        length = len(json.dumps(packet, separators=(",", ":")).encode())
        if chunks[-1] and size + length > _ARCHITECT_EXCHANGE_BYTES:
            chunks.append([])
            size = 0
        chunks[-1].append(packet)
        size += length
    return chunks


def _review_job(jobs, workspace: Path, job: dict, allowed: frozenset, *, instructions) -> dict:
    document = read_json(workspace / job["input_artifact"])
    proposals: dict = {}
    for index, packets in enumerate(_packet_chunks(document["packets"]), 1):
        packet_ids = [packet["packet_id"] for packet in packets]
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["schema_version", "job_id", "proposals"],
            "properties": {
                "schema_version": {"const": 1},
                "job_id": {"const": job["job_id"]},
                "proposals": {
                    "type": "object",
                    "propertyNames": {"enum": packet_ids},
                    "additionalProperties": {"type": "object"},
                },
            },
        }

        def validate(artifact, ranges):
            for row in ranges:
                if (row["repository_id"], row["path"]) not in allowed:
                    raise ExchangeError("Architect review read a source outside its component")

        artifact = jobs.execute(
            role="architect_reviewer",
            selector=f"architect:{job['job_id']}:{index}",
            instructions=instructions(
                "architect_reviewer",
                "Return the proposals document for the supplied job packets, one correction proposal per "
                "packet_id under the architect correction contract. `sources` lists the only files you may "
                "read, the reviewed component's own sources; read them only to check a rating or a fix.",
            ),
            context={
                **{key: document[key] for key in ("schema_version", "job_id", "run_id", "component_id")},
                "packets": packets,
                "sources": [{"repository_id": rid, "path": path} for rid, path in sorted(allowed)],
            },
            schema=schema,
            allowed_sources=allowed,
            validate=validate,
            # Packets without a proposal stay unreviewed, which OR-33 reports (OR-39).
            on_failure=lambda reason: {"proposals": {}},
        )
        proposals.update(artifact["proposals"])
    return {"schema_version": 1, "job_id": job["job_id"], "proposals": proposals}


def run_architect_review(scope, jobs, names, workspace, cfg, *, instructions, run_script, progress) -> list[str]:
    """Review every evidenced finding per component before triage; apply corrections deterministically."""
    from analyzers.architect_review import ReviewError
    from analyzers.architect_review_runtime import advance_review, load_review, review_coverage

    if not cfg.get("architect_review") or cfg.get("dry_run"):
        return ["Architect review disabled"]
    workspace = Path(workspace)
    analyst = workspace / ".stride-analyst-context.json"
    if not analyst.exists():
        # No per-component business or architecture declarations exist in a
        # combined assessment; the review context records them as null.
        write_json(analyst, {})
    review_cfg = {**cfg, "run_id": cfg.get("run_id") or "assessment-" + scope.inventory()["scope_sha256"][:32]}
    components = {row["id"]: row for row in read_json(workspace / ".components.json")["components"]}
    try:
        for _ in range(_MAX_ARCHITECT_WAVES):
            wave = advance_review(workspace, review_cfg)
            if wave is None:
                break
            for job in wave:
                progress("Reviewing findings as architect: " + job["component_id"])
                allowed = _component_sources(components, job["component_id"], names)
                proposals = _review_job(jobs, workspace, job, allowed, instructions=instructions)
                write_json(workspace / job["output_artifact"], proposals)
        else:
            raise AssessmentReviewError("architect review exceeded its wave bound")
        coverage = review_coverage(load_review(workspace))
    except (OSError, ReviewError) as exc:
        raise AssessmentReviewError("architect review transaction failed") from exc
    run_script("validators/validate_intermediate.py", ["threats_merged", str(workspace / ".threats-merged.json")])
    return [
        f"architect review {coverage['outcome']}: {coverage['reviewed']} reviewed, "
        f"{coverage['unreviewed']} unreviewed, {coverage['unresolved']} unresolved"
    ]
