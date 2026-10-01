"""Controller-owned bounded review and durable correction preservation.

The review runs as controller-dispatched ``architect_reviewer`` agent jobs:
``advance_review`` plans per-component jobs, returns them wave by wave, and
collects each job's proposal file once before applying all proposals in one
transaction. Rebuilds and the final CLI gate validate the saved transaction
and never dispatch, retry, or rewrite a report.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path

import yaml
from contexts.build_architect_context import SCHEMA_ROOT, _contracts, build_context
from jsonschema import Draft202012Validator
from orchestrator.stride_dispatch_waves import DEFAULT_CONCURRENCY
from referencing import Resource
from shared._atomic_io import atomic_write_json

from analyzers.architect_review import (
    MAX_PROPOSAL_BYTES,
    ReviewError,
    apply_review,
    fingerprint,
    project_reviewed_mitigations,
    reviewed_mitigation_errors,
)

ARTIFACT = ".architect-review.json"
# Conservative work bounds, not a measured throughput or quality claim.
LIMITS = {"max_findings": 3, "max_packet_bytes": 16_384, "max_packets": 128}
JOB_DIR = ".dispatch-context/architect"
# Packets per agent job; 24 x 16 KiB keeps one job file under 400 KiB.
JOB_PACKET_LIMIT = 24
MAX_PROPOSAL_FILE_BYTES = JOB_PACKET_LIMIT * MAX_PROPOSAL_BYTES
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


def validate_status(value: dict) -> None:
    """Raise ``ReviewError`` unless the status matches its schema and its counts agree with its outcome."""
    schema = json.loads((SCHEMA_ROOT / "architect-review-runtime.schema.json").read_text(encoding="utf-8"))
    if not Draft202012Validator(schema["$defs"]["status"]).is_valid(value):
        raise ReviewError("invalid architect status contract")
    total = value["findings_recorded"]
    if any(value[key] > total for key in ("assessment_corrected", "remediation_corrected", "unresolved_or_unreviewed")):
        raise ReviewError("architect coverage counts exceed reviewed scope")
    if (value["outcome"] == "reviewed" and value["unresolved_or_unreviewed"]) or (
        value["outcome"] == "not_run" and total
    ):
        raise ReviewError("architect outcome contradicts coverage")
    unavailable = value["outcome"] == "unavailable"
    if unavailable != ("reason" in value) or (unavailable and (not total or value.get("reviewed", 0))):
        raise ReviewError("architect outcome contradicts coverage")
    if value.get("reviewed", 0) > total or value.get("jobs_returned", 0) > value.get("jobs_dispatched", 0):
        raise ReviewError("architect coverage counts exceed reviewed scope")


def _read(path: Path) -> dict:
    if path.is_symlink():
        raise ReviewError("architect artifact must not be a symlink")
    with path.open("rb") as stream:
        raw = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(raw) > MAX_ARTIFACT_BYTES:
        raise ReviewError("architect artifact exceeds its size bound")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ReviewError("architect artifact must be an object")
    return value


def _validate(value: dict) -> None:
    _, _, _, registry = _contracts()
    for name in (
        "architect-corrections.schema.json",
        "architect-review-calibration.schema.json",
        "architect-review-runtime.schema.json",
    ):
        schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    if not Draft202012Validator(schema, registry=registry).is_valid(value):
        raise ReviewError("invalid architect runtime contract")
    ids = [packet["packet_id"] for packet in value["manifest"]["packets"]]
    if [job["packet_id"] for job in value["jobs"]] != ids:
        raise ReviewError("architect job coverage differs from admitted packets")
    if value["run_id"] != value["manifest"]["run_id"]:
        raise ReviewError("architect run identity differs from admitted packets")


def _save(output_dir: Path, value: dict) -> None:
    _validate(value)
    if len(json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode()) + 1 > MAX_ARTIFACT_BYTES:
        raise ReviewError("architect artifact exceeds its size bound")
    if (output_dir / ARTIFACT).is_symlink():
        raise ReviewError("architect artifact must not be a symlink")
    atomic_write_json(output_dir / ARTIFACT, value)


@contextmanager
def _validation_directory(value: dict):
    """Replay the original scoring contract after transient config cleanup."""
    # Use the existing validator's profile reader without restoring run state
    # or letting the artifact choose a path. Only the scoring waiver is needed.
    with tempfile.TemporaryDirectory(prefix="appsec-review-validation-") as directory:
        path = Path(directory)
        atomic_write_json(path / ".skill-config.json", {"stride_profile": value["scoring_profile"]})
        yield path


def _replay(value: dict) -> tuple[dict, dict]:
    with _validation_directory(value) as profile_dir:
        return apply_review(
            value["input"],
            value["analyst_context"],
            value["manifest"],
            value["proposals"],
            run_id=value["run_id"],
            output_dir=profile_dir,
            **LIMITS,
        )


def load_review(output_dir: Path) -> dict | None:
    """Reconstruct the accepted transaction; a saved report alone is not proof."""
    path = output_dir / ARTIFACT
    if not path.exists() and not path.is_symlink():
        return None
    value = _read(path)
    _validate(value)
    if value["phase"] != "complete":
        raise ReviewError("architect review has not completed its transaction")
    snapshot, application = _replay(value)
    if snapshot != value["snapshot"] or application != value["application"]:
        raise ReviewError("architect review transaction was altered")
    return value


def _verdict_replaced(before: object, after: object) -> bool:
    """The evidence floor fills a verdict the sampled verifier left open; nothing may replace a set one."""
    from validators.validate_evidence_lines import _RESPECTED_PRIOR_STATES

    return after != before and str(before or "").strip() in _RESPECTED_PRIOR_STATES


def _source_errors(merged: dict, value: dict) -> list[str]:
    """Ranking may add derived fields but cannot undo accepted source values."""
    rows = {row["t_id"]: row for row in merged["threats"]}
    original = {row["t_id"]: row for row in value["snapshot"]["threats"]}
    errors = []
    for correction in value["application"]["accepted"]:
        tid = correction["t_id"]
        row = rows.get(tid)
        if (
            row is None
            or any(row.get(k) != original[tid].get(k) for k in ("component_id", "evidence", "cwe", "source"))
            or _verdict_replaced(original[tid].get("evidence_check"), row.get("evidence_check"))
        ):
            errors.append(f"{tid}: reviewed finding identity or evidence changed")
            continue
        keys = []
        if correction["rating"]:
            keys.extend(("risk", "likelihood", "impact"))
        if correction["remediation"]:
            keys.extend(("mitigation_title", "remediation"))
        if any(row.get(key) != original[tid].get(key) for key in keys):
            errors.append(f"{tid}: accepted source correction changed")
    return errors


def _scoring_profile(output_dir: Path) -> dict:
    from validators.validate_intermediate import _read_stride_profile

    return {"skip_cvss_scoring": bool(_read_stride_profile(output_dir).get("skip_cvss_scoring"))}


def job_input_path(component_id: str) -> str:
    return f"{JOB_DIR}/{component_id}.json"


def job_output_path(component_id: str) -> str:
    return f"{JOB_DIR}/{component_id}.proposals.json"


def _plan_dispatch(packets: list[dict], concurrency: int) -> list[dict]:
    """One job per component packet chunk, in waves of at most ``concurrency`` jobs.

    Chunks of one component share its job paths, so they land in successive
    waves; a wave never names a component twice.
    """
    by_component: dict[str, list[str]] = {}
    for packet in packets:
        by_component.setdefault(packet["component_id"], []).append(packet["packet_id"])
    jobs: list[dict] = []
    wave_sizes: list[int] = []
    for component in sorted(by_component):
        ids = by_component[component]
        earliest = 0
        for chunk, start in enumerate(range(0, len(ids), JOB_PACKET_LIMIT), 1):
            wave = earliest
            while wave < len(wave_sizes) and wave_sizes[wave] >= concurrency:
                wave += 1
            if wave == len(wave_sizes):
                wave_sizes.append(0)
            wave_sizes[wave] += 1
            earliest = wave + 1
            jobs.append(
                {
                    "job_id": f"architect-review:{component}:{chunk}",
                    "component_id": component,
                    "packet_ids": ids[start : start + JOB_PACKET_LIMIT],
                    "wave": wave,
                    "status": "pending",
                }
            )
    return sorted(jobs, key=lambda job: (job["wave"], job["component_id"], job["job_id"]))


def _job_file(value: dict, job: dict) -> dict:
    packets = {packet["packet_id"]: packet for packet in value["manifest"]["packets"]}
    return {
        "schema_version": 1,
        "job_id": job["job_id"],
        "run_id": value["run_id"],
        "component_id": job["component_id"],
        "packets": [packets[packet_id] for packet_id in job["packet_ids"]],
    }


def _proposal_file(output_dir: Path, job: dict) -> dict | None:
    """The job's proposal file, or ``None`` when it is absent or not the contracted shape."""
    path = output_dir / job_output_path(job["component_id"])
    if path.is_symlink() or not path.is_file():
        return None
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROPOSAL_FILE_BYTES + 1)
        value = json.loads(raw) if len(raw) <= MAX_PROPOSAL_FILE_BYTES else None
    except (OSError, ValueError, RecursionError):
        return None
    schema = json.loads((SCHEMA_ROOT / "architect-review-proposals.schema.json").read_text(encoding="utf-8"))
    if not Draft202012Validator(schema).is_valid(value) or value["job_id"] != job["job_id"]:
        return None
    return value


def _collect(output_dir: Path, value: dict) -> None:
    """Record every dispatched job's result once; a returned job is never dispatched again."""
    by_packet = {row["packet_id"]: row for row in value["jobs"]}
    for job in value["dispatch_jobs"]:
        if job["status"] != "dispatched":
            continue
        path = output_dir / job_output_path(job["component_id"])
        document = _proposal_file(output_dir, job)
        if document is None:
            job["status"] = "invalid" if path.exists() or path.is_symlink() else "missing"
        else:
            job["status"] = "returned"
        for packet_id in job["packet_ids"]:
            proposal = (document or {}).get("proposals", {}).get(packet_id)
            if isinstance(proposal, dict) and len(json.dumps(proposal).encode()) <= MAX_PROPOSAL_BYTES:
                value["proposals"][packet_id] = proposal
                by_packet[packet_id]["status"] = "completed"
            else:
                by_packet[packet_id]["status"] = "invalid" if document is not None or path.exists() else "missing"


def advance_review(output_dir: Path, cfg: dict, *, concurrency: int = DEFAULT_CONCURRENCY) -> list[dict] | None:
    """Advance the review before triage by one step.

    Returns the next wave's jobs for the controller to dispatch, or ``None``
    once the transaction is complete and published (or review is disabled).
    Re-entry collects returned jobs once and never dispatches a job twice.
    """
    if not cfg.get("architect_review") or cfg.get("dry_run"):
        return None
    import fcntl

    # Lock the directory inode rather than a replaceable artifact. A duplicate
    # boundary must not consume an in-flight transaction.
    descriptor = os.open(output_dir, os.O_RDONLY)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReviewError("architect review is already running") from exc
        return _advance_review(output_dir, cfg, concurrency)
    finally:
        os.close(descriptor)


def _advance_review(output_dir: Path, cfg: dict, concurrency: int) -> list[dict] | None:
    run_id = cfg.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ReviewError("architect review requires the controller run identity")
    current = _read(output_dir / ".threats-merged.json")
    path = output_dir / ARTIFACT
    if path.exists() or path.is_symlink():
        value = _read(path)
        _validate(value)
        if value["run_id"] != run_id:
            raise ReviewError("architect review belongs to another run")
        if value["phase"] == "complete":
            value = load_review(output_dir)
            if fingerprint(current) == value["manifest"]["input_sha256"]:
                atomic_write_json(output_dir / ".threats-merged.json", value["snapshot"])
            elif _source_errors(current, value):
                raise ReviewError("accepted architect source values changed")
            return None
        if fingerprint(current) != value["manifest"]["input_sha256"]:
            raise ReviewError("architect source changed during the review")
    else:
        analyst = _read(output_dir / ".stride-analyst-context.json")
        manifest = build_context(current, analyst, run_id=run_id, output_dir=output_dir, **LIMITS)
        value = {
            "schema_version": 1,
            "run_id": run_id,
            "phase": "running",
            "input": current,
            "analyst_context": analyst,
            "manifest": manifest,
            "model": cfg.get("architect_model") or "sonnet",
            "scoring_profile": _scoring_profile(output_dir),
            "proposals": {},
            "jobs": [{"packet_id": p["packet_id"], "status": "pending", "telemetry": {}} for p in manifest["packets"]],
            "dispatch_jobs": _plan_dispatch(manifest["packets"], concurrency),
            "snapshot": None,
            "application": None,
        }
    _collect(output_dir, value)
    pending = [job for job in value["dispatch_jobs"] if job["status"] == "pending"]
    if pending:
        wave = min(job["wave"] for job in pending)
        batch = [job for job in pending if job["wave"] == wave]
        for job in batch:
            target = output_dir / job_input_path(job["component_id"])
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_json(target, _job_file(value, job))
            job["status"] = "dispatched"
        _save(output_dir, value)
        return [
            {
                "job_id": job["job_id"],
                "component_id": job["component_id"],
                "input_artifact": job_input_path(job["component_id"]),
                "output_artifact": job_output_path(job["component_id"]),
                "packet_count": len(job["packet_ids"]),
            }
            for job in batch
        ]
    for row in value["jobs"]:
        if row["status"] == "pending":
            row["status"] = "missing"
    if fingerprint(_read(output_dir / ".stride-analyst-context.json")) != value["manifest"]["context_sha256"]:
        raise ReviewError("architect context changed before publication")
    if _scoring_profile(output_dir) != value["scoring_profile"]:
        raise ReviewError("architect scoring profile changed before publication")
    value["snapshot"], value["application"] = _replay(value)
    value["phase"] = "complete"
    # Save the transaction before publishing. Re-entry can finish publication
    # from these exact bytes without repeating any dispatch.
    _save(output_dir, value)
    atomic_write_json(output_dir / ".threats-merged.json", value["snapshot"])
    return None


def review_coverage(value: dict | None) -> dict:
    """Coverage fields of the status receipt, derived from the saved transaction."""
    outcomes = value["application"]["outcomes"] if value else []
    dispatch = (value or {}).get("dispatch_jobs") or []
    unresolved = sum(
        row["status"] != "accepted" or "unresolved" in (row["assessment"], row["remediation"]) for row in outcomes
    )
    reviewed = sum(row["status"] == "accepted" for row in outcomes)
    dispatched = sum(job["status"] != "pending" for job in dispatch)
    returned = sum(job["status"] == "returned" for job in dispatch)
    if value is None:
        outcome = "not_run"
    elif outcomes and not reviewed:
        outcome = "unavailable"
    else:
        outcome = "incomplete" if unresolved else "reviewed"
    coverage = {
        "outcome": outcome,
        "findings_recorded": len(outcomes),
        "unresolved_or_unreviewed": unresolved,
        "reviewed": reviewed,
        "jobs_dispatched": dispatched,
        "jobs_returned": returned,
        "assessment_corrected": sum(row["assessment"] == "corrected" for row in outcomes),
        "remediation_corrected": sum(row["remediation"] == "corrected" for row in outcomes),
    }
    if outcome == "unavailable":
        coverage["reason"] = (
            "not_dispatched" if not dispatched else "no_proposals" if not returned else "rejected_proposals"
        )
    return coverage


def project_model(output_dir: Path, model: dict, merged: dict) -> dict:
    """Apply the accepted mitigation corrections to a rebuilt model; unchanged without a saved review."""
    value = load_review(output_dir)
    if value is None:
        return model
    if _source_errors(merged, value):
        raise ReviewError("accepted architect source values changed before rebuild")
    with _validation_directory(value) as profile_dir:
        return project_reviewed_mitigations(
            model, value["application"], merged_snapshot=value["snapshot"], output_dir=profile_dir
        )


def verify_model(output_dir: Path, model: dict) -> dict | None:
    """Raise ``ReviewError`` when the delivered model lost an accepted correction; return the saved review.

    A correction is lost when its source values changed, its finding dropped out of the register while
    still above the severity floor, or its reviewed mitigation no longer matches. ``None`` without a review.
    """
    if not isinstance(model, dict):
        raise ReviewError("architect preservation requires a canonical model object")
    value = load_review(output_dir)
    if value is None:
        return None
    errors = _source_errors(_read(output_dir / ".threats-merged.json"), value)
    from model.build_threat_model_yaml import build_threats

    cfg = _read(output_dir / ".skill-config.json") if (output_dir / ".skill-config.json").exists() else {}
    eligible, _ = build_threats(
        _read(output_dir / ".threats-merged.json"), cfg.get("register_severity_floor", "medium")
    )
    eligible_ids = {row["id"] for row in eligible}
    delivered_ids = {row["id"] for row in model.get("threats", [])}
    if any(row["t_id"] in eligible_ids - delivered_ids for row in value["application"]["accepted"]):
        errors.append("an accepted correction disappeared above the report floor")
    with _validation_directory(value) as profile_dir:
        errors.extend(
            reviewed_mitigation_errors(
                model, value["application"], merged_snapshot=value["snapshot"], output_dir=profile_dir
            )
        )
    if errors:
        raise ReviewError("accepted architect corrections were lost downstream")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        # A failed close must invalidate a previous gate receipt first.
        (args.output_dir / ".architect-status.json").unlink(missing_ok=True)
        model = yaml.safe_load((args.output_dir / "threat-model.yaml").read_text(encoding="utf-8"))
        value = verify_model(args.output_dir, model)
        cfg_path = args.output_dir / ".skill-config.json"
        cfg = _read(cfg_path) if cfg_path.exists() else {}
        if value is None and cfg.get("architect_review") and cfg.get("mode", "full") in {"full", "rebuild"}:
            raise ReviewError("required architect review transaction is missing")
        # The gate verifies preservation; review completeness is reported
        # separately, so an unavailable review still closes with status pass.
        status = {"status": "pass", "review_kind": "semantic", **review_coverage(value)}
        validate_status(status)
        atomic_write_json(args.output_dir / ".architect-status.json", status)
        reason = f" ({status['reason']})" if status.get("reason") else ""
        print(
            f"Architect review: {status['outcome']}{reason}; {status['findings_recorded']} findings recorded, "
            f"{status['unresolved_or_unreviewed']} unresolved or unreviewed."
        )
        return 0
    except (OSError, ValueError, RecursionError):
        print("Architect correction preservation gate failed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
