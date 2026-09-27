"""Controller-owned bounded review and durable correction preservation.

Only run_review calls a model. Rebuilds and the final CLI gate validate the
saved transaction and never dispatch, retry, or rewrite a report.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import yaml
from _atomic_io import atomic_write_json
from architect_review import (
    ReviewError,
    apply_review,
    fingerprint,
    project_reviewed_mitigations,
    reviewed_mitigation_errors,
)
from architect_review_worker import run_packet
from build_architect_context import SCHEMA_ROOT, _contracts, build_context
from jsonschema import Draft202012Validator
from referencing import Resource

ARTIFACT = ".architect-review.json"
# Conservative work bounds, not a measured throughput or quality claim.
LIMITS = {"max_findings": 3, "max_packet_bytes": 16_384, "max_packets": 128}
JOB_SECONDS = 90
STAGE_SECONDS = 360
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024


def validate_status(value: dict) -> None:
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


def _source_errors(merged: dict, value: dict) -> list[str]:
    """Ranking may add derived fields but cannot undo accepted source values."""
    rows = {row["t_id"]: row for row in merged["threats"]}
    original = {row["t_id"]: row for row in value["snapshot"]["threats"]}
    errors = []
    for correction in value["application"]["accepted"]:
        tid = correction["t_id"]
        row = rows.get(tid)
        if row is None or any(
            row.get(k) != original[tid].get(k) for k in ("component_id", "evidence", "evidence_check", "cwe", "source")
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
    from validate_intermediate import _read_stride_profile

    return {"skip_cvss_scoring": bool(_read_stride_profile(output_dir).get("skip_cvss_scoring"))}


def run_review(output_dir: Path, cfg: dict) -> dict | None:
    """Review once before triage; recover a saved transaction without new calls."""
    if not cfg.get("architect_review") or cfg.get("dry_run"):
        return None
    import fcntl

    # Lock the directory inode rather than a replaceable artifact. A duplicate
    # boundary must not consume an in-flight transaction or start another call.
    descriptor = os.open(output_dir, os.O_RDONLY)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ReviewError("architect review is already running") from exc
        return _run_review(output_dir, cfg)
    finally:
        os.close(descriptor)


def _run_review(output_dir: Path, cfg: dict) -> dict:
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
            return value
        # A crash may have happened inside the host. Do not re-spend that call
        # or reset the stage allowance on re-entry.
        if fingerprint(current) != value["manifest"]["input_sha256"]:
            raise ReviewError("architect source changed during interrupted review")
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
            "jobs": [
                {"packet_id": p["packet_id"], "status": "stage_exhausted", "telemetry": {}} for p in manifest["packets"]
            ],
            "snapshot": None,
            "application": None,
        }
        _save(output_dir, value)
        deadline = time.monotonic() + STAGE_SECONDS
        for packet, job in zip(manifest["packets"], value["jobs"], strict=True):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            job["status"] = "interrupted"
            _save(output_dir, value)
            status, proposal = run_packet(
                packet, model=value["model"], timeout_seconds=min(JOB_SECONDS, remaining), telemetry=job["telemetry"]
            )
            job["status"] = status
            if proposal is not None:
                value["proposals"][packet["packet_id"]] = proposal
            _save(output_dir, value)
            if status in {"unavailable", "unsupported_host", "failed", "deadline_exceeded", "output_limit_exceeded"}:
                # An unavailable host must not cost one timeout per packet.
                break
        if fingerprint(_read(output_dir / ".threats-merged.json")) != manifest["input_sha256"]:
            raise ReviewError("architect source changed while the host was running")
    if fingerprint(_read(output_dir / ".stride-analyst-context.json")) != value["manifest"]["context_sha256"]:
        raise ReviewError("architect context changed before publication")
    if _scoring_profile(output_dir) != value["scoring_profile"]:
        raise ReviewError("architect scoring profile changed before publication")
    value["snapshot"], value["application"] = _replay(value)
    value["phase"] = "complete"
    # Save the transaction before publishing. Re-entry can finish publication
    # from these exact bytes without repeating any model calls.
    _save(output_dir, value)
    atomic_write_json(output_dir / ".threats-merged.json", value["snapshot"])
    return value


def project_model(output_dir: Path, model: dict, merged: dict) -> dict:
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
    if not isinstance(model, dict):
        raise ReviewError("architect preservation requires a canonical model object")
    value = load_review(output_dir)
    if value is None:
        return None
    errors = _source_errors(_read(output_dir / ".threats-merged.json"), value)
    from build_threat_model_yaml import build_threats

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
        outcomes = value["application"]["outcomes"] if value else []
        unresolved = sum(
            row["status"] != "accepted" or "unresolved" in (row["assessment"], row["remediation"]) for row in outcomes
        )
        outcome = "not_run" if value is None else ("incomplete" if unresolved else "reviewed")
        status = {
            "status": "pass",
            "outcome": outcome,
            "review_kind": "semantic",
            "findings_recorded": len(outcomes),
            "unresolved_or_unreviewed": unresolved,
            "assessment_corrected": sum(row["assessment"] == "corrected" for row in outcomes),
            "remediation_corrected": sum(row["remediation"] == "corrected" for row in outcomes),
        }
        validate_status(status)
        atomic_write_json(args.output_dir / ".architect-status.json", status)
        print(f"Architect review: {outcome}; {len(outcomes)} findings recorded, {unresolved} unresolved or unreviewed.")
        return 0
    except (OSError, ValueError, RecursionError):
        print("Architect correction preservation gate failed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
