"""Prepare or explicitly run a four-call synthetic architect calibration.

Default execution is offline. --live spends model budget and must be approved
separately. This maintainer driver never changes a real run or enables review.
Transport acceptance is not a semantic quality verdict; inspect the fixture's
rubric against the accepted before/after values in the output.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import re
import sys
import time
from pathlib import Path

from _atomic_io import atomic_write_json
from architect_review import ReviewError, apply_review, fingerprint
from architect_review_worker import run_packet
from build_architect_context import SCHEMA_ROOT, _contracts, build_context
from jsonschema import Draft202012Validator
from referencing import Resource

DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent / "tests/fixtures/architect-review/calibration.json"
SCHEMA_NAME = "architect-review-calibration.schema.json"


def validate(value: dict, *, fixture: bool = False) -> None:
    """Resolve only plugin-owned schema resources, without network retrieval."""
    _, _, _, registry = _contracts()
    schema = json.loads((SCHEMA_ROOT / SCHEMA_NAME).read_text(encoding="utf-8"))
    corrections = json.loads((SCHEMA_ROOT / "architect-corrections.schema.json").read_text(encoding="utf-8"))
    registry = registry.with_resources((doc["$id"], Resource.from_contents(doc)) for doc in (schema, corrections))
    ref = schema["$id"] + ("#/$defs/fixture" if fixture else "")
    if not Draft202012Validator({"$ref": ref}, registry=registry).is_valid(value):
        raise ReviewError("invalid architect calibration contract")


def calibrate(
    fixture: dict, *, live: bool = False, model: str = "sonnet", job_seconds: float = 90, stage_seconds: float = 360
) -> dict:
    """Compare one-finding and three-finding packets on the same fixed input."""
    if type(live) is not bool:
        raise ReviewError("calibration requires an explicit boolean live selection")
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}", model):
        raise ReviewError("invalid calibration model")
    validate(fixture, fixture=True)
    if (
        len(fixture["merged"]["threats"]) != 3
        or len({row["component_id"] for row in fixture["merged"]["threats"]}) != 1
    ):
        raise ReviewError("calibration requires exactly three findings in one component")
    if {row["t_id"] for row in fixture["rubric"]} != {row["t_id"] for row in fixture["merged"]["threats"]}:
        raise ReviewError("calibration rubric does not cover its findings")
    if (
        type(job_seconds) not in (int, float)
        or type(stage_seconds) not in (int, float)
        or not math.isfinite(job_seconds)
        or not math.isfinite(stage_seconds)
        or not 0 < job_seconds <= 90
        or not 0 < stage_seconds <= 360
    ):
        raise ReviewError("invalid calibration execution bounds")
    result = {
        "schema_version": 1,
        "live": live,
        "model": model,
        "limits": {"job_seconds": job_seconds, "stage_seconds": stage_seconds, "max_worker_calls": 4},
        "comparisons": [],
        "fixture_sha256": fingerprint(fixture),
        "rubric": copy.deepcopy(fixture["rubric"]),
    }
    deadline = time.monotonic() + stage_seconds
    calls = 0
    # Admit both groupings before spending anything. A large three-finding
    # packet must not split after the singleton calls have already been paid.
    for size in (1, 3):
        run_id = f"architect-calibration-group-{size}"
        limits = {"max_findings": size, "max_packet_bytes": 16_384, "max_packets": 3}
        manifest = build_context(fixture["merged"], fixture["analyst_context"], run_id=run_id, **limits)
        if manifest["excluded"] or len(manifest["packets"]) != (3 if size == 1 else 1):
            raise ReviewError("calibration fixture does not fit both planned groupings")
        result["comparisons"].append({"group_size": size, "manifest": manifest, "application": None, "jobs": []})
    for comparison in result["comparisons"]:
        manifest = comparison["manifest"]
        proposals = {}
        for packet in manifest["packets"]:
            remaining = deadline - time.monotonic()
            telemetry: dict = {}
            if not live:
                status, proposal = "prepared", None
            elif remaining <= 0 or calls >= 4:
                status, proposal = "stage_exhausted", None
            else:
                calls += 1
                status, proposal = run_packet(
                    packet, model=model, timeout_seconds=min(job_seconds, remaining), telemetry=telemetry
                )
            comparison["jobs"].append({"packet_id": packet["packet_id"], "status": status, "telemetry": telemetry})
            if proposal is not None:
                proposals[packet["packet_id"]] = proposal
        if live:
            _, comparison["application"] = apply_review(
                fixture["merged"],
                fixture["analyst_context"],
                manifest,
                proposals,
                run_id=manifest["run_id"],
                **manifest["limits"],
            )
    validate(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--live", action="store_true", help="Explicitly spend model budget; up to four calls, six minutes total"
    )
    parser.add_argument("--model", default="sonnet")
    args = parser.parse_args(argv)
    try:
        with args.fixture.open("rb") as stream:
            payload = stream.read(1_048_577)
        if len(payload) > 1_048_576:
            raise ReviewError("calibration fixture exceeds its input bound")
        fixture = json.loads(payload)
        result = calibrate(fixture, live=args.live, model=args.model)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(args.output_dir / "architect-calibration.json", result)
    except (OSError, ValueError, RecursionError) as exc:
        # Do not echo fixture content or raw host diagnostics.
        print(f"Architect calibration failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    if args.live and any(
        any(job["status"] != "completed" for job in comparison["jobs"])
        or any(outcome["status"] != "accepted" for outcome in comparison["application"]["outcomes"])
        for comparison in result["comparisons"]
    ):
        print("Live calibration is incomplete or has rejected results; inspect architect-calibration.json.")
        return 2
    print(
        "Live calibration recorded; review the semantic rubric."
        if args.live
        else "Prepared four calls offline; no model budget spent."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
