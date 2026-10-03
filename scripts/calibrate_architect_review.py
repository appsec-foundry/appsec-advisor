"""Prepare a four-packet synthetic architect calibration offline.

The review runs as dispatched agent jobs inside an assessment, so this
maintainer driver only proves that the fixture admits both planned groupings
(three one-finding packets and one three-finding packet) and records them for
a manual comparison. It never calls a model, changes a real run, or enables
review.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from analyzers.architect_review import ReviewError, fingerprint
from contexts.build_architect_context import SCHEMA_ROOT, _contracts, build_context
from jsonschema import Draft202012Validator
from referencing import Resource
from shared._atomic_io import atomic_write_json

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


def calibrate(fixture: dict, *, model: str = "sonnet") -> dict:
    """Admit one-finding and three-finding packets on the same fixed input."""
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
    result = {
        "schema_version": 1,
        "live": False,
        "model": model,
        "comparisons": [],
        "fixture_sha256": fingerprint(fixture),
        "rubric": [dict(row) for row in fixture["rubric"]],
    }
    for size in (1, 3):
        run_id = f"architect-calibration-group-{size}"
        limits = {"max_findings": size, "max_packet_bytes": 16_384, "max_packets": 3}
        # The fixture calibrates rating corrections on a Low finding, which a
        # run reviews only when its register keeps Low findings.
        manifest = build_context(
            fixture["merged"], fixture["analyst_context"], run_id=run_id, register_floor="low", **limits
        )
        if manifest["excluded"] or len(manifest["packets"]) != (3 if size == 1 else 1):
            raise ReviewError("calibration fixture does not fit both planned groupings")
        jobs = [
            {"packet_id": packet["packet_id"], "status": "prepared", "telemetry": {}} for packet in manifest["packets"]
        ]
        result["comparisons"].append({"group_size": size, "manifest": manifest, "application": None, "jobs": jobs})
    validate(result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--model", default="sonnet")
    args = parser.parse_args(argv)
    try:
        with args.fixture.open("rb") as stream:
            payload = stream.read(1_048_577)
        if len(payload) > 1_048_576:
            raise ReviewError("calibration fixture exceeds its input bound")
        fixture = json.loads(payload)
        result = calibrate(fixture, model=args.model)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(args.output_dir / "architect-calibration.json", result)
    except (OSError, ValueError, RecursionError) as exc:
        # Do not echo fixture content.
        print(f"Architect calibration failed ({type(exc).__name__}).", file=sys.stderr)
        return 1
    print("Prepared four packets offline; no model budget spent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
