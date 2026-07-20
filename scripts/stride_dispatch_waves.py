#!/usr/bin/env python3
"""Plan bounded STRIDE dispatch waves and verify component completion.

The dispatch manifest remains the source of truth for analyzer prompts. This
helper adds only deterministic scheduling state: stable waves of component IDs
and a strict completion check over the corresponding ``.stride-<id>.json``
files. Completed files are the resume checkpoint, so re-running ``next`` after
an interrupted parent session returns only unfinished components from the
earliest incomplete wave.

Exit codes:
  0  command succeeded; ``verify`` found complete coverage
  1  ``verify`` found missing, partial, or invalid component output
  2  invalid invocation, manifest, or wave plan
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from validate_intermediate import validate_stride

DEFAULT_CONCURRENCY = 8
MAX_CONCURRENCY = 32
PLAN_NAME = ".dispatch-waves.json"
_COMPONENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class WavePlanError(ValueError):
    """The manifest or persisted wave plan violates the scheduling contract."""


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise WavePlanError(f"could not read {label} {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise WavePlanError(f"invalid JSON in {label} {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise WavePlanError(f"{label} root must be a JSON object: {path}")
    return data


def _manifest_components(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    raw = manifest.get("components")
    if not isinstance(raw, list) or not raw:
        raise WavePlanError("dispatch manifest components must be a non-empty array")
    components: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, component in enumerate(raw):
        if not isinstance(component, dict):
            raise WavePlanError(f"dispatch manifest components[{index}] must be an object")
        component_id = component.get("component_id")
        if not isinstance(component_id, str) or not _COMPONENT_ID_RE.fullmatch(component_id):
            raise WavePlanError(f"invalid component_id at components[{index}]: {component_id!r}")
        if component_id in seen:
            raise WavePlanError(f"duplicate component_id in dispatch manifest: {component_id}")
        seen.add(component_id)
        components.append(component)
    return components


def _fingerprint(manifest: dict[str, Any]) -> str:
    components = _manifest_components(manifest)
    stable = {
        "generated_at": manifest.get("generated_at"),
        "components": components,
    }
    encoded = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_plan(manifest: dict[str, Any], concurrency: int) -> dict[str, Any]:
    if isinstance(concurrency, bool) or not isinstance(concurrency, int) or not 1 <= concurrency <= MAX_CONCURRENCY:
        raise WavePlanError(f"concurrency must be between 1 and {MAX_CONCURRENCY}")
    component_ids = [component["component_id"] for component in _manifest_components(manifest)]
    waves = [
        {"index": offset // concurrency + 1, "component_ids": component_ids[offset : offset + concurrency]}
        for offset in range(0, len(component_ids), concurrency)
    ]
    return {
        "schema_version": 1,
        "manifest_fingerprint": _fingerprint(manifest),
        "manifest_generated_at": manifest.get("generated_at"),
        "concurrency": concurrency,
        "component_ids": component_ids,
        "attempts": {component_id: 0 for component_id in component_ids},
        "waves": waves,
    }


def validate_plan(plan: dict[str, Any], manifest: dict[str, Any]) -> None:
    if plan.get("schema_version") != 1:
        raise WavePlanError("wave plan schema_version must be 1")
    concurrency = plan.get("concurrency")
    if not isinstance(concurrency, int) or isinstance(concurrency, bool) or not 1 <= concurrency <= MAX_CONCURRENCY:
        raise WavePlanError(f"wave plan concurrency must be between 1 and {MAX_CONCURRENCY}")
    if plan.get("manifest_fingerprint") != _fingerprint(manifest):
        raise WavePlanError("wave plan does not match the current dispatch manifest")

    expected = [component["component_id"] for component in _manifest_components(manifest)]
    if plan.get("component_ids") != expected:
        raise WavePlanError("wave plan component_ids do not preserve manifest order")
    attempts = plan.get("attempts")
    if not isinstance(attempts, dict) or set(attempts) != set(expected):
        raise WavePlanError("wave plan attempts must cover every manifest component exactly once")
    if any(not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 2 for value in attempts.values()):
        raise WavePlanError("wave plan attempt counts must be integers between 0 and 2")
    waves = plan.get("waves")
    if not isinstance(waves, list) or not waves:
        raise WavePlanError("wave plan waves must be a non-empty array")
    flattened: list[str] = []
    for expected_index, wave in enumerate(waves, start=1):
        if not isinstance(wave, dict) or wave.get("index") != expected_index:
            raise WavePlanError("wave indexes must be contiguous and one-based")
        ids = wave.get("component_ids")
        if not isinstance(ids, list) or not ids or len(ids) > concurrency:
            raise WavePlanError(f"wave {expected_index} must contain 1..{concurrency} component IDs")
        if not all(isinstance(component_id, str) for component_id in ids):
            raise WavePlanError(f"wave {expected_index} component_ids must be strings")
        flattened.extend(ids)
    if flattened != expected:
        raise WavePlanError("waves must cover every manifest component exactly once and in order")


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def completion_error(output_dir: Path, component_id: str) -> str | None:
    path = output_dir / f".stride-{component_id}.json"
    if not path.is_file():
        return "missing output"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return f"unreadable or invalid JSON: {exc}"
    if not isinstance(data, dict):
        return "output root is not an object"
    if data.get("component_id") != component_id:
        return f"component_id mismatch: {data.get('component_id')!r}"
    if data.get("partial") is not False:
        return "partial is not false"
    if data.get("skipped_categories") != []:
        return "skipped_categories is not empty"
    if not isinstance(data.get("threats"), list):
        return "threats is not an array"
    ok, errors = validate_stride(data)
    if not ok:
        return "schema validation failed: " + "; ".join(errors[:3])
    return None


def status(plan: dict[str, Any], manifest: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    validate_plan(plan, manifest)
    by_id = {component["component_id"]: component for component in _manifest_components(manifest)}
    wave_rows: list[dict[str, Any]] = []
    all_incomplete: list[dict[str, str]] = []
    next_wave: dict[str, Any] | None = None
    complete_count = 0

    for wave in plan["waves"]:
        incomplete: list[dict[str, str]] = []
        complete_ids: list[str] = []
        for component_id in wave["component_ids"]:
            error = completion_error(output_dir, component_id)
            if error is None:
                complete_ids.append(component_id)
                complete_count += 1
            else:
                row = {"component_id": component_id, "reason": error}
                incomplete.append(row)
                all_incomplete.append(row)
        wave_rows.append(
            {
                "index": wave["index"],
                "complete_ids": complete_ids,
                "incomplete": incomplete,
            }
        )
        if incomplete and next_wave is None:
            pending_ids = [row["component_id"] for row in incomplete]
            next_wave = {
                "index": wave["index"],
                "total_waves": len(plan["waves"]),
                "components": [by_id[component_id] for component_id in pending_ids],
                "attempts": {component_id: plan["attempts"][component_id] for component_id in pending_ids},
            }

    return {
        "status": "complete" if not all_incomplete else "pending",
        "complete": complete_count,
        "total": len(plan["component_ids"]),
        "concurrency": plan["concurrency"],
        "waves": wave_rows,
        "incomplete": all_incomplete,
        "next_wave": next_wave,
    }


def claim(plan: dict[str, Any], manifest: dict[str, Any], output_dir: Path) -> tuple[dict[str, Any], bool]:
    """Reserve the next incomplete wave and persist per-component attempts.

    Returns ``(payload, changed)``. A component gets at most two claims (initial
    dispatch plus one retry), including across parent-session resumes.
    """
    current = status(plan, manifest, output_dir)
    next_wave = current["next_wave"]
    if next_wave is None:
        return current, False
    blocked = [
        component["component_id"]
        for component in next_wave["components"]
        if plan["attempts"][component["component_id"]] >= 2
    ]
    if blocked:
        return {
            "status": "blocked",
            "complete": current["complete"],
            "total": current["total"],
            "concurrency": current["concurrency"],
            "wave": next_wave["index"],
            "blocked_components": blocked,
            "incomplete": current["incomplete"],
        }, False
    for component in next_wave["components"]:
        component_id = component["component_id"]
        plan["attempts"][component_id] += 1
    next_wave["attempts"] = {
        component["component_id"]: plan["attempts"][component["component_id"]] for component in next_wave["components"]
    }
    return {
        "status": "claimed",
        "complete": current["complete"],
        "total": current["total"],
        "concurrency": current["concurrency"],
        "wave": next_wave,
    }, True


def _paths(output_dir: Path, manifest_arg: Path | None = None) -> tuple[Path, Path]:
    manifest = manifest_arg or output_dir / ".stride-dispatch-manifest.json"
    return manifest, output_dir / PLAN_NAME


def load_status(output_dir: Path, manifest_path: Path | None = None) -> dict[str, Any]:
    """Load and validate persisted scheduling state, then inspect outputs."""
    manifest_path, plan_path = _paths(output_dir, manifest_path)
    manifest = _read_object(manifest_path, "dispatch manifest")
    plan = _read_object(plan_path, "wave plan")
    return status(plan, manifest, output_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="create or refresh the deterministic wave plan")
    init_parser.add_argument("output_dir", type=Path)
    init_parser.add_argument("--manifest", type=Path)
    init_parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)

    for command in ("claim", "next", "status", "verify"):
        command_parser = sub.add_parser(command)
        command_parser.add_argument("output_dir", type=Path)
        command_parser.add_argument("--manifest", type=Path)

    args = parser.parse_args(argv)
    output_dir: Path = args.output_dir
    if not output_dir.is_dir():
        print(f"stride_dispatch_waves: output directory does not exist: {output_dir}", file=sys.stderr)
        return 2
    manifest_path, plan_path = _paths(output_dir, getattr(args, "manifest", None))

    try:
        manifest = _read_object(manifest_path, "dispatch manifest")
        if args.command == "init":
            reused = False
            if plan_path.is_file():
                existing = _read_object(plan_path, "wave plan")
                if existing.get("manifest_fingerprint") == _fingerprint(manifest):
                    validate_plan(existing, manifest)
                    if existing.get("concurrency") == args.concurrency:
                        plan = existing
                        reused = True
                    else:
                        plan = build_plan(manifest, args.concurrency)
                        plan["attempts"] = existing["attempts"]
                else:
                    plan = build_plan(manifest, args.concurrency)
            else:
                plan = build_plan(manifest, args.concurrency)
            _atomic_write_json(plan_path, plan)
            payload = {
                "status": "initialized",
                "plan": str(plan_path),
                "reused": reused,
                "concurrency": plan["concurrency"],
                "total_components": len(plan["component_ids"]),
                "total_waves": len(plan["waves"]),
            }
        else:
            plan = _read_object(plan_path, "wave plan")
            if args.command == "claim":
                payload, changed = claim(plan, manifest, output_dir)
                if changed:
                    _atomic_write_json(plan_path, plan)
                elif payload["status"] == "blocked":
                    print(json.dumps(payload, indent=2))
                    print(
                        "stride_dispatch_waves: retry budget exhausted; selected-component coverage is incomplete",
                        file=sys.stderr,
                    )
                    return 1
            else:
                payload = status(plan, manifest, output_dir)
            if args.command == "next":
                payload = {
                    "status": payload["status"],
                    "complete": payload["complete"],
                    "total": payload["total"],
                    "concurrency": payload["concurrency"],
                    "next_wave": payload["next_wave"],
                }
            elif args.command == "verify" and payload["status"] != "complete":
                print(json.dumps(payload, indent=2))
                print(
                    "stride_dispatch_waves: selected-component coverage is incomplete; do not continue to merge",
                    file=sys.stderr,
                )
                return 1
    except WavePlanError as exc:
        print(f"stride_dispatch_waves: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
