#!/usr/bin/env python3
"""Write one STRIDE progress record with controller-owned analysis depth."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from pathlib import Path

import agent_lifecycle
import jsonschema

_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")


def authoritative_depth(output_dir: Path, component_id: str, plugin_root: Path) -> str:
    if not _COMPONENT_RE.fullmatch(component_id):
        raise ValueError("unsafe component id")
    path = output_dir / ".dispatch-context" / component_id / "context-plan.json"
    schema_path = plugin_root / "schemas" / "stride-component-context-plan.schema.json"
    plan = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(plan)
    if plan.get("component_id") != component_id:
        raise ValueError("component context plan belongs to another component")
    depth = (plan.get("analysis") or {}).get("depth")
    if depth not in {"full", "light"}:
        raise ValueError("component context plan has no canonical analysis depth")
    return depth


def authoritative_call(output_dir: Path, component_id: str, plugin_root: Path) -> dict:
    """Resolve the call that owns the current component attempt.

    A call that has returned still owns its attempt until the wave moves on.
    An analyzer's last progress write routinely lands after SubagentStop closed
    its call, so demanding a *running* call discarded legitimate final records:
    the 2026-08-31 juice-shop run lost 8 that way, five of them within 43s of
    realtime-service closing. Ambiguity — more than one running call for the
    component — stays fatal, because that is the misattribution this guard
    exists for. Staleness is caught by the claim check below, which compares the
    attempt against the active claim and is unaffected by liveness.
    """
    depth = authoritative_depth(output_dir, component_id, plugin_root)
    matches = [call for call in agent_lifecycle.running_calls(output_dir) if call.get("component_id") == component_id]
    if len(matches) > 1:
        raise ValueError("progress requires exactly one running Agent call for the component")
    call = matches[0] if matches else agent_lifecycle.latest_call_for_component(output_dir, component_id)
    if call is None:
        raise ValueError("progress found no Agent call for the component")
    if not all(call.get(key) not in (None, "") for key in ("action_id", "job_id", "attempt")):
        raise ValueError("progress Agent call has no action, job, or attempt identity")
    if call.get("analysis_depth") != depth:
        raise ValueError("progress Agent call contradicts the authoritative analysis depth")
    if not agent_lifecycle.claim_is_authoritative(output_dir, call):
        raise ValueError("progress Agent call does not own the current dispatch claim")
    return call


def write_progress(
    output_dir: Path,
    component_id: str,
    component_name: str,
    step: int,
    total: int,
    label: str,
    plugin_root: Path,
) -> dict:
    if step < 1 or total < 1 or step > total:
        raise ValueError("progress step must be within its total")
    call = authoritative_call(output_dir, component_id, plugin_root)
    depth = call["analysis_depth"]
    payload = {
        "schema_version": 2,
        "component_id": component_id,
        "component_name": component_name.replace("\n", " ").replace("\r", " ")[:200],
        "action_id": call["action_id"],
        "job_id": call["job_id"],
        "attempt": call["attempt"],
        "analysis_depth": depth,
        "step": step,
        "total": total,
        "label": label.replace("\n", " ").replace("\r", " ")[:300],
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    schema = json.loads((plugin_root / "schemas" / "stride-progress.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(payload)
    directory = output_dir / ".progress"
    directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink():
        raise ValueError("progress directory must not be a symlink")
    fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=f".{component_id}-progress-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
        os.replace(tmp, directory / f"{component_id}.json")
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("component_id")
    parser.add_argument("component_name")
    parser.add_argument("step", type=int)
    parser.add_argument("total", type=int)
    parser.add_argument("label")
    parser.add_argument("--plugin-root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    try:
        write_progress(
            args.output_dir,
            args.component_id,
            args.component_name,
            args.step,
            args.total,
            args.label,
            args.plugin_root,
        )
    except (OSError, ValueError, json.JSONDecodeError, jsonschema.ValidationError) as exc:
        # Not `parser.error`: it prefixes an argparse usage block, and the
        # BASH_WARN excerpt anchors on `usage:` and keeps that line instead of
        # the reason. The 2026-08-31 run recorded a late-write rejection as an
        # unreadable usage dump, which is how it was filed as an argv defect.
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
