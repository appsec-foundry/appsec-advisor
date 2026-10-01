#!/usr/bin/env python3
"""Persist one STRIDE analyzer attempt category by category (OR-36).

The analyzer used to rewrite its whole attempt file after every category and
then spend a separate turn logging the step: the file grew with each category
and every later turn re-read the full rewrite (juice-shop 2026-10-01: 112k
redundant tokens across eight components). This writer takes only the
category's threats on stdin, merges them into the attempt file under a lock,
and logs, reports progress, and checks the turn budget in the same call.

The attempt path is never taken from the caller: it is resolved from the
component's authoritative Agent call, the same owner ``runtime/log_event.py``
checks, so a write cannot land outside this attempt's own artifact.

Subcommands, each one Bash turn:

* ``init``      write the write-first pre-seed, or report the resumed file
                (``resumed_from_attempt``) without rewriting it.
* ``category``  merge one category's threats (stdin JSON) and log it complete.
* ``finish``    merge final top-level fields (stdin JSON); with every category
                persisted it sets ``partial: false``, otherwise the file stays
                partial with only unstarted categories skipped (budget stop).

Refusal safety is unchanged: each category is persisted before it is logged,
so a declined later turn loses nothing already written.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import argparse
import fcntl
import json
import os
import re
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import runtime.budget_watchdog as budget_watchdog
import runtime.log_event as log_event
import runtime.write_stride_progress as write_stride_progress

CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)
#: Progress steps 1-2 (context, source reads) stay with the analyzer.
CATEGORY_FIRST_STEP = 3
PROGRESS_TOTAL = 9
MAX_STDIN_BYTES = 2_000_000

#: Fields only this writer or the controller sets.
_OWNED = {
    "component_id",
    "component_name",
    "started_at",
    "analyzed_at",
    "partial",
    "seed_only",
    "skipped_categories",
    "threats",
    "resumed_from_attempt",
    "coverage_declined",
}
_REPLACED = {"declined_turns", "compliance_scope_applied"}
_APPENDED = {"discovery_escapes", "resolved_prior_findings"}
_BY_ITEM = {"lens_coverage"}


class WriterError(ValueError):
    pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _plugin_root() -> Path:
    return Path(__file__).resolve().parents[2]


def attempt_path(output_dir: Path, component_id: str) -> tuple[Path, dict[str, Any]]:
    """The attempt file the component's authoritative call owns, and that call."""
    from orchestrator.stride_dispatch_waves import ATTEMPT_DIR_NAME, attempt_artifact  # noqa: PLC0415

    call = write_stride_progress.authoritative_call(output_dir, component_id, _plugin_root())
    path = output_dir / attempt_artifact(component_id, int(call["attempt"]))
    directory = (output_dir / ATTEMPT_DIR_NAME).resolve()
    if path.is_symlink() or path.parent.is_symlink() or path.resolve().parent != directory:
        raise WriterError(f"attempt file {path} must be a regular file inside {directory}")
    return path, call


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path.with_name(path.name + ".lock"), "a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _read(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise WriterError(f"attempt file {path.name} is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise WriterError(f"attempt file {path.name} is not a JSON object")
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def seed(component_id: str, component_name: str) -> dict[str, Any]:
    stamp = _now()
    return {
        "component_id": component_id,
        "component_name": component_name,
        "started_at": stamp,
        "analyzed_at": stamp,
        "partial": True,
        "seed_only": True,
        "skipped_categories": list(CATEGORIES),
        "discovery_escapes": [],
        "threats": [],
    }


def _summary(data: dict[str, Any]) -> dict[str, Any]:
    ids = [str(t.get("local_id")) for t in data.get("threats") or [] if isinstance(t, dict)]
    numbers = [int(m.group(1)) for i in ids if (m := re.search(r"-(\d+)$", i))]
    return {
        "skipped_categories": data.get("skipped_categories") or [],
        "threat_count": len(ids),
        "next_local_number": max(numbers, default=0) + 1,
        **({"resumed_from_attempt": data["resumed_from_attempt"]} if "resumed_from_attempt" in data else {}),
    }


def init(output_dir: Path, component_id: str, component_name: str) -> dict[str, Any]:
    path, _call = attempt_path(output_dir, component_id)
    with _locked(path):
        existing = _read(path)
        if existing is not None and isinstance(existing.get("resumed_from_attempt"), int):
            return {"resumed": True, **_summary(existing)}
        data = seed(component_id, component_name)
        _write(path, data)
    return {"resumed": False, **_summary(data)}


def _payload(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > MAX_STDIN_BYTES:
        raise WriterError(f"stdin exceeds {MAX_STDIN_BYTES} bytes")
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise WriterError(f"stdin is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise WriterError('stdin must be a JSON object such as {"threats": [...]}')
    unknown = sorted(set(payload) - _REPLACED - _APPENDED - _BY_ITEM - {"threats"})
    if unknown:
        raise WriterError(f"stdin carries fields this writer owns or does not know: {', '.join(unknown)}")
    return payload


def _merge_extras(data: dict[str, Any], payload: dict[str, Any]) -> None:
    for key in _REPLACED & set(payload):
        data[key] = payload[key]
    for key in _APPENDED & set(payload):
        if not isinstance(payload[key], list):
            raise WriterError(f"{key} must be an array")
        merged = list(data.get(key) or [])
        for entry in payload[key]:
            if entry not in merged:
                merged.append(entry)
        data[key] = merged
    for key in _BY_ITEM & set(payload):
        if not isinstance(payload[key], list) or not all(isinstance(e, dict) for e in payload[key]):
            raise WriterError(f"{key} must be an array of objects")
        merged = {str(e.get("item")): e for e in data.get(key) or [] if isinstance(e, dict)}
        for entry in payload[key]:
            merged[str(entry.get("item"))] = entry
        data[key] = list(merged.values())


def _checked_threats(payload: dict[str, Any], component_id: str, category: str, data: dict[str, Any]) -> list[dict]:
    threats = payload.get("threats", [])
    if not isinstance(threats, list):
        raise WriterError("threats must be an array")
    pattern = re.compile(rf"^{re.escape(component_id)}-\d{{3,}}$")
    taken = {
        str(t.get("local_id")) for t in data.get("threats") or [] if isinstance(t, dict) and t.get("stride") != category
    }
    seen: set[str] = set()
    for index, threat in enumerate(threats):
        if not isinstance(threat, dict):
            raise WriterError(f"threats[{index}] is not an object")
        if threat.get("stride") != category:
            raise WriterError(f"threats[{index}].stride is {threat.get('stride')!r}, not {category!r}")
        local_id = threat.get("local_id")
        if not isinstance(local_id, str) or not pattern.fullmatch(local_id):
            raise WriterError(f"threats[{index}].local_id {local_id!r} must match {component_id}-NNN")
        if local_id in seen or local_id in taken:
            raise WriterError(f"threats[{index}].local_id {local_id} is already used")
        seen.add(local_id)
    return threats


def _ordered(threats: list[dict]) -> list[dict]:
    rank = {name: i for i, name in enumerate(CATEGORIES)}
    return sorted(threats, key=lambda t: rank.get(t.get("stride"), len(CATEGORIES)))


def write_category(output_dir: Path, component_id: str, category: str, raw: str) -> dict[str, Any]:
    if category not in CATEGORIES:
        raise WriterError(f"category must be one of {', '.join(CATEGORIES)}")
    payload = _payload(raw)
    path, _call = attempt_path(output_dir, component_id)
    with _locked(path):
        data = _read(path)
        if data is None:
            raise WriterError("no attempt file yet: run `init` first")
        threats = _checked_threats(payload, component_id, category, data)
        kept = [t for t in data.get("threats") or [] if not (isinstance(t, dict) and t.get("stride") == category)]
        data["threats"] = _ordered(kept + threats)
        data["skipped_categories"] = [c for c in data.get("skipped_categories") or [] if c != category]
        data.pop("seed_only", None)
        data["partial"] = True
        data["analyzed_at"] = _now()
        _merge_extras(data, payload)
        _write(path, data)
    return data


def finish(output_dir: Path, component_id: str, raw: str) -> dict[str, Any]:
    payload = _payload(raw)
    if "threats" in payload:
        raise WriterError("finish takes no threats; write them with `category`")
    path, _call = attempt_path(output_dir, component_id)
    with _locked(path):
        data = _read(path)
        if data is None:
            raise WriterError("no attempt file yet: run `init` first")
        _merge_extras(data, payload)
        data["partial"] = bool(data.get("skipped_categories")) or data.get("seed_only") is True
        data["analyzed_at"] = _now()
        _write(path, data)
    return data


def _log(output_dir: Path, component_id: str, *args: str) -> None:
    code = log_event.main(
        ["log_event.py", str(output_dir), *args, "--agent", "stride-analyzer-v2", "--component-id", component_id]
    )
    if code != 0:
        raise WriterError(f"log_event refused {args[0]}")


def _budget(output_dir: Path, call: dict[str, Any]) -> str:
    critical = budget_watchdog.has_active_critical_job_claim(
        output_dir, action_id=str(call["action_id"]), job_id=str(call["job_id"])
    )
    return "critical" if critical else "ok"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "category", "finish"):
        cmd = sub.add_parser(name)
        cmd.add_argument("output_dir", type=Path)
        cmd.add_argument("--component-id", required=True)
        if name == "init":
            cmd.add_argument("--component-name", required=True)
        if name == "category":
            cmd.add_argument("--category", required=True)
    args = parser.parse_args(argv)
    output_dir: Path = args.output_dir
    try:
        if args.command == "init":
            result = init(output_dir, args.component_id, args.component_name)
        elif args.command == "category":
            data = write_category(output_dir, args.component_id, args.category, sys.stdin.read())
            _log(output_dir, args.component_id, "step-end", f"category complete: {args.category}")
            _, call = attempt_path(output_dir, args.component_id)
            write_stride_progress.write_progress(
                output_dir,
                args.component_id,
                str(data.get("component_name") or args.component_id),
                CATEGORY_FIRST_STEP + CATEGORIES.index(args.category),
                PROGRESS_TOTAL,
                f"{args.category} written",
                _plugin_root(),
            )
            result = {**_summary(data), "budget": _budget(output_dir, call)}
        else:
            data = finish(output_dir, args.component_id, sys.stdin.read())
            done = not data["partial"]
            if done:
                _, call = attempt_path(output_dir, args.component_id)
                write_stride_progress.write_progress(
                    output_dir,
                    args.component_id,
                    str(data.get("component_name") or args.component_id),
                    PROGRESS_TOTAL,
                    PROGRESS_TOTAL,
                    "Complete",
                    _plugin_root(),
                )
            _log(
                output_dir,
                args.component_id,
                "info",
                "AGENT_END",
                f"stride-analyzer-v2 complete: {len(data.get('threats') or [])} threats written"
                if done
                else f"stride-analyzer-v2 stopped early: skipped {', '.join(data.get('skipped_categories') or [])}",
            )
            result = {**_summary(data), "partial": data["partial"]}
    except (WriterError, OSError, ValueError) as exc:
        print(f"stride_attempt_writer: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
