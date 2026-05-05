#!/usr/bin/env python3
"""
apply_content_repair.py — Sprint 3A (M3.5) deterministic applier for the
QA reviewer's content-repair plan.

The QA reviewer cannot edit `threat-model.md` directly because the
PreToolUse hook (`agent_logger.py:1253`) blocks all Write/Edit calls
against it (AGENTS.md invariant: only `compose_threat_model.py`
may write the canonical Markdown). Pre-Sprint-3A, this meant the
reviewer's most useful checks (linkification, placeholder removal,
anchor injection) ran in read-only mode — the findings were enumerated
in `.qa-status.json` but never actually applied. The 2026-04-27 run
shipped 18 NARRATIVE_PLACEHOLDER comments, missing Linked Threats
columns in §4/§5, and a missing Critical Attack Chain section because
the reviewer's edits were silently dropped.

The new flow:

  1. QA reviewer emits `.qa-content-repair-plan.json` (schema:
     `schemas/qa-content-repair-plan.schema.json`) when it detects fixes
     that should be applied to the underlying fragments.
  2. The skill calls this script after Stage 3 returns. The script reads
     the plan, applies each action to the named fragment under
     `.fragments/`, and emits a per-action diff line.
  3. The skill then re-runs `compose_threat_model.py --strict` so the
     fragment edits flow through to `threat-model.md`.

Hard guarantees:

  * Writes are restricted to paths under `<output_dir>/.fragments/`.
    Any other target is rejected with a non-zero exit.
  * Each action validates its operation BEFORE writing — a
    `replace_string` whose `find` does not appear (or appears more
    than once) is logged and skipped.
  * Failures are isolated: one bad action does not stop the rest of
    the plan. The exit code reflects the worst outcome.

Exit codes:
  0 — every action applied (or plan was empty)
  1 — one or more actions failed; stderr lists the failures
  2 — invalid arguments / unreadable plan
  3 — schema validation failed against qa-content-repair-plan.schema.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
PLAN_FILENAME = ".qa-content-repair-plan.json"
ALLOWED_FRAGMENT_PREFIX = ".fragments/"


# ---------------------------------------------------------------------------
# Operation appliers — one per operation `op` value declared in the schema
# ---------------------------------------------------------------------------

class ApplyError(Exception):
    """Raised by an operation applier when the operation cannot be performed.

    The caller logs the message and continues with the next action — a
    single bad action never aborts the whole plan.
    """


def _op_replace_string(text: str, op: dict) -> str:
    find = op["find"]
    count = text.count(find)
    if count == 0:
        raise ApplyError(
            f"replace_string: needle not found (find={find!r:.80})"
        )
    if count > 1:
        raise ApplyError(
            f"replace_string: needle is ambiguous (found {count}× — "
            f"refine `find` to a unique substring; find={find!r:.80})"
        )
    return text.replace(find, op["replace"], 1)


def _op_append_after(text: str, op: dict) -> str:
    anchor = op["anchor"]
    if anchor not in text:
        raise ApplyError(f"append_after: anchor not found (anchor={anchor!r:.80})")
    insertion = "\n" + op["content"]
    # Insert after the FIRST occurrence — operations are intentionally
    # single-shot to keep blast radius bounded.
    idx = text.index(anchor) + len(anchor)
    return text[:idx] + insertion + text[idx:]


def _op_insert_before(text: str, op: dict) -> str:
    anchor = op["anchor"]
    if anchor not in text:
        raise ApplyError(f"insert_before: anchor not found (anchor={anchor!r:.80})")
    insertion = op["content"] + "\n"
    idx = text.index(anchor)
    return text[:idx] + insertion + text[idx:]


def _op_regex_replace(text: str, op: dict) -> str:
    try:
        pat = re.compile(op["pattern"], re.MULTILINE)
    except re.error as e:
        raise ApplyError(f"regex_replace: invalid pattern ({e})") from e
    cap = int(op.get("max_substitutions", 0) or 0)
    new_text, n = pat.subn(op["replacement"], text, count=cap if cap > 0 else 0)
    if n == 0:
        raise ApplyError(
            f"regex_replace: pattern matched 0 times "
            f"(pattern={op['pattern']!r:.80})"
        )
    return new_text


_OP_HANDLERS = {
    "replace_string": _op_replace_string,
    "append_after":   _op_append_after,
    "insert_before":  _op_insert_before,
    "regex_replace":  _op_regex_replace,
}


# ---------------------------------------------------------------------------
# Plan validation + dispatch
# ---------------------------------------------------------------------------

def _validate_plan(plan: dict) -> list[str]:
    """Lightweight schema check — full JSONSchema validation requires the
    `jsonschema` package which is not always installed. Catches the few
    field-shape errors that would otherwise surface as cryptic Python
    KeyErrors during application. Returns a list of error strings (empty
    on success)."""
    errs: list[str] = []
    if not isinstance(plan, dict):
        return ["plan is not a JSON object"]
    if plan.get("schema_version") != SCHEMA_VERSION:
        errs.append(
            f"schema_version mismatch: expected {SCHEMA_VERSION}, "
            f"got {plan.get('schema_version')!r}"
        )
    actions = plan.get("actions")
    if not isinstance(actions, list):
        errs.append(f"`actions` must be a list, got {type(actions).__name__}")
        return errs
    for i, a in enumerate(actions):
        if not isinstance(a, dict):
            errs.append(f"actions[{i}] is not an object")
            continue
        for required in ("check", "type", "fragment", "operation"):
            if required not in a:
                errs.append(f"actions[{i}] missing field {required!r}")
        op = a.get("operation")
        if isinstance(op, dict):
            op_kind = op.get("op")
            if op_kind not in _OP_HANDLERS:
                errs.append(
                    f"actions[{i}].operation.op is unknown: "
                    f"{op_kind!r} (allowed: {sorted(_OP_HANDLERS)})"
                )
    return errs


def _resolve_fragment_path(output_dir: Path, fragment: str) -> Path:
    """Return the absolute resolved path to a fragment, or raise ApplyError
    when the path escapes ``output_dir/.fragments/``. Symlink-resolves
    BOTH sides so a maliciously-crafted symlink cannot escape the jail."""
    if not fragment.startswith(ALLOWED_FRAGMENT_PREFIX):
        raise ApplyError(
            f"fragment path must start with {ALLOWED_FRAGMENT_PREFIX!r}, "
            f"got {fragment!r}"
        )
    candidate = (output_dir / fragment).resolve()
    jail = (output_dir / ".fragments").resolve()
    try:
        candidate.relative_to(jail)
    except ValueError:
        raise ApplyError(
            f"fragment path escapes the jail: {fragment!r} resolves outside "
            f"{jail}"
        )
    if not candidate.is_file():
        raise ApplyError(f"fragment file does not exist: {candidate}")
    return candidate


def apply_plan(plan: dict, output_dir: Path) -> dict:
    """Apply every action in ``plan`` against fragments under ``output_dir``.

    Returns a structured report:

        {
          "applied":   [<action index>],
          "skipped":   [{"index": int, "reason": str}],
          "fragments_touched": ["<rel path>", ...],
          "exit_code": 0 | 1
        }
    """
    report: dict = {
        "applied":           [],
        "skipped":           [],
        "fragments_touched": [],
        "exit_code":         0,
    }

    actions = plan.get("actions", []) or []
    if not actions:
        return report

    # Group actions by fragment so each fragment is read/written exactly once.
    by_fragment: dict[str, list[tuple[int, dict]]] = {}
    for idx, action in enumerate(actions):
        by_fragment.setdefault(action.get("fragment", ""), []).append((idx, action))

    for fragment, group in by_fragment.items():
        try:
            path = _resolve_fragment_path(output_dir, fragment)
        except ApplyError as exc:
            for idx, _ in group:
                report["skipped"].append({"index": idx, "reason": str(exc)})
            report["exit_code"] = 1
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            for idx, _ in group:
                report["skipped"].append(
                    {"index": idx, "reason": f"read error: {exc}"}
                )
            report["exit_code"] = 1
            continue

        original = text
        for idx, action in group:
            op = action.get("operation", {})
            handler = _OP_HANDLERS.get(op.get("op", ""))
            if handler is None:
                report["skipped"].append(
                    {"index": idx, "reason": f"unknown op {op.get('op')!r}"}
                )
                report["exit_code"] = 1
                continue
            try:
                text = handler(text, op)
                report["applied"].append(idx)
                print(
                    f"[content-repair] ✓ action[{idx}] check={action.get('check','?')} "
                    f"type={action.get('type','?')} fragment={fragment} "
                    f"op={op.get('op')}",
                    file=sys.stderr,
                )
            except ApplyError as exc:
                report["skipped"].append({"index": idx, "reason": str(exc)})
                report["exit_code"] = 1
                print(
                    f"[content-repair] ✗ action[{idx}] check={action.get('check','?')} "
                    f"fragment={fragment}: {exc}",
                    file=sys.stderr,
                )

        if text != original:
            try:
                path.write_text(text, encoding="utf-8")
                report["fragments_touched"].append(fragment)
            except OSError as exc:
                report["skipped"].append(
                    {"index": -1,
                     "reason": f"write error on {fragment}: {exc}"}
                )
                report["exit_code"] = 1

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="apply_content_repair.py",
        description=__doc__.splitlines()[0] if __doc__ else "",
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="$OUTPUT_DIR (parent of .fragments/ and .qa-content-repair-plan.json)",
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=None,
        help=f"Plan path (default: <output_dir>/{PLAN_FILENAME})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate the plan and resolve every action, but do not write fragments.",
    )
    args = parser.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"error: output_dir is not a directory: {args.output_dir}",
              file=sys.stderr)
        return 2

    plan_path = args.plan or (args.output_dir / PLAN_FILENAME)
    if not plan_path.is_file():
        # No plan = no work. Exit 0 — this is the common case.
        print(f"[content-repair] no plan at {plan_path} — nothing to do",
              file=sys.stderr)
        return 0

    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read plan {plan_path}: {exc}", file=sys.stderr)
        return 2

    errors = _validate_plan(plan)
    if errors:
        print(f"error: plan failed validation:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 3

    if args.dry_run:
        # Resolve each action's fragment and operation handler without
        # writing. Surfaces "needle not found" type errors.
        actions = plan.get("actions", []) or []
        bad = 0
        for idx, action in enumerate(actions):
            try:
                path = _resolve_fragment_path(args.output_dir,
                                              action.get("fragment", ""))
                text = path.read_text(encoding="utf-8")
                op = action.get("operation", {})
                handler = _OP_HANDLERS.get(op.get("op", ""))
                if handler is None:
                    raise ApplyError(f"unknown op {op.get('op')!r}")
                handler(text, op)  # discard result — dry run
                print(f"[content-repair-dry] ✓ action[{idx}] would apply",
                      file=sys.stderr)
            except ApplyError as exc:
                bad += 1
                print(f"[content-repair-dry] ✗ action[{idx}]: {exc}",
                      file=sys.stderr)
        return 1 if bad else 0

    report = apply_plan(plan, args.output_dir)
    print(
        json.dumps(
            {
                "applied_count": len(report["applied"]),
                "skipped_count": len(report["skipped"]),
                "fragments_touched": report["fragments_touched"],
            },
            indent=2,
        )
    )
    return report["exit_code"]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
