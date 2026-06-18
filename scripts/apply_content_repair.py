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
columns in §4/§5, and a missing Critical Attack Tree section because
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
import re
import sys
from pathlib import Path

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


def _norm_ws(s: str) -> str:
    """Collapse ``<br/>`` → space, then any whitespace run → single space.

    Used by the ``replace_string`` fuzzy fallback so a ``find`` string the QA
    reviewer reconstructed from the *rendered* Markdown (which differs from the
    fragment source by ``<br/>`` placement / collapsed spacing) still locates
    its span instead of silently no-op'ing.
    """
    s = re.sub(r"<br\s*/?>", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _op_replace_string(text: str, op: dict) -> str:
    find = op["find"]
    count = text.count(find)
    if count == 1:
        return text.replace(find, op["replace"], 1)
    if count > 1:
        raise ApplyError(
            f"replace_string: needle is ambiguous (found {count}× — "
            f"refine `find` to a unique substring; find={find!r:.80})"
        )
    # count == 0 → whitespace/<br/>-normalized fallback. The QA reviewer
    # frequently authors `find` from the rendered MD line, which differs from
    # the fragment source by <br/> placement and collapsed spacing; a verbatim
    # str.count then misses and the (valid) fix was silently dropped.
    needle_n = _norm_ws(find)
    if not needle_n:
        raise ApplyError(f"replace_string: needle not found (find={find!r:.80})")
    parts = [re.escape(tok) for tok in needle_n.split(" ")]
    fuzzy = re.compile(r"(?:\s|<br\s*/?>)+".join(parts))
    hits = fuzzy.findall(text)
    if len(hits) == 0:
        raise ApplyError(f"replace_string: needle not found (find={find!r:.80})")
    if len(hits) > 1:
        raise ApplyError(
            f"replace_string: fuzzy needle is ambiguous (found {len(hits)}× — refine `find`; find={find!r:.80})"
        )
    print(
        f"[content-repair] ~ replace_string fuzzy-matched (whitespace/<br/> normalized) find={find!r:.80}",
        file=sys.stderr,
    )
    return fuzzy.sub(lambda _m: op["replace"], text, count=1)


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
        raise ApplyError(f"regex_replace: pattern matched 0 times (pattern={op['pattern']!r:.80})")
    return new_text


# ---------------------------------------------------------------------------
# heading_rename_cascade (RC-2)
# ---------------------------------------------------------------------------
#
# Rename an H4 control heading AND cascade the rename to every mechanical
# place that references the old name. For ``security-architecture.md`` the
# referenced places are:
#
#   1. The H4 heading itself:                ``#### 7.2.1 <old_name>``
#   2. The pre-heading anchor tag:           ``<a id="<old-kebab>"></a>``
#   3. ``**Controls covered:**`` link text:  ``[<old_name>](#<old-kebab>)``
#   4. §7.1 overview-table row text:         ``(e.g. <old_name>)``
#
# The op refuses to write when the H4 heading is not found (no needle to
# cascade FROM). Anchor / link / table-row cascades are best-effort: a
# missing cascade target logs a warning but does not abort, because legitimate
# repository structures may omit one or more of them.
#
# Op shape:
#
#   {
#     "op": "heading_rename_cascade",
#     "old_name": "JWT RS256 Authentication",
#     "new_name": "JWT Bearer Authentication"
#   }


def _kebab(name: str) -> str:
    """Same kebab-case rule used by compose_threat_model.py's anchor builder:
    lowercase, collapse non-alphanumeric runs to a single hyphen, strip
    leading/trailing hyphens."""
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s


def _op_heading_rename_cascade(text: str, op: dict) -> str:
    old_name = op.get("old_name")
    new_name = op.get("new_name")
    if not isinstance(old_name, str) or not old_name.strip():
        raise ApplyError("heading_rename_cascade: missing/empty `old_name`")
    if not isinstance(new_name, str) or not new_name.strip():
        raise ApplyError("heading_rename_cascade: missing/empty `new_name`")
    if old_name == new_name:
        # Treat as no-op rather than error: idempotent re-runs of a content
        # repair plan should not fail just because the cascade already ran.
        return text

    old_kebab = _kebab(old_name)
    new_kebab = _kebab(new_name)

    # (1) Heading line — required cascade target. Match `#### N.M.X <old_name>`
    # with optional intra-line whitespace; the numbering must survive verbatim
    # and the trailing newline must NOT be consumed (using `\s*$` would let
    # the greedy class eat newlines and collapse the blank line between the
    # heading and its **Security assessment** trailer).
    heading_pat = re.compile(
        r"^(####[ \t]+\d+\.\d+\.\d+[ \t]+)" + re.escape(old_name) + r"[ \t]*$",
        re.MULTILINE,
    )
    text, h_n = heading_pat.subn(rf"\1{new_name}", text, count=1)
    if h_n == 0:
        # Fallback — sometimes the heading has no `N.M.X` numbering (e.g. raw
        # H4 in a fragment). Try the bare form.
        bare_heading_pat = re.compile(
            r"^(####[ \t]+)" + re.escape(old_name) + r"[ \t]*$",
            re.MULTILINE,
        )
        text, h_n = bare_heading_pat.subn(rf"\1{new_name}", text, count=1)
    if h_n == 0:
        raise ApplyError(f"heading_rename_cascade: no H4 heading found for old_name={old_name!r:.80} — needle missing")

    # (2) Anchor tag — best effort. Match `<a id="<old-kebab>"></a>` (HTML).
    anchor_pat = re.compile(r'<a\s+id="' + re.escape(old_kebab) + r'"\s*>\s*</a>')
    text = anchor_pat.sub(f'<a id="{new_kebab}"></a>', text)

    # (3) Markdown link with the old anchor — match `[Some Text](#<old-kebab>)`
    # — replace BOTH the link text (when it equals old_name) and the anchor.
    link_text_anchor_pat = re.compile(r"\[" + re.escape(old_name) + r"\]\(#" + re.escape(old_kebab) + r"\)")
    text = link_text_anchor_pat.sub(f"[{new_name}](#{new_kebab})", text)
    # And: link with different text but same anchor (rare; preserve label).
    bare_anchor_pat = re.compile(r"\]\(#" + re.escape(old_kebab) + r"\)")
    text = bare_anchor_pat.sub(f"](#{new_kebab})", text)

    # (4) §7.1 overview-table row — `(e.g. <old_name>)`. The §7.1 table is
    # mechanical-frozen and uses the control name verbatim in its "Main
    # reason" cell. Cascade replaces all such mentions.
    eg_pat = re.compile(r"\(e\.g\.\s+" + re.escape(old_name) + r"\)")
    text = eg_pat.sub(f"(e.g. {new_name})", text)

    return text


_OP_HANDLERS = {
    "replace_string": _op_replace_string,
    "append_after": _op_append_after,
    "insert_before": _op_insert_before,
    "regex_replace": _op_regex_replace,
    "heading_rename_cascade": _op_heading_rename_cascade,
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
        errs.append(f"schema_version mismatch: expected {SCHEMA_VERSION}, got {plan.get('schema_version')!r}")
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
                errs.append(f"actions[{i}].operation.op is unknown: {op_kind!r} (allowed: {sorted(_OP_HANDLERS)})")
        elif op is not None:
            # Reject the flat producer drift form
            # (`operation: "replace_string"` + sibling search_text/replace_text)
            # explicitly. Without this branch a non-dict operation slipped past
            # validation and crashed apply_plan with an AttributeError.
            errs.append(
                f"actions[{i}].operation must be a JSON object with an 'op' key, "
                f"got {type(op).__name__} — the flat form "
                f'(operation:"replace_string" + search_text/replace_text) is not '
                f"supported; use the nested object "
                f"{{'op': 'replace_string', 'find': ..., 'replace': ...}}"
            )
    return errs


def _resolve_fragment_path(output_dir: Path, fragment: str) -> Path:
    """Return the absolute resolved path to a fragment, or raise ApplyError
    when the path escapes ``output_dir/.fragments/``. Symlink-resolves
    BOTH sides so a maliciously-crafted symlink cannot escape the jail."""
    if not fragment.startswith(ALLOWED_FRAGMENT_PREFIX):
        raise ApplyError(f"fragment path must start with {ALLOWED_FRAGMENT_PREFIX!r}, got {fragment!r}")
    candidate = (output_dir / fragment).resolve()
    jail = (output_dir / ".fragments").resolve()
    try:
        candidate.relative_to(jail)
    except ValueError:
        raise ApplyError(f"fragment path escapes the jail: {fragment!r} resolves outside {jail}")
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
        "applied": [],
        "skipped": [],
        "fragments_touched": [],
        "exit_code": 0,
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
                report["skipped"].append({"index": idx, "reason": f"read error: {exc}"})
            report["exit_code"] = 1
            continue

        original = text
        for idx, action in group:
            op = action.get("operation", {})
            if not isinstance(op, dict):
                # Defensive: the validator already rejects this at plan level,
                # but guard the library entry point too so a non-dict operation
                # can never raise an uncaught AttributeError here.
                report["skipped"].append(
                    {
                        "index": idx,
                        "reason": (
                            f"operation is not an object (got {type(op).__name__}); "
                            f"flat form unsupported — use nested {{'op': ...}}"
                        ),
                    }
                )
                report["exit_code"] = 1
                print(
                    f"[content-repair] ✗ action[{idx}] check={action.get('check', '?')} "
                    f"fragment={fragment}: operation is not an object "
                    f"({type(op).__name__}) — skipped",
                    file=sys.stderr,
                )
                continue
            handler = _OP_HANDLERS.get(op.get("op", ""))
            if handler is None:
                report["skipped"].append({"index": idx, "reason": f"unknown op {op.get('op')!r}"})
                report["exit_code"] = 1
                continue
            try:
                text = handler(text, op)
                report["applied"].append(idx)
                print(
                    f"[content-repair] ✓ action[{idx}] check={action.get('check', '?')} "
                    f"type={action.get('type', '?')} fragment={fragment} "
                    f"op={op.get('op')}",
                    file=sys.stderr,
                )
            except ApplyError as exc:
                report["skipped"].append({"index": idx, "reason": str(exc)})
                report["exit_code"] = 1
                print(
                    f"[content-repair] ✗ action[{idx}] check={action.get('check', '?')} fragment={fragment}: {exc}",
                    file=sys.stderr,
                )

        if text != original:
            try:
                path.write_text(text, encoding="utf-8")
                report["fragments_touched"].append(fragment)
            except OSError as exc:
                report["skipped"].append({"index": -1, "reason": f"write error on {fragment}: {exc}"})
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
        "--dry-run",
        action="store_true",
        help="Validate the plan and resolve every action, but do not write fragments.",
    )
    args = parser.parse_args(argv)

    if not args.output_dir.is_dir():
        print(f"error: output_dir is not a directory: {args.output_dir}", file=sys.stderr)
        return 2

    plan_path = args.plan or (args.output_dir / PLAN_FILENAME)
    if not plan_path.is_file():
        # No plan = no work. Exit 0 — this is the common case.
        print(f"[content-repair] no plan at {plan_path} — nothing to do", file=sys.stderr)
        return 0

    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read plan {plan_path}: {exc}", file=sys.stderr)
        return 2

    errors = _validate_plan(plan)
    if errors:
        print("error: plan failed validation:", file=sys.stderr)
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
                path = _resolve_fragment_path(args.output_dir, action.get("fragment", ""))
                text = path.read_text(encoding="utf-8")
                op = action.get("operation", {})
                handler = _OP_HANDLERS.get(op.get("op", ""))
                if handler is None:
                    raise ApplyError(f"unknown op {op.get('op')!r}")
                handler(text, op)  # discard result — dry run
                print(f"[content-repair-dry] ✓ action[{idx}] would apply", file=sys.stderr)
            except ApplyError as exc:
                bad += 1
                print(f"[content-repair-dry] ✗ action[{idx}]: {exc}", file=sys.stderr)
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
