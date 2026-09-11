#!/usr/bin/env python3
"""apply_editorial_plan.py — apply the Stage-4 editorial plan deterministically.

The editorial pass emits bounded, run-bound id packets validated against
``schemas/editorial-plan.schema.json``. This script resolves their originals
through the validated work projection and performs the report writes. Legacy
explicit ``--plan`` inputs retain their exact-match address format.

Two action shapes, both exact-match:

  * a **field address** into ``threat-model.yaml`` or a JSON fragment, e.g.
    ``threats[12].scenario``. ``find`` must equal the field's current value
    verbatim — it is the optimistic lock — and the address must be on the
    editable allow-list owned by ``check_editorial_diff.py``.
  * a **verbatim block** in ``.fragments/security-architecture.md``, which must
    occur exactly once.

Rejected actions never abort the run: a stale lock or an off-list address is
skipped, reported, and the remaining actions still apply. Exit 0 when every
action applied and all packets completed, 1 for rejected or incomplete work,
2 on a usage or I/O error. The caller
runs ``check_editorial_diff.py verify --restore`` afterwards; that guard, not
this script, decides whether the result may ship.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _atomic_io import atomic_write_text  # noqa: E402
from _path_guard import run_path_arg  # noqa: E402
from build_editorial_context import MAX_BATCH_BYTES, is_editorial_path, validate_work  # noqa: E402
from check_editorial_diff import (  # noqa: E402
    YAML_NAME,
    fragment_editable_paths,
    prose_violations,
    yaml_editable_paths,
)

PLAN_NAME = ".dispatch-context/editorial/plan.json"
SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "editorial-plan.schema.json"

# Same dump options as build_threat_model_yaml.py, so re-serialising the model
# after a prose edit does not reformat the whole file.
_YAML_DUMP = {"sort_keys": False, "allow_unicode": True, "default_flow_style": False, "width": 120}

_PATH_TOKEN_RE = re.compile(r"\[(\d+)\]|\.?([A-Za-z_][A-Za-z0-9_]*)")


class PlanError(RuntimeError):
    """The plan itself is unusable — missing, malformed, or schema-invalid."""


def parse_field_path(text: str) -> tuple:
    """``mitigations[3].steps[1]`` -> ``("mitigations", 3, "steps", 1)``."""
    out: list[Any] = []
    position = 0
    for match in _PATH_TOKEN_RE.finditer(text):
        if match.start() != position:
            raise ValueError(f"unparseable field address: {text!r}")
        position = match.end()
        index, name = match.groups()
        out.append(int(index) if index is not None else name)
    if position != len(text) or not out:
        raise ValueError(f"unparseable field address: {text!r}")
    return tuple(out)


def _read_path(data: Any, path: tuple) -> Any:
    node = data
    for key in path:
        try:
            node = node[key]
        except (KeyError, IndexError, TypeError):
            return None
    return node


def _write_path(data: Any, path: tuple, value: str) -> None:
    node = data
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value


def load_plan(plan_path: Path) -> dict:
    try:
        if plan_path.stat().st_size > 256_000:
            raise PlanError("editorial plan exceeds the file size limit")
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PlanError(f"cannot read {plan_path}: {exc}") from exc
    except ValueError as exc:
        raise PlanError(f"{plan_path} is not valid JSON: {exc}") from exc

    try:
        import jsonschema

        jsonschema.validate(plan, json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    except ImportError as exc:  # pragma: no cover — declared dependency
        raise PlanError("jsonschema is required to validate editorial plans") from exc
    except Exception as exc:  # noqa: BLE001 — jsonschema raises its own error types
        raise PlanError(f"plan fails {SCHEMA_PATH.name}") from exc

    actions = plan.get("actions") or []
    if plan.get("status") == "no_change" and actions:
        raise PlanError("status is no_change but the plan carries actions")
    if plan.get("status") == "edits" and not actions:
        raise PlanError("edits requires an action")
    if plan.get("schema_version") == 2:
        if len({a["id"] for a in actions}) != len(actions):
            raise PlanError("duplicate block id in packet")
        if sum(len(a["replace"].encode("utf-8")) for a in actions) > MAX_BATCH_BYTES * 2:
            raise PlanError("packet replacements exceed the byte budget")
        return plan
    for i, action in enumerate(actions):
        is_markdown = str(action.get("file", "")).endswith(".md")
        if is_markdown and action.get("path"):
            raise PlanError(f"actions[{i}]: a Markdown target takes a verbatim block, not a field address")
        if not is_markdown and not action.get("path"):
            raise PlanError(f"actions[{i}]: a structured target needs a field address")
    return plan


def load_packets(output_dir: Path) -> tuple[dict, dict]:
    """Resolve only this run's assigned packet names, preserving valid siblings."""
    context = output_dir / ".dispatch-context/editorial"
    work_path = context / "blocks.json"
    if not is_editorial_path(work_path, output_dir):
        raise PlanError("editorial work escapes output directory")
    try:
        if work_path.stat().st_size > 8_000_000:
            raise ValueError("editorial work exceeds the file size limit")
        work = json.loads(work_path.read_text(encoding="utf-8"))
        validate_work(work)
    except (OSError, ValueError) as exc:
        raise PlanError("missing or invalid editorial work") from exc
    except Exception as exc:
        raise PlanError("editorial work fails schema validation") from exc
    blocks = {b["id"]: b for b in work["blocks"]}
    actions = []
    completed = 0
    reviewed = 0
    errors = []
    for batch in work["batches"]:
        path = context / f"plan-{batch['id']}.json"
        try:
            if not is_editorial_path(path, output_dir):
                raise PlanError("packet escapes output directory")
            plan = load_plan(path)
            if plan.get("schema_version") != 2 or plan["run_id"] != work["run_id"] or plan["batch_id"] != batch["id"]:
                raise PlanError("packet belongs to a different run or batch")
            if any(a["id"] not in batch["block_ids"] for a in plan["actions"]):
                raise PlanError("packet references an unassigned block")
        except PlanError:
            errors.append(batch["id"])
            continue
        completed += 1
        reviewed += len(batch["block_ids"])
        for action in plan["actions"]:
            block = blocks[action["id"]]
            actions.append(
                {"file": block["file"], "path": block["path"], "find": block["text"], "replace": action["replace"]}
            )
    return {"actions": actions}, {
        "run_id": work["run_id"],
        "batches_expected": len(work["batches"]),
        "batches_completed": completed,
        "blocks_reviewed": reviewed,
        "blocks_skipped": work["selection"]["blocks_skipped"],
        "invalid_batches": errors,
        "proposed_count": len(actions),
        "complete": completed == len(work["batches"]) and not work["selection"]["blocks_skipped"],
    }


def _allowed_paths(name: str, document: Any) -> set[tuple]:
    if name == YAML_NAME:
        return set(yaml_editable_paths(document))
    return set(fragment_editable_paths(name, document))


def _apply_structured(name: str, path_obj: Path, actions: list[dict]) -> tuple[int, list[dict], bool]:
    import yaml

    text = path_obj.read_text(encoding="utf-8")
    document = json.loads(text) if name.endswith(".json") else yaml.safe_load(text)
    allowed = _allowed_paths(name, document)

    applied = 0
    rejected: list[dict] = []
    for action in actions:
        raw_path = action["path"]
        try:
            path = parse_field_path(raw_path)
        except ValueError as exc:
            rejected.append({"file": name, "path": raw_path, "reason": str(exc)})
            continue
        if path not in allowed:
            rejected.append({"file": name, "path": raw_path, "reason": "address is not on the editable allow-list"})
            continue
        current = _read_path(document, path)
        if current != action["find"]:
            rejected.append({"file": name, "path": raw_path, "reason": "current value does not match `find`"})
            continue
        if current == action["replace"]:
            continue
        _write_path(document, path, action["replace"])
        applied += 1

    if applied:
        rendered = (
            json.dumps(document, indent=2, ensure_ascii=False) + "\n"
            if name.endswith(".json")
            else yaml.safe_dump(document, **_YAML_DUMP)
        )
        atomic_write_text(path_obj, rendered)
    return applied, rejected, bool(applied)


def _apply_markdown(name: str, path_obj: Path, actions: list[dict]) -> tuple[int, list[dict], bool]:
    text = path_obj.read_text(encoding="utf-8")
    original = text
    applied = 0
    rejected: list[dict] = []
    for action in actions:
        occurrences = text.count(action["find"])
        if occurrences != 1:
            rejected.append({"file": name, "path": None, "reason": f"`find` matches {occurrences} times, expected 1"})
            continue
        if action["find"] == action["replace"]:
            continue
        text = text.replace(action["find"], action["replace"], 1)
        applied += 1
    if text != original:
        atomic_write_text(path_obj, text)
    return applied, rejected, text != original


def apply_plan(plan: dict, output_dir: Path, dry_run: bool = False) -> dict:
    by_file: dict[str, list[dict]] = {}
    for action in plan.get("actions") or []:
        by_file.setdefault(action["file"], []).append(action)

    applied = 0
    rejected: list[dict] = []
    touched: list[str] = []
    for name, actions in sorted(by_file.items()):
        target = output_dir / name
        if name not in {
            YAML_NAME,
            ".fragments/security-architecture.md",
            ".fragments/ms-verdict.json",
            ".fragments/ms-anti-patterns.json",
        } or not is_editorial_path(target, output_dir):
            rejected.extend(
                {"file": name, "path": a.get("path"), "reason": "target is outside the allow-list"} for a in actions
            )
            continue
        if not target.is_file():
            rejected.extend({"file": name, "path": a.get("path"), "reason": "target file is absent"} for a in actions)
            continue
        valid = []
        for action in actions:
            if prose_violations(action["find"], action["replace"]):
                rejected.append({"file": name, "path": action.get("path"), "reason": "prose invariant changed"})
            else:
                valid.append(action)
        if dry_run:
            continue
        handler = _apply_markdown if name.endswith(".md") else _apply_structured
        count, file_rejected, changed = handler(name, target, valid)
        applied += count
        rejected.extend(file_rejected)
        if changed:
            touched.append(name)
    return {
        "applied_count": applied,
        "rejected_count": len(rejected),
        "rejected": rejected,
        "files_touched": sorted(touched),
        "dry_run": dry_run,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="apply_editorial_plan.py", description=__doc__)
    parser.add_argument("output_dir", type=run_path_arg)
    parser.add_argument("--plan", help=f"plan path (default: <output_dir>/{PLAN_NAME})")
    parser.add_argument("--dry-run", action="store_true", help="validate the plan and its targets, write nothing")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"apply_editorial_plan.py: output dir not found: {output_dir}", file=sys.stderr)
        return 2
    plan_path = Path(args.plan) if args.plan else output_dir / PLAN_NAME

    try:
        work_path = output_dir / ".dispatch-context/editorial/blocks.json"
        # A new projection owns packet discovery. Never fall back to a stale
        # legacy plan when its packets are missing or malformed.
        if not args.plan and work_path.exists():
            plan, packet_report = load_packets(output_dir)
        else:
            plan = load_plan(plan_path)
            if plan.get("schema_version") != 1:
                raise PlanError("id plans require their run's work manifest")
            packet_report = {"complete": True, "proposed_count": len(plan["actions"])}
        report = apply_plan(plan, output_dir, dry_run=args.dry_run)
        report.update(packet_report)
    except PlanError as exc:
        print(f"apply_editorial_plan.py: {exc}", file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"apply_editorial_plan.py: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    for entry in report["rejected"]:
        where = f"{entry['file']}:{entry['path']}" if entry["path"] else entry["file"]
        print(f"[editorial] rejected {where} — {entry['reason']}", file=sys.stderr)
    return 1 if report["rejected"] or not report["complete"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
