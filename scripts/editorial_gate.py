#!/usr/bin/env python3
"""Compare Stage-4 QA with the accepted pre-edit state, never numeric exits.

The controller's compact runtime invokes prepare before dispatch and check
after rendering. Exit 1 means a regression, 2 means unusable gate evidence.
Cosmetic advisories may change; manual-review observations must already have
been accepted in Stage 3. Tool errors and actionable blockers never pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import jsonschema
from _atomic_io import atomic_write_json
from _path_guard import run_path_arg
from build_editorial_context import is_editorial_path, validate_work
from qa_release_gate import scan

SCRIPT_DIR = Path(__file__).resolve().parent
SCHEMA = SCRIPT_DIR.parent / "schemas/editorial-gate.schema.json"
CONTEXT = ".dispatch-context/editorial"


def action_keys(plan: dict) -> list[str]:
    """Fingerprint inspected observations, including merged findings and severity.

    Auto-generated action IDs and remediation prose do not identify the
    observation. Changing an observation under the same ID must still fail.
    """
    if not isinstance(plan, dict) or not isinstance(plan.get("actions"), list):
        raise ValueError("QA plan has no action list")
    keys = []
    for action in plan["actions"]:
        if not isinstance(action, dict) or not isinstance(action.get("raw_issue"), str) or not action["raw_issue"]:
            raise ValueError("QA action has no inspected observation")
        severity = action.get("severity", "blocking")
        if severity not in {"blocking", "manual_review", "cosmetic"}:
            raise ValueError("unknown QA severity")
        if severity == "cosmetic":
            continue
        signal = {
            key: action.get(key)
            for key in ("type", "section_id", "raw_issue", "merged_raw_issues", "fragments_to_rewrite")
        }
        signal["severity"] = severity
        keys.append(hashlib.sha256(json.dumps(signal, sort_keys=True).encode()).hexdigest())
    return sorted(keys)


def compare(before: dict, gate_exit: int, actions: list[str]) -> bool:
    """Exit codes describe categories; 1 is not an improvement over 3."""
    from collections import Counter

    if gate_exit not in {0, 3, 4}:
        return False
    return not (Counter(actions) - Counter(before["actions"]))


def _read(path: Path, output: Path) -> dict:
    if not is_editorial_path(path, output) or path.stat().st_size > 8_000_000:
        raise ValueError("invalid QA artifact path or size")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("QA artifact is not an object")
    return value


def _gate(output: Path, repo: Path) -> tuple[int, list[str]]:
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_DIR / "qa_checks.py"),
            "gate",
            str(output / "threat-model.md"),
            str(output),
            str(repo),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
        check=False,
    )
    if proc.returncode == 0:
        return 0, []
    if proc.returncode not in {1, 3, 4}:
        return proc.returncode, []
    plan = _read(output / ".qa-repair-plan.json", output)
    expected = {1: "fail", 3: "manual_review", 4: "cosmetic_advisory"}[proc.returncode]
    if plan.get("status") != expected:
        raise ValueError("QA exit and plan status disagree")
    return proc.returncode, action_keys(plan)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "check", "close"])
    parser.add_argument("--output-dir", required=True, type=run_path_arg)
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args(argv)
    output = args.output_dir
    context = output / CONTEXT
    baseline_path = context / "gate-baseline.json"
    try:
        work = _read(context / "blocks.json", output)
        validate_work(work)
        qa_status = _read(output / ".qa-status.json", output)
        qa_hash = hashlib.sha256(json.dumps(qa_status, sort_keys=True).encode()).hexdigest()
        if args.command == "prepare":
            status = _read(output / ".qa-status.json", output)
            if status.get("status") != "pass" or scan(output / ".qa-status.json")[0]:
                raise ValueError("Stage 3 has no accepted release receipt")
            previous_path = output / ".qa-repair-plan.json"
            previous = action_keys(_read(previous_path, output)) if previous_path.exists() else []
            code, actions = _gate(output, args.repo_root)
            if not compare({"actions": previous}, code, actions):
                raise ValueError("pre-edit QA does not match accepted Stage-3 observations")
            result = {
                "schema_version": 1,
                "run_id": work["run_id"],
                "status": "baseline",
                "gate_exit": code,
                "actions": actions,
                "qa_status_hash": qa_hash,
            }
            target = baseline_path
        else:
            before = _read(baseline_path, output)
            jsonschema.validate(before, json.loads(SCHEMA.read_text()))
            if before["run_id"] != work["run_id"] or before["status"] != "baseline":
                raise ValueError("QA baseline belongs to another pass")
            if before["qa_status_hash"] != qa_hash:
                raise ValueError("accepted QA disposition changed during editorial pass")
            if args.command == "close":
                report = _read(context / "gate-report.json", output)
                jsonschema.validate(report, json.loads(SCHEMA.read_text()))
                if report["run_id"] != work["run_id"] or report["status"] != "accepted":
                    raise ValueError("no accepted post-edit gate")
                secret_path = output / ".qa-secret-scan.json"
                secret = _read(secret_path, output)
                if secret.get("check") != "unmasked_secrets" or secret.get("ok") != 1 or secret.get("issues") != []:
                    raise ValueError("no clean secret gate")
                inputs = [output / "threat-model.md", output / "threat-model.yaml"]
                inputs.extend(path for path in (output / ".fragments").glob("*") if path.is_file())
                newest = max(path.stat().st_mtime_ns for path in inputs)
                if min(secret_path.stat().st_mtime_ns, (context / "gate-report.json").stat().st_mtime_ns) < newest:
                    raise ValueError("post-edit gates are stale")
                atomic_write_json(output / ".qa-status.json", qa_status)
                return 0
            # Invalidate a previous success before calling the mutating gate.
            pending = {**before, "status": "regression", "gate_exit": 2, "actions": []}
            pending_path = context / "gate-report.json"
            if not is_editorial_path(pending_path, output):
                raise ValueError("QA output escapes run directory")
            atomic_write_json(pending_path, pending)
            code, actions = _gate(output, args.repo_root)
            result = {
                "schema_version": 1,
                "run_id": work["run_id"],
                "status": "accepted" if compare(before, code, actions) else "regression",
                "gate_exit": code,
                "actions": actions,
                "qa_status_hash": qa_hash,
            }
            target = context / "gate-report.json"
        jsonschema.validate(result, json.loads(SCHEMA.read_text()))
        if not is_editorial_path(target, output):
            raise ValueError("QA output escapes run directory")
        atomic_write_json(target, result)
        print(json.dumps({key: value for key, value in result.items() if key != "actions"}))
        return 1 if result["status"] == "regression" else 0
    except (OSError, ValueError, subprocess.SubprocessError, jsonschema.ValidationError):
        print("editorial_gate.py: missing, invalid, or unaccepted QA evidence", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
