#!/usr/bin/env python3
"""render_run_diagnosis.py — render the `-- Plugin Diagnosis --` console block.

Reads `$OUTPUT_DIR/.run-bugs.json` (written by the `appsec-run-diagnostician`
agent at the end of a run when `APPSEC_PLUGIN_DEV=1`), validates it against
`schemas/run-bugs.schema.json`, and prints the developer-facing block.

Why the rendering lives here and not in the agent
-------------------------------------------------
The agent decides *what is true*; this script decides *what the user sees*.
Same split as `render_completion_summary.py`: the LLM never hand-authors a
console block, so the format cannot drift run to run and is testable.

Failure behaviour: this is observability, never a gate. A missing file, invalid
JSON, or a schema violation prints at most one stderr warning and exits 0 — a
diagnosis sidecar must not be able to fail a run that already produced a valid
threat model.
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Optional

SCHEMA_REL = "schemas/run-bugs.schema.json"

# Console geometry — matches render_completion_summary.py so the blocks align.
LABEL_WIDTH = 20
WRAP_WIDTH = 78
# Column where a value starts: 2 spaces of indent, the padded label, then `: `.
# Values are clipped or wrapped to VALUE_WIDTH so a verbose diagnosis cannot
# break the block's alignment.
VALUE_COL = 2 + LABEL_WIDTH + 2
VALUE_WIDTH = 64

VERDICT_LABELS = {
    "plugin_bug": "plugin bug",
    "environment": "environment",
    "expected": "expected",
    "inconclusive": "inconclusive",
}


def _label(text: str, value: str) -> str:
    return f"  {text:<{LABEL_WIDTH}}: {value}"


def _clip(value: str, width: int) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= width else value[: width - 1] + "…"


def _indented(value: str) -> list[str]:
    """Wrapped free text aligned under the value column, with no label."""
    pad = " " * VALUE_COL
    return [f"{pad}{line}" for line in textwrap.wrap(" ".join(str(value).split()), width=VALUE_WIDTH)]


def _paragraph(label: str, value: str) -> list[str]:
    """`    <label>  : <first line>` plus continuation lines aligned under it."""
    wrapped = textwrap.wrap(" ".join(str(value).split()), width=VALUE_WIDTH) or [""]
    pad = " " * VALUE_COL
    return [f"  {label:<{LABEL_WIDTH}}: {wrapped[0]}"] + [f"{pad}{line}" for line in wrapped[1:]]


def load_diagnosis(output_dir: Path) -> tuple[Optional[dict], Optional[str]]:
    """Read `.run-bugs.json`. Returns (data, error). Both None means 'absent',
    which is the normal case (dev mode off, clean run, agent declined)."""
    path = output_dir / ".run-bugs.json"
    if not path.is_file():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"{path.name} is unreadable: {exc}"
    if not isinstance(data, dict):
        return None, f"{path.name} is not a JSON object"
    return data, None


def validate(data: dict, plugin_root: Path) -> list[str]:
    """Validate against schemas/run-bugs.schema.json.

    Returns a list of human-readable errors (empty when valid). When
    `jsonschema` is unavailable the structural fallback still catches the
    mistakes that would break rendering — a missing key or a bad verdict.
    """
    schema_path = plugin_root / SCHEMA_REL
    try:
        import jsonschema  # type: ignore
    except ImportError:
        jsonschema = None  # noqa: N816

    if jsonschema is not None and schema_path.is_file():
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [f"schema unreadable: {exc}"]
        validator = jsonschema.Draft202012Validator(schema)
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path))
        return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors[:5]]

    problems: list[str] = []
    for key in ("schema_version", "generated", "issues_total", "issues_examined", "summary", "diagnoses"):
        if key not in data:
            problems.append(f"<root>: missing required key '{key}'")
    for idx, d in enumerate(data.get("diagnoses") or []):
        if not isinstance(d, dict):
            problems.append(f"diagnoses/{idx}: not an object")
            continue
        for key in ("issue_id", "issue_title", "verdict", "confidence", "rationale", "evidence"):
            if key not in d:
                problems.append(f"diagnoses/{idx}: missing required key '{key}'")
        if d.get("verdict") not in VERDICT_LABELS:
            problems.append(f"diagnoses/{idx}: unknown verdict {d.get('verdict')!r}")
        if d.get("verdict") == "plugin_bug" and not isinstance(d.get("root_cause"), dict):
            problems.append(f"diagnoses/{idx}: plugin_bug requires a root_cause object")
    return problems[:5]


def render(data: dict, output_dir: Path) -> list[str]:
    """Build the console block. Returns [] when there is nothing worth printing."""
    diagnoses = data.get("diagnoses") or []
    if not diagnoses:
        return []

    summary = data.get("summary") or {}
    total = data.get("issues_total", 0)
    examined = data.get("issues_examined", len(diagnoses))

    lines: list[str] = []
    lines.append("  -- Plugin Diagnosis (APPSEC_PLUGIN_DEV) -------------------")
    lines.append(_label("Run issues", f"{examined} of {total} examined"))

    counts = " · ".join(
        f"{summary.get(key, 0)} {label}" for key, label in VERDICT_LABELS.items() if summary.get(key, 0)
    )
    lines.append(_label("Verdicts", counts or "none recorded"))

    if total > examined:
        cap = data.get("examination_cap")
        cap_note = f" (cap {cap})" if cap else ""
        lines.append(_label("Not examined", f"{total - examined} lower-severity issue(s){cap_note}"))

    bugs = [d for d in diagnoses if d.get("verdict") == "plugin_bug"]
    if not bugs:
        lines.append(_label("Result", "no plugin bug identified in this run"))
        lines.append("")
        return lines

    lines.append(_label("Artifact", f"{output_dir}/.run-bugs.json"))
    lines.append("")

    for bug in bugs:
        title = _clip(bug.get("issue_title", "(no title)"), 55)
        confidence = bug.get("confidence", "?")
        lines.append(f"  [{bug.get('issue_id', 'ISSUE-???')}] {title} ({confidence} confidence)")

        root = bug.get("root_cause") or {}
        # Location first — it is the one field a developer navigates to. The
        # optional component label is appended only if it still fits the column.
        value = _clip(root.get("location", "(no location)"), VALUE_WIDTH)
        component = root.get("component")
        if component and len(value) + len(component) + 3 <= VALUE_WIDTH:
            value = f"{value} — {component}"
        lines.append(_label("  Root cause", value))
        if root.get("description"):
            lines.extend(_indented(root["description"]))
        if root.get("causal_path"):
            lines.extend(_paragraph("  Causal path", root["causal_path"]))
        if bug.get("suggested_fix"):
            lines.extend(_paragraph("  Suggested fix", bug["suggested_fix"]))
        evidence = bug.get("evidence") or []
        if evidence:
            lines.append(_label("  Evidence", _clip(", ".join(str(e) for e in evidence[:3]), VALUE_WIDTH)))
        lines.append("")

    other = len(diagnoses) - len(bugs)
    if other:
        lines.append(f"  ({other} issue(s) not classified as plugin bugs — see .run-bugs.json)")
        lines.append("")
    return lines


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="render_run_diagnosis.py", description=__doc__.splitlines()[0])
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument(
        "--plugin-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="appsec-advisor checkout (schema lookup). Defaults to this script's repository.",
    )
    args = p.parse_args(argv)

    data, err = load_diagnosis(args.output_dir)
    if err:
        print(f"  ⚠ Plugin diagnosis skipped — {err}", file=sys.stderr)
        return 0
    if data is None:
        return 0

    problems = validate(data, args.plugin_root)
    if problems:
        print("  ⚠ Plugin diagnosis skipped — .run-bugs.json failed schema validation:", file=sys.stderr)
        for problem in problems:
            print(f"      {problem}", file=sys.stderr)
        return 0

    for line in render(data, args.output_dir):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
