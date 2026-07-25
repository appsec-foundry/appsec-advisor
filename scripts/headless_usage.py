#!/usr/bin/env python3
"""headless_usage.py — authoritative per-model token/cost readout for a headless run.

``claude -p --output-format json`` ends with a single result object that carries
``total_cost_usd`` plus a per-model ``modelUsage`` breakdown. Those numbers come
from Claude Code's own accounting — the same source the interactive ``/cost``
command reports — and, unlike ``.hook-events.log``, they include sub-agent spend.

Why this script and not the existing cost tooling:
  - ``verify_run_costs.py`` / ``cost_running_total.py`` reconstruct cost from
    cumulative ``SESSION_STOP`` hook lines times a locally maintained pricing
    table. The hook only fires for the *host* session, so sub-agent spend is a
    lower bound, and the pricing table can drift from the real rates. Both are
    estimates by construction.
  - The result object needs no pricing table and no reconstruction. It is the
    only readout that can be labelled as exact.

Deliberately NOT reconstructed from ``--output-format stream-json``: the
per-message ``usage`` in the streamed ``assistant`` events is partial and
excludes sub-agents (measured 2026-07-25: 6 vs 356 output tokens for the same
run), so summing it would produce a confident-looking wrong number. When the
result object is absent — a killed, timed-out or interrupted run — this script
reports nothing and the caller falls back to a clearly labelled estimate.

Usage:
    headless_usage.py <capture-file> [--format table|json] [--result-text]

Exit codes:
  0 — an authoritative result object was found and rendered
  1 — no result object in the capture (caller must fall back / stay silent)
  2 — usage error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# modelUsage field name → our short column key.
_USAGE_FIELDS = {
    "inputTokens": "input",
    "outputTokens": "output",
    "cacheReadInputTokens": "cache_read",
    "cacheCreationInputTokens": "cache_write",
}

_COLUMNS = [
    ("input", "input"),
    ("output", "output"),
    ("cache_read", "cache read"),
    ("cache_write", "cache write"),
]


def load_result(path: Path) -> dict[str, Any] | None:
    """Return the run's result object from a captured stdout file, or None.

    Accepts every shape the CLI can produce, so the caller is free to switch
    ``--output-format`` or add ``--verbose`` without breaking the readout:
      - ``json``             — the file is one result object
      - ``json --verbose``   — a JSON *array* of every event; the result is last
      - ``stream-json``      — JSONL; the last ``type == "result"`` line wins

    A truncated or malformed capture (killed process) yields None rather than
    an exception: an unusable number must never be presented as a real one.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if not text.strip():
        return None

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        pass
    else:
        if isinstance(obj, list):
            return next((e for e in reversed(obj) if _is_result(e)), None)
        return obj if _is_result(obj) else None

    # JSONL — scan backwards so the terminal result line is found first.
    for line in reversed(text.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if _is_result(obj):
            return obj
    return None


def _is_result(obj: Any) -> bool:
    """A result object is identified by its type, or by carrying the total."""
    if not isinstance(obj, dict):
        return False
    return obj.get("type") == "result" or "total_cost_usd" in obj


def extract_usage(result: dict[str, Any]) -> dict[str, Any]:
    """Normalise the result object into a per-model usage summary.

    ``modelUsage`` is keyed by the concrete model id the API billed. We prefer
    the ``canonicalModel`` label for display (``claude-haiku-4-5`` rather than
    ``claude-haiku-4-5-20251001``) because it is what the operator recognises,
    but we never merge two ids that resolve to the same canonical name — a run
    that used two dated snapshots of one model should stay visible as two rows.
    """
    models: list[dict[str, Any]] = []
    raw = result.get("modelUsage")
    if isinstance(raw, dict):
        for model_id, entry in raw.items():
            if not isinstance(entry, dict):
                continue
            row: dict[str, Any] = {
                "model": entry.get("canonicalModel") or model_id,
                "model_id": model_id,
                "cost_usd": _as_float(entry.get("costUSD")),
            }
            for src, key in _USAGE_FIELDS.items():
                row[key] = _as_int(entry.get(src))
            row["total_tokens"] = row["input"] + row["output"] + row["cache_read"] + row["cache_write"]
            models.append(row)
    models.sort(key=lambda r: (-r["cost_usd"], r["model"]))

    return {
        "total_cost_usd": _as_float(result.get("total_cost_usd")),
        "models": models,
        "num_turns": _as_int(result.get("num_turns")),
        "duration_ms": _as_int(result.get("duration_ms")),
        "is_error": bool(result.get("is_error")),
        "session_id": result.get("session_id"),
    }


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def format_table(usage: dict[str, Any]) -> str:
    """Render the per-model breakdown as an indented console table.

    Indentation matches the surrounding run-headless summary blocks (two spaces
    for the heading, four for rows).
    """
    models = usage["models"]
    headers = ["model"] + [label for _, label in _COLUMNS] + ["cost"]
    rows: list[list[str]] = []
    for m in models:
        rows.append([m["model"]] + [f"{m[key]:,}" for key, _ in _COLUMNS] + [_fmt_cost(m["cost_usd"])])

    totals = [sum(m[key] for m in models) for key, _ in _COLUMNS]
    total_row = ["total"] + [f"{t:,}" for t in totals] + [_fmt_cost(usage["total_cost_usd"])]

    widths = [max(len(headers[i]), *(len(r[i]) for r in [*rows, total_row])) for i in range(len(headers))]

    def _line(cells: list[str]) -> str:
        out = cells[0].ljust(widths[0])
        for i in range(1, len(cells)):
            out += "  " + cells[i].rjust(widths[i])
        return "    " + out.rstrip()

    lines = ["  Token usage & cost — Claude Code accounting, same source as /cost", _line(headers)]
    lines.extend(_line(r) for r in rows)
    if len(rows) != 1:
        # A single-model run needs no separator: its row and the total are equal.
        lines.append("    " + "─" * (sum(widths) + 2 * (len(widths) - 1)))
        lines.append(_line(total_row))
    lines.append("    API-equivalent list price; on a subscription the marginal cost is $0.")
    return "\n".join(lines)


def _fmt_cost(value: float) -> str:
    """Sub-cent totals would render as $0.00 and read as 'free', so keep digits."""
    if 0 < value < 0.01:
        return f"${value:.4f}"
    return f"${value:.2f}"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("capture", help="file holding the captured `claude -p` stdout")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument(
        "--result-text",
        action="store_true",
        help="print the run's final assistant text instead of the usage table",
    )
    args = parser.parse_args(argv)

    result = load_result(Path(args.capture))
    if result is None:
        return 1

    if args.result_text:
        text = result.get("result")
        if isinstance(text, str) and text.strip():
            print(text)
        return 0

    usage = extract_usage(result)
    if args.format == "json":
        print(json.dumps(usage, indent=2, sort_keys=True))
        return 0

    if not usage["models"] and not usage["total_cost_usd"]:
        return 1
    print(format_table(usage))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except SystemExit:
        raise
    except Exception as exc:  # pragma: no cover - defensive: never break the run
        print(f"headless_usage: {exc}", file=sys.stderr)
        sys.exit(1)
