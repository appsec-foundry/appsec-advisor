#!/usr/bin/env python3
"""phase_budgets.py — shared loader for ``data/phase-budgets.yaml``.

Single source of truth for phase wall-time thresholds. Replaces the
duplicated ``PHASE_DURATION_LIMITS_SECONDS`` dicts that previously lived in
``aggregate_run_issues.py``, ``watch_run.py``, and (implicitly) the
``HEARTBEAT_STALE_SECONDS`` constant in ``acquire_lock.py`` /
``check_state.py``.

Two consumers, two access patterns
----------------------------------

  * **Phase-aware**  — caller knows the current phase (orchestrator
    heartbeat, skill watchdog, ``aggregate_run_issues``):
    ``threshold_for_phase(phase, depth)``.

  * **Phase-agnostic** — caller has no phase context (cold ``acquire_lock``
    classification, external ``check_state`` invocation, post-mortem
    tools):  ``default_heartbeat_stale_seconds()``.

Both paths share a single YAML read with a process-wide cache; calling
either repeatedly is essentially free.

Fallback
--------

When ``data/phase-budgets.yaml`` is missing or unparseable the loader
returns the historical pre-M3.6 hard-coded values so existing tests and
external callers without the YAML keep working unchanged. The YAML is
parsed with the stdlib ``json``-via-PyYAML chain when available, falling
back to a minimal hand-rolled parser otherwise — the file is constrained
enough (flat scalar values, three depth keys, six phase keys per depth)
that the fallback is reliable.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

# Pre-M3.6 hard-coded values — used as fallback when the YAML cannot be
# loaded. Kept identical to the values that lived in the three duplicated
# dicts so behaviour is unchanged on systems without the file.
_FALLBACK_BUDGETS: dict[str, dict[str, int]] = {
    "quick":    {"1": 180, "2": 120, "3": 60, "9": 180, "10b": 60, "11": 300},
    "standard": {"1": 240, "2": 180, "3": 120, "9": 360, "10b": 120, "11": 600},
    "thorough": {"1": 360, "2": 240, "3": 180, "9": 720, "10b": 180, "11": 900},
}
_FALLBACK_DEFAULTS: dict[str, Any] = {
    "heartbeat_stale_seconds":         300,
    "unlisted_phase_fallback_seconds": 180,
    "hard_ceiling_seconds":            1800,
    "stall_multiplier":                1.5,
}

_CACHE: dict[str, Any] | None = None


def _yaml_path() -> Path:
    """Resolve ``data/phase-budgets.yaml`` relative to the plugin root."""
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if plugin_root:
        return Path(plugin_root) / "data" / "phase-budgets.yaml"
    return Path(__file__).resolve().parent.parent / "data" / "phase-budgets.yaml"


def _try_pyyaml(text: str) -> dict | None:
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _minimal_yaml_parse(text: str) -> dict:
    """Fallback parser for ``data/phase-budgets.yaml``.

    Handles the exact shape we ship — two top-level keys
    (``phase_budgets_seconds``, ``defaults``), nested mappings of scalar
    integers / floats, comments and blank lines. Anything else is silently
    ignored. This keeps the script importable in environments without
    PyYAML.
    """
    out: dict = {}
    stack: list[tuple[int, dict]] = [(0, out)]
    for raw in text.splitlines():
        line = raw.rstrip()
        # Drop comments and blank lines.
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # Strip trailing comment.
        if "#" in stripped:
            stripped = stripped.split("#", 1)[0].rstrip()
            if not stripped:
                continue
        indent = len(line) - len(line.lstrip())
        # Pop deeper scopes.
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        key = key.strip().strip('"')
        value = value.strip()
        if not value:
            new_scope: dict = {}
            parent[key] = new_scope
            stack.append((indent, new_scope))
            continue
        # Strip surrounding quotes.
        if (value.startswith('"') and value.endswith('"')) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        # Coerce to int / float when possible — phase budgets are numeric.
        coerced: Any = value
        try:
            coerced = int(value)
        except ValueError:
            try:
                coerced = float(value)
            except ValueError:
                pass
        parent[key] = coerced
    return out


def _load() -> dict[str, Any]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    path = _yaml_path()
    text: str | None = None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        text = None

    parsed: dict | None = None
    if text:
        parsed = _try_pyyaml(text)
        if parsed is None:
            try:
                parsed = _minimal_yaml_parse(text)
            except Exception:
                parsed = None

    budgets = (parsed or {}).get("phase_budgets_seconds")
    defaults = (parsed or {}).get("defaults")
    if not isinstance(budgets, dict) or not budgets:
        budgets = _FALLBACK_BUDGETS
    if not isinstance(defaults, dict):
        defaults = {}
    # Merge fallback defaults so callers can rely on every key being present.
    for k, v in _FALLBACK_DEFAULTS.items():
        defaults.setdefault(k, v)

    _CACHE = {"budgets": budgets, "defaults": defaults}
    return _CACHE


def budgets_for_depth(depth: str) -> dict[str, int]:
    """Return the per-phase budget mapping for ``depth``.

    Falls back to the ``standard`` row when ``depth`` is not in the table.
    Result is always a fresh copy — callers may mutate freely.
    """
    cfg = _load()["budgets"]
    return dict(cfg.get(depth) or cfg.get("standard") or _FALLBACK_BUDGETS["standard"])


def default_heartbeat_stale_seconds() -> int:
    """Phase-agnostic stall threshold (used when caller has no phase)."""
    return int(_load()["defaults"]["heartbeat_stale_seconds"])


def unlisted_phase_fallback_seconds() -> int:
    """Threshold used when phase IS known but absent from the budget table.

    Phases 4–8 share a generic boundary in the orchestrator and have no
    discrete budget entry; this is the per-phase wall-time treated as
    expected when the lookup misses. Distinct from
    ``default_heartbeat_stale_seconds`` (which fires when no phase context
    is resolvable at all).
    """
    return int(_load()["defaults"]["unlisted_phase_fallback_seconds"])


def hard_ceiling_seconds() -> int:
    """Absolute upper bound — always a stall regardless of phase / depth."""
    return int(_load()["defaults"]["hard_ceiling_seconds"])


def default_stall_multiplier() -> float:
    """Default multiplier applied to phase budgets by watch_run.py."""
    return float(_load()["defaults"]["stall_multiplier"])


def threshold_for_phase(
    phase: str | None,
    depth: str = "standard",
    multiplier: float | None = None,
) -> int:
    """Return the stall threshold (seconds) for a given phase.

    * ``phase`` is the checkpoint phase string (``"1"``, ``"2"``, …,
      ``"10b"``, ``"11"``). ``None`` / unknown values fall through to the
      depth-agnostic default.
    * ``depth`` is the assessment depth; unknown values fall back to
      ``standard``.
    * ``multiplier`` overrides the default grace factor (1.5×). Callers
      that already encode a multiplier upstream pass ``1.0`` to disable.

    The returned value is clamped to ``hard_ceiling_seconds()`` — no
    threshold ever exceeds the absolute ceiling.
    """
    if phase is None or not str(phase).strip():
        return default_heartbeat_stale_seconds()
    table = budgets_for_depth(depth)
    raw = table.get(str(phase))
    mult = multiplier if multiplier is not None else default_stall_multiplier()
    if raw is None:
        # Phase is known to the caller but has no explicit budget — apply
        # the multiplier to the unlisted-phase fallback so behaviour matches
        # what watch_run.py did historically (180 s × 1.5 = 270 s).
        scaled = int(unlisted_phase_fallback_seconds() * float(mult))
    else:
        scaled = int(int(raw) * float(mult))
    ceiling = hard_ceiling_seconds()
    return min(scaled, ceiling)


def reset_cache() -> None:
    """Test hook — drop the module-level cache so reload picks up edits."""
    global _CACHE
    _CACHE = None


def main(argv: list[str]) -> int:
    """CLI: ``phase_budgets.py [<phase>] [--depth <d>] [--multiplier <m>]``.

    With no args, prints the entire resolved YAML as JSON. With a phase
    argument, prints just that threshold (so shell callers can do
    ``T=$(phase_budgets.py 9 --depth quick)``).
    """
    import argparse
    import json

    p = argparse.ArgumentParser(prog="phase_budgets.py")
    p.add_argument("phase", nargs="?", default=None)
    p.add_argument("--depth", default="standard",
                   choices=("quick", "standard", "thorough"))
    p.add_argument("--multiplier", type=float, default=None)
    p.add_argument("--json", action="store_true",
                   help="Force JSON output even with a phase argument.")
    args = p.parse_args(argv[1:])

    if args.phase is None:
        sys.stdout.write(json.dumps(_load(), indent=2) + "\n")
        return 0

    t = threshold_for_phase(args.phase, args.depth, args.multiplier)
    if args.json:
        sys.stdout.write(json.dumps({
            "phase": args.phase,
            "depth": args.depth,
            "multiplier": args.multiplier,
            "threshold_seconds": t,
        }) + "\n")
    else:
        sys.stdout.write(f"{t}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
