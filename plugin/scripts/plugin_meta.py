#!/usr/bin/env python3
"""
plugin_meta.py — single source of truth for plugin version metadata.

Reads plugin/.claude-plugin/plugin.json and exposes:
  - plugin_version         (SemVer string, e.g. "0.9.0-beta")
  - analysis_version       (int, bumped when STRIDE prompts / recon categories /
                            severity logic / CWE mapping change in a way that
                            makes prior baselines semantically stale)
  - compatible_analysis_versions (list[int] — which baseline analysis_versions
                                   the current plugin can still read without
                                   forcing a full re-run)

This is kept separate from baseline_state.SCHEMA_VERSION, which covers the
on-disk cache layout. The three axes are orthogonal:

  plugin_version         -> informative (does not break incremental)
  analysis_version       -> semantic analysis compatibility (recommend full)
  SCHEMA_VERSION         -> on-disk file format (hard full-run required)

CLI usage (shell-friendly, avoids needing jq/yq in the orchestrator):

  plugin_meta.py get plugin_version
  plugin_meta.py get analysis_version
  plugin_meta.py get compatible_analysis_versions
  plugin_meta.py check-compat --baseline-version 1
      exit 0  -> compatible (equal version)
      exit 10 -> compatible but baseline older (recommend --full)
      exit 20 -> incompatible (hard-fail, must run --full)
      exit 30 -> baseline version missing (legacy baseline, treat as incompat)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Exit codes — keep stable; consumed by shell callers and tests.
EXIT_COMPAT_EQUAL = 0
EXIT_COMPAT_RECOMMEND_FULL = 10
EXIT_INCOMPAT = 20
EXIT_BASELINE_MISSING = 30
EXIT_ERROR = 2


def _find_plugin_json() -> Path | None:
    """Locate plugin.json. Priority:
    1. $CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json
    2. Walk up from this file until a .claude-plugin/plugin.json is found.
    """
    env_root = os.environ.get("CLAUDE_PLUGIN_ROOT", "").strip()
    if env_root:
        candidate = Path(env_root) / ".claude-plugin" / "plugin.json"
        if candidate.is_file():
            return candidate

    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / ".claude-plugin" / "plugin.json"
        if candidate.is_file():
            return candidate
    return None


def load_meta() -> dict:
    """Return the plugin meta dict. Missing fields default to safe values so
    callers never crash on an older plugin.json that predates this feature.
    """
    path = _find_plugin_json()
    if path is None:
        return {
            "plugin_version": "unknown",
            "analysis_version": 0,
            "compatible_analysis_versions": [],
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "plugin_version": "unknown",
            "analysis_version": 0,
            "compatible_analysis_versions": [],
        }

    return {
        "plugin_version": str(data.get("version", "unknown")),
        "analysis_version": int(data.get("analysis_version", 0)),
        "compatible_analysis_versions": list(data.get("compatible_analysis_versions", [])),
    }


def cmd_get(args: argparse.Namespace) -> int:
    meta = load_meta()
    key = args.key
    if key not in meta:
        print(f"plugin_meta: unknown key: {key}", file=sys.stderr)
        return EXIT_ERROR
    value = meta[key]
    if isinstance(value, list):
        print(",".join(str(v) for v in value))
    else:
        print(value)
    return 0


def classify_compat(baseline_version: int | None, meta: dict) -> tuple[int, str]:
    """Return (exit_code, human_message).

    Semantics:
      - baseline_version is None (legacy baseline written by pre-versioning plugin)
          -> EXIT_BASELINE_MISSING. Caller decides whether to warn or block;
             by default, skills treat this like "recommend full" rather than
             hard-fail so that the pre-M2 bootstrap path keeps working.
      - baseline_version == current analysis_version
          -> EXIT_COMPAT_EQUAL.
      - baseline_version is in compatible_analysis_versions but older than
        the current analysis_version
          -> EXIT_COMPAT_RECOMMEND_FULL.
      - baseline_version is NOT in compatible_analysis_versions
          -> EXIT_INCOMPAT. Hard-fail: cache layout/semantics diverged too far.
    """
    current = int(meta.get("analysis_version", 0))
    compat = list(meta.get("compatible_analysis_versions", []))

    if baseline_version is None:
        return (
            EXIT_BASELINE_MISSING,
            f"baseline has no analysis_version (legacy or pre-versioning); "
            f"current plugin is analysis_version={current}. "
            "Recommend a full run to establish a versioned baseline.",
        )

    if baseline_version == current:
        return (EXIT_COMPAT_EQUAL, f"analysis_version={current} unchanged")

    if baseline_version in compat:
        return (
            EXIT_COMPAT_RECOMMEND_FULL,
            f"baseline analysis_version={baseline_version}, current={current}. "
            "Incremental is still supported, but a --full run is recommended "
            "to pick up analysis improvements.",
        )

    return (
        EXIT_INCOMPAT,
        f"baseline analysis_version={baseline_version} is NOT in the current "
        f"plugin's compatible_analysis_versions={compat}. "
        "Run with --full to rebuild the baseline.",
    )


def cmd_check_compat(args: argparse.Namespace) -> int:
    meta = load_meta()
    baseline_version = args.baseline_version
    if baseline_version is not None and baseline_version < 0:
        print("plugin_meta: baseline_version must be >= 0", file=sys.stderr)
        return EXIT_ERROR
    exit_code, msg = classify_compat(baseline_version, meta)
    stream = sys.stderr if exit_code != EXIT_COMPAT_EQUAL else sys.stdout
    print(f"COMPAT_CHECK: {msg}", file=stream)
    return exit_code


def cmd_print(args: argparse.Namespace) -> int:
    meta = load_meta()
    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="plugin_meta.py",
        description="Plugin version metadata helper.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("get", help="Print a single field (plugin_version, analysis_version, compatible_analysis_versions).")
    g.add_argument("key")
    g.set_defaults(func=cmd_get)

    pr = sub.add_parser("print", help="Print the full meta as JSON.")
    pr.set_defaults(func=cmd_print)

    cc = sub.add_parser(
        "check-compat",
        help="Classify baseline compatibility against the current plugin.",
    )
    cc.add_argument(
        "--baseline-version",
        type=lambda s: None if s in ("", "null", "None") else int(s),
        default=None,
        help="Baseline analysis_version to compare (empty/None = missing).",
    )
    cc.set_defaults(func=cmd_check_compat)

    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
