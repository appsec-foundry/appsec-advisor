#!/usr/bin/env python3
"""Deterministic cache-key handling for Phase-2.7 actor discovery.

The phase prompt previously computed a shell variable and then tried to read it
from ``os.environ`` in a child Python process. Unexported shell variables are
not environment variables, so the cache check always missed. This helper takes
all paths as explicit arguments and owns both key computation and comparison.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from pathlib import Path

_PROMPT_VERSION_RE = re.compile(r"DISCOVERY_PROMPT_VERSION:\s*([0-9]+\.[0-9]+\.[0-9]+)")


def _sha_file(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _actors_input_fingerprint(output_dir: Path) -> str:
    path = output_dir / ".actor-fingerprints.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return ""
    value = payload.get("actors_inputs_fingerprint") if isinstance(payload, dict) else ""
    return value if isinstance(value, str) else ""


def _prompt_version(agent_path: Path) -> str:
    try:
        text = agent_path.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = _PROMPT_VERSION_RE.search(text)
    return match.group(1) if match else ""


def compute_key(output_dir: Path, plugin_root: Path) -> str:
    """Return the stable five-input discovery cache key."""
    agent_path = plugin_root / "agents" / "appsec-actor-discoverer.md"
    parts = (
        _sha_file(output_dir / ".recon-summary.md"),
        _sha_file(output_dir / ".config-scan-findings.json"),
        _actors_input_fingerprint(output_dir),
        _sha_file(agent_path),
        _prompt_version(agent_path),
    )
    return hashlib.sha256("||".join(parts).encode()).hexdigest()


def cache_status(discovery_output: Path, expected_key: str) -> str:
    """Return ``hit`` only for a readable mapping with the exact key."""
    try:
        payload = json.loads(discovery_output.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return "miss"
    if not isinstance(payload, dict):
        return "miss"
    return "hit" if payload.get("discovery_cache_key") == expected_key else "miss"


def write_empty(output: Path, cache_key: str, rationale: str) -> None:
    """Write the schema-valid fallback consumed after a failed LLM contract."""
    payload = {
        "schema_version": 1,
        "discovery_cache_key": cache_key,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "confirmed_relevant": [],
        "proposed_additional": [],
        "inputs_questioned": [],
        "coverage_rationale": rationale,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    compute = sub.add_parser("compute")
    compute.add_argument("--output-dir", required=True, type=Path)
    compute.add_argument("--plugin-root", required=True, type=Path)

    check = sub.add_parser("check")
    check.add_argument("--discovery-output", required=True, type=Path)
    check.add_argument("--expected-key", required=True)

    empty = sub.add_parser("write-empty")
    empty.add_argument("--output", required=True, type=Path)
    empty.add_argument("--cache-key", required=True)
    empty.add_argument("--rationale", required=True)

    args = parser.parse_args()
    if args.command == "compute":
        print(compute_key(args.output_dir, args.plugin_root))
    elif args.command == "check":
        print(cache_status(args.discovery_output, args.expected_key))
    else:
        write_empty(args.output, args.cache_key, args.rationale)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
