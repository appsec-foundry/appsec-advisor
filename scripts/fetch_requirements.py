#!/usr/bin/env python3
"""Deterministic fetch-or-abort gate for security requirements.

Why this exists
---------------
When a run asks to be checked against security requirements
(``CHECK_REQUIREMENTS=true``) the source must actually load. The abort-on-
failure path used to live only as soft prose in ``appsec-context-resolver.md``
(an LLM agent): "stop immediately … the orchestrator will detect the missing
context file and abort". Under turn pressure the agent sometimes wrote the
context file anyway and the run proceeded **without requirements** — silently
producing a report that claims a requirements check that never happened. This
script makes the fetch-or-abort mechanical so a skill-level Bash gate can
enforce it with ``|| exit 2``, exactly like the secret-leak / YAML gates.

It resolves the active source (CLI ``--requirements`` override, org-profile, or
legacy config) via ``resolve_requirements_source.resolve`` so the ``fail_mode``
contract is honoured:

  * ``fail_closed``    (CLI ``--requirements <url>``) — the explicit URL MUST be
                       reachable; no cache fallback. Fetch failure -> exit 2.
  * ``cache_fallback`` (org-profile / legacy config)  — on fetch failure fall
                       back to a non-empty plugin cache; abort only if both the
                       remote AND the cache are unavailable.

On success it writes ``<output-dir>/.requirements.yaml`` (and refreshes the
plugin cache) so the context-resolver agent reads a pre-populated file instead
of fetching again.

Exit codes
----------
0   Requirements available — ``.requirements.yaml`` written (remote fetch,
    cache fallback, or a ``skipped`` stub when the check is disabled).
2   Requirements were requested but are UNAVAILABLE — the caller MUST abort.
3   Usage / tool error (bad output dir).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Reuse the single source of truth for source resolution + fail_mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import resolve_requirements_source as rrs  # noqa: E402

_SKIPPED_STUB = '{"source": "skipped", "categories": [], "blueprints": []}\n'


def _http_get(url: str, timeout: int) -> bytes:
    """Fetch ``url`` and return its bytes. Raises on any failure.

    Isolated so tests can point ``--url`` at a ``file://`` path (urllib handles
    http/https/file uniformly) and exercise both the success and failure paths
    without a network.
    """
    req = urllib.request.Request(url, headers={"Accept": "application/yaml"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def _cache_path(explicit: str | None, plugin_root: Path) -> Path:
    if explicit:
        return Path(explicit)
    return plugin_root / ".cache" / "requirements.yaml"


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)


def _abort(msg_lines: list[str]) -> int:
    print("", file=sys.stderr)
    print("✗ Requirements check is active but the requirements could not be loaded.", file=sys.stderr)
    for line in msg_lines:
        print(f"  {line}", file=sys.stderr)
    print("", file=sys.stderr)
    return 2


def run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"error: output dir does not exist: {output_dir}", file=sys.stderr)
        return 3

    plugin_root = (
        Path(args.plugin_root).resolve()
        if args.plugin_root
        else Path(__file__).resolve().parent.parent
    )
    out_file = output_dir / ".requirements.yaml"
    cache = _cache_path(args.cache_path, plugin_root)

    # Resolve the active source (honours --requirements / --no-requirements /
    # org-profile / legacy config and assigns the fail_mode contract).
    effective = rrs._load_effective(output_dir / ".org-profile-effective.json")
    legacy = rrs._load_legacy_default(plugin_root)
    src = rrs.resolve(
        args.requirements,
        args.no_requirements,
        args.base_mode,
        args.caller,
        effective,
        legacy,
    )

    # The caller (skill) owns the enabled decision via --require / --no-requirements
    # so this gate never diverges from the skill's already-resolved
    # CHECK_REQUIREMENTS (e.g. quick-depth defaults differ between
    # resolve_config and the org-profile re-derivation). An explicit
    # --requirements <url> override also implies required. With neither flag
    # (standalone CLI use) fall back to the resolved `enabled`.
    if args.no_requirements:
        required = False
    elif args.require or args.requirements:
        required = True
    else:
        required = bool(src.get("enabled"))

    if not required:
        # Not requested -> write the skipped stub and succeed (no abort).
        _write(out_file, _SKIPPED_STUB)
        print("↳ Requirements: skipped (not requested)")
        return 0

    url = src.get("url")
    fail_mode = src.get("fail_mode", "cache_fallback")
    cache_allowed = bool(src.get("cache", True)) and fail_mode != "fail_closed"

    # 1. Remote fetch (when a URL is configured).
    if url:
        try:
            body = _http_get(url, args.timeout)
            if not body.strip():
                raise ValueError("empty response")
            _write(out_file, body)
            if cache_allowed:
                _write(cache, body)  # refresh cache for the fallback path
            print(f"↳ Requirements: fetched from {url} ({src.get('source')})")
            return 0
        except (urllib.error.URLError, ValueError, OSError) as exc:
            if not cache_allowed:
                # fail_closed (e.g. --requirements <url>): the explicit URL must
                # be reachable; no cache fallback.
                return _abort([
                    f"Source: {url}  (fail_mode={fail_mode})",
                    f"Reason: {exc}",
                    "The URL was passed explicitly (--requirements) and must be",
                    "reachable. Verify the URL and that the server is running.",
                ])
            print(f"↳ Requirements: remote fetch failed ({url}) — checking plugin cache…", file=sys.stderr)

    # 2. Cache fallback (cache_fallback mode only).
    if cache_allowed and cache.is_file() and cache.stat().st_size > 0:
        _write(out_file, cache.read_bytes())
        print(f"↳ Requirements: loaded from plugin cache ({cache})")
        return 0

    # 3. Requested but nothing loaded -> abort.
    return _abort([
        f"Source: {url or '(no URL configured)'}  (fail_mode={fail_mode})",
        "No remote endpoint responded and no usable plugin cache exists.",
        "Fix: make the requirements URL reachable, populate the cache, or",
        "re-run with --no-requirements to skip the requirements check.",
    ])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="fetch_requirements.py",
        description="Deterministic fetch-or-abort gate for security requirements.",
    )
    p.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR"), required=False)
    p.add_argument("--requirements", default=None, help="CLI requirements URL override")
    p.add_argument("--no-requirements", action="store_true")
    p.add_argument("--require", action="store_true",
                   help="caller asserts requirements ARE requested (skip enabled re-derivation)")
    p.add_argument("--base-mode", default=None, choices=[None, "quick", "standard", "thorough"])
    p.add_argument("--caller", default="create-threat-model",
                   choices=["create-threat-model", "audit-security-requirements"])
    p.add_argument("--plugin-root", default=None)
    p.add_argument("--cache-path", default=None, help="override plugin cache path")
    p.add_argument("--timeout", type=int, default=15)
    args = p.parse_args(argv)
    if not args.output_dir:
        print("error: --output-dir (or OUTPUT_DIR) is required", file=sys.stderr)
        return 3
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
