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
contract is honoured. A source is fetched remotely only when it is an
``http://`` / ``https://`` URL; anything else is read as a local file path
(absolute, relative, or ``~``-prefixed — no ``file://`` scheme):

  * ``fail_closed``    (CLI ``--requirements <src>``) — the explicit source MUST
                       load; no cache fallback. Load failure -> exit 2.
  * ``cache_fallback`` (org-profile / legacy config)  — on load failure fall
                       back to a non-empty plugin cache; abort only if both the
                       source AND the cache are unavailable.

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
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Only http(s) sources are fetched remotely. Everything else — including a bare
# path, ``./reqs.yaml``, ``/abs/reqs.yaml``, or ``~/reqs.yaml`` — is a local file.
_REMOTE_RE = re.compile(r"^https?://", re.IGNORECASE)


def _is_remote(src: str) -> bool:
    """True iff ``src`` is an ``http://`` / ``https://`` URL.

    Anything without an http(s) scheme is interpreted as a local filesystem
    path, so users can say ``--requirements reqs.yaml`` or
    ``--requirements https://host/reqs.yaml`` and nothing else (no ``file://``).
    """
    return bool(_REMOTE_RE.match(src))


def _read_local(path: str) -> bytes:
    """Read a local requirements file. Raises ``OSError`` on any failure.

    Relative paths resolve against the current working directory; ``~`` expands.
    """
    return Path(path).expanduser().read_bytes()


# Reuse the single source of truth for source resolution + fail_mode.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import requirements_state as rstate  # noqa: E402
import resolve_requirements_source as rrs  # noqa: E402

_SKIPPED_STUB = '{"source": "skipped", "categories": [], "blueprints": []}\n'


def _http_get(url: str, timeout: int) -> bytes:
    """Fetch an ``http(s)`` ``url`` and return its bytes. Raises on any failure."""
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


def _emit_summary(output_dir: Path, summary: dict) -> None:
    """Write the resolution summary the skill renders as a startup banner."""
    try:
        (output_dir / ".requirements-resolution.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
    except OSError:
        pass


def _validate_or_abort(body: bytes, src: dict) -> int | None:
    """Validate a loaded catalog against the canonical schema.

    Content-quality issues are printed as warnings and the run proceeds;
    structural breakage (not a catalog at all) returns the abort code so the
    gate fail-closes — a 404 HTML page or truncated file never silently grades
    as zero requirements. Returns ``2`` on abort, ``None`` to proceed.
    """
    errors, warnings = rstate.validate_catalog(body)
    for w in warnings:
        print(f"↳ Requirements: ⚠ {w}", file=sys.stderr)
    if errors:
        return _abort(
            [
                f"Loaded content is not a valid requirements catalog (source: {src.get('source')}).",
                *(f"- {e}" for e in errors[:6]),
                "Fix the catalog structure, run --update, or pass a valid --requirements <src> / --demo.",
            ]
        )
    return None


def _cache_summary(src: dict, cache: Path, disposition: str, fresh: dict | None, body: bytes | None = None) -> dict:
    """Build a resolution-summary dict from the active source + cache state.

    When ``body`` is given (a just-loaded catalog), its metadata wins — so a
    demo/local/CLI source that is never cached reports its own description and
    count rather than whatever the sidecar last remembered.
    """
    sidecar = rstate.read_sidecar(rstate.sidecar_path_for_cache(cache)) or {}
    if body is not None:
        meta = rstate.catalog_meta(body)
        generated, description, count = meta.get("generated"), meta.get("description"), meta.get("count")
        fetched_at = rstate.now_iso()
    else:
        generated, description, count = sidecar.get("generated"), sidecar.get("description"), sidecar.get("count")
        fetched_at = sidecar.get("fetched_at")
    return {
        "source_kind": src.get("source"),
        "url": src.get("url"),
        "label": src.get("label") or sidecar.get("label"),
        "human_source_url": src.get("human_source_url"),
        "demo": bool(src.get("demo")),
        "surfaced": bool(src.get("surfaced")),
        "disposition": disposition,
        "fetched_at": fetched_at,
        "generated": generated,
        "description": description,
        "count": count,
        "freshness": fresh,
        "cache_path": str(cache),
    }


def run(args: argparse.Namespace) -> int:
    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"error: output dir does not exist: {output_dir}", file=sys.stderr)
        return 3

    plugin_root = Path(args.plugin_root).resolve() if args.plugin_root else Path(__file__).resolve().parent.parent
    out_file = output_dir / ".requirements.yaml"
    cache = _cache_path(args.cache_path, plugin_root)
    sidecar_file = rstate.sidecar_path_for_cache(cache)

    # --- Maintenance mode: forget the remembered source + cached catalog. ------
    if args.clear_requirements:
        removed = rstate.clear_state(cache)
        if removed:
            print("↳ Requirements: cleared remembered source and cache:")
            for p in removed:
                print(f"    removed {p}")
        else:
            print("↳ Requirements: nothing to clear (no cache or sidecar present).")
        return 0

    # Backfill a sidecar for a cache that predates this feature so the remembered
    # source is available to resolution, freshness, --status and --update.
    if rstate.read_sidecar(sidecar_file) is None:
        rstate.backfill_sidecar_from_cache(cache)

    # Resolve the active source, honouring the full precedence chain (CLI /
    # --demo / local repo file / org-profile / legacy / remembered sidecar).
    effective = rrs._load_effective(output_dir / ".org-profile-effective.json")
    legacy = rrs._load_legacy_default(plugin_root)
    demo_path = str(plugin_root / "examples" / "appsec-requirements-example.yaml") if args.demo else None
    local_path = rstate.local_repo_source(output_dir)
    remembered = rstate.read_sidecar(sidecar_file)
    src = rrs.resolve(
        args.requirements,
        args.no_requirements,
        args.base_mode,
        args.caller,
        effective,
        legacy,
        demo_path=demo_path,
        local_path=local_path,
        remembered=remembered,
    )

    # The caller (skill) owns the enabled decision via --require / --no-requirements.
    if args.no_requirements:
        required = False
    elif args.require or args.requirements or args.demo or args.update or args.status or args.cache_only:
        required = True
    else:
        required = bool(src.get("enabled"))

    if not required:
        _write(out_file, _SKIPPED_STUB)
        _emit_summary(output_dir, _cache_summary(src, cache, "skipped", None))
        print("↳ Requirements: skipped (not requested)")
        return 0

    src_loc = src.get("url")  # http(s) URL or a local file path
    fail_mode = src.get("fail_mode", "cache_fallback")
    cache_allowed = bool(src.get("cache", True)) and fail_mode != "fail_closed"

    fresh = None
    if cache.is_file() and cache.stat().st_size > 0:
        fetched_at = (remembered or {}).get("fetched_at")
        fresh = rstate.freshness(fetched_at)

    # --- Status mode: report what would be used; never fetch. ------------------
    if args.status:
        _emit_summary(output_dir, _cache_summary(src, cache, "status", fresh))
        return 0

    cache_present = cache.is_file() and cache.stat().st_size > 0

    # --- Cache-only mode: never touch the network. -----------------------------
    if args.cache_only:
        if cache_present:
            body = cache.read_bytes()
            rc = _validate_or_abort(body, src)
            if rc is not None:
                return rc
            _write(out_file, body)
            _emit_summary(output_dir, _cache_summary(src, cache, "cache_only", fresh))
            print(f"↳ Requirements: loaded from plugin cache, offline ({cache})")
            return 0
        return _abort(
            [
                "--cache-only was requested but the plugin cache is empty.",
                "Fix: run once online (or pass --requirements <src>) to populate the cache.",
            ]
        )

    # --- Default flow: use a fresh cache without a network round-trip; only ----
    # try the source when the cache is stale, absent, or --update was passed.
    use_cache_directly = cache_allowed and cache_present and fresh and fresh.get("fresh") and not args.update
    if use_cache_directly:
        body = cache.read_bytes()
        rc = _validate_or_abort(body, src)
        if rc is not None:
            return rc
        _write(out_file, body)
        _emit_summary(output_dir, _cache_summary(src, cache, "cache", fresh))
        age = fresh.get("age_days")
        print(f"↳ Requirements: using cached catalog (fresh, {age}d old) ({cache})")
        return 0

    # 1. Load the source: http(s) -> remote fetch, anything else -> local file.
    if src_loc and src_loc.lower().startswith("file://"):
        src_loc = src_loc[7:]
    if src_loc:
        remote = _is_remote(src_loc)
        try:
            body = _http_get(src_loc, args.timeout) if remote else _read_local(src_loc)
            if not body.strip():
                raise ValueError("empty response")
            # Validate before persisting so a 404 page / garbage never lands in
            # the cache or refreshes the remembered sidecar.
            rc = _validate_or_abort(body, src)
            if rc is not None:
                return rc
            _write(out_file, body)
            if cache_allowed:
                _write(cache, body)  # refresh cache for the fallback path
                rstate.write_sidecar(
                    sidecar_file,
                    rstate.build_sidecar(src_loc, src.get("source", "remembered"), body, rstate.now_iso()),
                )
            verb = "fetched from" if remote else "read from"
            disposition = "demo" if src.get("demo") else ("local" if src.get("source") == "local" else "fetched")
            _emit_summary(output_dir, _cache_summary(src, cache, disposition, fresh, body=body))
            print(f"↳ Requirements: {verb} {src_loc} ({src.get('source')})")
            return 0
        except (urllib.error.URLError, ValueError, OSError) as exc:
            if not cache_allowed:
                # fail_closed (--requirements / --demo / local): must load; no cache.
                hint = (
                    "Verify the URL and that the server is running."
                    if remote
                    else "Verify the path points at an existing, readable file."
                )
                return _abort(
                    [
                        f"Source: {src_loc}  (fail_mode={fail_mode})",
                        f"Reason: {exc}",
                        "The source was passed explicitly and must load. " + hint,
                    ]
                )
            print(f"↳ Requirements: source load failed ({src_loc}) — checking plugin cache…", file=sys.stderr)

    # 2. Cache fallback (cache_fallback mode only).
    if cache_allowed and cache_present:
        body = cache.read_bytes()
        rc = _validate_or_abort(body, src)
        if rc is not None:
            return rc
        _write(out_file, body)
        _emit_summary(output_dir, _cache_summary(src, cache, "cache_after_fetch_fail", fresh))
        when = ""
        if fresh and fresh.get("known"):
            when = f", fetched {fresh.get('age_days')}d ago"
        print(f"↳ Requirements: source unavailable — using cached catalog{when} ({cache})", file=sys.stderr)
        return 0

    # 2b. Bundled best-practices baseline fallback (opt-in via --fallback-baseline).
    if args.fallback_baseline:
        baseline = Path(args.fallback_baseline)
        if baseline.is_file() and baseline.stat().st_size > 0:
            body = baseline.read_bytes()
            rc = _validate_or_abort(body, src)
            if rc is not None:
                return rc
            _write(out_file, body)
            _emit_summary(output_dir, _cache_summary(src, cache, "baseline", fresh))
            print(f"↳ Requirements: no company source — using bundled best-practices baseline ({baseline})")
            return 0

    # 3. Requested but nothing loaded -> abort.
    _emit_summary(output_dir, _cache_summary(src, cache, "unavailable", fresh))
    return _abort(
        [
            f"Source: {src_loc or '(no source configured)'}  (fail_mode={fail_mode})",
            "The configured source did not load and no usable plugin cache exists.",
            "Fix: make the requirements source reachable, populate the cache, pass",
            "--demo to use the packaged example, or --no-requirements to skip.",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="fetch_requirements.py",
        description="Deterministic fetch-or-abort gate for security requirements.",
    )
    p.add_argument("--output-dir", default=os.environ.get("OUTPUT_DIR"), required=False)
    p.add_argument(
        "--requirements", default=None, help="requirements source override: http(s):// URL or a local file path"
    )
    p.add_argument("--no-requirements", action="store_true")
    p.add_argument(
        "--require", action="store_true", help="caller asserts requirements ARE requested (skip enabled re-derivation)"
    )
    p.add_argument("--demo", action="store_true", help="use the packaged example catalog (DEMO, never cached)")
    p.add_argument("--update", action="store_true", help="force re-fetch from the remembered/configured source")
    p.add_argument("--cache-only", action="store_true", help="use the plugin cache only; never touch the network")
    p.add_argument("--status", action="store_true", help="emit the resolution summary only; never fetch")
    p.add_argument(
        "--clear-requirements", action="store_true", help="delete the cached catalog and remembered source sidecar"
    )
    p.add_argument("--base-mode", default=None, choices=[None, "quick", "standard", "thorough"])
    p.add_argument(
        "--caller",
        default="create-threat-model",
        choices=["create-threat-model", "audit-security-requirements", "verify-requirements"],
    )
    p.add_argument(
        "--fallback-baseline",
        default=None,
        help="opt-in: on the cache_fallback path, if no company source/cache loads, "
        "write this baseline catalog instead of aborting (dev-security-helper). "
        "Never overrides an explicit --requirements failure (that still aborts).",
    )
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
