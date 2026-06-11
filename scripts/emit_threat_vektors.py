#!/usr/bin/env python3
"""Deterministic vektor (breach-vector) assignment for threats[].

Stage 1 today never populates `threats[].vektor`. The composer falls back
to `"internet-user"` for every threat, which paints all 30 rows of §8 with
the same label even when the actual reachability is `internet-anon`
(public route + no auth) or `repo-read` (hardcoded secret in public repo).

This emitter fills `vektor` deterministically post-Stage-1, before the
renderer reads the YAML. Two signals:

1.  **CWE class** — strong, position-independent signal:
      - Hardcoded credentials / key material exposure (798, 321, 312, 540)
        → `repo-read`
      - XSS / CSRF / open redirect / click-jacking (79, 352, 601, 1021)
        → `victim-required`
      - Else → fall through to signal 2.

2.  **Route auth_required** — derived by matching the threat's
    `evidence[].file` against `attack_surface[].entry_point`. When a
    matching unauthenticated route exists → `internet-anon`. Authenticated
    route → `internet-user`. No match → `internet-anon` (most honest
    default; the prior `internet-user` default actively misled readers
    when the bug was on a public endpoint).

The field is only written when missing (`vektor` not set on the threat).
Hand-set values are preserved. Idempotent.

Usage:
    python3 emit_threat_vektors.py <output_dir>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

# CWE → vektor overrides. Position-independent — applies regardless of
# whether the route is authenticated or not.
_CWE_VEKTOR: dict[str, str] = {
    # repo-read: anything that's an offline-extractable secret/value
    "CWE-798": "repo-read",  # hardcoded credentials
    "CWE-321": "repo-read",  # hardcoded crypto key
    "CWE-312": "repo-read",  # cleartext storage of sensitive info
    "CWE-540": "repo-read",  # inclusion of sensitive info in source code
    # victim-required: needs a browser victim to interact
    "CWE-79": "victim-required",  # XSS
    "CWE-352": "victim-required",  # CSRF
    "CWE-601": "victim-required",  # open redirect
    "CWE-1021": "victim-required",  # frame injection / click-jacking
}


# Tokenisation for matching a handler filename to a route entry_point.
# Express convention: `routes/<name>.ts` handles a route whose URL contains
# the camelCase-split tokens of `<name>` (singular ↔ plural). We split on
# both non-alnum separators and case/digit transitions, then lowercase.
_TOKEN_SPLIT = re.compile(
    r"""
    [^a-zA-Z0-9]+          # punctuation / slashes / spaces
    | (?<=[a-z])(?=[0-9])  # camel: lower → digit
    | (?<=[0-9])(?=[a-z])  # camel: digit → lower
    | (?<=[a-z])(?=[A-Z])  # camel: lower → upper
    | (?<=[A-Z])(?=[A-Z][a-z])  # camel: ALLCAP → CamelCase (HTTPRequest → HTTP + Request)
    """,
    re.VERBOSE,
)


def _tokens(text: str) -> set[str]:
    """Split into ≥3-char lowercase tokens, with naive singular form."""
    raw = _TOKEN_SPLIT.split(text or "")
    out: set[str] = set()
    for piece in raw:
        t = (piece or "").lower().strip()
        if len(t) >= 3:
            out.add(t)
            # Naive singularisation: orders → order, baskets → basket
            if t.endswith("s") and len(t) >= 4 and not t.endswith("ss"):
                out.add(t[:-1])
    return out


def _file_route_tokens(file_path: str) -> set[str]:
    """Return tokens to match against entry_points. Empty when the file
    is a top-level setup file (`server.ts`, `app.ts`) where the threat
    is not tied to a specific route.
    """
    name = Path(file_path).stem
    if not name:
        return set()
    name_lc = name.lower()
    if name_lc in {"server", "app", "index"}:
        return set()
    # Allow frontend/* and lib/* files but they won't typically tokenise
    # against routes — that's fine, the matcher returns None and the
    # caller falls back to the CWE/default branch.
    # Strip canonical handler suffixes
    base = name
    for suf in ("Controller", "Handler", "Route", "Routes"):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    return _tokens(base)


def _route_auth_required(
    file_path: str | None,
    attack_surface: list[dict],
) -> bool | None:
    """Match a threat's evidence.file against the attack_surface[] catalog
    by token overlap. Returns the auth_required boolean of the strongest
    match, or None when no entry can be confidently linked.
    """
    if not file_path:
        return None
    file_tokens = _file_route_tokens(file_path)
    if not file_tokens:
        return None
    best: tuple[int, bool | None] = (0, None)
    for entry in attack_surface or []:
        ep = entry.get("entry_point") or ""
        if not ep:
            continue
        ep_tokens = _tokens(ep)
        overlap = file_tokens & ep_tokens
        if not overlap:
            continue
        score = len(overlap)
        if score > best[0]:
            best = (score, bool(entry.get("auth_required")))
    return best[1]


def _derive_vektor(threat: dict, attack_surface: list[dict]) -> str:
    """Pick a vektor slug for a threat using the two-signal logic above."""
    cwe = (threat.get("cwe") or "").strip().upper()
    if cwe in _CWE_VEKTOR:
        return _CWE_VEKTOR[cwe]

    # Evidence file → route auth_required → vektor
    evidence = threat.get("evidence") or []
    file_path: str = ""
    if evidence and isinstance(evidence, list):
        first = evidence[0] if isinstance(evidence[0], dict) else {}
        file_path = first.get("file") or ""
        auth = _route_auth_required(file_path, attack_surface)
        if auth is True:
            return "internet-user"
        if auth is False:
            return "internet-anon"

    # No attack_surface[] match. Use file-location heuristic:
    #   routes/*    → most likely an authenticated route not in the curated
    #                 public surface list → internet-user
    #   server.ts / app.ts / index.ts / lib/* → router setup, libraries,
    #                 middleware that applies broadly → internet-anon (the
    #                 finding is reachable to anyone hitting any route)
    #   frontend/*  → internet-anon (a client-side bug is reachable by
    #                 anyone who loads the page; XSS / CSRF cases already
    #                 hit the victim-required branch via CWE override)
    fp = (file_path or "").lower()
    if fp.startswith("routes/"):
        return "internet-user"
    return "internet-anon"


def emit(output_dir: Path) -> tuple[int, int, int]:
    """Returns (total, filled_now, preserved). Total = # threats in yaml,
    filled_now = # we just wrote vektor to, preserved = # already had one.
    """
    yaml_path = output_dir / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"emit_threat_vektors: no yaml at {yaml_path}", file=sys.stderr)
        return (0, 0, 0)
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"emit_threat_vektors: parse failed: {exc}", file=sys.stderr)
        return (0, 0, 0)
    if not isinstance(data, dict):
        return (0, 0, 0)

    threats = data.get("threats") or []
    attack_surface = data.get("attack_surface") or []
    filled = 0
    preserved = 0
    for t in threats:
        if not isinstance(t, dict):
            continue
        existing = (t.get("vektor") or "").strip()
        if existing:
            preserved += 1
            continue
        t["vektor"] = _derive_vektor(t, attack_surface)
        filled += 1

    if filled > 0:
        yaml_path.write_text(
            yaml.safe_dump(
                data,
                sort_keys=False,
                allow_unicode=True,
                width=4096,
                default_flow_style=False,
            ),
            encoding="utf-8",
        )
    return (len(threats), filled, preserved)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: emit_threat_vektors.py <output_dir>", file=sys.stderr)
        return 2
    total, filled, preserved = emit(Path(argv[0]))
    print(f"emit_threat_vektors: total={total} filled={filled} preserved={preserved}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
