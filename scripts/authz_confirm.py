#!/usr/bin/env python3
"""authz_confirm.py — route-inventory-driven IDOR/BOLA + missing-route-auth
instance confirmer (cross-language).

The deterministic regex scanner (source_auth_scanner.py) covers IDOR (AUTHZ-002)
and missing route auth (AUTHZ-008) for Node/Express only, because those rules
key on an *inline* request marker (`req.params`). Other stacks have no such
inline marker, so a flat regex would flag every `findById(id)` call.

This module closes that gap without high false positives by REUSING the
multi-language `route_inventory.py` output (`.route-inventory.json`, which parses
Express/Fastify/NestJS/Flask/FastAPI/Django/Spring/JAX-RS/Go/GraphQL into
per-route `handler_file:handler_line` + `missing_authz_suspect` /
`missing_auth_suspect` flags) and then reading the handler *function body* to
confirm the gap:

  * `missing_authz_suspect` (authn present, no authz signal, `:id` path param —
    the BOLA/IDOR primitive) → emit **AUTHZ-301** (CWE-639) UNLESS the handler
    body contains an ownership / tenant / policy predicate.
  * `missing_auth_suspect` (state-changing / management route, authn unknown) →
    emit **AUTHZ-302** (CWE-862) UNLESS the body contains an authentication
    check.

A suspect the reader cannot resolve (no handler file/line, file missing, body
not extractable) is deliberately NOT emitted — it stays a design-level
hypothesis via the architecture-coverage ARCH-BOLA-001 / ARCH-AUTHN-001 rules.
We only upgrade to a *confirmed* instance when the body affirmatively shows the
predicate is absent. This keeps the confirmed-instance channel low-FP (a false
negative on suppression — over-including a neighbouring function's ownership
check — errs toward NOT emitting, never toward a spurious finding).

Output: `<output_dir>/.authz-confirm-findings.json` in the
`schemas/source-auth-findings.schema.yaml` shape. `merge_threats.py` ingests it
beside `.source-auth-findings.json` → `source=source-scan` → folds into the
`missing_authz` weakness class (idor-object-authz / missing-route-auth groups).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_auth_scanner import _source_type_for  # noqa: E402  (reuse ext→enum map)

# --- handler-body extraction ------------------------------------------------

_C_FAMILY = (
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java", ".kt",
    ".go", ".cs", ".php", ".swift", ".dart", ".scala",
)
_MAX_BODY_LINES = 80


_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|`(?:[^`\\]|\\.)*`')


def _extract_brace_body(lines: list[str], i0: int, max_lines: int) -> str:
    """Body of a C-family handler: from the first `{` at/after i0, brace-match
    to its close. String literals are stripped before counting so a literal
    brace (e.g. the `{id}` path template in `@GetMapping("/orders/{id}")`) does
    not terminate the block early. An over-included body only risks a false
    NEGATIVE on emit (safe direction)."""
    depth = 0
    started = False
    out: list[str] = []
    for idx in range(i0, min(len(lines), i0 + max_lines)):
        out.append(lines[idx])
        stripped = _STRING_LITERAL_RE.sub("", lines[idx])
        for ch in stripped:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
                if started and depth <= 0:
                    return "\n".join(out)
    return "\n".join(out)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _extract_python_body(lines: list[str], i0: int, max_lines: int) -> str:
    """Body of a Python handler: find the `def`/`async def` at/after i0 (the
    route decorator may sit on handler_line), then take the indent block."""
    n = len(lines)
    def_idx = None
    for idx in range(i0, min(n, i0 + 5)):
        if re.match(r"\s*(async\s+)?def\s", lines[idx]):
            def_idx = idx
            break
    if def_idx is None:
        return "\n".join(lines[i0 : i0 + 30])
    base = _indent(lines[def_idx])
    out = [lines[def_idx]]
    for idx in range(def_idx + 1, min(n, def_idx + max_lines)):
        line = lines[idx]
        if not line.strip():
            out.append(line)
            continue
        if _indent(line) <= base:
            break
        out.append(line)
    return "\n".join(out)


def extract_body(lines: list[str], handler_line_1based: int, path: Path) -> str:
    """Best-effort handler-body text. Brace-matched for C-family, indent-based
    for Python, bounded forward window otherwise (Ruby, unknown)."""
    if handler_line_1based is None or handler_line_1based < 1:
        return ""
    i0 = min(handler_line_1based - 1, len(lines) - 1)
    if i0 < 0:
        return ""
    ext = path.suffix.lower()
    if ext == ".py":
        return _extract_python_body(lines, i0, _MAX_BODY_LINES)
    if ext in _C_FAMILY:
        return _extract_brace_body(lines, i0, _MAX_BODY_LINES)
    return "\n".join(lines[i0 : i0 + 30])


# --- predicates -------------------------------------------------------------

_OWNERSHIP_RE = re.compile(
    r"(?i)("
    r"owner_?id|user_?id|tenant_?id|account_?id|customer_?id"
    r"|current_?user|\breq(?:uest)?\.user\b|@PreAuthorize|@Secured|@RolesAllowed"
    r"|\bauthorize\b|\.can\(|\bpolicy\b|isOwner|ensureOwner|verifyOwner"
    r"|assertOwnership|getCurrentUser|CurrentUser|\bprincipal\b|belongs_to"
    r"|scope[_.]?to[_.]?user|\.where\([^)]*user"
    r")"
)

_AUTH_RE = re.compile(
    r"(?i)("
    r"authenticate|require_?auth|requireLogin|login_required|@PreAuthorize"
    r"|@Secured|@RolesAllowed|\[Authorize\]|before_action[^\n]*(auth|login)"
    r"|verify_?token|verify_?jwt|\bjwt\b|current_?user|\breq(?:uest)?\.user\b"
    r"|isAuthenticated|passport\.authenticate|ensureLoggedIn|unauthorized|\b401\b"
    r")"
)


def has_ownership_predicate(body: str) -> bool:
    return bool(_OWNERSHIP_RE.search(body or ""))


def has_auth_check(body: str) -> bool:
    return bool(_AUTH_RE.search(body or ""))


# --- confirmation -----------------------------------------------------------

_SNIPPET_MAX = 160


def _snippet(body: str) -> str:
    first = (body or "").strip().splitlines()
    return (first[0][:_SNIPPET_MAX] if first else "")


def confirm_instances(repo_root: Path, inventory: dict) -> list[dict]:
    """Return schema-shaped findings for confirmed IDOR / missing-route-auth."""
    routes = inventory.get("routes") if isinstance(inventory, dict) else None
    if not isinstance(routes, list):
        return []
    findings: list[dict] = []
    seq = 0
    for r in routes:
        if not isinstance(r, dict):
            continue
        hf = (r.get("handler_file") or "").strip()
        hl = r.get("handler_line")
        if not hf or not isinstance(hl, int):
            continue
        path = repo_root / hf
        if not path.exists() or not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        body = extract_body(lines, hl, path)
        if not body:
            continue
        method = (r.get("method") or "").upper()
        route_path = r.get("path") or ""

        check_id = cwe = ft = title = None
        if r.get("missing_authz_suspect") and not has_ownership_predicate(body):
            check_id, cwe, ft = "AUTHZ-301", "CWE-639", "FT-040"
            title = f"IDOR / broken object-level authorization — {method} {route_path}"
            scenario = (
                f"The `{method} {route_path}` handler ({hf}:{hl}) loads a resource by "
                f"a request-supplied id and enforces authentication but no ownership "
                f"predicate in the handler body, so any authenticated user can access "
                f"another user's object."
            )
        elif r.get("missing_auth_suspect") and not has_auth_check(body):
            check_id, cwe, ft = "AUTHZ-302", "CWE-862", "FT-042"
            title = f"Missing authorization on sensitive route — {method} {route_path}"
            scenario = (
                f"The state-changing / management route `{method} {route_path}` "
                f"({hf}:{hl}) has no authentication or authorization check in its "
                f"handler body, so it is reachable by an unauthenticated caller."
            )
        if not check_id:
            continue

        seq += 1
        findings.append(
            {
                "local_id": f"SAF-{seq:03d}",
                "check_id": check_id,
                "source_type": _source_type_for(hf),
                "file": hf,
                "line": hl,
                "title": title,
                "scenario": scenario,
                "severity": "High",
                "cwe": [cwe],
                "finding_type_id": ft,
                "breach_vector": "Internet Anon",
                "evidence_snippet": _snippet(body),
            }
        )
    return findings


def build_document(repo_root: Path, inventory: dict, checks_run: int = 2) -> dict:
    findings = confirm_instances(repo_root, inventory)
    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks_run": checks_run,
        "violations": len(findings),
        "findings": findings,
    }


def _load_inventory(output_dir: Path) -> dict | None:
    path = output_dir / ".route-inventory.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", required=True, type=Path)
    ap.add_argument("--output-dir", required=True, type=Path)
    ap.add_argument("--stdout", action="store_true", help="print the document instead of writing")
    args = ap.parse_args(argv)

    inventory = _load_inventory(args.output_dir)
    if inventory is None:
        # No route inventory → nothing to confirm; emit an empty (valid) doc so
        # merge ingestion is uniform. Absence is the default on repos without
        # a detected route surface.
        inventory = {"routes": []}
    doc = build_document(args.repo_root, inventory)

    if args.stdout:
        print(json.dumps(doc, indent=2))
        return 0
    out = args.output_dir / ".authz-confirm-findings.json"
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    sys.stderr.write(
        f"authz_confirm: wrote {doc['violations']} confirmed authz instance(s) to {out}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
