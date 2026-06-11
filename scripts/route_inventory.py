#!/usr/bin/env python3
"""
route_inventory.py — deterministic route-extractor MVP.

Writes $OUTPUT_DIR/.route-inventory.json conforming to
schemas/route-inventory.schema.json. Consumed by Phase 6
(attack_surface[]) and scripts/architecture_coverage_checks.py.

Scope (per arch.md §Route Inventory):
  * Express / Koa / Fastify / Hapi / NestJS pattern: app.METHOD(...) and decorators
  * Python FastAPI / Flask / Django: @app.METHOD / @router.METHOD / path() / url()
  * Spring / JAX-RS: @GetMapping / @RequestMapping / @Path
  * ASP.NET minimal APIs: app.MapGet / MapPost / MapPut / MapDelete

Out of scope (NOT MVP):
  * Cross-file router composition / mounting
  * Dynamic path construction
  * Object-level authorization, tenant scope
  * Full control-flow analysis

AuthN / AuthZ are SIGNALS, never verdicts. The default is `unknown`;
`absent` is only emitted when the engine actively saw the route handler
declared at module level with no candidate guard in the file. The
`unknown-is-not-absent` gate is downstream policy (handled in
architecture_coverage_checks.py).

CLI:
    python3 scripts/route_inventory.py --repo-root <repo> --output-dir <dir>
    python3 scripts/route_inventory.py --repo-root <repo> --stdout
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import yaml  # noqa: F401  (kept for parity with sibling scripts; not used here yet)
except ImportError:  # pragma: no cover
    pass


_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
try:
    from scan_excludes import is_excluded as _scan_is_excluded  # type: ignore
except Exception:  # pragma: no cover
    _scan_is_excluded = None


_SOURCE_EXTS = {
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".py",
    ".java",
    ".kt",
    ".scala",
    ".cs",
    ".vb",
    ".go",
    ".rb",
    ".php",
}

_MANAGEMENT_PATH_PATTERN = re.compile(
    r"(?i)("
    r"actuator|/admin\b|/internal\b|/debug\b|/dev\b|/test\b|/metrics\b|/health\b|"
    r"/env\b|/heapdump|/threaddump|/logfile|swagger|graphiql|h2-console|"
    r"openapi(?:\.|/)|/_status|/private"
    r")"
)

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options", "all", "any")


# ---------------------------------------------------------------------------
# Walking
# ---------------------------------------------------------------------------


def _is_excluded(rel: str) -> bool:
    if _scan_is_excluded is not None:
        try:
            return bool(_scan_is_excluded(rel))
        except Exception:  # pragma: no cover
            pass
    parts = rel.split("/")
    return any(
        p in {"node_modules", ".git", "dist", "build", "vendor", "target", "out", ".venv", "venv"} for p in parts
    )


def _walk_sources(repo_root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(repo_root):
        rel_dir = str(Path(dirpath).relative_to(repo_root)).replace("\\", "/")
        dirnames[:] = [d for d in dirnames if not _is_excluded(f"{rel_dir}/{d}" if rel_dir != "." else d)]
        for name in filenames:
            rel = str((Path(dirpath) / name).relative_to(repo_root)).replace("\\", "/")
            if _is_excluded(rel):
                continue
            p = Path(dirpath) / name
            if p.suffix.lower() not in _SOURCE_EXTS:
                continue
            yield p


def _read_lines(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Per-framework extractors. Each returns list[dict] with raw fields:
#   {method, path, framework, handler_file, handler_line}
# ---------------------------------------------------------------------------


_JS_ROUTE_RE = re.compile(
    r"""(?ix)
    # Match named router/app variable followed by HTTP-method call and a path literal.
    # The path literal may appear on the same line or the next few lines (multiline
    # route definitions like router.get(\n  '/path',\n  middleware,\n  handler)).
    \b(?P<obj>app|router|api|server|fastify|hapi|route|r)\b
    \s*\.\s*
    (?P<method>get|post|put|patch|delete|head|options|all|any)
    \s*\(\s*
    (?P<quote>['"`])
    (?P<path>[^'"`]+)
    (?P=quote)
    """,
    re.DOTALL,
)

_JS_DECORATOR_RE = re.compile(
    r"""(?ix)
    @(?P<method>Get|Post|Put|Patch|Delete|Head|Options|All)
    \s*\(\s*
    (?P<quote>['"`])?
    (?P<path>[^'"`)]+)?
    (?P=quote)?
    """
)

_PY_DECORATOR_RE = re.compile(
    r"""(?ix)
    @(?P<obj>app|router|blueprint|bp)
    \s*\.\s*
    (?P<method>get|post|put|patch|delete|head|options|route|api_route|add_api_route)
    \s*\(\s*
    (?P<quote>['"])
    (?P<path>[^'"]+)
    (?P=quote)
    (?P<rest>.*)
    """
)

_PY_DJANGO_ROUTE_RE = re.compile(
    r"""(?ix)
    \b(path|re_path|url)\s*\(\s*
    (?P<quote>['"])
    (?P<path>[^'"]+)
    (?P=quote)
    """
)

_JAVA_MAPPING_RE = re.compile(
    r"""(?ix)
    @(?P<kind>Get|Post|Put|Delete|Patch|Request)Mapping
    \s*\(
    (?:\s*(?:value\s*|path\s*)?=?\s*)?
    \{?\s*
    (?P<quote>")
    (?P<path>[^"]+)
    (?P=quote)
    """
)

_JAVA_PATH_RE = re.compile(
    r"""(?ix)
    @Path\s*\(\s*
    (?P<quote>")
    (?P<path>[^"]+)
    (?P=quote)
    """
)

_JAVA_HTTP_METHOD_RE = re.compile(r"(?i)@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")

_ASPNET_MAP_RE = re.compile(
    r"""(?ix)
    \b(?:app|endpoints|builder)\s*\.\s*
    Map(?P<method>Get|Post|Put|Patch|Delete|Methods)
    \s*\(\s*
    (?P<quote>")
    (?P<path>[^"]+)
    (?P=quote)
    """
)


# ---------------------------------------------------------------------------
# Auth signals
# ---------------------------------------------------------------------------

_AUTHN_PATTERNS = re.compile(
    r"(?i)\b("
    r"authenticate|requireAuth|requireUser|isAuthenticated|ensureAuthenticated|"
    r"passport\.authenticate|verifyToken|jwt(?:Auth|Verify|Middleware)|"
    r"@?login_required|IsAuthenticated|AuthenticationFilter|"
    r"\[Authorize\]|@Secured|@PreAuthorize|requires_auth|"
    r"middleware\(['\"]auth['\"]\)|auth_required|"
    # Common Express/Juice-Shop-style gate names (the gate is named for the
    # authZ check but is the de-facto authN boundary — without a session it
    # rejects). Including these fixes the "every route auth=unknown" miss.
    r"isAuthorized|isLoggedIn|ensureLoggedIn|requireLogin|restrictToLoggedIn|denyAll"
    r")\b"
)

# Path-prefix middleware mounting that carries an auth guard, e.g.
#   app.use('/rest/basket', security.isAuthorized())
#   app.get('/api/Users', security.isAuthorized())
# Juice Shop (and many Express apps) protect whole path prefixes this way,
# separately from where the route handler is defined — so the per-handler
# window scan cannot see the guard. build_inventory collects these prefixes
# globally and marks routes underneath them as guarded.
_GUARD_MOUNT_RE = re.compile(
    r"""\b\w+\.(?:use|all|get|post|put|delete|patch|head|options)\(\s*"""
    r"""['"](?P<path>/[^'"]*)['"]\s*,[^)]*?\b(?:isAuthorized|isAuthenticated|"""
    r"""authenticate|requireAuth|requireLogin|ensureLoggedIn|isLoggedIn|"""
    r"""restrictToLoggedIn|denyAll|passport\.authenticate)\b"""
)

# HTTP verbs that change state — an unauthenticated one is a missing-auth
# suspect worth a review warning (not an assertion).
_STATE_CHANGING = {"POST", "PUT", "DELETE", "PATCH"}

# Paths that are unauthenticated BY DESIGN (the auth-flow entry points and
# common public probes). Excluded from the missing-auth advisory so the
# warning stays low-noise — flagging the login endpoint as "missing auth"
# is a false positive.
_PUBLIC_BY_DESIGN_RE = re.compile(
    r"(?i)(?:^|/)(?:login|logout|register|signup|sign-up|reset-password|"
    r"forgot-password|forgot|recover|2fa|mfa|otp|captcha|token|refresh|"
    r"oauth|openid|sso|saml|health|healthz|readyz|livez|ping|status|version|"
    r"webhook|webhooks)\b"
)

_AUTHZ_PATTERNS = re.compile(
    r"(?i)\b("
    r"requireRole|hasPermission|hasRole|checkPermission|authorize|"
    r"@PreAuthorize|@Secured|@RolesAllowed|"
    r"@?permission_required|@?has_role|"
    r"\[Authorize\(Roles|policy|RoleBasedAccess|Casbin|Oso|"
    r"can\?|ability\.can|enforce\("
    r")\b"
)


@dataclass
class RouteCandidate:
    method: str
    path: str
    framework: str
    handler_file: str
    handler_line: int
    authn_signal: str = "unknown"
    authz_signal: str = "unknown"
    management_surface: bool = False
    missing_auth_suspect: bool = False
    confidence: str = "medium"


def _detect_management_surface(path: str) -> bool:
    return bool(_MANAGEMENT_PATH_PATTERN.search(path))


def _scan_auth_signals(lines: list[str], handler_line: int) -> tuple[str, str]:
    """Search a small window around the handler line for guards.

    Window: 5 lines above + the handler line itself + 3 below. The window
    is intentionally narrow — long-distance inference is out of scope for
    the MVP and produces false-positive guard claims.
    """
    start = max(0, handler_line - 6)
    end = min(len(lines), handler_line + 8)
    window = "".join(lines[start:end])

    authn = "unknown"
    authz = "unknown"

    if _AUTHN_PATTERNS.search(window):
        authn = "middleware_present"
    if _AUTHZ_PATTERNS.search(window):
        authz = "decorator_present" if "@" in window else "middleware_present"

    return authn, authz


# ---------------------------------------------------------------------------
# Extractor dispatch
# ---------------------------------------------------------------------------


def _extract_javascript(path: Path, lines: list[str]) -> list[RouteCandidate]:
    out: list[RouteCandidate] = []
    text = "".join(lines)

    nestjs = bool(re.search(r"@(Controller|Module|Injectable)\s*\(", text)) and bool(_JS_DECORATOR_RE.search(text))
    fastify = "fastify" in text.lower()
    koa = "@koa" in text.lower() or "koa-router" in text.lower()
    hapi = "@hapi" in text.lower()

    if nestjs:
        framework = "nestjs"
    elif fastify:
        framework = "fastify"
    elif koa:
        framework = "koa"
    elif hapi:
        framework = "hapi"
    else:
        framework = "express"

    for m in _JS_ROUTE_RE.finditer(text):
        method = m.group("method").upper()
        route = m.group("path")
        n = text.count("\n", 0, m.start()) + 1
        authn, authz = _scan_auth_signals(lines, n)
        out.append(
            RouteCandidate(
                method=method,
                path=route,
                framework=framework,
                handler_file=str(path).replace("\\", "/"),
                handler_line=n,
                authn_signal=authn,
                authz_signal=authz,
                management_surface=_detect_management_surface(route),
            )
        )

    if nestjs:
        for n, line in enumerate(lines, start=1):
            for m in _JS_DECORATOR_RE.finditer(line):
                route = (m.group("path") or "/").strip()
                method = m.group("method").upper()
                authn, authz = _scan_auth_signals(lines, n + 1)  # decorator above handler
                out.append(
                    RouteCandidate(
                        method=method,
                        path=route,
                        framework="nestjs",
                        handler_file=str(path).replace("\\", "/"),
                        handler_line=n,
                        authn_signal=authn,
                        authz_signal=authz,
                        management_surface=_detect_management_surface(route),
                    )
                )

    return out


def _extract_python(path: Path, lines: list[str]) -> list[RouteCandidate]:
    out: list[RouteCandidate] = []
    text = "".join(lines)

    if "fastapi" in text.lower() or "APIRouter" in text:
        framework = "fastapi"
    elif "from flask" in text.lower() or "flask.Flask" in text:
        framework = "flask"
    elif "django.urls" in text or "urlpatterns" in text:
        framework = "django"
    else:
        framework = "flask"

    for n, line in enumerate(lines, start=1):
        for m in _PY_DECORATOR_RE.finditer(line):
            method_token = m.group("method").lower()
            if method_token in ("route", "api_route", "add_api_route"):
                rest = m.group("rest") or ""
                methods_match = re.search(r"methods\s*=\s*\[([^\]]+)\]", rest)
                methods = []
                if methods_match:
                    methods = [t.strip().strip("'\"").upper() for t in methods_match.group(1).split(",") if t.strip()]
                if not methods:
                    methods = ["GET"]
            else:
                methods = [method_token.upper()]
            route = m.group("path")
            authn, authz = _scan_auth_signals(lines, n + 1)
            for meth in methods:
                out.append(
                    RouteCandidate(
                        method=meth,
                        path=route,
                        framework=framework,
                        handler_file=str(path).replace("\\", "/"),
                        handler_line=n,
                        authn_signal=authn,
                        authz_signal=authz,
                        management_surface=_detect_management_surface(route),
                    )
                )

    if framework == "django":
        for n, line in enumerate(lines, start=1):
            for m in _PY_DJANGO_ROUTE_RE.finditer(line):
                route = m.group("path")
                if not route or route == "":
                    continue
                authn, authz = _scan_auth_signals(lines, n)
                out.append(
                    RouteCandidate(
                        method="ANY",
                        path=route,
                        framework="django",
                        handler_file=str(path).replace("\\", "/"),
                        handler_line=n,
                        authn_signal=authn,
                        authz_signal=authz,
                        management_surface=_detect_management_surface(route),
                        confidence="low",
                    )
                )

    return out


def _extract_java(path: Path, lines: list[str]) -> list[RouteCandidate]:
    out: list[RouteCandidate] = []
    text = "".join(lines)

    if re.search(r"\borg\.springframework\b|@RestController|@SpringBootApplication", text):
        framework = "spring"
    elif re.search(r"\bjavax\.ws\.rs\b|\bjakarta\.ws\.rs\b", text):
        framework = "jaxrs"
    else:
        framework = "spring"

    for n, line in enumerate(lines, start=1):
        for m in _JAVA_MAPPING_RE.finditer(line):
            kind = m.group("kind")
            method = {
                "Get": "GET",
                "Post": "POST",
                "Put": "PUT",
                "Delete": "DELETE",
                "Patch": "PATCH",
            }.get(kind, "ANY")
            route = m.group("path")
            authn, authz = _scan_auth_signals(lines, n + 1)
            out.append(
                RouteCandidate(
                    method=method,
                    path=route,
                    framework=framework,
                    handler_file=str(path).replace("\\", "/"),
                    handler_line=n,
                    authn_signal=authn,
                    authz_signal=authz,
                    management_surface=_detect_management_surface(route),
                )
            )

    if framework == "jaxrs":
        for n, line in enumerate(lines, start=1):
            for m in _JAVA_PATH_RE.finditer(line):
                route = m.group("path")
                method = "ANY"
                lookahead = "".join(lines[n : n + 5])
                meth_match = _JAVA_HTTP_METHOD_RE.search(lookahead)
                if meth_match:
                    method = meth_match.group(1).upper()
                authn, authz = _scan_auth_signals(lines, n + 2)
                out.append(
                    RouteCandidate(
                        method=method,
                        path=route,
                        framework="jaxrs",
                        handler_file=str(path).replace("\\", "/"),
                        handler_line=n,
                        authn_signal=authn,
                        authz_signal=authz,
                        management_surface=_detect_management_surface(route),
                    )
                )

    return out


def _extract_aspnet(path: Path, lines: list[str]) -> list[RouteCandidate]:
    out: list[RouteCandidate] = []

    for n, line in enumerate(lines, start=1):
        for m in _ASPNET_MAP_RE.finditer(line):
            method = m.group("method").upper()
            if method == "METHODS":
                method = "ANY"
            route = m.group("path")
            authn, authz = _scan_auth_signals(lines, n)
            out.append(
                RouteCandidate(
                    method=method,
                    path=route,
                    framework="aspnet-minimal",
                    handler_file=str(path).replace("\\", "/"),
                    handler_line=n,
                    authn_signal=authn,
                    authz_signal=authz,
                    management_surface=_detect_management_surface(route),
                )
            )

    return out


def _extract_file(repo_root: Path, path: Path) -> list[RouteCandidate]:
    rel = path.relative_to(repo_root)
    lines = _read_lines(path)
    if not lines:
        return []
    suffix = path.suffix.lower()

    routes: list[RouteCandidate] = []

    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        routes = _extract_javascript(rel, lines)
    elif suffix == ".py":
        routes = _extract_python(rel, lines)
    elif suffix in {".java", ".kt", ".scala"}:
        routes = _extract_java(rel, lines)
    elif suffix in {".cs", ".vb"}:
        routes = _extract_aspnet(rel, lines)
    else:
        routes = []

    return routes


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def build_inventory(repo_root: Path) -> dict:
    all_routes: list[RouteCandidate] = []
    frameworks_seen: set[str] = set()
    unsupported: list[str] = []
    guarded_prefixes: set[str] = set()

    for src in _walk_sources(repo_root):
        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError:
            lines = []
        # Collect path prefixes mounted with an auth guard (cross-file: a guard
        # in server.ts protects handlers defined in routes/*.ts).
        for gm in _GUARD_MOUNT_RE.finditer("".join(lines)):
            guarded_prefixes.add(gm.group("path").rstrip("/") or "/")
        try:
            extracted = _extract_file(repo_root, src)
        except Exception:  # pragma: no cover
            extracted = []
        for r in extracted:
            frameworks_seen.add(r.framework)
            all_routes.append(r)

    # Apply prefix guards + compute the missing-auth advisory flag.
    def _prefix_guarded(path: str) -> bool:
        p = (path or "").rstrip("/") or "/"
        for g in guarded_prefixes:
            if p == g or p.startswith(g + "/"):
                return True
        return False

    for r in all_routes:
        if r.authn_signal == "unknown" and _prefix_guarded(r.path):
            r.authn_signal = "middleware_present"
        # Warning (not a finding): a state-changing or management route with no
        # detected auth guard looks like it SHOULD require authentication —
        # unless it is an auth-flow / public-probe endpoint (login, register,
        # captcha, health…) which is unauthenticated by design.
        if (
            r.authn_signal == "unknown"
            and (r.method.upper() in _STATE_CHANGING or r.management_surface)
            and not _PUBLIC_BY_DESIGN_RE.search(r.path or "")
        ):
            r.missing_auth_suspect = True

    seen_keys: set[tuple] = set()
    deduped: list[RouteCandidate] = []
    for r in all_routes:
        key = (r.method, r.path, r.handler_file, r.handler_line)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(r)

    routes_out = []
    for i, r in enumerate(deduped, start=1):
        d = asdict(r)
        d["route_id"] = f"R-{i:03d}"
        ordered = {
            "route_id": d["route_id"],
            "method": d["method"],
            "path": d["path"],
            "framework": d["framework"],
            "handler_file": d["handler_file"],
            "handler_line": d["handler_line"],
            "authn_signal": d["authn_signal"],
            "authz_signal": d["authz_signal"],
            "management_surface": d["management_surface"],
            "missing_auth_suspect": d["missing_auth_suspect"],
            "confidence": d["confidence"],
        }
        routes_out.append(ordered)

    mgmt_count = sum(1 for r in routes_out if r["management_surface"])
    missing_auth_count = sum(1 for r in routes_out if r["missing_auth_suspect"])

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(repo_root),
        "routes": routes_out,
        "coverage": {
            "frameworks_detected": sorted(frameworks_seen),
            "unsupported_route_files": unsupported,
            "route_count": len(routes_out),
            "management_surface_count": mgmt_count,
            "missing_auth_suspect_count": missing_auth_count,
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="route_inventory.py", description=__doc__)
    p.add_argument("--repo-root", required=True, help="Repository root to scan.")
    p.add_argument("--output-dir", help="If provided, writes .route-inventory.json there.")
    p.add_argument("--stdout", action="store_true", help="Emit JSON to stdout.")
    args = p.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"route_inventory.py: repo-root not found: {repo_root}", file=sys.stderr)
        return 1

    inventory = build_inventory(repo_root)

    if args.output_dir:
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / ".route-inventory.json"
        out_path.write_text(json.dumps(inventory, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        if not args.stdout:
            print(str(out_path))

    if args.stdout or not args.output_dir:
        json.dump(inventory, sys.stdout, indent=2)
        sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
