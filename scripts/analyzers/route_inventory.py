#!/usr/bin/env python3
"""
analyzers/route_inventory.py — deterministic route extractor.

Writes $OUTPUT_DIR/.route-inventory.json conforming to
schemas/route-inventory.schema.json. Consumed by Phase 6
(attack_surface[]), scripts/analyzers/architecture_coverage_checks.py and
scripts/analyzers/authz_confirm.py.

Route extractors:
  * Express / Koa / Fastify / Hapi / NestJS pattern: app.METHOD(...) and decorators
  * Python FastAPI / Flask / Django: @app.METHOD / @router.METHOD / path() / url()
  * Spring / JAX-RS: @GetMapping / @RequestMapping / @Path
  * ASP.NET minimal APIs: app.MapGet / MapPost / MapPut / MapDelete
  * GraphQL SDL operations: type Query / Mutation / Subscription fields
Go, Ruby and PHP files have no route extractor; they are read only by the
path-prefix guard-mount scan.

Out of scope:
  * Cross-file router composition (a mount prefix is not joined to the route path)
  * Dynamic path construction
  * Object-level authorization, tenant scope
  * Full control-flow analysis

AuthN / AuthZ are SIGNALS, never verdicts. The default is `unknown`.
A guard counts only for the registration it belongs to (FE-10); a guard
mounted on a path prefix in any scanned file lifts matching routes to
`middleware_present`. `analyzers/handler_resolver.py` then classifies the
resolved handler chain (FE-14): `verified` sets `present`, and `absent` is
emitted only when the resolver returns `none` or `decode_only` for a route
still `unknown`. The `unknown-is-not-absent` gate is downstream policy
(handled in analyzers/architecture_coverage_checks.py).

CLI:
    python3 scripts/analyzers/route_inventory.py --repo-root <repo> --output-dir <dir>
    python3 scripts/analyzers/route_inventory.py --repo-root <repo> --stdout
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from shared._path_guard import is_safe_to_read

from analyzers.handler_resolver import HandlerResolver

try:
    import yaml  # noqa: F401  (kept for parity with sibling scripts; not used here yet)
except ImportError:  # pragma: no cover
    pass


_HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_HERE))
try:
    from analyzers.scan_excludes import is_excluded as _scan_is_excluded  # type: ignore
    from analyzers.scan_excludes import is_oversize as _scan_is_oversize  # type: ignore
except Exception:  # pragma: no cover
    _scan_is_excluded = None
    _scan_is_oversize = None


_JS_EXTS = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

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
    ".graphql",
    ".gql",
    ".graphqls",
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
            # Central per-file byte cap: skip oversize blobs (not real source).
            if _scan_is_oversize is not None and _scan_is_oversize(p):
                continue
            if is_safe_to_read(p, repo_root):
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
    \s*(?P<open>\()\s*
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
    \b(path|re_path|url)\s*(?P<open>\()\s*
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

_GRAPHQL_OPERATION_RE = re.compile(
    r"""(?imsx)
    ^\s*(?:extend\s+)?type\s+
    (?P<op>Query|Mutation|Subscription)\b
    (?P<header>[^{]*)
    \{
    (?P<body>.*?)
    ^\s*\}
    """
)

_GRAPHQL_FIELD_RE = re.compile(
    r"""(?x)
    ^\s*
    (?P<name>[_A-Za-z][_0-9A-Za-z]*)
    \s*
    (?:\((?P<args>[^)]*)\))?
    \s*:\s*
    (?P<returns>[^@#]+?)
    \s*
    (?P<directives>@.*)?
    $
    """
)

_GRAPHQL_ARG_NAME_RE = re.compile(r"\b([_A-Za-z][_0-9A-Za-z]*)\s*:")

_GRAPHQL_AUTHN_RE = re.compile(
    r"(?i)@(?:auth|authenticated|requires?Auth|loginRequired|isAuthenticated|guard|aws_auth|aws_cognito_user_pools)\b"
)

_GRAPHQL_AUTHZ_RE = re.compile(
    r"(?i)(@(?:hasRole|hasPermission|requires?Role|requires?Scope|authz|authorization|policy|role|roles|scope|scopes|allow)\b|"
    r"\b(?:roles?|permissions?|scopes?|policy|requires)\s*:)"
)

_GRAPHQL_OBJECT_ARG_RE = re.compile(r"(?i)(^id$|_id$|Id$|ID$|uuid|slug|key)")

_GRAPHQL_SENSITIVE_RE = re.compile(
    r"(?i)(user|account|tenant|org|order|invoice|payment|card|wallet|address|email|"
    r"password|secret|token|key|role|permission|admin|profile|session)"
)


# ---------------------------------------------------------------------------
# Auth signals
# ---------------------------------------------------------------------------

_AUTHN_PATTERNS = re.compile(
    r"(?i)\b("
    r"authenticate|requireAuth|requireUser|isAuthenticated|ensureAuthenticated|"
    r"passport\.authenticate|verifyToken|"
    r"@?login_required|IsAuthenticated|AuthenticationFilter|"
    r"requires_auth|auth_required|"
    # Common Express/Juice-Shop-style gate names (the gate is named for the
    # authZ check but is the de-facto authN boundary — without a session it
    # rejects). Including these fixes the "every route auth=unknown" miss.
    r"isAuthorized|isLoggedIn|ensureLoggedIn|requireLogin|restrictToLoggedIn|denyAll"
    r")\b"
    # Annotations and attributes start with a non-word character, so they
    # cannot sit behind the `\b` above. Any `[Authorize]` form requires a user.
    r"|(?<![\w@])@(?:Secured|PreAuthorize|RolesAllowed)\b|\[Authorize\b"
    # jwt{Auth,Verify,Middleware} only when invoked as a function call or
    # passed as a middleware argument — not when it appears as a TypeScript
    # parameter declaration (e.g. `jwtMiddleware: ExpressMiddleware`).
    r"|\bjwt(?:Auth|Verify|Middleware)\s*\("
)

# Guard registrations away from the handler, e.g.
#   app.use('/rest/basket', security.isAuthorized())   # every method below the prefix
#   app.get('/api/Users', security.isAuthorized())      # this method on this exact path
# Many Express apps protect routes this way, separately from where the handler
# is defined. build_inventory collects them globally: `use` (and a wildcard
# `all`) guards a prefix, any other verb guards only its own method and path.
# The guard is searched in the call's middleware arguments (`_mount_middleware`),
# so a guard with nested parentheses such as `rateLimit({..}), requireAuth` counts.
_MOUNT_HEAD_RE = re.compile(
    r"""\b\w+\.(?P<verb>use|all|get|post|put|delete|patch|head|options)(?P<open>\()\s*"""
    r"""['"](?P<path>/[^'"]*)['"]\s*,"""
)
_GUARD_NAME_RE = re.compile(
    r"""\b(?:isAuthorized|isAuthenticated|authenticate|requireAuth|requireLogin|"""
    r"""ensureLoggedIn|isLoggedIn|restrictToLoggedIn|denyAll|passport\.authenticate)\b"""
)
#: A registration call is short; the cap only bounds an unbalanced one.
_MOUNT_SCOPE_CAP = 4000


def _mount_middleware(text: str, head: re.Match) -> str:
    """The middleware arguments of one guard registration, literals emptied.

    The scan stops at an inline handler (`=>` or a `{` body at argument level),
    because a check inside the handler body is not a mount guard.
    """
    open_paren = head.start("open")
    scope = _strip_literals(
        _call_scope(text, open_paren, open_paren, min(len(text), open_paren + _MOUNT_SCOPE_CAP), "//")
    )
    depth = 0
    for i, ch in enumerate(scope):
        if ch in "([{":
            if ch == "{" and depth == 1:
                return scope[:i]
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 1 and scope.startswith("=>", i):
            return scope[:i]
    return scope


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

_PUBLIC_OPERATION_NAME_RE = re.compile(
    r"(?i)\b(?:login|logout|register|signup|sign-up|reset-password|"
    r"forgot-password|forgot|recover|token|refresh|oauth|openid|sso|saml)\b"
)


def _is_public_by_design(path: str | None) -> bool:
    value = path or ""
    if _PUBLIC_BY_DESIGN_RE.search(value):
        return True
    # GraphQL logical operation names are not URL segments (`Mutation login`),
    # so the path-oriented regex above cannot see their public auth-flow names.
    # Keep this branch off normal HTTP paths to avoid broadening the URL rule.
    return "/" not in value and bool(_PUBLIC_OPERATION_NAME_RE.search(value))


# Positive security-relevance patterns — INTENTIONALLY NARROWER than
# _PUBLIC_BY_DESIGN_RE, which also matches health/ping/version/webhook noise we
# do NOT want to surface. A finding-free route whose path matches one of these
# still earns an individual row in §5 Attack Surface because it sits on the
# account-lifecycle / identity surface an attacker probes first. These drive the
# per-route `relevance_tags` advisory — display signal only, never a finding.
_REGISTRATION_PATH_RE = re.compile(r"(?i)(?:^|/)(?:register|signup|sign-up)\b")
_AUTHFLOW_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:login|logout|signin|sign-in|password|passwd|"
    r"reset-password|forgot-password|forgot|recover|token|jwt|oauth|openid|"
    r"sso|saml|2fa|mfa|otp|session|credential)\b"
)

# An endpoint that carries user text into a model prompt is its own attack
# surface (OWASP LLM01/LLM06), but its path alone proves nothing — plenty of
# applications have a `/chat` that never reaches a model. The tag therefore
# requires both halves: an LLM-shaped path AND a declared LLM SDK dependency in
# the repository. A chat route in a project with no such dependency stays
# untagged, and an LLM dependency alone tags nothing.
_LLM_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:chat|chatbot|completion|completions|prompt|prompts|"
    r"assistant|copilot|ask|llm|ai|agent|generate|summarize|embed|embedding|embeddings)\b"
)

#: Package names that establish a model-inference dependency. Matched against
#: declared dependencies only, never against arbitrary source text, so a
#: mention in a comment or a test fixture cannot trigger the tag.
_LLM_SDK_NAMES = (
    "openai",
    "anthropic",
    "@ai-sdk/",
    "@anthropic-ai/",
    "@google/generative-ai",
    "@langchain/",
    "langchain",
    "llamaindex",
    "llama-index",
    "cohere",
    "mistralai",
    "ollama",
    "replicate",
    "google-generativeai",
    "vertexai",
    "semantic-kernel",
    "transformers",
    "litellm",
    "huggingface_hub",
    "huggingface-hub",
    "@huggingface/inference",
    "groq",
    "together-ai",
    "togetherai",
    "fireworks-ai",
    "dashscope",
    "haystack-ai",
    "bedrock-runtime",
    "amazon-bedrock",
    "langchain-aws",
)

#: Manifests whose declared dependencies are read for the SDK signal.
_LLM_MANIFESTS = (
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "Pipfile",
    "go.mod",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Cargo.toml",
)


def _declares_llm_sdk(repo_root: Path) -> bool:
    """True when a top-level manifest declares a model-inference dependency."""
    for name in _LLM_MANIFESTS:
        manifest = repo_root / name
        try:
            if not manifest.is_file():
                continue
            text = manifest.read_text(encoding="utf-8", errors="replace")[:_MAX_MANIFEST_BYTES]
        except OSError:
            continue
        lowered = text.lower()
        if any(sdk in lowered for sdk in _LLM_SDK_NAMES):
            return True
    return False


#: Manifests are small; the cap only bounds a pathological file.
_MAX_MANIFEST_BYTES = 512_000


_AUTHZ_PATTERNS = re.compile(
    r"(?i)\b("
    r"requireRole|hasPermission|hasRole|checkPermission|(?<!\[)authorize|"
    r"@?permission_required|@?has_role|"
    r"policy|RoleBasedAccess|Casbin|Oso|"
    r"can\?|ability\.can|enforce\("
    r")\b"
    # A bare `[Authorize]` only authenticates; roles or a policy authorize.
    r"|(?<![\w@])@(?:PreAuthorize|Secured|RolesAllowed)\b"
    r"|\[Authorize\s*\(\s*(?:Roles|Policy)\b"
)

# Path-prefix middleware mounting that carries an authoriZation guard (role /
# permission / policy), e.g.
#   app.use('/api/admin', requireRole('admin'))
#   router.use('/billing', authorize('billing:write'))
# Mirrors _GUARD_NAME_RE (which only resolves authN) so a centralised authZ
# layer mounted away from the handler is not mis-read as "no authz". Without
# this lift, every route under a central RBAC mount stays authz=unknown and
# floods the BOLA hypothesis with false positives.
_AUTHZ_GUARD_NAME_RE = re.compile(
    r"""\b(?:requireRole|hasPermission|hasRole|checkPermission|authorize|RolesAllowed|"""
    r"""requirePermission|enforce|casbin|oso|opa|can|ability)\b"""
)

# A route path that addresses a specific object by id — the BOLA/IDOR surface.
# Matches Express/Rails ':id', FastAPI/Spring/.NET '{id}'/'{id:int}', and
# Flask/Django '<id>'/'<int:id>'.
_PATH_PARAM_RE = re.compile(r":[A-Za-z_][\w-]*|\{[A-Za-z_][\w:-]*\}|<[A-Za-z_][\w:-]*>")

# Signal values that mean "a guard WAS detected" (authN or authZ). A route is a
# missing-authz suspect only when it is authenticated (authN present) AND no
# authZ gate was detected.
_AUTHN_PRESENT = {"present", "middleware_present", "decorator_present"}
_AUTHZ_PRESENT = {"present", "middleware_present", "decorator_present"}


def route_authenticated(route: dict) -> bool:
    """Whether the inventory proves a route authenticated: a registration guard or a verified handler check."""
    return route.get("authn_signal") in _AUTHN_PRESENT


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
    missing_authz_suspect: bool = False
    relevance_tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    confidence: str = "medium"
    authn_handler_signal: str | None = None
    authn_handler_scheme: str | None = None
    authn_handler_evidence: list[dict] = field(default_factory=list)
    handler_module: str | None = None


def _detect_management_surface(path: str) -> bool:
    return bool(_MANAGEMENT_PATH_PATTERN.search(path))


_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`')


def _strip_literals(text: str) -> str:
    """Empty every string literal: a guard is code, never a path such as `/privacy-policy`."""
    return _STRING_LITERAL_RE.sub('""', text)


# String literals are matched as a unit so a `//` or `#` inside one is no comment;
# an unterminated quote ends at its line, an unterminated block at the file end.
_STRINGS = r'"(?:[^"\\\n]|\\[\s\S])*"?|\'(?:[^\'\\\n]|\\[\s\S])*\'?|`(?:[^`\\]|\\[\s\S])*`?'
_COMMENT_RES = {
    "//": re.compile(_STRINGS + r"|//[^\n]*|/\*[\s\S]*?(?:\*/|\Z)"),
    "#": re.compile(_STRINGS + r"|#[^\n]*"),
}
_NOT_NEWLINE_RE = re.compile(r"[^\n]")


def _mask_comments(text: str, line_comment: str) -> str:
    """Blank comments with spaces, keeping offsets and newlines, so a commented-out
    registration or guard is not code."""

    def blank(m: re.Match) -> str:
        token = m.group(0)
        return token if token[0] in "'\"`" else _NOT_NEWLINE_RE.sub(" ", token)

    return _COMMENT_RES[line_comment].sub(blank, text)


def _scan_auth_text(text: str) -> tuple[str, str]:
    text = _strip_literals(text)
    authn = "middleware_present" if _AUTHN_PATTERNS.search(text) else "unknown"
    authz = "unknown"
    if _AUTHZ_PATTERNS.search(text):
        authz = "decorator_present" if "@" in text else "middleware_present"
    return authn, authz


def _scan_auth_signals(lines: list[str], handler_line: int) -> tuple[str, str]:
    """Search a small window around the handler line for guards.

    Only decorator- and attribute-based extractors use this window, because
    their guards sit on neighbouring lines. It can still reach a neighbouring
    handler's guard; call-based registrations use `_call_scope` instead.
    """
    start = max(0, handler_line - 6)
    end = min(len(lines), handler_line + 8)
    return _scan_auth_text("".join(lines[start:end]))


def _call_scope(text: str, start: int, open_paren: int, limit: int, line_comment: str) -> str:
    """The registration call alone: a guard in a neighbouring call never protects this route.

    Scans from `open_paren` to its closing bracket; brackets inside string
    literals do not count and comments are left out of the returned code.
    `limit` (the next registration) bounds an unbalanced call.
    """
    code, depth, i = [text[start:open_paren]], 0, open_paren
    while i < limit:
        ch = text[i]
        if ch in "'\"`":
            end = i + 1
            while end < limit and text[end] != ch:
                end += 2 if text[end] == "\\" else 1
            code.append(text[i : end + 1])
            i = end + 1
            continue
        if text.startswith(line_comment, i):
            newline = text.find("\n", i)
            i = limit if newline < 0 else newline
            continue
        if line_comment == "//" and text.startswith("/*", i):
            close = text.find("*/", i + 2)
            i = limit if close < 0 else close + 2
            continue
        code.append(ch)
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                break
        i += 1
    return "".join(code)


_JS_PATHLESS_USE_RE = re.compile(r"""\b(?P<obj>\w+)\s*\.\s*use\s*(?P<open>\()\s*(?!['"`])""")


# ---------------------------------------------------------------------------
# Extractor dispatch
# ---------------------------------------------------------------------------


def _extract_javascript(path: Path, lines: list[str]) -> list[RouteCandidate]:
    out: list[RouteCandidate] = []
    text = _mask_comments("".join(lines), "//")
    lines = text.splitlines(keepends=True)

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

    pathless_guards = []
    for use in _JS_PATHLESS_USE_RE.finditer(text):
        signals = _scan_auth_text(_call_scope(text, use.start(), use.start("open"), len(text), "//"))
        if signals != ("unknown", "unknown"):
            pathless_guards.append((use.start(), use.group("obj").lower(), signals))

    registrations = list(_JS_ROUTE_RE.finditer(text))
    for index, m in enumerate(registrations):
        method = m.group("method").upper()
        route = m.group("path")
        n = text.count("\n", 0, m.start()) + 1
        limit = registrations[index + 1].start() if index + 1 < len(registrations) else len(text)
        authn, authz = _scan_auth_text(_call_scope(text, m.start(), m.start("open"), limit, "//"))
        # A path-less `use` guards every later registration on the same router.
        for position, owner, (use_authn, use_authz) in pathless_guards:
            if position < m.start() and owner == m.group("obj").lower():
                authn = use_authn if authn == "unknown" else authn
                authz = use_authz if authz == "unknown" else authz
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
    text = _mask_comments("".join(lines), "#")
    lines = text.splitlines(keepends=True)

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
        registrations = list(_PY_DJANGO_ROUTE_RE.finditer(text))
        for index, m in enumerate(registrations):
            route = m.group("path")
            if not route or route == "":
                continue
            n = text.count("\n", 0, m.start()) + 1
            limit = registrations[index + 1].start() if index + 1 < len(registrations) else len(text)
            authn, authz = _scan_auth_text(_call_scope(text, m.start(), m.start("open"), limit, "#"))
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
    text = _mask_comments("".join(lines), "//")
    lines = text.splitlines(keepends=True)

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
    lines = _mask_comments("".join(lines), "//").splitlines(keepends=True)

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


def _strip_graphql_comments(line: str) -> str:
    """Remove GraphQL # comments for schema parsing.

    GraphQL descriptions can contain comment-like text inside quoted strings,
    but route inventory only needs operation signatures. Keeping this simple
    avoids treating human schema comments as instructions or executable input.
    """
    return line.split("#", 1)[0].strip()


def _graphql_arg_names(args: str | None) -> list[str]:
    if not args:
        return []
    return [m.group(1) for m in _GRAPHQL_ARG_NAME_RE.finditer(args)]


def _graphql_return_name(raw: str) -> str:
    value = re.sub(r"[\[\]!]", "", raw or "").strip()
    return value.split()[0] if value else ""


def _graphql_has_object_arg(arg_names: list[str]) -> bool:
    return any(_GRAPHQL_OBJECT_ARG_RE.search(name or "") for name in arg_names)


def _graphql_is_sensitive(operation: str, field_name: str, return_name: str, arg_names: list[str]) -> bool:
    haystack = " ".join([operation, field_name, return_name, *arg_names])
    return bool(_GRAPHQL_SENSITIVE_RE.search(haystack))


def _extract_graphql(path: Path, lines: list[str]) -> list[RouteCandidate]:
    """Extract logical GraphQL operations from SDL schema files.

    A GraphQL API normally exposes one HTTP mount (often `/graphql`), but the
    security-relevant entry points are the Query/Mutation/Subscription fields:
    `Mutation updateUser` is materially different from `Query products`. The
    inventory records those logical operations so §5 and architecture coverage
    can reason about authn/authz hypotheses instead of collapsing everything
    into a single POST /graphql row.
    """
    out: list[RouteCandidate] = []
    text = "".join(lines)
    for block in _GRAPHQL_OPERATION_RE.finditer(text):
        op_type = block.group("op")
        header = block.group("header") or ""
        body = block.group("body") or ""
        body_start_line = text.count("\n", 0, block.start("body")) + 1
        header_authn = bool(_GRAPHQL_AUTHN_RE.search(header) or _GRAPHQL_AUTHZ_RE.search(header))
        header_authz = bool(_GRAPHQL_AUTHZ_RE.search(header))

        for offset, raw_line in enumerate(body.splitlines(), start=0):
            line = _strip_graphql_comments(raw_line)
            if not line or line.startswith(("}", "@")):
                continue
            # Multi-line argument lists are intentionally left to the LLM
            # fallback for now; the deterministic pass handles the common
            # single-line SDL form without pretending to understand every schema.
            m = _GRAPHQL_FIELD_RE.match(line)
            if not m:
                continue
            field_name = m.group("name")
            if field_name.startswith("__"):
                continue
            directives = m.group("directives") or ""
            auth_blob = f"{header} {directives}"
            authz = bool(header_authz or _GRAPHQL_AUTHZ_RE.search(auth_blob))
            authn = bool(header_authn or authz or _GRAPHQL_AUTHN_RE.search(auth_blob))
            arg_names = _graphql_arg_names(m.group("args"))
            return_name = _graphql_return_name(m.group("returns"))
            object_access = _graphql_has_object_arg(arg_names)
            sensitive = _graphql_is_sensitive(op_type, field_name, return_name, arg_names)
            notes = [f"GraphQL {op_type}"]
            if arg_names:
                notes.append("args: " + ",".join(arg_names[:5]))
            if return_name:
                notes.append(f"returns: {return_name}")
            if object_access:
                notes.append("object-id argument")
            if sensitive:
                notes.append("sensitive-name signal")

            out.append(
                RouteCandidate(
                    method="GRAPHQL",
                    path=f"{op_type} {field_name}",
                    framework="graphql",
                    handler_file=str(path).replace("\\", "/"),
                    handler_line=body_start_line + offset,
                    authn_signal="decorator_present" if authn else "unknown",
                    authz_signal="decorator_present" if authz else "unknown",
                    management_surface=False,
                    notes=notes,
                    confidence="medium",
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

    if suffix in _JS_EXTS:
        routes = _extract_javascript(rel, lines)
    elif suffix == ".py":
        routes = _extract_python(rel, lines)
    elif suffix in {".java", ".kt", ".scala"}:
        routes = _extract_java(rel, lines)
    elif suffix in {".cs", ".vb"}:
        routes = _extract_aspnet(rel, lines)
    elif suffix in {".graphql", ".gql", ".graphqls"}:
        routes = _extract_graphql(rel, lines)
    else:
        routes = []

    return routes


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _record_mount(match: re.Match, prefixes: set[str], exact: set[tuple[str, str]]) -> None:
    """Record a guarded mount as a path prefix or an exact (verb, path) pair."""
    verb, path = match.group("verb").lower(), match.group("path")
    wildcard = path.endswith("*")
    path = path.rstrip("*").rstrip("/") or "/"
    if verb == "use" or wildcard:
        prefixes.add(path)
    else:
        exact.add(("ANY" if verb == "all" else verb.upper(), path))


def _guarded(route: RouteCandidate, prefixes: set[str], exact: set[tuple[str, str]]) -> bool:
    """Return whether a recorded mount guard covers the route."""
    p = (route.path or "").rstrip("/") or "/"
    if (route.method.upper(), p) in exact or ("ANY", p) in exact:
        return True
    return any(p == g or p.startswith(g.rstrip("/") + "/") for g in prefixes)


def _collect_routes(
    repo_root: Path,
    all_routes: list[RouteCandidate],
    frameworks_seen: set[str],
    guarded_prefixes: set[str],
    authz_guarded_prefixes: set[str],
    guarded_exact: set[tuple[str, str]],
    authz_guarded_exact: set[tuple[str, str]],
) -> None:
    """Extract routes and guarded mounts from every source file."""
    for src in _walk_sources(repo_root):
        try:
            lines = src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError:
            lines = []
        blob = "".join(lines)
        if src.suffix.lower() in _JS_EXTS:
            blob = _mask_comments(blob, "//")
        # Collect path prefixes mounted with an auth guard (cross-file: a guard
        # in server.ts protects handlers defined in routes/*.ts), and the same
        # for authoriZation guards (role/permission/policy middleware).
        for gm in _MOUNT_HEAD_RE.finditer(blob):
            middleware = _mount_middleware(blob, gm)
            if _GUARD_NAME_RE.search(middleware):
                _record_mount(gm, guarded_prefixes, guarded_exact)
            if _AUTHZ_GUARD_NAME_RE.search(middleware):
                _record_mount(gm, authz_guarded_prefixes, authz_guarded_exact)
        try:
            extracted = _extract_file(repo_root, src)
        except Exception:  # pragma: no cover
            extracted = []
        for r in extracted:
            frameworks_seen.add(r.framework)
            all_routes.append(r)


def _lift_auth_signals(
    r: RouteCandidate,
    resolver: HandlerResolver,
    guarded_prefixes: set[str],
    authz_guarded_prefixes: set[str],
    guarded_exact: set[tuple[str, str]],
    authz_guarded_exact: set[tuple[str, str]],
) -> None:
    """Lift authn/authz signals from mount guards and the resolved handler chain."""
    if r.authn_signal == "unknown" and _guarded(r, guarded_prefixes, guarded_exact):
        r.authn_signal = "middleware_present"
    # Cross-file authZ lift: a route under a centrally-mounted role/permission
    # guard is authorized even though the per-handler scan cannot see the
    # mount. Mirrors the authN lift above.
    if r.authz_signal == "unknown" and _guarded(r, authz_guarded_prefixes, authz_guarded_exact):
        r.authz_signal = "middleware_present"
    # The handler chain itself: a verified credential check proves authentication;
    # `absent` needs a fully resolved chain that never checks a credential.
    route_ref = {
        "framework": r.framework,
        "handler_file": r.handler_file,
        "handler_line": r.handler_line,
        "path": r.path,
    }
    handler = resolver.route_signal(route_ref)
    r.handler_module = resolver.handler_module(route_ref)
    if handler is not None:
        r.authn_handler_signal = handler.signal
        r.authn_handler_scheme = handler.scheme
        r.authn_handler_evidence = handler.evidence
        if r.authn_signal == "unknown" and handler.signal == "verified":
            r.authn_signal = "present"
        elif r.authn_signal == "unknown" and handler.signal in ("none", "decode_only"):
            r.authn_signal = "absent"


def _flag_route(r: RouteCandidate, llm_sdk_declared: bool) -> None:
    """Set the suspect flags and relevance tags from the lifted signals."""
    is_graphql = r.framework == "graphql"
    gql_notes = set(r.notes or [])
    gql_object_access = "object-id argument" in gql_notes
    gql_sensitive = "sensitive-name signal" in gql_notes
    gql_mutation = (r.path or "").startswith("Mutation ")
    gql_subscription = (r.path or "").startswith("Subscription ")
    # Warning (not a finding): a state-changing or management route with no
    # detected auth guard looks like it SHOULD require authentication —
    # unless it is an auth-flow / public-probe endpoint (login, register,
    # captcha, health…) which is unauthenticated by design.
    if (
        r.authn_signal in ("unknown", "absent")
        and (r.method.upper() in _STATE_CHANGING or r.management_surface)
        and not _is_public_by_design(r.path)
    ):
        r.missing_auth_suspect = True
    # GraphQL SDL has no HTTP verb per operation. Treat unauthenticated
    # mutations/subscriptions and sensitive object lookups as review
    # candidates so the existing ARCH-AUTHN hypothesis covers GraphQL too.
    if (
        is_graphql
        and r.authn_signal == "unknown"
        and (
            (gql_mutation and not _is_public_by_design(r.path))
            or gql_subscription
            or (gql_object_access and gql_sensitive)
        )
    ):
        r.missing_auth_suspect = True
    # Advisory (not a finding): an AUTHENTICATED, object-addressing route
    # (path carries a resource id) with no detected role/ownership gate is
    # the canonical BOLA/IDOR primitive — a logged-in user swaps the id for
    # another tenant's record. Hypothesis, not assertion: the scan cannot
    # prove a gate is absent (unknown != absent), so this seeds an
    # investigate-class hypothesis, never a hard finding.
    if (
        r.authn_signal in _AUTHN_PRESENT
        and r.authz_signal not in _AUTHZ_PRESENT
        and (bool(_PATH_PARAM_RE.search(r.path or "")) or (is_graphql and gql_object_access and gql_sensitive))
        and not _is_public_by_design(r.path)
    ):
        r.missing_authz_suspect = True
    # Display relevance (NOT a finding): reasons a route still merits an
    # individual §5 row even with zero linked findings. The renderer keeps
    # these out of the "N further entry points" collapse and shows the
    # reason as a review chip. Order is deterministic.
    tags: list[str] = []
    if _REGISTRATION_PATH_RE.search(r.path or "") or (
        is_graphql and re.search(r"(?i)\b(?:register|signup|sign-up)\b", r.path or "")
    ):
        tags.append("registration")
    if _AUTHFLOW_PATH_RE.search(r.path or "") or (is_graphql and _PUBLIC_OPERATION_NAME_RE.search(r.path or "")):
        tags.append("authentication")
    if r.management_surface:
        tags.append("management")
    if is_graphql and (gql_mutation or gql_subscription):
        tags.append("graphql-mutation")
    if is_graphql and gql_object_access and gql_sensitive:
        tags.append("graphql-object-access")
    if r.missing_auth_suspect:
        tags.append("missing-auth")
    if r.missing_authz_suspect:
        tags.append("missing-authz")
    if llm_sdk_declared and _LLM_PATH_RE.search(r.path or ""):
        tags.append("llm")
    r.relevance_tags = tags


def _dedupe_routes(all_routes: list[RouteCandidate]) -> list[RouteCandidate]:
    """Drop repeated (method, path, handler_file, handler_line) routes, keeping the first."""
    seen_keys: set[tuple] = set()
    deduped: list[RouteCandidate] = []
    for r in all_routes:
        key = (r.method, r.path, r.handler_file, r.handler_line)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(r)
    return deduped


def _serialize_route(i: int, r: RouteCandidate) -> dict:
    """Emit one route dict with its `R-NNN` id in the contracted key order."""
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
        "missing_authz_suspect": d["missing_authz_suspect"],
        "relevance_tags": d["relevance_tags"],
        "notes": d["notes"],
        "confidence": d["confidence"],
    }
    if d["authn_handler_signal"]:
        ordered["authn_handler_signal"] = d["authn_handler_signal"]
        if d["authn_handler_scheme"]:
            ordered["authn_handler_scheme"] = d["authn_handler_scheme"]
        if d["authn_handler_evidence"]:
            ordered["authn_handler_evidence"] = d["authn_handler_evidence"]
    if d["handler_module"]:
        ordered["handler_module"] = d["handler_module"]
    return ordered


def _coverage(routes_out: list[dict], frameworks_seen: set[str], unsupported: list[str]) -> dict:
    """Count frameworks, suspects, and authentication states over the emitted routes."""
    mgmt_count = sum(1 for r in routes_out if r["management_surface"])
    missing_auth_count = sum(1 for r in routes_out if r["missing_auth_suspect"])
    missing_authz_count = sum(1 for r in routes_out if r["missing_authz_suspect"])
    authenticated_count = sum(1 for r in routes_out if route_authenticated(r))
    authn_absent_count = sum(1 for r in routes_out if r["authn_signal"] == "absent")
    return {
        "frameworks_detected": sorted(frameworks_seen),
        "unsupported_route_files": unsupported,
        "route_count": len(routes_out),
        "management_surface_count": mgmt_count,
        "missing_auth_suspect_count": missing_auth_count,
        "missing_authz_suspect_count": missing_authz_count,
        # FE-14: only `absent` is proven unauthenticated; the rest is unknown.
        "authenticated_count": authenticated_count,
        "authn_absent_count": authn_absent_count,
        "authn_unknown_count": len(routes_out) - authenticated_count - authn_absent_count,
    }


def build_inventory(repo_root: Path) -> dict:
    """Extract routes, lift their auth signals from mounted guards and resolved handlers, and
    return the `.route-inventory.json` document with `R-NNN` ids and coverage counts.

    `missing_auth_suspect` and `missing_authz_suspect` are review flags, never findings.
    """
    llm_sdk_declared = _declares_llm_sdk(repo_root)
    all_routes: list[RouteCandidate] = []
    frameworks_seen: set[str] = set()
    unsupported: list[str] = []
    guarded_prefixes: set[str] = set()
    authz_guarded_prefixes: set[str] = set()
    guarded_exact: set[tuple[str, str]] = set()
    authz_guarded_exact: set[tuple[str, str]] = set()

    _collect_routes(
        repo_root,
        all_routes,
        frameworks_seen,
        guarded_prefixes,
        authz_guarded_prefixes,
        guarded_exact,
        authz_guarded_exact,
    )

    # Apply prefix guards + compute the missing-auth advisory flag.
    resolver = HandlerResolver(repo_root)
    for r in all_routes:
        _lift_auth_signals(r, resolver, guarded_prefixes, authz_guarded_prefixes, guarded_exact, authz_guarded_exact)
        _flag_route(r, llm_sdk_declared)

    deduped = _dedupe_routes(all_routes)

    routes_out = []
    for i, r in enumerate(deduped, start=1):
        routes_out.append(_serialize_route(i, r))

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repo_root": str(repo_root),
        "routes": routes_out,
        "coverage": _coverage(routes_out, frameworks_seen, unsupported),
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
        print(f"analyzers/route_inventory.py: repo-root not found: {repo_root}", file=sys.stderr)
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
