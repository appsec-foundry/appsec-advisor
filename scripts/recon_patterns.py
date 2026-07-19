#!/usr/bin/env python3
"""
recon_patterns.py — deterministic recon pattern scans (Sprint 3 Item #1).

Replaces four pattern-only categories that the LLM-driven recon-scanner
used to grep for. These are pure regex scans with no judgement involved:

  Cat 11  Exposed Routes — admin/debug/swagger/actuator endpoints
  Cat 9   OAuth / OIDC — redirect-flow and token-handling anti-patterns
  Cat 10  SPA / BFF — browser token and client-trust anti-patterns
  Cat 14  CI/CD Supply Chain — unpinned GitHub Actions (no SHA ref),
          GitLab CI image directives
  Cat 15  Container Base Images — unpinned Docker / Compose images
  Cat 17  Postinstall Scripts — package.json lifecycle hooks,
          Python setup.py install-time shell, .npmrc ignore-scripts
  Cat 18  Security Headers & CORS — presence of hardening config
  Cat 19  Frontend Framework & XSS Patterns — unsafe framework HTML sinks
  Cat 20  DOM-Based XSS Sources — browser-controlled source/sink candidates
  Cat 21  Client-Side Secrets — public frontend env var secret patterns
  Cat 22  WebSocket & Real-Time — WebSocket / Socket.IO entry points
  Cat 23  postMessage & iframe — browser message / iframe surfaces
  Cat 24  Client-Side Routing & Auth Guards — frontend auth guard signals
  Cat 27  GitHub Actions Workflow Privilege Hardening
  Cat 28  AI Coding Assistant & IDE Agent Configurations
  Cat 29  Mobile App Architecture — platform config, WebView, storage, TLS

The script walks `REPO_ROOT` honouring `data/scan-excludes.yaml`, emits
findings as JSON on stdout, and runs in a single process instead of N
LLM turns. The recon-scanner agent consumes the JSON and skips these
categories in its grep loop.

CLI:
  python3 recon_patterns.py all             --repo-root <path>
  python3 recon_patterns.py oauth-oidc      --repo-root <path>
  python3 recon_patterns.py spa-bff         --repo-root <path>
  python3 recon_patterns.py exposed-routes  --repo-root <path>
  python3 recon_patterns.py ci-supply-chain --repo-root <path>
  python3 recon_patterns.py container-images --repo-root <path>
  python3 recon_patterns.py postinstall     --repo-root <path>
  python3 recon_patterns.py security-headers --repo-root <path>
  python3 recon_patterns.py frontend-xss    --repo-root <path>
  python3 recon_patterns.py dom-xss         --repo-root <path>
  python3 recon_patterns.py client-secrets  --repo-root <path>
  python3 recon_patterns.py websocket       --repo-root <path>
  python3 recon_patterns.py postmessage     --repo-root <path>
  python3 recon_patterns.py client-routing  --repo-root <path>
  python3 recon_patterns.py gha-privileges  --repo-root <path>
  python3 recon_patterns.py ai-assistant-configs --repo-root <path>
  python3 recon_patterns.py mobile-architecture --repo-root <path>

Scan manifest (only with 'all'):
  --scan-manifest               embed sorted file list in JSON as 'scan_manifest'
  --manifest-file <path>        write plain newline-separated file list to <path>
                                (implies --scan-manifest)

Exit codes:
  0 — success (JSON on stdout), regardless of finding count
  1 — hard error (missing repo, bad args)
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator

# Try to load the central exclude policy. Fall back to a minimal built-in
# set if scan_excludes is unavailable — the script must not hard-fail when
# installed in a stripped-down plugin layout.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import scan_excludes

    _SCAN_EXCLUDES = True
except Exception:  # pragma: no cover
    _SCAN_EXCLUDES = False


# Repo-relative paths skipped this run because they exceed the central
# per-file byte cap (scan_excludes.max_file_bytes). Accumulated across every
# per-category walk, deduped, surfaced on stderr (once each) and in run_all's
# JSON. Cleared at the start of each run_all().
_OVERSIZE_SKIPPED: set[str] = set()


# ---------------------------------------------------------------------------
# Default fallback excludes when scan_excludes.yaml is unavailable.
# ---------------------------------------------------------------------------
_FALLBACK_DIRS = frozenset(
    {
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "out",
        "coverage",
        ".next",
        ".nuxt",
        "__pycache__",
        "__tests__",
        "__mocks__",
        ".git",
        ".cache",
        ".venv",
        "venv",
    }
)

_TEXT_EXT = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".java",
    ".kt",
    ".scala",
    ".groovy",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".m",
    ".mm",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".xml",
    ".conf",
    ".cfg",
    ".ini",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".html",
    ".htm",
    ".md",
    ".adoc",
    ".env",
    ".npmrc",
    ".yarnrc",
    ".gradle",
    ".properties",
    ".plist",
    ".entitlements",
    ".xcconfig",
    ".pbxproj",
    # Also match files with no extension when the name suggests code (Dockerfile, Jenkinsfile)
}


# Directories that MUST NEVER be scanned, even when scan_excludes' whitelist
# would otherwise include a file inside them (e.g. `node_modules/foo/package.json`).
# These are dependency/build caches — anything inside is third-party artefact,
# not application source. This is a recon-scanner-specific policy: the shared
# scan_excludes.yaml whitelist is designed for "don't overlook security
# signals" (a committed .env anywhere is interesting), but in the recon pass
# we explicitly want the application surface, not the dependency tree.
_HARD_EXCLUDE_DIRS = frozenset(
    {
        "node_modules",
        "vendor",
        "bower_components",
        ".tox",
        ".gradle",
        ".cache",
        ".appsec-cache",
        "__pycache__",
        "dist",
        "build",
        "target",
        "out",
        "coverage",
        ".next",
        ".nuxt",
        ".git",
        "Pods",
    }
)

# Directory-name glob patterns that are also hard-excluded. Covers python
# virtualenv variants (.venv, venv, .venv-tests, venv_linux, …) and build
# directories whose names carry a profile suffix.
_HARD_EXCLUDE_PATTERNS = (
    ".venv*",
    "venv",
    "venv-*",
    "venv_*",
    "build-*",
    "dist-*",
    "target-*",
)


def _has_hard_excluded_segment(rel_path: str) -> bool:
    parts = PurePosixPath(rel_path.replace("\\", "/")).parts
    for p in parts:
        if p in _HARD_EXCLUDE_DIRS:
            return True
        for pat in _HARD_EXCLUDE_PATTERNS:
            if fnmatch.fnmatch(p, pat):
                return True
    return False


def _is_github_composite_action_descriptor(rel_path: str) -> bool:
    parts = PurePosixPath(rel_path.replace("\\", "/")).parts
    return (
        len(parts) >= 4
        and parts[0] == ".github"
        and parts[1] == "actions"
        and parts[-1] in {"action.yml", "action.yaml"}
    )


def _is_excluded(rel_path: str) -> bool:
    # Composite action descriptors are CI/CD source. A valid action directory
    # can be named "build", which would otherwise trip the generic build-cache
    # hard exclude before the shared whitelist can preserve action.yml.
    if _is_github_composite_action_descriptor(rel_path):
        return False
    # Hard exclusion wins over every whitelist — dep trees must not leak
    # into the recon results regardless of filename.
    if _has_hard_excluded_segment(rel_path):
        return True
    if _SCAN_EXCLUDES:
        try:
            if scan_excludes.is_always_included(rel_path):
                return False
            if scan_excludes.is_excluded(rel_path):
                return True
        except Exception:
            pass
    # Fallback heuristic
    parts = PurePosixPath(rel_path.replace("\\", "/")).parts
    return any(p in _FALLBACK_DIRS for p in parts)


def _should_read(path: Path) -> bool:
    # Only read plausible text files. The pattern scanners are narrow,
    # so this just protects from reading blobs.
    if path.suffix.lower() in _TEXT_EXT:
        return True
    if path.name in {
        "Dockerfile",
        "Containerfile",
        "Jenkinsfile",
        "Makefile",
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        "bitbucket-pipelines.yml",
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        ".travis.yml",
        "renovate.json",
        ".renovaterc",
        ".npmrc",
        ".yarnrc",
        "package.json",
        "setup.py",
        "setup.cfg",
        "pyproject.toml",
        "AndroidManifest.xml",
        "Info.plist",
        "network_security_config.xml",
        "build.gradle",
        "gradle.properties",
    }:
        return True
    if path.name.startswith(".env") or path.name.startswith("Dockerfile."):
        return True
    return False


def _walk_repo(
    repo_root: Path,
    manifest: list[str] | None = None,
) -> Iterable[Path]:
    """Yield every file under repo_root that survives the exclude policy
    AND looks like a text file worth scanning.

    If *manifest* is a list, each scanned file's repo-relative path is
    appended to it so the caller can write a scan-manifest log.
    """
    root_resolved = Path(repo_root).resolve(strict=False)
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        # Prune excluded directories up-front for speed
        rel_dir = str(Path(dirpath).relative_to(repo_root)).replace("\\", "/")
        dirnames[:] = [d for d in dirnames if not _is_excluded(f"{rel_dir}/{d}" if rel_dir != "." else d)]
        for name in filenames:
            rel = str((Path(dirpath) / name).relative_to(repo_root)).replace("\\", "/")
            if _is_excluded(rel):
                continue
            p = Path(dirpath) / name
            # Skip symlinks whose target escapes the repo root — they
            # would otherwise let an attacker-controlled symlink leak
            # ~/.ssh/id_rsa or similar into recon evidence.
            if p.is_symlink():
                try:
                    target = p.resolve(strict=False)
                    target.relative_to(root_resolved)
                except (OSError, RuntimeError, ValueError):
                    continue
            if not _should_read(p):
                continue
            # Central per-file byte cap: a file past the cap is almost never
            # application source (data blob / bundle / generated artifact);
            # skip it rather than burn tokens reading it. Report once per
            # unique path so the omission is visible, not silent.
            if _SCAN_EXCLUDES and scan_excludes.is_oversize(p):
                if rel not in _OVERSIZE_SKIPPED:
                    _OVERSIZE_SKIPPED.add(rel)
                    try:
                        sz = p.stat().st_size
                    except OSError:
                        sz = -1
                    print(
                        f"recon_patterns.py: skipped oversize file "
                        f"({sz} bytes > cap {scan_excludes.max_file_bytes()}): {rel}",
                        file=sys.stderr,
                    )
                continue
            if manifest is not None:
                manifest.append(rel)
            yield p


def _grep_file(path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    """Return (line_no, line_text) for every line in `path` matching `pattern`."""
    out: list[tuple[int, str]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, start=1):
                if pattern.search(line):
                    # Strip trailing newline and trim very long lines
                    stripped = line.rstrip("\r\n")
                    if len(stripped) > 400:
                        stripped = stripped[:400] + "…"
                    out.append((n, stripped))
    except OSError:
        pass
    return out


# ---------------------------------------------------------------------------
# Category 9 — OAuth / OIDC
# ---------------------------------------------------------------------------


_CAT9_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".java",
    ".kt",
    ".scala",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".env",
    ".html",
    ".htm",
}

_CAT9_SURFACE = re.compile(
    r"(?i)(\boauth2?\b|\boidc\b|openid(?:connect)?|@auth0\b|next-auth\b|NextAuth\b|"
    r"passport-(?:google|oauth|openidconnect)|\bopenid-client\b|\boidc-client\b|"
    r"loginWithRedirect|loginWithPopup|signInWithRedirect|signInWithPopup|"
    r"\buseSession\s*\(|\buseAuth\s*\(|@azure/msal|msal-browser|"
    r"accounts\.google\.com/o/oauth|googleapis\.com/oauth|/\.well-known/openid-configuration|"
    r"\bjwks_uri\b|\bid_token\b|\baccess_token\b|\brefresh_token\b|"
    r"\bcode_verifier\b|\bcode_challenge\b|\bredirect_uri\b|\bredirectUri\b|"
    r"\bresponse_type\b|\bresponseType\b|\bgrant_type\b|\bgrantType\b)"
)

_CAT9_FRONTEND_HINT = re.compile(
    r"(?i)(frontend|client|spa|browser|src/app|components?|pages?|views?|\.tsx?$|\.jsx?$|\.html?$)"
)
_CAT9_AUTH_REQUEST = re.compile(
    r"(?i)(response_type|responseType|authorization_endpoint|authorize\b|/authorize\b|loginWithRedirect|loginWithPopup|signInWithRedirect|signInWithPopup)"
)
_CAT9_IMPLICIT = re.compile(
    r"(?i)(response[_-]?type\s*[:=]\s*['\"]?(?:token|id_token\s+token|token\s+id_token)\b|"
    r"responseType\s*[:=]\s*['\"]?(?:token|id_token\s+token|token\s+id_token)\b|"
    r"#(?:access_token|id_token)=|location\.hash[^\\n]*(?:access_token|id_token))"
)
_CAT9_CODE_FLOW = re.compile(
    r"(?i)(response[_-]?type\s*[:=]\s*['\"]?code\b|responseType\s*[:=]\s*['\"]?code\b|"
    r"grant[_-]?type\s*[:=]\s*['\"]?authorization_code\b|authorization_code)"
)
_CAT9_PKCE_PRESENT = re.compile(r"(?i)(\bpkce\b|\bcode_verifier\b|\bcode_challenge\b|codeChallenge|codeVerifier)")
_CAT9_PKCE_PLAIN = re.compile(
    r"(?i)(code_challenge_method\s*[:=]\s*['\"]?plain\b|codeChallengeMethod\s*[:=]\s*['\"]?plain\b)"
)
_CAT9_PKCE_S256 = re.compile(
    r"(?i)(code_challenge_method\s*[:=]\s*['\"]?S256\b|codeChallengeMethod\s*[:=]\s*['\"]?S256\b)"
)
_CAT9_STATE_TOKEN = re.compile(r"(?i)\bstate\b")
_CAT9_NONCE_TOKEN = re.compile(r"(?i)\bnonce\b")
_CAT9_ID_TOKEN_FLOW = re.compile(r"(?i)(\bid_token\b|\bscope\s*[:=][^\n]*(?:openid)|response[_-]?type[^\n]*id_token)")
_CAT9_REFRESH_BROWSER = re.compile(
    r"(?i)refresh[_-]?token[^\n]{0,120}(localStorage|sessionStorage)|"
    r"(localStorage|sessionStorage)[^\n]{0,120}refresh[_-]?token"
)
_CAT9_ROPC = re.compile(r"(?i)(grant[_-]?type\s*[:=]\s*['\"]?password\b|grant_type=password|resource owner password)")
_CAT9_CLIENT_SECRET = re.compile(r"(?i)\bclient_secret\b|\bclientSecret\b")
_CAT9_HTTP_REDIRECT = re.compile(
    r"(?i)(redirect_uri|redirectUri)[^\n]{0,120}http://(?!localhost\b|127\.0\.0\.1\b|\[::1\])"
)
_CAT9_REDIRECT_WEAK_MATCH = re.compile(
    r"(?i)(redirect_uri|redirectUri|callbackUrl|callback_url|allowedRedirect|allowed_redirect|post_logout_redirect_uri)"
    r"[^\n]{0,160}(includes|startsWith|indexOf|contains|match\s*\(|regex|wildcard|\*)|"
    r"(includes|startsWith|indexOf|contains|match\s*\(|regex|wildcard)[^\n]{0,160}"
    r"(redirect_uri|redirectUri|callbackUrl|callback_url|post_logout_redirect_uri)"
)
_CAT9_POST_LOGOUT = re.compile(r"(?i)post_logout_redirect_uri|postLogoutRedirectUri")
_CAT9_CLAIM_CONTEXT = re.compile(r"(?i)(id_token|issuer|jwks|jwks_uri|audience|\baud\b|\biss\b|nonce)")
_CAT9_CLAIM_VALIDATION = re.compile(
    r"(?i)(issuer|expectedIssuer|\biss\b|audience|expectedAudience|\baud\b|jwks|jwks_uri|verifyIdToken|validateIdToken|nonce)"
)
_CAT9_STATIC_STATE_NONCE = re.compile(
    r"(?i)\b(state|nonce)\b\s*[:=]\s*['\"](?:state|nonce|test|changeme|static|12345|abcdef)['\"]"
)


def _line_hits(lines: list[str], pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for n, line in enumerate(lines, start=1):
        if pattern.search(line):
            text = line.rstrip("\r\n")
            if len(text) > 400:
                text = text[:400] + "…"
            hits.append((n, text.strip()))
    return hits


def _add_cat9(
    findings: list[dict[str, Any]],
    *,
    rel: str,
    subcategory: str,
    severity: str,
    line: int | None,
    match: str,
    evidence: str,
) -> None:
    findings.append(
        {
            "category": 9,
            "subcategory": subcategory,
            "file": rel,
            "line": line,
            "severity": severity,
            "match": match,
            "evidence": evidence,
        }
    )


def scan_oauth_oidc(repo_root: Path) -> dict[str, Any]:
    """Detect OAuth/OIDC surfaces and common security anti-patterns.

    This is intentionally a signal scanner, not a full protocol verifier. It
    finds high-value review candidates from RFC 9700 / OIDC Core: no implicit
    token response, PKCE/S256 on code flows, state/nonce, exact redirect checks,
    no ROPC, no browser refresh tokens, and validated ID-token claims.
    """
    findings: list[dict[str, Any]] = []

    for p in _walk_repo(repo_root):
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        if p.suffix.lower() not in _CAT9_EXTS:
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        surface_hits = _line_hits(lines, _CAT9_SURFACE)
        if not surface_hits:
            continue

        _add_cat9(
            findings,
            rel=rel,
            subcategory="oauth-oidc-surface",
            severity="Info",
            line=surface_hits[0][0],
            match=surface_hits[0][1],
            evidence="OAuth/OIDC-related token, endpoint, SDK, or config pattern present",
        )

        frontend_like = bool(_CAT9_FRONTEND_HINT.search(rel))
        for n, line in _line_hits(lines, _CAT9_IMPLICIT):
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-implicit-flow",
                severity="High",
                line=n,
                match=line,
                evidence="Implicit/hybrid token response or token-in-fragment pattern; RFC 9700 deprecates less-secure browser token delivery",
            )

        code_hits = _line_hits(lines, _CAT9_CODE_FLOW)
        if code_hits and not _CAT9_PKCE_PRESENT.search(text):
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-code-without-pkce",
                severity="High" if frontend_like else "Medium",
                line=code_hits[0][0],
                match=code_hits[0][1],
                evidence="Authorization-code flow found without PKCE markers in the same file",
            )

        for n, line in _line_hits(lines, _CAT9_PKCE_PLAIN):
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-pkce-plain",
                severity="High",
                line=n,
                match=line,
                evidence="PKCE uses plain challenge method instead of S256",
            )

        if _CAT9_AUTH_REQUEST.search(text) and not _CAT9_STATE_TOKEN.search(text):
            auth_hits = _line_hits(lines, _CAT9_AUTH_REQUEST)
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-missing-state",
                severity="High",
                line=auth_hits[0][0] if auth_hits else surface_hits[0][0],
                match=auth_hits[0][1] if auth_hits else surface_hits[0][1],
                evidence="OAuth authorization request pattern without state marker in the same file",
            )

        id_token_flow = bool(_CAT9_ID_TOKEN_FLOW.search(text))
        if id_token_flow and not _CAT9_NONCE_TOKEN.search(text):
            id_hits = _line_hits(lines, _CAT9_ID_TOKEN_FLOW)
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oidc-missing-nonce",
                severity="High",
                line=id_hits[0][0] if id_hits else surface_hits[0][0],
                match=id_hits[0][1] if id_hits else surface_hits[0][1],
                evidence="OIDC id_token/openid flow without nonce marker in the same file",
            )

        if id_token_flow and _CAT9_CLAIM_CONTEXT.search(text) and not _CAT9_CLAIM_VALIDATION.search(text):
            id_hits = _line_hits(lines, _CAT9_ID_TOKEN_FLOW)
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oidc-claim-validation-gap",
                severity="High",
                line=id_hits[0][0] if id_hits else surface_hits[0][0],
                match=id_hits[0][1] if id_hits else surface_hits[0][1],
                evidence="OIDC token handling without issuer/audience/JWKS/nonce validation markers in the same file",
            )

        for n, line in _line_hits(lines, _CAT9_REFRESH_BROWSER):
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-refresh-token-browser-storage",
                severity="High",
                line=n,
                match=line,
                evidence="Refresh token appears to be stored in browser-accessible storage",
            )

        for n, line in _line_hits(lines, _CAT9_ROPC):
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-ropc-grant",
                severity="High",
                line=n,
                match=line,
                evidence="Resource Owner Password Credentials grant is present; RFC 9700 says it MUST NOT be used",
            )

        for n, line in _line_hits(lines, _CAT9_CLIENT_SECRET):
            if frontend_like:
                _add_cat9(
                    findings,
                    rel=rel,
                    subcategory="oauth-client-secret-in-frontend",
                    severity="High",
                    line=n,
                    match=line,
                    evidence="Client secret marker appears in frontend/browser code",
                )

        for n, line in _line_hits(lines, _CAT9_HTTP_REDIRECT):
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-insecure-redirect-uri",
                severity="High",
                line=n,
                match=line,
                evidence="OAuth redirect URI uses non-loopback HTTP",
            )

        for n, line in _line_hits(lines, _CAT9_REDIRECT_WEAK_MATCH):
            subcat = (
                "oauth-post-logout-redirect-weak" if _CAT9_POST_LOGOUT.search(line) else "oauth-redirect-uri-weak-match"
            )
            _add_cat9(
                findings,
                rel=rel,
                subcategory=subcat,
                severity="High",
                line=n,
                match=line,
                evidence="Redirect URI allowlist appears to use substring/prefix/wildcard matching instead of exact matching",
            )

        for n, line in _line_hits(lines, _CAT9_STATIC_STATE_NONCE):
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-static-state-or-nonce",
                severity="High",
                line=n,
                match=line,
                evidence="State or nonce appears to be a static constant",
            )

        if _CAT9_PKCE_PRESENT.search(text) and not _CAT9_PKCE_S256.search(text) and _CAT9_CODE_FLOW.search(text):
            pkce_hits = _line_hits(lines, _CAT9_PKCE_PRESENT)
            _add_cat9(
                findings,
                rel=rel,
                subcategory="oauth-pkce-s256-not-evident",
                severity="Medium",
                line=pkce_hits[0][0] if pkce_hits else code_hits[0][0],
                match=pkce_hits[0][1] if pkce_hits else code_hits[0][1],
                evidence="PKCE markers found on code flow but S256 is not evident in the same file",
            )

    return {
        "category": 9,
        "name": "OAuth / OIDC",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 11 — Exposed routes
# ---------------------------------------------------------------------------


# Path-fragment matches need a word-boundary on both sides so `/env` does
# not match `/usr/bin/env` in a shebang and `/test` does not match
# `/context_test` or `src/test.ts`. The lookbehind rejects any alphanumeric
# or hyphen or underscore before the slash — routes are typically preceded
# by a quote, whitespace, or the start of an HTTP-method concatenation.
_CAT11_PATTERN = re.compile(
    r"(?i)"
    r"(?:actuator"
    r"|(?<![\w.-])/debug(?:\b|[/?\"'])"
    r"|(?<![\w.-])/admin(?:\b|[/?\"'])"
    r"|(?<![\w.-])/internal(?:\b|[/?\"'])"
    r"|(?<![\w.-])/test(?:\b|[/?\"'])"
    r"|(?<![\w.-])/dev(?:\b|[/?\"'])"
    r"|swagger"
    r"|openapi\.(?:json|yaml|yml)|openapi/v\d"
    r"|graphiql"
    r"|h2-console"
    r"|(?<![\w.-])/metrics(?:\b|[/?\"'])"
    r"|(?<![\w.-])/health(?:\b|[/?\"'])"
    r"|(?<![\w.-])/env(?:\b|[/?\"'])"
    r"|(?<![\w.-])/heapdump"
    r"|(?<![\w.-])/threaddump"
    r"|(?<![\w.-])/logfile)"
)

# Only scan source-code-ish extensions for exposed routes (routes live in
# code, not in markdown/yaml configs).
_CAT11_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".java",
    ".kt",
    ".scala",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".rs",
}


def scan_exposed_routes(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CAT11_EXTS:
            continue
        for line_no, text in _grep_file(p, _CAT11_PATTERN):
            findings.append(
                {
                    "category": 11,
                    "file": str(p.relative_to(repo_root)).replace("\\", "/"),
                    "line": line_no,
                    "match": text.strip(),
                }
            )
    return {"category": 11, "name": "Exposed Routes", "findings": findings, "count": len(findings)}


# ---------------------------------------------------------------------------
# Category 14 — CI/CD supply chain
# ---------------------------------------------------------------------------


# `uses: owner/name@ref` where ref is NOT a 40-char hex SHA.
# Lines typically start with `- uses:` (YAML list item) but may also appear
# as plain `uses:` inside a composite-action step. Match both.
_CAT14_UNPINNED_ACTION = re.compile(r"^(?P<indent>\s*-?\s*)uses:\s*(?P<ref>[^\s#@]+@(?P<tag>[^\s#]+))")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")

# GitLab CI `image: foo:bar` directive (informational — non-pinned tags)
_CAT14_GITLAB_IMAGE = re.compile(r"^\s*image:\s*(?P<image>[^\s#]+)", re.MULTILINE)


def scan_ci_supply_chain(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    # GitHub Actions workflows
    wf_dir = repo_root / ".github" / "workflows"
    if wf_dir.is_dir():
        for p in sorted(wf_dir.iterdir()):
            if p.suffix.lower() not in {".yml", ".yaml"} or not p.is_file():
                continue
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for n, line in enumerate(lines, start=1):
                m = _CAT14_UNPINNED_ACTION.match(line)
                if not m:
                    continue
                tag = m.group("tag")
                # Skip when pinned by 40-char SHA (the desired secure state)
                if _SHA40.match(tag):
                    continue
                # Skip the special "./" local action / workflow reference
                if m.group("ref").startswith("./"):
                    continue
                findings.append(
                    {
                        "category": 14,
                        "subcategory": "unpinned-github-action",
                        "file": str(p.relative_to(repo_root)).replace("\\", "/"),
                        "line": n,
                        "action": m.group("ref"),
                        "tag": tag,
                        "match": line.strip(),
                    }
                )

    # GitLab CI (optional)
    for candidate in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
        p = repo_root / candidate
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _CAT14_GITLAB_IMAGE.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(
                {
                    "category": 14,
                    "subcategory": "gitlab-image",
                    "file": candidate,
                    "line": line_no,
                    "image": m.group("image"),
                    "match": text[m.start() : m.end()].strip(),
                }
            )

    return {
        "category": 14,
        "name": "CI/CD Supply Chain",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 15 — Container base images
# ---------------------------------------------------------------------------


_CAT15_FROM = re.compile(r"^\s*FROM\s+(?P<image>[^\s#]+)", re.IGNORECASE)
_CAT15_COMPOSE_IMAGE = re.compile(r"^\s*image:\s*(?P<image>[^\s#]+)", re.IGNORECASE)


def _container_image_issue(image: str) -> str | None:
    if image.lower() == "scratch":
        return None
    if "@sha256:" in image:
        return None
    tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
    if not tag:
        return "missing-tag"
    if tag == "latest":
        return "latest-tag"
    return "missing-digest"


def scan_container_images(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        name = p.name.lower()
        is_dockerfile = p.name == "Dockerfile" or p.name.startswith("Dockerfile.")
        is_compose = name.startswith("docker-compose") and p.suffix.lower() in {".yml", ".yaml"}
        if not is_dockerfile and not is_compose:
            continue
        pattern = _CAT15_FROM if is_dockerfile else _CAT15_COMPOSE_IMAGE
        for line_no, text in _grep_file(p, pattern):
            m = pattern.search(text)
            if not m:
                continue
            image = m.group("image").strip().strip("\"'")
            issue = _container_image_issue(image)
            if not issue:
                continue
            findings.append(
                {
                    "category": 15,
                    "subcategory": issue,
                    "file": rel,
                    "line": line_no,
                    "image": image,
                    "match": text.strip(),
                }
            )
    return {
        "category": 15,
        "name": "Container Base Images",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 17 — Postinstall scripts
# ---------------------------------------------------------------------------


_CAT17_NPM_LIFECYCLE_KEYS = ("preinstall", "postinstall", "prepare", "prebuild", "postpublish")


def scan_postinstall(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    # npm / node lifecycle scripts in package.json
    for p in repo_root.rglob("package.json"):
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        if _is_excluded(rel):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        scripts = data.get("scripts") if isinstance(data, dict) else None
        if not isinstance(scripts, dict):
            continue
        for key, value in scripts.items():
            if key in _CAT17_NPM_LIFECYCLE_KEYS:
                findings.append(
                    {
                        "category": 17,
                        "subcategory": "npm-lifecycle",
                        "file": rel,
                        "line": None,
                        "hook": key,
                        "command": str(value),
                    }
                )

    # .npmrc ignore-scripts
    for candidate in (".npmrc", repo_root.name + "/.npmrc"):
        p = repo_root / ".npmrc"
        if not p.is_file():
            break
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            break
        for n, line in enumerate(text.splitlines(), start=1):
            if re.match(r"^\s*ignore-scripts\s*=", line, re.IGNORECASE):
                findings.append(
                    {
                        "category": 17,
                        "subcategory": "npmrc-ignore-scripts",
                        "file": ".npmrc",
                        "line": n,
                        "match": line.strip(),
                    }
                )
        break

    # Python setup.py install-time shell escape
    py_shell_re = re.compile(
        r"(?:cmdclass\s*=|install_requires.*subprocess|os\.system\s*\(|subprocess\.(?:run|call|Popen))"
    )
    for p in repo_root.rglob("setup.py"):
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        if _is_excluded(rel):
            continue
        for line_no, text in _grep_file(p, py_shell_re):
            findings.append(
                {
                    "category": 17,
                    "subcategory": "python-setup-shell",
                    "file": rel,
                    "line": line_no,
                    "match": text.strip(),
                }
            )

    return {
        "category": 17,
        "name": "Postinstall Scripts",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 18 — Security headers & CORS
# ---------------------------------------------------------------------------


_CAT18_PATTERN = re.compile(
    r"(?i)"
    r"("
    r"Content-Security-Policy"
    r"|X-Frame-Options"
    r"|X-Content-Type-Options"
    r"|Referrer-Policy"
    r"|Permissions-Policy"
    r"|Strict-Transport-Security"
    r"|helmet\("
    r"|helmet\.contentSecurityPolicy"
    r"|Access-Control-Allow-Origin"
    r"|cors\("
    r"|enableCors"
    r"|CorsMiddleware"
    r"|@CrossOrigin"
    r")"
)

_CAT18_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".java",
    ".kt",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".yml",
    ".yaml",
    ".conf",
    ".toml",
}


def scan_security_headers(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CAT18_EXTS:
            continue
        for line_no, text in _grep_file(p, _CAT18_PATTERN):
            findings.append(
                {
                    "category": 18,
                    "file": str(p.relative_to(repo_root)).replace("\\", "/"),
                    "line": line_no,
                    "match": text.strip(),
                }
            )
    return {
        "category": 18,
        "name": "Security Headers & CORS",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Categories 10, 19–24 — frontend/client runtime patterns
# ---------------------------------------------------------------------------


_CLIENT_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm"}

_CAT10_TOKEN_STORAGE = re.compile(
    r"(?i)((localStorage|sessionStorage|indexedDB|document\.cookie)[^\n]{0,180}"
    r"(token|jwt|bearer|access[_-]?token|refresh[_-]?token|id[_-]?token|session)"
    r"|"
    r"(token|jwt|bearer|access[_-]?token|refresh[_-]?token|id[_-]?token|session)"
    r"[^\n]{0,180}(localStorage|sessionStorage|indexedDB|document\.cookie))"
)
_CAT10_REFRESH_STORAGE = re.compile(
    r"(?i)((localStorage|sessionStorage|indexedDB|document\.cookie)[^\n]{0,180}refresh[_-]?token"
    r"|refresh[_-]?token[^\n]{0,180}(localStorage|sessionStorage|indexedDB|document\.cookie))"
)
_CAT10_BFF = re.compile(
    r"(?i)(backend[-_ ]?for[-_ ]?frontend|\bbff\b|proxy[^\n]{0,80}auth|forward[^\n]{0,80}token|"
    r"httpOnly|SameSite|server-side session)"
)
_CAT10_CREDENTIALS = re.compile(r"(?i)(withCredentials\s*[:=]\s*true|credentials\s*:\s*['\"]include['\"])")
_CAT10_CLIENT_ROLE = re.compile(
    r"(?i)((localStorage|sessionStorage|jwtDecode|jwt_decode|atob\s*\()[^\n]{0,180}"
    r"(isAdmin|admin|role|roles|permission|permissions|scope|scopes|claim|claims)"
    r"|"
    r"(isAdmin|admin|role|roles|permission|permissions|scope|scopes|claim|claims)"
    r"[^\n]{0,180}(localStorage|sessionStorage|jwtDecode|jwt_decode|atob\s*\())"
)

_FRONTEND_DEPS = {
    "@angular/core": "Angular",
    "react": "React",
    "react-dom": "React",
    "vue": "Vue",
    "svelte": "Svelte",
    "next": "Next.js",
    "nuxt": "Nuxt",
}
_CAT19_UNSAFE_HTML = re.compile(
    r"(?i)(dangerouslySetInnerHTML|bypassSecurityTrust(?:Html|Url|ResourceUrl|Script|Style)?|"
    r"\bDomSanitizer\b|\bv-html\b|\{@html\b|ng-bind-html|innerHTML\s*=|insertAdjacentHTML\s*\()"
)
_CAT19_STRONG_SANITIZER = re.compile(r"(?i)(DOMPurify\.sanitize|sanitize\s*\(|TrustedHTML|trustedTypes)")

_CAT20_DOM_SOURCE = re.compile(
    r"(?i)(location\.(?:hash|search|href|pathname)|window\.name|document\.(?:referrer|URL|documentURI)|"
    r"URLSearchParams|useParams\s*\(|useSearchParams\s*\(|paramMap|queryParamMap|hashchange|popstate)"
)
_CAT20_DOM_SINK = re.compile(
    r"(?i)(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\s*\(|new\s+Function\s*\(|"
    r"dangerouslySetInnerHTML|bypassSecurityTrust|v-html|\{@html)"
)

_CAT21_PATTERN = re.compile(
    r"(?i)(REACT_APP_|NEXT_PUBLIC_|VITE_|NUXT_ENV_|EXPO_PUBLIC_).{0,120}"
    r"(api[_-]?key|apikey|api[_-]?secret|secret|token|auth0|firebase|stripe|algolia|maps|sentry)"
    r"|(stripe|supabase|firebase|amplify|sentry)[^\n]{0,80}"
    r"(secret|service[_-]?role|admin[_-]?key|auth[_-]?token|sk_live|sk_test)"
)
_CAT22_PATTERN = re.compile(
    r"(?i)(new\s+WebSocket|WebSocketServer|socket\.io|ws://|wss://|\.on\(\s*['\"]message|io\(|createServer.*socket|handleUpgrade)"
)
_CAT22_CLEARTEXT = re.compile(r"(?i)\bws://(?!localhost\b|127\.0\.0\.1\b|\[::1\])")
_CAT22_AUTH = re.compile(r"(?i)(auth|token|jwt|bearer|cookie|session|Authorization|withCredentials|credentials)")
_CAT22_SERVER_SOCKET = re.compile(r"(?i)(handleUpgrade|\.on\(\s*['\"]connection|io\(|socket\.io|WebSocketServer)")
_CAT22_ORIGIN = re.compile(r"(?i)(origin|allowRequest|cors|verifyClient)")

_CAT23_PATTERN = re.compile(
    r"(?i)(postMessage|addEventListener\s*\(\s*['\"]message|window\.opener|parent\.postMessage|<iframe|sandbox=|allow=|target=['\"]_blank)"
)
_CAT23_WILDCARD_TARGET = re.compile(r"(?i)postMessage\s*\([^,\n]+,\s*['\"]\*['\"]")
_CAT23_MESSAGE_LISTENER = re.compile(r"(?i)addEventListener\s*\(\s*['\"]message")
_CAT23_ORIGIN_CHECK = re.compile(r"(?i)(event\.origin|\borigin\b|allowedOrigins?|trustedOrigins?|includes\s*\()")
_CAT23_IFRAME = re.compile(r"(?i)<iframe\b")
_CAT23_IFRAME_SANDBOX = re.compile(r"(?i)\bsandbox\s*=")
_CAT23_PERMISSIVE_SANDBOX = re.compile(r"(?i)sandbox\s*=\s*['\"][^'\"]*allow-scripts[^'\"]*allow-same-origin")
_CAT23_BLANK_NO_NOOPENER = re.compile(
    r"(?i)(target\s*=\s*['\"]_blank['\"](?![^>\n]*(?:noopener|noreferrer))|window\.open\s*\([^;\n]*(?!noopener|noreferrer))"
)

_CAT24_PATTERN = re.compile(
    r"(?i)(canActivate|canDeactivate|beforeEach|beforeEnter|requireAuth|PrivateRoute|ProtectedRoute|useAuth|authGuard|RouteGuard|\.guard\.ts)"
)
_CAT24_SERVER_AUTHORITY = re.compile(
    r"(?i)(HttpClient|fetch\s*\(|axios\.|superagent|/me\b|/session\b|/authorize\b|/permissions\b)"
)


def _add_client_finding(
    findings: list[dict[str, Any]],
    *,
    category: int,
    rel: str,
    subcategory: str,
    severity: str,
    line: int | None,
    match: str,
    evidence: str,
    **extra: Any,
) -> None:
    item: dict[str, Any] = {
        "category": category,
        "subcategory": subcategory,
        "file": rel,
        "line": line,
        "severity": severity,
        "match": match.strip() if isinstance(match, str) else match,
        "evidence": evidence,
    }
    item.update(extra)
    findings.append(item)


def _scan_pattern_category(
    repo_root: Path,
    category: int,
    name: str,
    pattern: re.Pattern[str],
    exts: set[str] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if exts is not None and p.suffix.lower() not in exts:
            continue
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        for line_no, text in _grep_file(p, pattern):
            findings.append(
                {
                    "category": category,
                    "file": rel,
                    "line": line_no,
                    "match": text.strip(),
                }
            )
    return {"category": category, "name": name, "findings": findings, "count": len(findings)}


def scan_spa_bff(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    token_hits: list[dict[str, Any]] = []
    credentials_hits: list[dict[str, Any]] = []
    bff_seen = False

    for p in _walk_repo(repo_root):
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        if _CAT10_BFF.search(text):
            bff_seen = True
        if p.suffix.lower() not in _CLIENT_EXTS:
            continue

        for n, line in _line_hits(lines, _CAT10_TOKEN_STORAGE):
            subcat = "spa-token-browser-storage"
            severity = "High"
            if _CAT10_REFRESH_STORAGE.search(line):
                subcat = "spa-refresh-token-browser-storage"
            item = {
                "category": 10,
                "subcategory": subcat,
                "file": rel,
                "line": n,
                "severity": severity,
                "match": line,
                "evidence": "Session credential appears in browser-accessible storage",
                "anti_pattern": "JWT in localStorage",
            }
            findings.append(item)
            token_hits.append(item)

        for n, line in _line_hits(lines, _CAT10_CREDENTIALS):
            item = {
                "category": 10,
                "subcategory": "spa-withcredentials-surface",
                "file": rel,
                "line": n,
                "severity": "Info",
                "match": line,
                "evidence": "Browser credentialed request mode is used",
            }
            findings.append(item)
            credentials_hits.append(item)

        for n, line in _line_hits(lines, _CAT10_CLIENT_ROLE):
            _add_client_finding(
                findings,
                category=10,
                rel=rel,
                subcategory="spa-client-side-role-trust",
                severity="High",
                line=n,
                match=line,
                evidence="Role, permission, or claim decision appears to be derived from browser state",
                anti_pattern="Client-side trust boundary",
            )

    if token_hits and credentials_hits:
        first = credentials_hits[0]
        _add_client_finding(
            findings,
            category=10,
            rel=first["file"],
            subcategory="spa-withcredentials-token-mix",
            severity="High",
            line=first["line"],
            match=first["match"],
            evidence="Credentialed browser requests coexist with browser-readable token storage",
            anti_pattern="Client-side trust boundary",
        )

    if token_hits and not bff_seen:
        first = token_hits[0]
        _add_client_finding(
            findings,
            category=10,
            rel=first["file"],
            subcategory="spa-without-bff-candidate",
            severity="High",
            line=first["line"],
            match=first["match"],
            evidence="Browser-readable session credential found and no BFF/server-side session marker was detected in scanned client files",
            anti_pattern="SPA without BFF",
        )

    return {"category": 10, "name": "SPA / BFF", "findings": findings, "count": len(findings)}


def _package_json_line(path: Path, dependency: str) -> int | None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    quoted = f'"{dependency}"'
    for n, line in enumerate(lines, start=1):
        if quoted in line:
            return n
    return None


def scan_frontend_xss(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    for p in repo_root.rglob("package.json"):
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        if _is_excluded(rel):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        deps: dict[str, Any] = {}
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            value = data.get(key) if isinstance(data, dict) else None
            if isinstance(value, dict):
                deps.update(value)
        for dep, framework in _FRONTEND_DEPS.items():
            if dep not in deps:
                continue
            _add_client_finding(
                findings,
                category=19,
                rel=rel,
                subcategory="frontend-framework-detected",
                severity="Info",
                line=_package_json_line(p, dep),
                match=f"{dep}: {deps[dep]}",
                evidence=f"{framework} dependency detected",
                framework=framework,
            )

    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CLIENT_EXTS:
            continue
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        has_strong_sanitizer = bool(_CAT19_STRONG_SANITIZER.search(text))
        for n, line in _line_hits(lines, _CAT19_UNSAFE_HTML):
            if re.search(r"(?i)bypassSecurityTrust", line):
                subcat = "frontend-sanitizer-bypass"
                severity = "High"
                evidence = "Framework sanitizer bypass API is used"
                anti_pattern = "Sanitizer bypass by default"
            elif re.search(r"(?i)\bDomSanitizer\b", line):
                subcat = "frontend-sanitizer-api-surface"
                severity = "Info"
                evidence = "Angular DomSanitizer API is referenced; verify it is not used as a default bypass"
                anti_pattern = None
            elif has_strong_sanitizer:
                subcat = "frontend-html-sink-with-sanitizer"
                severity = "Info"
                evidence = "Unsafe HTML sink is present with sanitizer markers in the same file"
                anti_pattern = None
            else:
                subcat = "frontend-unsafe-html-sink"
                severity = "High"
                evidence = "Unsafe HTML rendering sink is present without sanitizer markers in the same file"
                anti_pattern = "Sanitizer bypass by default"
            extra = {"anti_pattern": anti_pattern} if anti_pattern else {}
            _add_client_finding(
                findings,
                category=19,
                rel=rel,
                subcategory=subcat,
                severity=severity,
                line=n,
                match=line,
                evidence=evidence,
                **extra,
            )

    return {"category": 19, "name": "Frontend Framework & XSS Patterns", "findings": findings, "count": len(findings)}


def scan_dom_xss(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CLIENT_EXTS:
            continue
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        source_hits = _line_hits(lines, _CAT20_DOM_SOURCE)
        sink_hits = _line_hits(lines, _CAT20_DOM_SINK)
        for n, line in source_hits:
            _add_client_finding(
                findings,
                category=20,
                rel=rel,
                subcategory="dom-xss-source",
                severity="Info",
                line=n,
                match=line,
                evidence="Browser-controlled DOM source is read",
            )
        if source_hits and sink_hits:
            source_line, source_match = source_hits[0]
            sink_line, sink_match = sink_hits[0]
            _add_client_finding(
                findings,
                category=20,
                rel=rel,
                subcategory="dom-xss-source-sink-candidate",
                severity="High",
                line=source_line,
                match=source_match,
                evidence=f"Browser-controlled DOM source and HTML/code sink appear in the same file; sink at line {sink_line}",
                sink_line=sink_line,
                sink_match=sink_match,
                anti_pattern="Client-side trust boundary",
            )
    return {"category": 20, "name": "DOM-Based XSS Sources", "findings": findings, "count": len(findings)}


def scan_client_secrets(repo_root: Path) -> dict[str, Any]:
    return _scan_pattern_category(repo_root, 21, "Client-Side Secrets", _CAT21_PATTERN)


def scan_websocket(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in (_CLIENT_EXTS | {".py", ".go", ".java", ".kt", ".cs"}):
            continue
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        surface_hits = _line_hits(lines, _CAT22_PATTERN)
        for n, line in surface_hits:
            _add_client_finding(
                findings,
                category=22,
                rel=rel,
                subcategory="websocket-surface",
                severity="Info",
                line=n,
                match=line,
                evidence="WebSocket or Socket.IO surface is present",
            )
        for n, line in _line_hits(lines, _CAT22_CLEARTEXT):
            _add_client_finding(
                findings,
                category=22,
                rel=rel,
                subcategory="websocket-cleartext",
                severity="High",
                line=n,
                match=line,
                evidence="WebSocket URL uses cleartext ws:// outside loopback",
            )
        if surface_hits and _CAT22_SERVER_SOCKET.search(text) and not _CAT22_AUTH.search(text):
            n, line = surface_hits[0]
            _add_client_finding(
                findings,
                category=22,
                rel=rel,
                subcategory="websocket-missing-auth-candidate",
                severity="Medium",
                line=n,
                match=line,
                evidence="Server-side WebSocket surface without auth/token/session markers in the same file",
            )
        if surface_hits and _CAT22_SERVER_SOCKET.search(text) and not _CAT22_ORIGIN.search(text):
            n, line = surface_hits[0]
            _add_client_finding(
                findings,
                category=22,
                rel=rel,
                subcategory="websocket-origin-validation-gap",
                severity="Medium",
                line=n,
                match=line,
                evidence="Server-side WebSocket surface without origin/cors validation markers in the same file",
            )
    return {"category": 22, "name": "WebSocket & Real-Time", "findings": findings, "count": len(findings)}


def scan_postmessage(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CLIENT_EXTS:
            continue
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        surface_hits = _line_hits(lines, _CAT23_PATTERN)
        for n, line in surface_hits:
            _add_client_finding(
                findings,
                category=23,
                rel=rel,
                subcategory="browser-message-surface",
                severity="Info",
                line=n,
                match=line,
                evidence="postMessage, message listener, window opener, or iframe surface is present",
            )
        for n, line in _line_hits(lines, _CAT23_WILDCARD_TARGET):
            _add_client_finding(
                findings,
                category=23,
                rel=rel,
                subcategory="postmessage-wildcard-target",
                severity="High",
                line=n,
                match=line,
                evidence="postMessage uses wildcard target origin",
                anti_pattern="Client-side trust boundary",
            )
        if _CAT23_MESSAGE_LISTENER.search(text) and not _CAT23_ORIGIN_CHECK.search(text):
            listener = _line_hits(lines, _CAT23_MESSAGE_LISTENER)[0]
            _add_client_finding(
                findings,
                category=23,
                rel=rel,
                subcategory="message-listener-no-origin-check",
                severity="High",
                line=listener[0],
                match=listener[1],
                evidence="message event listener lacks origin allowlist markers in the same file",
                anti_pattern="Client-side trust boundary",
            )
        if _CAT23_IFRAME.search(text) and not _CAT23_IFRAME_SANDBOX.search(text):
            iframe = _line_hits(lines, _CAT23_IFRAME)[0]
            _add_client_finding(
                findings,
                category=23,
                rel=rel,
                subcategory="iframe-missing-sandbox",
                severity="Medium",
                line=iframe[0],
                match=iframe[1],
                evidence="iframe is present without sandbox attribute in the same file",
            )
        for n, line in _line_hits(lines, _CAT23_IFRAME_SANDBOX):
            lowered = line.lower()
            if "allow-scripts" in lowered and "allow-same-origin" in lowered:
                _add_client_finding(
                    findings,
                    category=23,
                    rel=rel,
                    subcategory="iframe-permissive-sandbox",
                    severity="Medium",
                    line=n,
                    match=line,
                    evidence="iframe sandbox combines allow-scripts and allow-same-origin",
                )
        for n, line in _line_hits(lines, _CAT23_BLANK_NO_NOOPENER):
            if "noopener" in line.lower() or "noreferrer" in line.lower():
                continue
            _add_client_finding(
                findings,
                category=23,
                rel=rel,
                subcategory="window-opener-noopener-missing",
                severity="Medium",
                line=n,
                match=line,
                evidence="new tab/window opener lacks noopener/noreferrer marker",
            )
    return {"category": 23, "name": "postMessage & iframe", "findings": findings, "count": len(findings)}


def scan_client_routing(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CLIENT_EXTS:
            continue
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        guard_hits = _line_hits(lines, _CAT24_PATTERN)
        for n, line in guard_hits:
            _add_client_finding(
                findings,
                category=24,
                rel=rel,
                subcategory="client-side-auth-guard-surface",
                severity="Info",
                line=n,
                match=line,
                evidence="Client-side route/auth guard surface is present",
            )
        for n, line in _line_hits(lines, _CAT10_CLIENT_ROLE):
            _add_client_finding(
                findings,
                category=24,
                rel=rel,
                subcategory="client-side-role-guard",
                severity="High",
                line=n,
                match=line,
                evidence="Client-side route guard appears to trust browser-held role or claim state",
                anti_pattern="Client-side trust boundary",
            )
        if guard_hits and not _CAT24_SERVER_AUTHORITY.search(text):
            n, line = guard_hits[0]
            _add_client_finding(
                findings,
                category=24,
                rel=rel,
                subcategory="guard-without-server-authority-candidate",
                severity="Medium",
                line=n,
                match=line,
                evidence="Client-side auth guard is present without same-file server authority check marker",
                anti_pattern="Client-side trust boundary",
            )
    return {
        "category": 24,
        "name": "Client-Side Routing & Auth Guards",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 29 — Mobile App Architecture & Platform Config
# ---------------------------------------------------------------------------


_MOBILE_EXTS = {
    ".xml",
    ".java",
    ".kt",
    ".swift",
    ".m",
    ".mm",
    ".plist",
    ".entitlements",
    ".gradle",
    ".properties",
}

_ANDROID_MANIFEST_SURFACE = re.compile(r"(?i)<manifest\b|<application\b|<activity\b|<service\b|<receiver\b|<provider\b")
_ANDROID_DEBUGGABLE = re.compile(r"android:debuggable\s*=\s*['\"]true['\"]")
_ANDROID_ALLOW_BACKUP = re.compile(r"android:allowBackup\s*=\s*['\"]true['\"]")
_ANDROID_CLEARTEXT = re.compile(r"android:usesCleartextTraffic\s*=\s*['\"]true['\"]")
_ANDROID_EXPORTED_TRUE = re.compile(r"android:exported\s*=\s*['\"]true['\"]")
_ANDROID_PERMISSION = re.compile(r"android:permission\s*=")
_ANDROID_COMPONENT = re.compile(r"<(activity|service|receiver|provider)\b", re.IGNORECASE)
_ANDROID_SCHEME = re.compile(r"android:scheme\s*=\s*['\"](?P<scheme>[^'\"]+)['\"]")
_ANDROID_AUTOVERIFY = re.compile(r"android:autoVerify\s*=\s*['\"]true['\"]")
_ANDROID_NETWORK_CLEAR = re.compile(r"cleartextTrafficPermitted\s*=\s*['\"]true['\"]")
_ANDROID_USER_CA = re.compile(r"<certificates\b[^>]*src\s*=\s*['\"]user['\"]", re.IGNORECASE)
_ANDROID_DEBUG_OVERRIDES = re.compile(r"<debug-overrides\b", re.IGNORECASE)

_ANDROID_WEBVIEW_JS = re.compile(r"\.setJavaScriptEnabled\s*\(\s*true\s*\)")
_ANDROID_WEBVIEW_BRIDGE = re.compile(r"\.addJavascriptInterface\s*\(")
_ANDROID_WEBVIEW_FILE = re.compile(
    r"\.(setAllowFileAccess|setAllowUniversalAccessFromFileURLs|setAllowFileAccessFromFileURLs)\s*\(\s*true\s*\)"
)
_ANDROID_WEBVIEW_DEBUG = re.compile(r"WebView\.setWebContentsDebuggingEnabled\s*\(\s*true\s*\)")
_ANDROID_SHARED_PREF_TOKEN = re.compile(
    r"(?i)(SharedPreferences|getSharedPreferences|EncryptedSharedPreferences|putString|getString)[^\n]{0,180}"
    r"(token|jwt|password|secret|refresh|access)"
)
_ANDROID_WORLD_READABLE = re.compile(r"\bMODE_WORLD_READABLE\b")
_ANDROID_ACCEPT_ALL_TLS = re.compile(
    r"(?i)(TrustAll|trustAll|X509TrustManager|HostnameVerifier|verify\s*\([^)]*\)\s*\{?\s*return\s+true|"
    r"checkServerTrusted\s*\([^)]*\)\s*\{?\s*\}|setHostnameVerifier\s*\([^)]*ALLOW_ALL)"
)

_IOS_ATS_ARBITRARY = re.compile(r"<key>NSAllowsArbitraryLoads</key>\s*<true/>")
_IOS_ATS_INSECURE_EXCEPTION = re.compile(r"<key>NSExceptionAllowsInsecureHTTPLoads</key>\s*<true/>")
_IOS_URL_SCHEME = re.compile(r"<key>CFBundleURLSchemes</key>")
_IOS_ASSOCIATED_DOMAINS = re.compile(r"com\.apple\.developer\.associated-domains|applinks:")
_IOS_WEBVIEW_BRIDGE = re.compile(
    r"(?i)(WKScriptMessageHandler|addScriptMessageHandler|evaluateJavaScript\s*\(|UIWebView)"
)
_IOS_USERDEFAULTS_TOKEN = re.compile(
    r"(?i)(UserDefaults|NSUserDefaults)[^\n]{0,180}(token|jwt|password|secret|refresh|access)"
)
_IOS_KEYCHAIN_ALWAYS = re.compile(r"kSecAttrAccessibleAlways")
_IOS_ACCEPT_ALL_TLS = re.compile(
    r"(?i)(allowsAnyHTTPSCertificateForHost|ServerTrustManager\s*\([^)]*allHostsMustBeEvaluated\s*:\s*false|"
    r"validateCertificateChain\s*:\s*false|certificateChainValidation\s*:\s*\.disabled|URLCredential\(trust:)"
)
_MOBILE_MINIFY_FALSE = re.compile(r"(?i)\b(minifyEnabled|isMinifyEnabled)\s*=?\s*false\b")
_ANDROID_CODE_HINT = re.compile(
    r"(?i)(\bandroid\.|\bandroidx\.|WebView|SharedPreferences|X509TrustManager|HostnameVerifier|"
    r"MODE_WORLD_READABLE|addJavascriptInterface|com\.android\.application)"
)
_IOS_CODE_HINT = re.compile(
    r"(?i)(\bUIKit\b|\bFoundation\b|WKWebView|UserDefaults|NSUserDefaults|CFBundle|Keychain|SecItem|Alamofire|"
    r"NSAppTransportSecurity)"
)


def _add_mobile(
    findings: list[dict[str, Any]],
    *,
    rel: str,
    subcategory: str,
    severity: str,
    line: int | None,
    match: str,
    evidence: str,
    platform: str,
    anti_pattern: str | None = None,
) -> None:
    item: dict[str, Any] = {
        "category": 29,
        "subcategory": subcategory,
        "file": rel,
        "line": line,
        "severity": severity,
        "match": match.strip(),
        "evidence": evidence,
        "platform": platform,
    }
    if anti_pattern:
        item["anti_pattern"] = anti_pattern
    findings.append(item)


def _android_component_blocks(lines: list[str]) -> list[tuple[int, str]]:
    blocks: list[tuple[int, str]] = []
    current: list[str] = []
    start: int | None = None
    for n, line in enumerate(lines, start=1):
        if start is None and _ANDROID_COMPONENT.search(line):
            start = n
            current = [line.strip()]
            if ">" in line:
                blocks.append((start, " ".join(current)))
                start = None
                current = []
            continue
        if start is not None:
            current.append(line.strip())
            if ">" in line:
                blocks.append((start, " ".join(current)))
                start = None
                current = []
    return blocks


def _plist_true_key_hits(lines: list[str], key: str) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    key_marker = f"<key>{key}</key>"
    for n, line in enumerate(lines, start=1):
        if key_marker not in line:
            continue
        for next_line in lines[n:]:
            stripped = next_line.strip()
            if not stripped:
                continue
            if stripped == "<true/>":
                hits.append((n, f"{line.strip()} {stripped}"))
            break
    return hits


def scan_mobile_architecture(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    surface_files: dict[str, str] = {}

    for p in _walk_repo(repo_root):
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        if p.suffix.lower() not in _MOBILE_EXTS and p.name not in {"AndroidManifest.xml", "Info.plist"}:
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        text = "\n".join(lines)
        lower_rel = rel.lower()
        is_android = (
            p.name == "AndroidManifest.xml"
            or "network_security_config" in lower_rel
            or "/android/" in f"/{lower_rel}"
            or bool(_ANDROID_MANIFEST_SURFACE.search(text))
            or bool(_ANDROID_CODE_HINT.search(text))
        )
        is_ios = (
            p.name == "Info.plist"
            or "/ios/" in f"/{lower_rel}"
            or "CFBundle" in text
            or bool(_IOS_CODE_HINT.search(text))
        )
        if is_android:
            surface_files[rel] = "Android"
        elif is_ios:
            surface_files[rel] = "iOS"

        if p.name == "AndroidManifest.xml":
            for n, line in _line_hits(lines, _ANDROID_DEBUGGABLE):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="android-debuggable-enabled",
                    severity="High",
                    line=n,
                    match=line,
                    evidence="Android manifest enables debuggable runtime",
                    platform="Android",
                    anti_pattern="Mobile debug build shipped",
                )
            for n, line in _line_hits(lines, _ANDROID_ALLOW_BACKUP):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="android-allowbackup-enabled",
                    severity="Medium",
                    line=n,
                    match=line,
                    evidence="Android app data backup is enabled in the manifest",
                    platform="Android",
                    anti_pattern="Mobile client stores sensitive state without platform hardening",
                )
            for n, line in _line_hits(lines, _ANDROID_CLEARTEXT):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="android-cleartext-traffic-enabled",
                    severity="High",
                    line=n,
                    match=line,
                    evidence="Android manifest permits cleartext network traffic",
                    platform="Android",
                    anti_pattern="Mobile cleartext network policy",
                )
            for start, block in _android_component_blocks(lines):
                if _ANDROID_EXPORTED_TRUE.search(block) and not _ANDROID_PERMISSION.search(block):
                    _add_mobile(
                        findings,
                        rel=rel,
                        subcategory="android-exported-component-without-permission",
                        severity="High",
                        line=start,
                        match=block[:400],
                        evidence="Exported Android component lacks an explicit permission in the component declaration",
                        platform="Android",
                        anti_pattern="Mobile IPC boundary exposed",
                    )
            for n, line in _line_hits(lines, _ANDROID_SCHEME):
                scheme_match = _ANDROID_SCHEME.search(line)
                scheme = scheme_match.group("scheme").lower() if scheme_match else ""
                if scheme and scheme not in {"http", "https"}:
                    _add_mobile(
                        findings,
                        rel=rel,
                        subcategory="android-custom-url-scheme",
                        severity="Medium",
                        line=n,
                        match=line,
                        evidence="Custom-scheme deep link is present; ownership is not OS-verified like app links",
                        platform="Android",
                        anti_pattern="Mobile deep-link trust boundary",
                    )
                elif scheme in {"http", "https"} and not _ANDROID_AUTOVERIFY.search(text):
                    _add_mobile(
                        findings,
                        rel=rel,
                        subcategory="android-applink-not-verified",
                        severity="Medium",
                        line=n,
                        match=line,
                        evidence="HTTP(S) deep link lacks autoVerify marker in the manifest",
                        platform="Android",
                        anti_pattern="Mobile deep-link trust boundary",
                    )

        if p.name == "network_security_config.xml" or "network_security_config" in lower_rel:
            for n, line in _line_hits(lines, _ANDROID_NETWORK_CLEAR):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="android-network-config-cleartext",
                    severity="High",
                    line=n,
                    match=line,
                    evidence="Android network security config permits cleartext traffic",
                    platform="Android",
                    anti_pattern="Mobile cleartext network policy",
                )
            for n, line in _line_hits(lines, _ANDROID_USER_CA):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="android-user-ca-trusted",
                    severity="Medium",
                    line=n,
                    match=line,
                    evidence="Android network security config trusts user-installed CAs",
                    platform="Android",
                    anti_pattern="Mobile TLS trust weakened",
                )
            for n, line in _line_hits(lines, _ANDROID_DEBUG_OVERRIDES):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="android-debug-overrides",
                    severity="Medium",
                    line=n,
                    match=line,
                    evidence="Android debug network trust overrides are present",
                    platform="Android",
                    anti_pattern="Mobile debug trust override",
                )

        if is_android:
            android_patterns = [
                (
                    _ANDROID_WEBVIEW_BRIDGE,
                    "android-webview-js-bridge",
                    "High",
                    "WebView JavaScript bridge is exposed",
                    "Mobile WebView bridge",
                ),
                (
                    _ANDROID_WEBVIEW_JS,
                    "android-webview-javascript-enabled",
                    "Medium",
                    "WebView JavaScript execution is enabled",
                    "Mobile WebView bridge",
                ),
                (
                    _ANDROID_WEBVIEW_FILE,
                    "android-webview-file-access",
                    "High",
                    "WebView file/universal file URL access is enabled",
                    "Mobile WebView bridge",
                ),
                (
                    _ANDROID_WEBVIEW_DEBUG,
                    "android-webview-debugging-enabled",
                    "High",
                    "WebView remote debugging is enabled",
                    "Mobile debug build shipped",
                ),
                (
                    _ANDROID_SHARED_PREF_TOKEN,
                    "android-token-sharedpreferences",
                    "High",
                    "Sensitive token/secret marker appears in SharedPreferences usage",
                    "Mobile token in app storage",
                ),
                (
                    _ANDROID_WORLD_READABLE,
                    "android-world-readable-storage",
                    "High",
                    "World-readable Android storage mode is used",
                    "Mobile token in app storage",
                ),
                (
                    _ANDROID_ACCEPT_ALL_TLS,
                    "android-accept-all-tls",
                    "Critical",
                    "Android TLS validation appears to accept arbitrary certificates or hosts",
                    "Mobile TLS trust disabled",
                ),
                (
                    _MOBILE_MINIFY_FALSE,
                    "android-minify-disabled",
                    "Info",
                    "Android build disables code shrinking/obfuscation",
                    "Mobile release hardening gap",
                ),
            ]
            for pattern, subcat, severity, evidence, anti_pattern in android_patterns:
                for n, line in _line_hits(lines, pattern):
                    _add_mobile(
                        findings,
                        rel=rel,
                        subcategory=subcat,
                        severity=severity,
                        line=n,
                        match=line,
                        evidence=evidence,
                        platform="Android",
                        anti_pattern=anti_pattern,
                    )

        if p.name == "Info.plist":
            for n, line in _plist_true_key_hits(lines, "NSAllowsArbitraryLoads"):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="ios-ats-arbitrary-loads",
                    severity="High",
                    line=n,
                    match=line,
                    evidence="iOS App Transport Security allows arbitrary loads",
                    platform="iOS",
                    anti_pattern="Mobile cleartext network policy",
                )
            for n, line in _plist_true_key_hits(lines, "NSExceptionAllowsInsecureHTTPLoads"):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="ios-ats-insecure-exception",
                    severity="High",
                    line=n,
                    match=line,
                    evidence="iOS ATS exception permits insecure HTTP loads",
                    platform="iOS",
                    anti_pattern="Mobile cleartext network policy",
                )
            for n, line in _line_hits(lines, _IOS_URL_SCHEME):
                _add_mobile(
                    findings,
                    rel=rel,
                    subcategory="ios-custom-url-scheme-surface",
                    severity="Info",
                    line=n,
                    match=line,
                    evidence="iOS custom URL scheme surface is present",
                    platform="iOS",
                    anti_pattern="Mobile deep-link trust boundary",
                )

        if is_ios:
            ios_patterns = [
                (
                    _IOS_WEBVIEW_BRIDGE,
                    "ios-webview-js-bridge",
                    "High",
                    "iOS WebView JavaScript bridge or evaluation API is present",
                    "Mobile WebView bridge",
                ),
                (
                    _IOS_USERDEFAULTS_TOKEN,
                    "ios-token-userdefaults",
                    "High",
                    "Sensitive token/secret marker appears in UserDefaults usage",
                    "Mobile token in app storage",
                ),
                (
                    _IOS_KEYCHAIN_ALWAYS,
                    "ios-keychain-accessible-always",
                    "Medium",
                    "Keychain item uses always-accessible class",
                    "Mobile token in app storage",
                ),
                (
                    _IOS_ACCEPT_ALL_TLS,
                    "ios-accept-all-tls",
                    "Critical",
                    "iOS TLS validation appears to accept arbitrary certificates or hosts",
                    "Mobile TLS trust disabled",
                ),
                (
                    _IOS_ASSOCIATED_DOMAINS,
                    "ios-associated-domains-surface",
                    "Info",
                    "iOS Associated Domains entitlement is present",
                    "Mobile deep-link trust boundary",
                ),
            ]
            for pattern, subcat, severity, evidence, anti_pattern in ios_patterns:
                for n, line in _line_hits(lines, pattern):
                    _add_mobile(
                        findings,
                        rel=rel,
                        subcategory=subcat,
                        severity=severity,
                        line=n,
                        match=line,
                        evidence=evidence,
                        platform="iOS",
                        anti_pattern=anti_pattern,
                    )

    for rel, platform in sorted(surface_files.items()):
        findings.insert(
            0,
            {
                "category": 29,
                "subcategory": "mobile-app-surface",
                "file": rel,
                "line": None,
                "severity": "Info",
                "match": rel,
                "evidence": "Mobile app source or platform configuration detected",
                "platform": platform,
            },
        )

    return {
        "category": 29,
        "name": "Mobile App Architecture & Platform Config",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 27 — GitHub Actions workflow privilege hardening
# ---------------------------------------------------------------------------


_CAT27_PERMISSIONS_WRITE = re.compile(
    r"^\s*(?P<scope>contents|packages|pages|id-token|actions|deployments|security-events|statuses|checks|issues|pull-requests):\s*write\s*$",
    re.IGNORECASE,
)
_CAT27_SELF_HOSTED = re.compile(r"^\s*runs-on\s*:.*self-hosted", re.IGNORECASE)


def scan_gha_privileges(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return {"category": 27, "name": "GitHub Actions Workflow Privilege Hardening", "findings": [], "count": 0}

    for p in sorted(wf_dir.iterdir()):
        if p.suffix.lower() not in {".yml", ".yaml"} or not p.is_file():
            continue
        rel = str(p.relative_to(repo_root)).replace("\\", "/")
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        has_permissions = False
        for n, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.match(r"^pull_request_target\s*:", stripped):
                findings.append(
                    {
                        "category": 27,
                        "subcategory": "pull-request-target",
                        "file": rel,
                        "line": n,
                        "match": stripped,
                    }
                )
            if re.match(r"^permissions\s*:", stripped):
                has_permissions = True
                if re.search(r":\s*write-all\s*$", stripped, re.IGNORECASE):
                    findings.append(
                        {
                            "category": 27,
                            "subcategory": "permissions-write-all",
                            "file": rel,
                            "line": n,
                            "match": stripped,
                        }
                    )
            m_perm = _CAT27_PERMISSIONS_WRITE.match(line)
            if m_perm:
                findings.append(
                    {
                        "category": 27,
                        "subcategory": "permissions-write",
                        "file": rel,
                        "line": n,
                        "scope": m_perm.group("scope"),
                        "match": stripped,
                    }
                )
            if _CAT27_SELF_HOSTED.match(line):
                findings.append(
                    {
                        "category": 27,
                        "subcategory": "self-hosted-runner",
                        "file": rel,
                        "line": n,
                        "match": stripped,
                    }
                )
        if not has_permissions:
            findings.append(
                {
                    "category": 27,
                    "subcategory": "missing-permissions-block",
                    "file": rel,
                    "line": None,
                    "match": "no permissions block",
                }
            )

    return {
        "category": 27,
        "name": "GitHub Actions Workflow Privilege Hardening",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 28 — AI coding assistant & IDE agent configurations
# ---------------------------------------------------------------------------


_AI_CONFIG_PATTERNS = (
    ".claude/CLAUDE.md",
    "CLAUDE.md",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks.json",
    ".claude/.mcp.json",
    ".cursor/rules",
    ".cursorrules",
    ".cursor/mcp.json",
    ".windsurfrules",
    ".continue/config.json",
    ".continue/config.yaml",
    ".continue/instructions.md",
    ".codeium/instructions.md",
    ".codeiumignore",
    ".github/copilot-instructions.md",
    ".aider.conf.yml",
    ".aider.model.settings.yml",
    ".aiderignore",
    "CONVENTIONS.md",
    "AGENTS.md",
    ".mcp.json",
    "MCP_CONFIG.json",
)
_AI_CONFIG_DIRS = (
    ".claude/agents",
    ".claude/skills",
    ".claude/commands",
    ".cursor",
    ".windsurf",
    ".continue/assistants",
    ".github/prompts",
    ".github/instructions",
    ".kiro",
    ".ai",
)
_CAT28_DANGEROUS = re.compile(
    r"(?i)(Bash\(\*\)|Bash\(\*:\*\)|allowDangerous|dangerously|mcpServers|postToolUse|preToolUse|curl\s+[^|;]*\|\s*(?:sh|bash)|rm\s+-rf|chmod\s+777)"
)

_MCP_CONFIG_NAMES = {"mcp.json", ".mcp.json", "MCP_CONFIG.json"}
_MCP_SECRET_KEY_RE = re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|pwd|authorization|bearer|credential)")
_MCP_REMOTE_URL_RE = re.compile(r"(?i)^https?://")
_MCP_PUBLIC_REGISTRY_COMMANDS = {"npx", "uvx", "pipx"}


def _is_mcp_config_path(rel: str) -> bool:
    return PurePosixPath(rel).name in _MCP_CONFIG_NAMES


def _mcp_servers_from_config(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    for key in ("mcpServers", "servers"):
        value = data.get(key)
        if isinstance(value, dict):
            return value
    nested = data.get("mcp")
    if isinstance(nested, dict):
        return _mcp_servers_from_config(nested)
    return {}


def _first_http_url(value: Any) -> str | None:
    if isinstance(value, str):
        return value if _MCP_REMOTE_URL_RE.match(value) else None
    if isinstance(value, dict):
        for v in value.values():
            found = _first_http_url(v)
            if found:
                return found
    if isinstance(value, list):
        for v in value:
            found = _first_http_url(v)
            if found:
                return found
    return None


def _mcp_command_parts(server_cfg: Any) -> list[str]:
    if not isinstance(server_cfg, dict):
        return []
    parts: list[str] = []
    command = server_cfg.get("command")
    if isinstance(command, str) and command.strip():
        parts.append(command.strip())
    args = server_cfg.get("args")
    if isinstance(args, list):
        parts.extend(str(a).strip() for a in args if str(a).strip())
    return parts


def _looks_like_env_ref(value: str) -> bool:
    stripped = value.strip()
    return bool(re.search(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", stripped))


def _mcp_hardcoded_secret(server_cfg: Any) -> tuple[str, str] | None:
    if not isinstance(server_cfg, dict):
        return None
    for container_name in ("env", "headers"):
        container = server_cfg.get(container_name)
        if not isinstance(container, dict):
            continue
        for key, value in container.items():
            if not _MCP_SECRET_KEY_RE.search(str(key)):
                continue
            if not isinstance(value, str):
                continue
            stripped = value.strip()
            if len(stripped) >= 8 and not _looks_like_env_ref(stripped):
                return str(key), container_name
    return None


def _mcp_has_auth_reference(server_cfg: Any) -> bool:
    if not isinstance(server_cfg, dict):
        return False
    for container_name in ("env", "headers"):
        container = server_cfg.get(container_name)
        if not isinstance(container, dict):
            continue
        for key, value in container.items():
            if _MCP_SECRET_KEY_RE.search(str(key)) and isinstance(value, str) and _looks_like_env_ref(value):
                return True
    return False


def _classify_mcp_server(server_cfg: Any) -> dict[str, Any]:
    if not isinstance(server_cfg, dict):
        return {
            "transport": "unknown",
            "origin": "unknown",
            "severity": "Info",
            "subcategory": "mcp-local-server",
            "reason": "server config is not an object",
        }

    cfg_type = str(server_cfg.get("type") or "").strip().lower()
    url = server_cfg.get("url") if isinstance(server_cfg.get("url"), str) else _first_http_url(server_cfg)
    command_parts = _mcp_command_parts(server_cfg)
    command_name = PurePosixPath(command_parts[0]).name if command_parts else ""

    if cfg_type in {"http", "sse"}:
        transport = cfg_type
    elif url:
        transport = "http"
    elif command_parts:
        transport = "stdio"
    else:
        transport = cfg_type or "unknown"

    secret = _mcp_hardcoded_secret(server_cfg)
    if secret:
        return {
            "transport": transport,
            "origin": "remote URL" if url else "local/public-registry",
            "severity": "Critical",
            "subcategory": "mcp-hardcoded-secret",
            "reason": f"hardcoded {secret[0]} in {secret[1]}",
        }

    if url or transport in {"http", "sse"}:
        reason = "remote MCP server controls assistant tool output"
        if _mcp_has_auth_reference(server_cfg):
            reason += " and requires an auth token from the environment"
        return {
            "transport": transport,
            "origin": "remote URL",
            "severity": "High",
            "subcategory": "mcp-remote-server",
            "reason": reason,
        }

    if command_name in _MCP_PUBLIC_REGISTRY_COMMANDS:
        return {
            "transport": "stdio",
            "origin": f"public registry ({command_name})",
            "severity": "High",
            "subcategory": "mcp-public-registry-server",
            "reason": "server binary is fetched from a public registry at invocation time",
        }

    return {
        "transport": transport,
        "origin": "local binary" if command_parts else "unknown",
        "severity": "Info",
        "subcategory": "mcp-local-server",
        "reason": "local MCP server config; manual binary review still warranted",
    }


def _scan_mcp_servers(path: Path, rel: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    findings: list[dict[str, Any]] = []
    for server_name, server_cfg in sorted(_mcp_servers_from_config(data).items()):
        if not isinstance(server_cfg, dict):
            continue
        classified = _classify_mcp_server(server_cfg)
        findings.append(
            {
                "category": 28,
                "subcategory": classified["subcategory"],
                "file": rel,
                "line": None,
                "server": str(server_name),
                "transport": classified["transport"],
                "origin": classified["origin"],
                "severity": classified["severity"],
                "match": classified["reason"],
            }
        )
    return findings


# --- Cat 28b: Claude Code permission model (deterministic) -----------------
# The flat `_CAT28_DANGEROUS` regex only ever matched literal `Bash(*)`. The
# checks below parse `permissions.allow` / `defaultMode` structurally so the
# recon template's 7.32 "dangerous permission patterns" table has a real
# producer. Only `allow` is graded: `deny`/`ask` entries are protective, and a
# thin or absent deny-list is hygiene, not an exploitable weakness.

_CLAUDE_SETTINGS_NAMES = {"settings.json", "settings.local.json"}
_PERM_RULE_RE = re.compile(r"^(?P<tool>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\((?P<arg>.*)\))?$", re.DOTALL)
_PERM_WILDCARDS = {"", "*", "*:*", "**", "**/*"}
# Commands that hand over the host (or an exfil channel) when granted with a
# `:*` argument wildcard. Deliberately narrow: `git`/`npm`/`pip` are omitted
# because `Bash(git:*)`-style rules are near-universal and mostly benign, and a
# noisy Cat 28b table would get ignored wholesale.
_BASH_HIGH_RISK = {
    "sudo", "su", "rm", "chmod", "chown", "ssh", "scp", "nc", "ncat",
    "eval", "exec", "dd", "mkfs", "curl", "wget",
}
_SENSITIVE_PATH_RE = re.compile(
    r"(?i)(\.ssh|\.aws|\.gnupg|\.kube|\.netrc|\.npmrc|\.env\b|id_rsa|id_ed25519|credential|\.git/config)"
)


def _classify_permission_rule(rule: str) -> dict[str, str] | None:
    """Grade one `permissions.allow` entry. Returns None when not a real risk."""
    match = _PERM_RULE_RE.match(rule.strip())
    if not match:
        return None
    tool = match.group("tool")
    arg = (match.group("arg") or "").strip()
    arg_is_wildcard = arg in _PERM_WILDCARDS

    if tool == "Bash":
        if arg_is_wildcard:
            return {
                "severity": "Critical",
                "reason": f"`{rule}` grants unrestricted shell execution without a permission prompt",
            }
        command = arg.split(":", 1)[0].strip()
        if command in _BASH_HIGH_RISK:
            return {
                "severity": "High",
                "reason": f"`{rule}` pre-approves the high-risk command `{command}` with an argument wildcard",
            }
        return None

    if tool in {"Write", "Edit", "MultiEdit", "NotebookEdit"}:
        if arg_is_wildcard:
            return {
                "severity": "High",
                "reason": f"`{rule}` allows unprompted writes to any path",
            }
        if _SENSITIVE_PATH_RE.search(arg):
            return {
                "severity": "High",
                "reason": f"`{rule}` allows unprompted writes to a credential-bearing path",
            }
        return None

    if tool == "Read":
        if _SENSITIVE_PATH_RE.search(arg):
            return {
                "severity": "High",
                "reason": f"`{rule}` grants read access to a credential-bearing path",
            }
        if arg_is_wildcard:
            return {
                "severity": "Medium",
                "reason": f"`{rule}` grants unrestricted read access, including files outside the project",
            }
        return None

    if tool in {"WebFetch", "WebSearch"} and (arg_is_wildcard or arg.lower() in {"domain:*", "domain:  *"}):
        return {
            "severity": "Medium",
            "reason": f"`{rule}` permits requests to any host — a usable exfiltration channel",
        }

    return None


def _find_line(text: str, needle: str) -> int | None:
    for idx, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return idx
    return None


def _scan_claude_permissions(path: Path, rel: str) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    findings: list[dict[str, Any]] = []
    permissions = data.get("permissions")
    permissions = permissions if isinstance(permissions, dict) else {}

    default_mode = permissions.get("defaultMode") or data.get("defaultMode")
    if isinstance(default_mode, str) and default_mode.strip() == "bypassPermissions":
        # Committed into a repo, this disables the tool's only guardrail for
        # every contributor who opens it — hence Critical rather than High.
        findings.append(
            {
                "category": 28,
                "subcategory": "permission-bypass-mode",
                "file": rel,
                "line": _find_line(raw, "bypassPermissions"),
                "severity": "Critical",
                "match": "`defaultMode: bypassPermissions` disables permission prompts for every tool call",
            }
        )

    allow = permissions.get("allow")
    if isinstance(allow, list):
        for entry in allow:
            if not isinstance(entry, str):
                continue
            classified = _classify_permission_rule(entry)
            if classified is None:
                continue
            findings.append(
                {
                    "category": 28,
                    "subcategory": "overbroad-permission-rule",
                    "file": rel,
                    "line": _find_line(raw, entry),
                    "rule": entry,
                    "severity": classified["severity"],
                    "match": classified["reason"],
                }
            )

    if data.get("enableAllProjectMcpServers") is True:
        findings.append(
            {
                "category": 28,
                "subcategory": "mcp-auto-trust",
                "file": rel,
                "line": _find_line(raw, "enableAllProjectMcpServers"),
                "severity": "High",
                "match": "`enableAllProjectMcpServers: true` auto-approves every MCP server declared in the repo",
            }
        )

    return findings


# --- Cat 28c: hook command bodies (deterministic) --------------------------
# `_CAT28_DANGEROUS` only ever matched the literal event-key names, so a benign
# formatter hook was flagged while an exfiltrating `curl` hook was not, and
# `UserPromptSubmit` was absent from the regex entirely. The checks below walk
# the hook structure and grade the actual `command` bodies.

_HOOK_EVENTS = {
    "PreToolUse", "PostToolUse", "UserPromptSubmit", "Stop", "SubagentStop",
    "SessionStart", "SessionEnd", "Notification", "PreCompact",
}
_HOOK_PIPE_TO_SHELL_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba)?sh\b")
_HOOK_SUBSTITUTION_RE = re.compile(r"\$\(|`")
_HOOK_EGRESS_RE = re.compile(r"(?i)(\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bscp\b|https?://)")
_HOOK_DESTRUCTIVE_RE = re.compile(r"(?i)(\brm\s+-[rf]{1,2}\b|\bchmod\s+777\b|\bdd\s+if=)")


def _classify_hook_command(event: str, command: str) -> dict[str, str] | None:
    """Grade one hook `command` body. Returns None when not a real risk."""
    if _HOOK_PIPE_TO_SHELL_RE.search(command):
        return {
            "severity": "Critical",
            "reason": f"`{event}` hook fetches and pipes remote content into a shell — remote code execution on every trigger",
        }
    if _HOOK_SUBSTITUTION_RE.search(command):
        if event == "UserPromptSubmit":
            # Attacker-controlled prompt text reaches the command line before
            # any filtering, so substitution here is directly injectable.
            return {
                "severity": "Critical",
                "reason": "`UserPromptSubmit` hook builds a shell command via substitution — prompt text reaches the command line unfiltered",
            }
        return {
            "severity": "High",
            "reason": f"`{event}` hook uses shell command substitution — tool payload can influence the executed command",
        }
    if _HOOK_EGRESS_RE.search(command):
        return {
            "severity": "High",
            "reason": f"`{event}` hook network-egresses on every trigger — a continuous exfiltration channel",
        }
    if _HOOK_DESTRUCTIVE_RE.search(command):
        return {
            "severity": "High",
            "reason": f"`{event}` hook runs a destructive command on every trigger",
        }
    return None


def _iter_hook_commands(data: Any) -> Iterator[tuple[str, str]]:
    """Yield (event, command) for every hook entry in a settings/hooks object."""
    if not isinstance(data, dict):
        return
    events = data.get("hooks") if isinstance(data.get("hooks"), dict) else data
    if not isinstance(events, dict):
        return
    for event, groups in events.items():
        if event not in _HOOK_EVENTS or not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            entries = group.get("hooks")
            entries = entries if isinstance(entries, list) else [group]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                command = entry.get("command")
                if isinstance(command, str) and command.strip():
                    yield str(event), command


def _find_hook_line(raw: str, event: str, command: str) -> int | None:
    """Locate a hook command in the raw JSON, tolerating string escaping."""
    escaped = json.dumps(command)[1:-1]
    for needle in (command[:60], escaped[:60], f'"{event}"'):
        line = _find_line(raw, needle)
        if line is not None:
            return line
    return None


def _scan_hook_commands(path: Path, rel: str) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return []

    findings: list[dict[str, Any]] = []
    for event, command in _iter_hook_commands(data):
        classified = _classify_hook_command(event, command)
        if classified is None:
            continue
        findings.append(
            {
                "category": 28,
                "subcategory": "dangerous-hook-command",
                "file": rel,
                "line": _find_hook_line(raw, event, command),
                "event": event,
                "command": command,
                "severity": classified["severity"],
                "match": classified["reason"],
            }
        )
    return findings


def _is_claude_hooks_path(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    return len(parts) >= 2 and parts[-2] == ".claude" and parts[-1] == "hooks.json"


def _is_claude_settings_path(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    return len(parts) >= 2 and parts[-2] == ".claude" and parts[-1] in _CLAUDE_SETTINGS_NAMES


def scan_ai_assistant_configs(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_path(path: Path) -> None:
        try:
            is_file = path.is_file()
        except OSError:
            return
        if not is_file:
            return
        rel = str(path.relative_to(repo_root)).replace("\\", "/")
        if rel in seen or _is_excluded(rel):
            return
        seen.add(rel)
        try:
            size = path.stat().st_size
        except OSError:
            size = None
        findings.append(
            {
                "category": 28,
                "subcategory": "assistant-config-present",
                "file": rel,
                "line": None,
                "size": size,
            }
        )
        for line_no, text in _grep_file(path, _CAT28_DANGEROUS):
            findings.append(
                {
                    "category": 28,
                    "subcategory": "dangerous-assistant-config-pattern",
                    "file": rel,
                    "line": line_no,
                    "match": text.strip(),
                }
            )
        if _is_mcp_config_path(rel):
            findings.extend(_scan_mcp_servers(path, rel))
        if _is_claude_settings_path(rel):
            findings.extend(_scan_claude_permissions(path, rel))
        if _is_claude_settings_path(rel) or _is_claude_hooks_path(rel):
            findings.extend(_scan_hook_commands(path, rel))

    for rel in _AI_CONFIG_PATTERNS:
        add_path(repo_root / rel)
    for rel_dir in _AI_CONFIG_DIRS:
        d = repo_root / rel_dir
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*")):
            add_path(p)
    for p in sorted(repo_root.rglob("mcp.json")):
        add_path(p)

    return {
        "category": 28,
        "name": "AI Coding Assistant & IDE Agent Configurations",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Category 13 — AI / LLM integration (deterministic; replaces the former
# LLM-grep 5-AND rule). Two signal strengths so a single import/framework/
# vector-DB/model-id (STRONG) is enough, while generic tokens (WEAK) only count
# in combination — see docs/analysis/plan-deterministic-ai-llm-detection-2026-06-23.md.
# ---------------------------------------------------------------------------

# Code + structured-config extensions only (all are a subset of _TEXT_EXT). Docs
# (.md/.adoc) are excluded on purpose: a README that merely *mentions* "OpenAI"
# is not an AI surface.
_CAT13_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".java",
    ".kt",
    ".scala",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".rs",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".env",
}

# (subcategory, strength, pattern). STRONG tokens essentially never occur outside
# genuine LLM code; one hit ⇒ AI surface. WEAK tokens also occur in non-LLM code
# (ML, sensors, games), so they only count via the anchored weak rule below.
_CAT13_GROUPS: list[tuple[str, str, re.Pattern[str]]] = [
    # --- STRONG -----------------------------------------------------------
    (
        "llm-sdk",
        "strong",
        re.compile(
            r"(?i)(\bopenai\b|\banthropic\b|@anthropic-ai|\blangchain\b|@langchain/"
            r"|llama[_-]?index|\bllamaindex\b|\bautogen\b|\bcrewai\b|\blitellm\b"
            r"|\bcohere\b|\bmistralai\b|google\.generativeai|@google/generative-ai"
            r"|\bollama\b|@azure/openai|\bbedrock-runtime\b|ChatCompletion"
            r"|chat\.completions|GenerativeModel|\bInvokeModel\b)"
        ),
    ),
    ("vector-db", "strong", re.compile(r"(?i)(\bchromadb\b|\bpinecone\b|\bweaviate\b|\bqdrant\b|\bmilvus\b)")),
    (
        "agent-framework",
        "strong",
        re.compile(r"(AgentExecutor|ReActAgent|create_react_agent|create_tool_calling_agent)"),
    ),
    (
        "prompt-framework",
        "strong",
        re.compile(r"(ChatPromptTemplate|\bSystemMessage\b|\bHumanMessage\b|\bPromptTemplate\b|from_messages)"),
    ),
    ("tokenizer", "strong", re.compile(r"(?i)\btiktoken\b")),
    (
        "model-name",
        "strong",
        re.compile(
            r"(?i)(gpt-4|gpt-3\.5|claude-3|claude-2|claude-sonnet|claude-opus"
            r"|gemini-1\.|text-embedding-(?:ada|3)|\bo1-(?:preview|mini)\b)"
        ),
    ),
    # --- WEAK -------------------------------------------------------------
    (
        "prompt-construction",
        "weak",
        re.compile(r"(?i)(system[ _-]?prompt|system[ _-]?message|prompt[ _-]?template|user[ _-]?prompt)"),
    ),
    (
        "model-config",
        "weak",
        re.compile(r"(?i)(\btemperature\b|max[ _-]?tokens|\btop[ _-]?p\b|model[ _-]?name|model[ _-]?id)"),
    ),
    (
        "vector-semantic",
        "weak",
        re.compile(r"(?i)(\bembedding|vector[ _-]?store|similarity[ _-]?search|\bpgvector\b|\bfaiss\b)"),
    ),
    ("tool-use", "weak", re.compile(r"(?i)(tool[ _-]?use|function[ _-]?call|tool[ _-]?choice)")),
]

_CAT13_PER_SUBCAT_CAP = 20

# AI-coding-assistant / IDE-agent config dirs. Their files name AI providers
# ("api.anthropic.com" in a Claude Code permission list) but describe the
# DEVELOPER's tooling, not the target app's LLM usage — so they must not flag an
# AI surface here. Cat 28 still catalogs them (that is a separate supply-chain
# signal), which is why this is a Cat-13-local skip, not a global hard-exclude.
_CAT13_SKIP_DIRS = frozenset({".claude", ".cursor", ".continue", ".codeium", ".aider", ".windsurf"})


def scan_ai_integration(repo_root: Path) -> dict[str, Any]:
    """Detect a genuine AI/LLM surface deterministically.

    Returns findings only when ``has_ai_surface`` holds:
      (>=1 STRONG hit anywhere) OR (a SINGLE file co-locating the
      'prompt-construction' weak group plus >=1 other distinct weak group).
      The anchored, co-located weak rule catches SDK-less REST integrations
      (whose prompt + model-config sit in the same module) while rejecting both
      non-LLM ML repos (embedding + temperature without a prompt anchor) and
      scattered security-vocabulary (a docs/taxonomy repo that merely *names*
      "prompt injection", "embeddings", "tool use" across separate files). An
      empty result ⇒ KNOWN_LLM_PATTERNS = none ⇒ the '### AI / LLM Exposure'
      section renders nothing.
    """
    findings: list[dict[str, Any]] = []
    per_cap: dict[str, int] = {}
    strong_seen: set[str] = set()
    weak_by_file: dict[str, set[str]] = {}
    truncated = False

    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CAT13_EXTS:
            continue
        rel_path = p.relative_to(repo_root)
        if any(part in _CAT13_SKIP_DIRS for part in rel_path.parts[:-1]):
            continue
        rel = str(rel_path).replace("\\", "/")
        try:
            with p.open("r", encoding="utf-8", errors="replace") as f:
                for n, line in enumerate(f, start=1):
                    for subcat, strength, pat in _CAT13_GROUPS:
                        if not pat.search(line):
                            continue
                        if strength == "strong":
                            strong_seen.add(subcat)
                        else:
                            weak_by_file.setdefault(rel, set()).add(subcat)
                        if per_cap.get(subcat, 0) < _CAT13_PER_SUBCAT_CAP:
                            stripped = line.rstrip("\r\n")
                            if len(stripped) > 400:
                                stripped = stripped[:400] + "…"
                            findings.append(
                                {
                                    "category": 13,
                                    "subcategory": subcat,
                                    "strength": strength,
                                    "file": rel,
                                    "line": n,
                                    "match": stripped.strip(),
                                }
                            )
                            per_cap[subcat] = per_cap.get(subcat, 0) + 1
                        else:
                            truncated = True
        except OSError:
            continue

    has_ai_surface = bool(strong_seen) or any(
        "prompt-construction" in groups and len(groups) >= 2 for groups in weak_by_file.values()
    )
    if not has_ai_surface:
        return {"category": 13, "name": "AI / LLM Integration", "findings": [], "count": 0}

    out: dict[str, Any] = {
        "category": 13,
        "name": "AI / LLM Integration",
        "findings": findings,
        "count": len(findings),
    }
    if truncated:
        out["truncated"] = True
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


# Cap findings per category in the aggregate `.recon-patterns.json` the
# recon-scanner agent Reads into its LLM context. A recon pre-pass is a SIGNAL,
# not an exhaustive enumeration — the analyst re-greps on demand — so an
# unbounded findings list (juice-shop 2026-07-14: 319 KB of `categories`,
# ~120k tokens re-read every turn, a major contributor to the multi-million
# cache_read that made the streaming call fragile) only inflates context. The
# true magnitude stays in each category's `count`; strong-strength hits are kept
# ahead of the cap so build_stride_dispatch_manifest still sees them.
_MAX_FINDINGS_PER_CATEGORY = 40


def _cap_category_findings(categories: dict[str, Any], cap: int) -> None:
    """Truncate each category's ``findings`` to ``cap`` in place, strong first.

    ``count`` is set by the scanners before this runs, so it keeps the true
    pre-cap total. A ``findings_truncated`` marker records how many were dropped.
    """
    for cat in categories.values():
        if not isinstance(cat, dict):
            continue
        findings = cat.get("findings")
        if not isinstance(findings, list) or len(findings) <= cap:
            continue
        ordered = sorted(
            findings,
            key=lambda f: 0 if isinstance(f, dict) and f.get("strength") == "strong" else 1,
        )
        cat["findings"] = ordered[:cap]
        cat["findings_truncated"] = len(findings) - cap


def run_all(
    repo_root: Path,
    include_manifest: bool = False,
) -> dict[str, Any]:
    _OVERSIZE_SKIPPED.clear()
    out: dict[str, Any] = {
        "version": 1,
        "repo_root": str(repo_root),
        "categories": {
            "9": scan_oauth_oidc(repo_root),
            "10": scan_spa_bff(repo_root),
            "11": scan_exposed_routes(repo_root),
            "13": scan_ai_integration(repo_root),
            "14": scan_ci_supply_chain(repo_root),
            "15": scan_container_images(repo_root),
            "17": scan_postinstall(repo_root),
            "18": scan_security_headers(repo_root),
            "19": scan_frontend_xss(repo_root),
            "20": scan_dom_xss(repo_root),
            "21": scan_client_secrets(repo_root),
            "22": scan_websocket(repo_root),
            "23": scan_postmessage(repo_root),
            "24": scan_client_routing(repo_root),
            "27": scan_gha_privileges(repo_root),
            "28": scan_ai_assistant_configs(repo_root),
            "29": scan_mobile_architecture(repo_root),
        },
    }
    _cap_category_findings(out["categories"], _MAX_FINDINGS_PER_CATEGORY)
    if include_manifest:
        manifest: list[str] = []
        # Re-walk once purely to collect the manifest; the per-category
        # scan functions already walked individually above.
        for _ in _walk_repo(repo_root, manifest=manifest):
            pass
        out["scan_manifest"] = sorted(manifest)
        out["scan_manifest_count"] = len(manifest)
    if _OVERSIZE_SKIPPED:
        out["skipped_oversize"] = sorted(_OVERSIZE_SKIPPED)
        out["skipped_oversize_count"] = len(_OVERSIZE_SKIPPED)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_DISPATCH = {
    "oauth-oidc": (scan_oauth_oidc, "Cat 9"),
    "spa-bff": (scan_spa_bff, "Cat 10"),
    "exposed-routes": (scan_exposed_routes, "Cat 11"),
    "ai-integration": (scan_ai_integration, "Cat 13"),
    "ci-supply-chain": (scan_ci_supply_chain, "Cat 14"),
    "container-images": (scan_container_images, "Cat 15"),
    "postinstall": (scan_postinstall, "Cat 17"),
    "security-headers": (scan_security_headers, "Cat 18"),
    "frontend-xss": (scan_frontend_xss, "Cat 19"),
    "dom-xss": (scan_dom_xss, "Cat 20"),
    "client-secrets": (scan_client_secrets, "Cat 21"),
    "websocket": (scan_websocket, "Cat 22"),
    "postmessage": (scan_postmessage, "Cat 23"),
    "client-routing": (scan_client_routing, "Cat 24"),
    "gha-privileges": (scan_gha_privileges, "Cat 27"),
    "ai-assistant-configs": (scan_ai_assistant_configs, "Cat 28"),
    "mobile-architecture": (scan_mobile_architecture, "Cat 29"),
}


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="recon_patterns.py", description=__doc__)
    p.add_argument(
        "command",
        choices=["all", *_DISPATCH.keys()],
        help="Scan to run",
    )
    p.add_argument("--repo-root", required=True, help="Repository to scan")
    p.add_argument(
        "--scan-manifest",
        action="store_true",
        default=False,
        help=(
            "Embed a sorted list of every scanned file (repo-relative paths) "
            "into the JSON output as 'scan_manifest'. Only valid with 'all'."
        ),
    )
    p.add_argument(
        "--manifest-file",
        metavar="PATH",
        default=None,
        help=(
            "Write the scan manifest as a plain newline-separated file to PATH "
            "in addition to (or instead of) embedding it in the JSON. "
            "Implies --scan-manifest. Only valid with 'all'."
        ),
    )
    args = p.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.is_dir():
        print(f"recon_patterns.py: repo-root not found: {repo_root}", file=sys.stderr)
        return 1

    include_manifest = args.scan_manifest or bool(args.manifest_file)

    if args.command == "all":
        out: dict[str, Any] = run_all(repo_root, include_manifest=include_manifest)
    else:
        if include_manifest:
            print(
                "recon_patterns.py: --scan-manifest / --manifest-file requires command 'all'",
                file=sys.stderr,
            )
            return 1
        fn, _ = _DISPATCH[args.command]
        out = fn(repo_root)

    if args.manifest_file and "scan_manifest" in out:
        manifest_path = Path(args.manifest_file)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("w", encoding="utf-8") as f:
            f.write("\n".join(out["scan_manifest"]))
            f.write("\n")

    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
