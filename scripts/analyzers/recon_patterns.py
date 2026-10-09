#!/usr/bin/env python3
"""
analyzers/recon_patterns.py — deterministic recon pattern scans.

Owns the pattern-only recon categories so the LLM-driven recon-scanner does
not grep for them. These are regex scans with no judgement involved; the
category set is the ``_DISPATCH`` table:

  Cat 9   OAuth / OIDC — redirect-flow and token-handling anti-patterns
  Cat 10  SPA / BFF — browser token and client-trust anti-patterns
  Cat 11  Exposed Routes — admin/debug/swagger/actuator endpoints
  Cat 13  AI / LLM Integration — genuine AI/LLM surface (a strong signal, or
          prompt construction co-located with another weak signal in one file)
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
  python3 analyzers/recon_patterns.py all             --repo-root <path>
  python3 analyzers/recon_patterns.py oauth-oidc      --repo-root <path>
  python3 analyzers/recon_patterns.py spa-bff         --repo-root <path>
  python3 analyzers/recon_patterns.py exposed-routes  --repo-root <path>
  python3 analyzers/recon_patterns.py ai-integration  --repo-root <path>
  python3 analyzers/recon_patterns.py ci-supply-chain --repo-root <path>
  python3 analyzers/recon_patterns.py container-images --repo-root <path>
  python3 analyzers/recon_patterns.py postinstall     --repo-root <path>
  python3 analyzers/recon_patterns.py security-headers --repo-root <path>
  python3 analyzers/recon_patterns.py frontend-xss    --repo-root <path>
  python3 analyzers/recon_patterns.py dom-xss         --repo-root <path>
  python3 analyzers/recon_patterns.py client-secrets  --repo-root <path>
  python3 analyzers/recon_patterns.py websocket       --repo-root <path>
  python3 analyzers/recon_patterns.py postmessage     --repo-root <path>
  python3 analyzers/recon_patterns.py client-routing  --repo-root <path>
  python3 analyzers/recon_patterns.py gha-privileges  --repo-root <path>
  python3 analyzers/recon_patterns.py ai-assistant-configs --repo-root <path>
  python3 analyzers/recon_patterns.py mobile-architecture --repo-root <path>

Scan manifest (only with 'all'):
  --scan-manifest               embed sorted file list in JSON as 'scan_manifest'
  --manifest-file <path>        write plain newline-separated file list to <path>
                                (implies --scan-manifest)

Exit codes:
  0 — success (JSON on stdout), regardless of finding count
  1 — hard error (missing repo, bad args)
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import fnmatch
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from runtime.agent_config_checks import classify_hook_command, classify_permission_rule, iter_hook_commands

# Try to load the central exclude policy. Fall back to a minimal built-in
# set if scan_excludes is unavailable — the script must not hard-fail when
# installed in a stripped-down plugin layout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    import analyzers.scan_excludes as scan_excludes

    _SCAN_EXCLUDES = True
except Exception:  # pragma: no cover
    _SCAN_EXCLUDES = False


# Repo-relative paths skipped this run because they exceed the central
# per-file byte cap (scan_excludes.max_file_bytes). Accumulated across every
# per-category walk, deduped, surfaced on stderr (once each) and in run_all's
# JSON. Cleared at the start of each run_all().
_OVERSIZE_SKIPPED: set[str] = set()


# ---------------------------------------------------------------------------
# Which files are scanned
# ---------------------------------------------------------------------------
# Every category reads the repository through _walk_repo (a few read fixed paths such as .github/workflows
# directly). A file is scanned when it survives the exclude policy below and looks like text. The policy is,
# in order: assessment artifacts are excluded; composite GitHub actions are kept; dependency and build trees
# (_HARD_EXCLUDE_*) are excluded; then data/scan-excludes.yaml decides, or _FALLBACK_DIRS when it is missing.
# discover_identity_providers.py and embedded_store_access.py walk the repository through _walk_repo too.

# Default fallback excludes when scan_excludes.yaml is unavailable.
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
    # Files without one of these extensions (Dockerfile, Jenkinsfile, ...) are matched by name in _should_read.
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
        # Served remediation/tutorial snippets contain deliberately vulnerable
        # before/after code and are evidence about a solution guide, not the
        # runtime application. Source-auth uses the same scanner-local rule.
        "codefixes",
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


def _is_excluded(rel_path: str, repo_root: Path | None = None) -> bool:
    if _SCAN_EXCLUDES and repo_root is not None:
        try:
            if scan_excludes.is_assessment_artifact(rel_path, repo_root):
                return True
        except Exception:
            pass
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
        dirnames[:] = [d for d in dirnames if not _is_excluded(f"{rel_dir}/{d}" if rel_dir != "." else d, repo_root)]
        for name in filenames:
            rel = str((Path(dirpath) / name).relative_to(repo_root)).replace("\\", "/")
            if _is_excluded(rel, repo_root):
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
                        f"analyzers/recon_patterns.py: skipped oversize file "
                        f"({sz} bytes > cap {scan_excludes.max_file_bytes()}): {rel}",
                        file=sys.stderr,
                    )
                continue
            if manifest is not None:
                manifest.append(rel)
            yield p


# A matched line is evidence, not content: minified bundles put a whole file on one line, so every quoted
# line is cut to this many characters.
_MAX_MATCH_CHARS = 400


def _clip_line(line: str) -> str:
    """The line without its line break, cut to _MAX_MATCH_CHARS with a trailing ellipsis."""
    stripped = line.rstrip("\r\n")
    if len(stripped) > _MAX_MATCH_CHARS:
        stripped = stripped[:_MAX_MATCH_CHARS] + "…"
    return stripped


def _rel(path: Path, repo_root: Path) -> str:
    """Repository-relative path with forward slashes, as every finding's ``file`` field carries it."""
    return str(path.relative_to(repo_root)).replace("\\", "/")


def _read_lines(path: Path) -> list[str] | None:
    """The file's lines, or ``None`` when it cannot be read; undecodable bytes are replaced."""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _source_files(repo_root: Path, exts: set[str] | None = None) -> Iterable[tuple[Path, str, list[str]]]:
    """(path, rel, lines) for every scanned file whose suffix is in ``exts`` (all files when ``None``)."""
    for p in _walk_repo(repo_root):
        if exts is not None and p.suffix.lower() not in exts:
            continue
        lines = _read_lines(p)
        if lines is not None:
            yield p, _rel(p, repo_root), lines


def _workflow_files(repo_root: Path) -> list[tuple[Path, list[str]]]:
    """(path, lines) of every readable GitHub Actions workflow, sorted by name; [] without .github/workflows.

    Read directly rather than through _walk_repo, so workflows are checked even where scan excludes apply.
    """
    wf_dir = repo_root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    out = []
    for p in sorted(wf_dir.iterdir()):
        if p.suffix.lower() not in {".yml", ".yaml"} or not p.is_file():
            continue
        lines = _read_lines(p)
        if lines is not None:
            out.append((p, lines))
    return out


def _category_result(category: int, name: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    """The per-category document every scanner returns; ``count`` is the uncapped total."""
    return {"category": category, "name": name, "findings": findings, "count": len(findings)}


def _scan_pattern_category(
    repo_root: Path,
    category: int,
    name: str,
    pattern: re.Pattern[str],
    exts: set[str] | None = None,
) -> dict[str, Any]:
    """A category whose findings are just the lines matching one pattern, without subcategory or severity."""
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if exts is not None and p.suffix.lower() not in exts:
            continue
        rel = _rel(p, repo_root)
        for line_no, text in _grep_file(p, pattern):
            findings.append({"category": category, "file": rel, "line": line_no, "match": text.strip()})
    return _category_result(category, name, findings)


def _grep_file(path: Path, pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    """Return (line_no, line_text) for every line in `path` matching `pattern`."""
    out: list[tuple[int, str]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, start=1):
                if pattern.search(line):
                    out.append((n, _clip_line(line)))
    except OSError:
        pass
    return out


def _line_hits(lines: list[str], pattern: re.Pattern[str]) -> list[tuple[int, str]]:
    """(line_no, clipped and stripped text) for every line matching ``pattern``."""
    return [(n, _clip_line(line).strip()) for n, line in enumerate(lines, start=1) if pattern.search(line)]


def _first_hit(hits: list[tuple[int, str]], fallback: list[tuple[int, str]]) -> tuple[int, str]:
    """The line a file-level finding points at: the first hit, else the first fallback hit."""
    return hits[0] if hits else fallback[0]


# ---------------------------------------------------------------------------
# Category 9 — OAuth / OIDC
# ---------------------------------------------------------------------------
# Detects: files that use OAuth/OIDC (surface), then RFC 9700 / OIDC Core anti-patterns in those files —
# implicit flow, code flow without PKCE or with plain PKCE, missing state or nonce, ID tokens without claim
# validation, refresh tokens in browser storage, the password grant, client secrets in frontend code,
# HTTP or loosely matched redirect URIs, static state/nonce values, and credentials derived from identity claims.
# False-positive limits: a check runs only in a file that already shows an OAuth/OIDC surface, and every
# "missing X" check looks for X anywhere in the same file, so a marker in the file suppresses the finding.


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
    r"#(?:access_token|id_token)=|location\.hash[^\n]*(?:access_token|id_token))"
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
_CAT9_DERIVED_CREDENTIAL = re.compile(
    r"(?i)\b(?:password|passwd|credential)\w*\s*[:=]\s*"
    r"(?:btoa\s*\(|Buffer\.from\s*\([^\n]{0,180}?\)\.toString\s*\(\s*['\"]base64['\"]|"
    r"base64(?:url)?(?:encode|_encode)\s*\()[^\n]{0,240}?"
    r"(?:email|e-mail|username|user_name|profile\.(?:email|name)|claims?\.(?:email|sub))"
)


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


def _oauth_surface_checks(
    findings: list[dict[str, Any]], rel: str, lines: list[str], surface_hits: list[tuple[int, str]]
) -> None:
    """Record the OAuth/OIDC surface and identity-derived local credentials."""
    _add_cat9(
        findings,
        rel=rel,
        subcategory="oauth-oidc-surface",
        severity="Info",
        line=surface_hits[0][0],
        match=surface_hits[0][1],
        evidence="OAuth/OIDC-related token, endpoint, SDK, or config pattern present",
    )

    # A reversible transform of an identity claim is not a password
    # generator. Keep this deliberately narrow: the assignment target must
    # be credential-like, the transform must be reversible encoding (not a
    # password KDF), and the input must be a user identity attribute in the
    # same source line. Test/spec/fixture paths are already excluded by the
    # repository walker. This is a review signal with exact file/line
    # evidence; the STRIDE analyzer still establishes reachability.
    for n, line in _line_hits(lines, _CAT9_DERIVED_CREDENTIAL):
        _add_cat9(
            findings,
            rel=rel,
            subcategory="oauth-derived-user-credential",
            severity="High",
            line=n,
            match=line,
            evidence="OAuth-local credential is predictably derived from a user identity attribute with reversible encoding",
        )
        findings[-1].update(
            {
                "cwe": "CWE-522",
                "finding_type": "credential-management-candidate",
                "false_positive_exclusions": "cryptographic password KDFs, random credentials, and excluded test/spec/fixture paths",
            }
        )


def _oauth_flow_checks(
    findings: list[dict[str, Any]],
    rel: str,
    lines: list[str],
    text: str,
    surface_hits: list[tuple[int, str]],
    frontend_like: bool,
) -> list[tuple[int, str]]:
    """Check implicit flow, PKCE, state, nonce, and ID-token claim validation."""
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
        line, match = _first_hit(_line_hits(lines, _CAT9_AUTH_REQUEST), surface_hits)
        _add_cat9(
            findings,
            rel=rel,
            subcategory="oauth-missing-state",
            severity="High",
            line=line,
            match=match,
            evidence="OAuth authorization request pattern without state marker in the same file",
        )

    id_token_flow = bool(_CAT9_ID_TOKEN_FLOW.search(text))
    if id_token_flow and not _CAT9_NONCE_TOKEN.search(text):
        line, match = _first_hit(_line_hits(lines, _CAT9_ID_TOKEN_FLOW), surface_hits)
        _add_cat9(
            findings,
            rel=rel,
            subcategory="oidc-missing-nonce",
            severity="High",
            line=line,
            match=match,
            evidence="OIDC id_token/openid flow without nonce marker in the same file",
        )

    if id_token_flow and _CAT9_CLAIM_CONTEXT.search(text) and not _CAT9_CLAIM_VALIDATION.search(text):
        line, match = _first_hit(_line_hits(lines, _CAT9_ID_TOKEN_FLOW), surface_hits)
        _add_cat9(
            findings,
            rel=rel,
            subcategory="oidc-claim-validation-gap",
            severity="High",
            line=line,
            match=match,
            evidence="OIDC token handling without issuer/audience/JWKS/nonce validation markers in the same file",
        )
    return code_hits


def _oauth_token_and_redirect_checks(
    findings: list[dict[str, Any]], rel: str, lines: list[str], frontend_like: bool
) -> None:
    """Check refresh-token storage, ROPC, client secrets, redirect URIs, and static state."""
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


def _oauth_pkce_s256_check(
    findings: list[dict[str, Any]], rel: str, lines: list[str], text: str, code_hits: list[tuple[int, str]]
) -> None:
    """Check that PKCE on a code flow uses S256."""
    if _CAT9_PKCE_PRESENT.search(text) and not _CAT9_PKCE_S256.search(text) and _CAT9_CODE_FLOW.search(text):
        line, match = _first_hit(_line_hits(lines, _CAT9_PKCE_PRESENT), code_hits)
        _add_cat9(
            findings,
            rel=rel,
            subcategory="oauth-pkce-s256-not-evident",
            severity="Medium",
            line=line,
            match=match,
            evidence="PKCE markers found on code flow but S256 is not evident in the same file",
        )


def scan_oauth_oidc(repo_root: Path) -> dict[str, Any]:
    """Detect OAuth/OIDC surfaces and common security anti-patterns.

    This is intentionally a signal scanner, not a full protocol verifier. It
    finds high-value review candidates from RFC 9700 / OIDC Core: no implicit
    token response, PKCE/S256 on code flows, state/nonce, exact redirect checks,
    no ROPC, no browser refresh tokens, and validated ID-token claims.
    """
    findings: list[dict[str, Any]] = []

    for _, rel, lines in _source_files(repo_root, _CAT9_EXTS):
        surface_hits = _line_hits(lines, _CAT9_SURFACE)
        if not surface_hits:
            continue
        text = "\n".join(lines)

        _oauth_surface_checks(findings, rel, lines, surface_hits)

        # Browser code cannot keep a secret, so some checks weigh heavier when the path looks like frontend code.
        frontend_like = bool(_CAT9_FRONTEND_HINT.search(rel))
        code_hits = _oauth_flow_checks(findings, rel, lines, text, surface_hits, frontend_like)
        _oauth_token_and_redirect_checks(findings, rel, lines, frontend_like)
        _oauth_pkce_s256_check(findings, rel, lines, text, code_hits)

    return _category_result(9, "OAuth / OIDC", findings)


# ---------------------------------------------------------------------------
# Category 11 — Exposed routes
# ---------------------------------------------------------------------------
# Detects: route strings of admin, debug, test, metrics, health and API-documentation endpoints in source code.
# A hit is a route string, not a confirmed endpoint: reachability and protection are not judged here.
# False-positive limits: path fragments need a non-word character before the slash (see below), and only
# source-code extensions are read.


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
    """Grep source files for debug, admin, actuator and API-doc route fragments (Cat 11)."""
    return _scan_pattern_category(repo_root, 11, "Exposed Routes", _CAT11_PATTERN, _CAT11_EXTS)


# ---------------------------------------------------------------------------
# Category 14 — CI/CD supply chain
# ---------------------------------------------------------------------------
# Detects: GitHub Actions `uses:` references that are not pinned to a full commit SHA, and every `image:`
# directive in a root .gitlab-ci.yml (listed for review; tags are not judged here).
# False-positive exclusions: SHA-pinned actions and local `./` actions. Only .github/workflows is read, so
# composite actions elsewhere are not checked.


# `uses: owner/name@ref` where ref is NOT a 40-char hex SHA.
# Lines typically start with `- uses:` (YAML list item) but may also appear
# as plain `uses:` inside a composite-action step. Match both.
_CAT14_UNPINNED_ACTION = re.compile(r"^(?P<indent>\s*-?\s*)uses:\s*(?P<ref>[^\s#@]+@(?P<tag>[^\s#]+))")
_SHA40 = re.compile(r"^[0-9a-f]{40}$")

# GitLab CI `image: foo:bar` directive (informational — non-pinned tags)
_CAT14_GITLAB_IMAGE = re.compile(r"^\s*image:\s*(?P<image>[^\s#]+)", re.MULTILINE)


def scan_ci_supply_chain(repo_root: Path) -> dict[str, Any]:
    """Flag GitHub Actions `uses:` refs not pinned to a 40-char SHA, and GitLab CI `image:` lines (Cat 14).

    Only `.github/workflows` and a root `.gitlab-ci.yml` are read; local `./` actions are skipped.
    """
    findings: list[dict[str, Any]] = []

    for p, lines in _workflow_files(repo_root):
        for n, line in enumerate(lines, start=1):
            m = _CAT14_UNPINNED_ACTION.match(line)
            if not m or _SHA40.match(m.group("tag")) or m.group("ref").startswith("./"):
                continue
            findings.append(
                {
                    "category": 14,
                    "subcategory": "unpinned-github-action",
                    "file": _rel(p, repo_root),
                    "line": n,
                    "action": m.group("ref"),
                    "tag": m.group("tag"),
                    "match": line.strip(),
                }
            )

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

    return _category_result(14, "CI/CD Supply Chain", findings)


# ---------------------------------------------------------------------------
# Category 15 — Container base images
# ---------------------------------------------------------------------------
# Detects: Dockerfile `FROM` and docker-compose `image:` references that are not pinned to a digest, graded as
# missing tag, `latest`, or tag without digest.
# False-positive exclusions: `scratch` and `@sha256:` references. Compose files are recognised only by the
# `docker-compose*` name; `compose.yaml` is not read here.


_CAT15_FROM = re.compile(r"^\s*FROM\s+(?P<image>[^\s#]+)", re.IGNORECASE)
_CAT15_COMPOSE_IMAGE = re.compile(r"^\s*image:\s*(?P<image>[^\s#]+)", re.IGNORECASE)


def _container_image_issue(image: str) -> str | None:
    """The pinning gap of an image reference, or ``None`` when it is digest-pinned or ``scratch``."""
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
    """Flag Dockerfile `FROM` and compose `image:` refs without a `@sha256` digest (Cat 15)."""
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        rel = _rel(p, repo_root)
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
    return _category_result(15, "Container Base Images", findings)


# ---------------------------------------------------------------------------
# Category 17 — Postinstall scripts
# ---------------------------------------------------------------------------
# Detects: code that runs at install time — npm lifecycle scripts in any package.json, an `ignore-scripts`
# setting in the root .npmrc (listed whatever its value), and shell calls or a custom `cmdclass` in setup.py.
# False-positive exclusions: package.json and setup.py files under excluded paths (dependency trees, tests).


_CAT17_NPM_LIFECYCLE_KEYS = ("preinstall", "postinstall", "prepare", "prebuild", "postpublish")
_CAT17_SETUP_PY_SHELL = re.compile(
    r"(?:cmdclass\s*=|install_requires.*subprocess|os\.system\s*\(|subprocess\.(?:run|call|Popen))"
)


def scan_postinstall(repo_root: Path) -> dict[str, Any]:
    """Collect install-time code execution: npm lifecycle scripts, `ignore-scripts` in the root
    `.npmrc`, and shell calls or `cmdclass` in `setup.py` (Cat 17).
    """
    findings: list[dict[str, Any]] = []

    for p in repo_root.rglob("package.json"):
        rel = _rel(p, repo_root)
        if _is_excluded(rel, repo_root):
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

    npmrc = repo_root / ".npmrc"
    npmrc_lines = _read_lines(npmrc) if npmrc.is_file() else None
    for n, line in enumerate(npmrc_lines or [], start=1):
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

    for p in repo_root.rglob("setup.py"):
        rel = _rel(p, repo_root)
        if _is_excluded(rel, repo_root):
            continue
        for line_no, text in _grep_file(p, _CAT17_SETUP_PY_SHELL):
            findings.append(
                {
                    "category": 17,
                    "subcategory": "python-setup-shell",
                    "file": rel,
                    "line": line_no,
                    "match": text.strip(),
                }
            )

    return _category_result(17, "Postinstall Scripts", findings)


# ---------------------------------------------------------------------------
# Category 18 — Security headers & CORS
# ---------------------------------------------------------------------------
# Detects: where security headers, Helmet and CORS are configured. This is an inventory of present
# configuration, not a weakness list: a missing header and a permissive CORS value are not reported here.


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
    """Grep for security-header, Helmet and CORS configuration lines (Cat 18).

    Hits mark where headers are set; a missing header is not reported here.
    """
    return _scan_pattern_category(repo_root, 18, "Security Headers & CORS", _CAT18_PATTERN, _CAT18_EXTS)


# ---------------------------------------------------------------------------
# Categories 10, 19–24 — frontend/client runtime patterns
# ---------------------------------------------------------------------------
# What runs in the browser and therefore cannot be trusted: tokens in browser storage and client-side role
# checks (10), unsafe HTML sinks (19), DOM XSS sources and sinks (20), secrets shipped in client bundles (21),
# WebSocket endpoints (22), postMessage and iframe use (23), and client-side route guards (24).
# Each category first records a low-severity "surface" finding per hit, then raises a candidate when a
# protective marker (sanitizer, origin check, auth or server call) is missing from the same file. These markers
# are judged per file, not per call site, so a marker anywhere in the file suppresses the candidate.


_CLIENT_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm"}
# WebSocket servers also live in backend languages.
_CAT22_EXTS = _CLIENT_EXTS | {".py", ".go", ".java", ".kt", ".cs"}

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
_CAT21_BUNDLED_CREDENTIAL = re.compile(
    r"(?i)\b(?P<name>(?:test(?:ing)?|demo|default|shared|sample)[_-]?"
    r"(?:password|passwd|credential|secret))\b\s*[:=]\s*['\"](?P<value>[^'\"\r\n]{8,})['\"]"
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
    """Append a frontend finding; ``extra`` adds fields such as ``anti_pattern`` after the common ones."""
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


def scan_spa_bff(repo_root: Path) -> dict[str, Any]:
    """Flag browser-stored tokens, `withCredentials` use and client-side role checks (Cat 10).

    Adds one `spa-without-bff-candidate` finding when tokens sit in browser storage and no BFF or
    server-session marker appears in any scanned file.
    """
    findings: list[dict[str, Any]] = []
    token_hits: list[dict[str, Any]] = []
    credentials_hits: list[dict[str, Any]] = []
    bff_seen = False

    # Every file is read, because a BFF or server-session marker in backend code also counts;
    # only client files are checked for the anti-patterns themselves.
    for p, rel, lines in _source_files(repo_root):
        if _CAT10_BFF.search("\n".join(lines)):
            bff_seen = True
        if p.suffix.lower() not in _CLIENT_EXTS:
            continue

        for n, line in _line_hits(lines, _CAT10_TOKEN_STORAGE):
            refresh = _CAT10_REFRESH_STORAGE.search(line)
            _add_client_finding(
                findings,
                category=10,
                rel=rel,
                subcategory="spa-refresh-token-browser-storage" if refresh else "spa-token-browser-storage",
                severity="High",
                line=n,
                match=line,
                evidence="Session credential appears in browser-accessible storage",
                anti_pattern="JWT in localStorage",
            )
            token_hits.append(findings[-1])

        for n, line in _line_hits(lines, _CAT10_CREDENTIALS):
            _add_client_finding(
                findings,
                category=10,
                rel=rel,
                subcategory="spa-withcredentials-surface",
                severity="Info",
                line=n,
                match=line,
                evidence="Browser credentialed request mode is used",
            )
            credentials_hits.append(findings[-1])

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

    return _category_result(10, "SPA / BFF", findings)


def _package_json_line(path: Path, dependency: str) -> int | None:
    """Line of the first occurrence of the quoted dependency name in a package.json."""
    quoted = f'"{dependency}"'
    return next((n for n, line in enumerate(_read_lines(path) or [], start=1) if quoted in line), None)


def scan_frontend_xss(repo_root: Path) -> dict[str, Any]:
    """Record frontend frameworks from `package.json` and unsafe HTML sinks in client code (Cat 19).

    A sink is High unless a sanitizer marker appears in the same file; sanitizer bypass APIs are
    always High.
    """
    findings: list[dict[str, Any]] = []

    for p in repo_root.rglob("package.json"):
        rel = _rel(p, repo_root)
        if _is_excluded(rel, repo_root):
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

    for _, rel, lines in _source_files(repo_root, _CLIENT_EXTS):
        has_strong_sanitizer = bool(_CAT19_STRONG_SANITIZER.search("\n".join(lines)))
        for n, line in _line_hits(lines, _CAT19_UNSAFE_HTML):
            subcat, severity, evidence, anti_pattern = _html_sink_verdict(line, has_strong_sanitizer)
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

    return _category_result(19, "Frontend Framework & XSS Patterns", findings)


def _html_sink_verdict(line: str, has_strong_sanitizer: bool) -> tuple[str, str, str, str | None]:
    """(subcategory, severity, evidence, anti_pattern) for one unsafe-HTML line.

    A sanitizer bypass API is High even next to a sanitizer; an Angular DomSanitizer reference is only a surface.
    """
    if re.search(r"(?i)bypassSecurityTrust", line):
        return (
            "frontend-sanitizer-bypass",
            "High",
            "Framework sanitizer bypass API is used",
            "Sanitizer bypass by default",
        )
    if re.search(r"(?i)\bDomSanitizer\b", line):
        evidence = "Angular DomSanitizer API is referenced; verify it is not used as a default bypass"
        return "frontend-sanitizer-api-surface", "Info", evidence, None
    if has_strong_sanitizer:
        evidence = "Unsafe HTML sink is present with sanitizer markers in the same file"
        return "frontend-html-sink-with-sanitizer", "Info", evidence, None
    evidence = "Unsafe HTML rendering sink is present without sanitizer markers in the same file"
    return "frontend-unsafe-html-sink", "High", evidence, "Sanitizer bypass by default"


def scan_dom_xss(repo_root: Path) -> dict[str, Any]:
    """Record DOM XSS sources and one High candidate per file that holds both a source and a sink (Cat 20)."""
    findings: list[dict[str, Any]] = []
    for _, rel, lines in _source_files(repo_root, _CLIENT_EXTS):
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
    return _category_result(20, "DOM-Based XSS Sources", findings)


def scan_client_secrets(repo_root: Path) -> dict[str, Any]:
    """Grep client code for secret patterns and shared credential literals, redacted to 4 chars (Cat 21)."""
    findings = _scan_pattern_category(repo_root, 21, "Client-Side Secrets", _CAT21_PATTERN)["findings"]
    for path in _walk_repo(repo_root):
        if path.suffix.lower() not in _CLIENT_EXTS:
            continue
        rel = path.relative_to(repo_root).as_posix()
        for line_no, line in enumerate(_read_lines(path) or [], start=1):
            match = _CAT21_BUNDLED_CREDENTIAL.search(line)
            if not match:
                continue
            # Never copy a secret into the evidence: keep four characters and the length.
            value = match.group("value")
            redacted = value[:4] + "****" if value else "****"
            _add_client_finding(
                findings,
                category=21,
                rel=rel,
                subcategory="client-bundled-shared-credential",
                severity="High",
                line=line_no,
                match=f"{match.group('name')} = {redacted} ({len(value)} chars)",
                evidence="A reusable test/demo/shared credential literal is shipped in executable client source",
                cwe="CWE-798",
                finding_type="configuration-defect-candidate",
                false_positive_exclusions="empty or short placeholders and excluded test/spec/fixture paths",
            )
    return _category_result(21, "Client-Side Secrets", findings)


def scan_websocket(repo_root: Path) -> dict[str, Any]:
    """Record WebSocket surfaces, cleartext `ws://` URLs, and server sockets with no auth or origin
    marker in the same file (Cat 22).
    """
    findings: list[dict[str, Any]] = []
    for _, rel, lines in _source_files(repo_root, _CAT22_EXTS):
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
        # Authentication and origin checks belong to the server side of a socket; a client file is not judged.
        server_side = bool(surface_hits) and bool(_CAT22_SERVER_SOCKET.search(text))
        if server_side and not _CAT22_AUTH.search(text):
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
        if server_side and not _CAT22_ORIGIN.search(text):
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
    return _category_result(22, "WebSocket & Real-Time", findings)


def scan_postmessage(repo_root: Path) -> dict[str, Any]:
    """Flag postMessage, message-listener, iframe and window-opener weaknesses in client code (Cat 23).

    Origin-check and sandbox absence are judged per file, not per call site.
    """
    findings: list[dict[str, Any]] = []
    for _, rel, lines in _source_files(repo_root, _CLIENT_EXTS):
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
            # The window.open lookahead follows a greedy match and excludes nothing; this line check does.
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
    return _category_result(23, "postMessage & iframe", findings)


def scan_client_routing(repo_root: Path) -> dict[str, Any]:
    """Record client-side route guards and flag those that trust browser-held roles or lack a
    same-file server authority marker (Cat 24).
    """
    findings: list[dict[str, Any]] = []
    for _, rel, lines in _source_files(repo_root, _CLIENT_EXTS):
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
    return _category_result(24, "Client-Side Routing & Auth Guards", findings)


# ---------------------------------------------------------------------------
# Category 29 — Mobile App Architecture & Platform Config
# ---------------------------------------------------------------------------
# Detects: Android manifest flags (debuggable, backup, cleartext), exported components without a permission,
# unverified deep links, weak network security configs, risky WebView, storage and TLS code on Android and iOS,
# and iOS App Transport Security exceptions and URL schemes.
# A file is classified as Android or iOS by its name, its path (/android/, /ios/) or platform API markers; code
# checks run only on files of that platform, so web code that mentions "WebView" in passing is the main
# false-positive risk. Each classified file also gets one leading `mobile-app-surface` Info finding.


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

# Line rules: (pattern, subcategory, severity, evidence, anti_pattern). Every matching line becomes one finding,
# rule by rule in table order, so reordering a table reorders the findings.
_MobileRule = tuple[re.Pattern[str], str, str, str, str]

_ANDROID_MANIFEST_FLAG_RULES: tuple[_MobileRule, ...] = (
    (
        _ANDROID_DEBUGGABLE,
        "android-debuggable-enabled",
        "High",
        "Android manifest enables debuggable runtime",
        "Mobile debug build shipped",
    ),
    (
        _ANDROID_ALLOW_BACKUP,
        "android-allowbackup-enabled",
        "Medium",
        "Android app data backup is enabled in the manifest",
        "Mobile client stores sensitive state without platform hardening",
    ),
    (
        _ANDROID_CLEARTEXT,
        "android-cleartext-traffic-enabled",
        "High",
        "Android manifest permits cleartext network traffic",
        "Mobile cleartext network policy",
    ),
)

_ANDROID_NETWORK_CONFIG_RULES: tuple[_MobileRule, ...] = (
    (
        _ANDROID_NETWORK_CLEAR,
        "android-network-config-cleartext",
        "High",
        "Android network security config permits cleartext traffic",
        "Mobile cleartext network policy",
    ),
    (
        _ANDROID_USER_CA,
        "android-user-ca-trusted",
        "Medium",
        "Android network security config trusts user-installed CAs",
        "Mobile TLS trust weakened",
    ),
    (
        _ANDROID_DEBUG_OVERRIDES,
        "android-debug-overrides",
        "Medium",
        "Android debug network trust overrides are present",
        "Mobile debug trust override",
    ),
)

_ANDROID_CODE_RULES: tuple[_MobileRule, ...] = (
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
)

_IOS_CODE_RULES: tuple[_MobileRule, ...] = (
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
)

# Info.plist booleans are a <key> line followed by a <true/> line, so they are matched by key, not by pattern:
# (key, subcategory, severity, evidence, anti_pattern).
_IOS_PLIST_TRUE_KEY_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "NSAllowsArbitraryLoads",
        "ios-ats-arbitrary-loads",
        "High",
        "iOS App Transport Security allows arbitrary loads",
        "Mobile cleartext network policy",
    ),
    (
        "NSExceptionAllowsInsecureHTTPLoads",
        "ios-ats-insecure-exception",
        "High",
        "iOS ATS exception permits insecure HTTP loads",
        "Mobile cleartext network policy",
    ),
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


def _add_mobile_rule_hits(
    findings: list[dict[str, Any]], rel: str, lines: list[str], rules: tuple[_MobileRule, ...], platform: str
) -> None:
    """One finding per line that a rule's pattern matches, rule by rule."""
    for pattern, subcat, severity, evidence, anti_pattern in rules:
        for n, line in _line_hits(lines, pattern):
            _add_mobile(
                findings,
                rel=rel,
                subcategory=subcat,
                severity=severity,
                line=n,
                match=line,
                evidence=evidence,
                platform=platform,
                anti_pattern=anti_pattern,
            )


def _android_component_blocks(lines: list[str]) -> list[tuple[int, str]]:
    """(start line, joined text) of each <activity|service|receiver|provider> opening tag, which may span lines.

    The tag ends at the first line holding ``>``, so an attribute value containing ``>`` ends it early.
    """
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
    """(line of <key>, "<key>… <true/>") for each occurrence of ``key`` whose next non-blank line is <true/>."""
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


def _mobile_platform(p: Path, lower_rel: str, text: str) -> tuple[bool, bool]:
    """Classify a file as Android and/or iOS source."""
    is_android = (
        p.name == "AndroidManifest.xml"
        or "network_security_config" in lower_rel
        or "/android/" in f"/{lower_rel}"
        or bool(_ANDROID_MANIFEST_SURFACE.search(text))
        or bool(_ANDROID_CODE_HINT.search(text))
    )
    is_ios = (
        p.name == "Info.plist" or "/ios/" in f"/{lower_rel}" or "CFBundle" in text or bool(_IOS_CODE_HINT.search(text))
    )
    return is_android, is_ios


def _mobile_android_manifest(findings: list[dict[str, Any]], rel: str, lines: list[str], text: str) -> None:
    """Check AndroidManifest.xml flags, exported components, and deep links."""
    _add_mobile_rule_hits(findings, rel, lines, _ANDROID_MANIFEST_FLAG_RULES, "Android")
    for start, block in _android_component_blocks(lines):
        if _ANDROID_EXPORTED_TRUE.search(block) and not _ANDROID_PERMISSION.search(block):
            _add_mobile(
                findings,
                rel=rel,
                subcategory="android-exported-component-without-permission",
                severity="High",
                line=start,
                match=block[:_MAX_MATCH_CHARS],
                evidence="Exported Android component lacks an explicit permission in the component declaration",
                platform="Android",
                anti_pattern="Mobile IPC boundary exposed",
            )
    # A custom scheme can be claimed by any app; an http(s) app link is OS-verified only with autoVerify.
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


def _mobile_network_security_config(findings: list[dict[str, Any]], rel: str, lines: list[str]) -> None:
    """Check an Android network security config for cleartext and weakened trust."""
    _add_mobile_rule_hits(findings, rel, lines, _ANDROID_NETWORK_CONFIG_RULES, "Android")


def _mobile_android_code(findings: list[dict[str, Any]], rel: str, lines: list[str]) -> None:
    """Check Android code for WebView, storage, TLS, and build hardening gaps."""
    _add_mobile_rule_hits(findings, rel, lines, _ANDROID_CODE_RULES, "Android")


def _mobile_info_plist(findings: list[dict[str, Any]], rel: str, lines: list[str]) -> None:
    """Check Info.plist for ATS exceptions and custom URL schemes."""
    for key, subcat, severity, evidence, anti_pattern in _IOS_PLIST_TRUE_KEY_RULES:
        for n, line in _plist_true_key_hits(lines, key):
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


def _mobile_ios_code(findings: list[dict[str, Any]], rel: str, lines: list[str]) -> None:
    """Check iOS code for WebView bridges, token storage, TLS, and associated domains."""
    _add_mobile_rule_hits(findings, rel, lines, _IOS_CODE_RULES, "iOS")


def scan_mobile_architecture(repo_root: Path) -> dict[str, Any]:
    """Flag Android manifest and network-config weaknesses and iOS ATS and URL-scheme settings (Cat 29).

    Each file classified as Android or iOS also yields one leading `mobile-app-surface` Info finding.
    """
    findings: list[dict[str, Any]] = []
    surface_files: dict[str, str] = {}

    for p in _walk_repo(repo_root):
        rel = _rel(p, repo_root)
        if p.suffix.lower() not in _MOBILE_EXTS and p.name not in {"AndroidManifest.xml", "Info.plist"}:
            continue
        lines = _read_lines(p)
        if lines is None:
            continue
        text = "\n".join(lines)
        lower_rel = rel.lower()
        is_android, is_ios = _mobile_platform(p, lower_rel, text)
        if is_android:
            surface_files[rel] = "Android"
        elif is_ios:
            surface_files[rel] = "iOS"

        if p.name == "AndroidManifest.xml":
            _mobile_android_manifest(findings, rel, lines, text)

        if p.name == "network_security_config.xml" or "network_security_config" in lower_rel:
            _mobile_network_security_config(findings, rel, lines)

        if is_android:
            _mobile_android_code(findings, rel, lines)

        if p.name == "Info.plist":
            _mobile_info_plist(findings, rel, lines)

        if is_ios:
            _mobile_ios_code(findings, rel, lines)

    # Inserting each surface row at the front in sorted order leaves them first, in reverse path order.
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

    return _category_result(29, "Mobile App Architecture & Platform Config", findings)


# ---------------------------------------------------------------------------
# Category 27 — GitHub Actions workflow privilege hardening
# ---------------------------------------------------------------------------
# Detects: `pull_request_target` triggers, `write-all` and per-scope `write` permissions, self-hosted runners,
# and workflows without any `permissions:` block (they inherit the repository default token scope).
# The checks are line-based: a `permissions:` key at any level counts as a block, and the trigger is found by its
# key name, so a flow-style `on: [pull_request_target]` is not detected.


_CAT27_PERMISSIONS_WRITE = re.compile(
    r"^\s*(?P<scope>contents|packages|pages|id-token|actions|deployments|security-events|statuses|checks|issues|pull-requests):\s*write\s*$",
    re.IGNORECASE,
)
_CAT27_SELF_HOSTED = re.compile(r"^\s*runs-on\s*:.*self-hosted", re.IGNORECASE)


def scan_gha_privileges(repo_root: Path) -> dict[str, Any]:
    """Flag `pull_request_target`, write permissions, self-hosted runners and workflows without a
    `permissions:` block in `.github/workflows` (Cat 27).
    """
    findings: list[dict[str, Any]] = []

    for p, lines in _workflow_files(repo_root):
        rel = _rel(p, repo_root)
        has_permissions = False
        for n, line in enumerate(lines, start=1):
            stripped = line.strip()
            if re.match(r"^pull_request_target\s*:", stripped):
                findings.append(_cat27_finding("pull-request-target", rel, n, stripped))
            if re.match(r"^permissions\s*:", stripped):
                has_permissions = True
                if re.search(r":\s*write-all\s*$", stripped, re.IGNORECASE):
                    findings.append(_cat27_finding("permissions-write-all", rel, n, stripped))
            m_perm = _CAT27_PERMISSIONS_WRITE.match(line)
            if m_perm:
                findings.append(_cat27_finding("permissions-write", rel, n, stripped, scope=m_perm.group("scope")))
            if _CAT27_SELF_HOSTED.match(line):
                findings.append(_cat27_finding("self-hosted-runner", rel, n, stripped))
        if not has_permissions:
            findings.append(_cat27_finding("missing-permissions-block", rel, None, "no permissions block"))

    return _category_result(27, "GitHub Actions Workflow Privilege Hardening", findings)


def _cat27_finding(subcategory: str, rel: str, line: int | None, match: str, **extra: Any) -> dict[str, Any]:
    return {"category": 27, "subcategory": subcategory, "file": rel, "line": line, **extra, "match": match}


# ---------------------------------------------------------------------------
# Category 28 — AI coding assistant & IDE agent configurations
# ---------------------------------------------------------------------------
# Committed assistant configuration runs with every contributor's privileges, so it is a supply-chain surface.
# Detects: which assistant config files exist (inventory), MCP servers that are remote, fetched from a public
# registry, carry hardcoded secrets, are auto-approved or trusted, Claude Code permission rules and hooks that
# grant too much (graded in runtime/agent_config_checks.py), agent files that grant shell or write tools, and
# prompt-injection payloads in instruction files.
# Only the fixed paths and directories below are read, plus every mcp.json; excluded paths are skipped.


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
    ".codex/config.toml",
    ".gemini/settings.json",
    ".kiro/settings/mcp.json",
    # `.vscode/` stays scan-excluded; the deterministic agent_config checks in
    # data/config-iac-checks.yaml own the VS Code agent-mode settings.
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
    ".codex",
    ".gemini",
    ".kiro/steering",
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

_AI_AGENT_DIR_MARKERS = (
    (".claude", "agents"),
    (".claude", "skills"),
    (".claude", "commands"),
    (".continue", "assistants"),
    (".windsurf", "workflows"),
    (".cursor", "rules"),
)
_AI_INSTRUCTION_FILENAMES = {
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "CONVENTIONS.md",
    ".cursorrules",
    ".windsurfrules",
}
_AI_INSTRUCTION_PATH_SUFFIXES = {
    ".continue/instructions.md",
    ".codeium/instructions.md",
    ".github/copilot-instructions.md",
}
_AGENT_TOOL_RE = re.compile(r"(?im)^\s*(?:tools|allowed-tools)\s*:\s*([^\n]+)")
_AGENT_CAPABLE_TOOL_RE = re.compile(r"(?i)\b(Bash|Write|Edit|MultiEdit|Agent)\b")
_AGENT_SHELL_RE = re.compile(
    r"(?i)(```(?:ba)?sh\b|\$\(|`(?:curl|wget|rm|sudo|sh|bash)\b[^`]*`"
    r"|\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b)"
)
_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"(?i)(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules|prompts)"
    r"|disregard\s+(?:the\s+)?(?:system|earlier)\s+(?:prompt|instructions)"
    r"|<\|?(?:im_start|system|assistant)\|?>|\[INST\]|\{role:\s*[\"']system[\"'])"
)
_INSTRUCTION_DESTRUCTIVE_RE = re.compile(
    r"(?i)\b(?:run|execute|invoke|use)\b.{0,32}"
    r"(?:rm\s+-rf|sudo\b|(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b|nc\s+-e|base64\s+-d[^|\n]*\|\s*(?:ba)?sh\b)"
)
_INSTRUCTION_ENCODED_PAYLOAD_RE = re.compile(r"(?:^|\s)[A-Za-z0-9+/]{100,}={0,2}(?:\s|$)")


def _is_mcp_config_path(rel: str) -> bool:
    return PurePosixPath(rel).name in _MCP_CONFIG_NAMES


def _is_ai_agent_artifact(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    return any(parts[: len(marker)] == marker for marker in _AI_AGENT_DIR_MARKERS)


def _is_ai_instruction_path(rel: str) -> bool:
    pure = PurePosixPath(rel)
    if pure.name in _AI_INSTRUCTION_FILENAMES or rel in _AI_INSTRUCTION_PATH_SUFFIXES:
        return True
    return _is_ai_agent_artifact(rel) or rel.startswith(".kiro/steering/") or rel.startswith(".github/instructions/")


def _scan_agent_artifact(path: Path, rel: str) -> list[dict[str, Any]]:
    """Flag executable capabilities in a committed agent artifact.

    A bundled agent is data from the target repository, not a trusted plugin
    instruction. We only flag concrete execution-capability declarations and
    shell constructs; prose that merely discusses agents remains out of scope.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[dict[str, Any]] = []
    for match in _AGENT_TOOL_RE.finditer(text):
        tools = sorted(set(_AGENT_CAPABLE_TOOL_RE.findall(match.group(1))))
        if not tools:
            continue
        findings.append(
            {
                "category": 28,
                "subcategory": "agent-capable-tool-declaration",
                "file": rel,
                "line": text.count("\n", 0, match.start()) + 1,
                "tools": tools,
                "severity": "High" if "Bash" in tools or "Agent" in tools else "Medium",
                "match": f"agent frontmatter grants {', '.join(tools)} capability",
            }
        )
    for line_no, line in enumerate(text.splitlines(), start=1):
        if _AGENT_SHELL_RE.search(line):
            findings.append(
                {
                    "category": 28,
                    "subcategory": "agent-shell-construct",
                    "file": rel,
                    "line": line_no,
                    "severity": "High",
                    "match": line.strip()[:_MAX_MATCH_CHARS],
                }
            )
    return findings


def _scan_instruction_red_flags(path: Path, rel: str) -> list[dict[str, Any]]:
    """Detect high-confidence prompt-injection payloads in assistant instructions."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rules = (
        ("instruction-override", "Critical", _INSTRUCTION_OVERRIDE_RE),
        ("destructive-command-in-instruction", "Critical", _INSTRUCTION_DESTRUCTIVE_RE),
        ("encoded-payload", "High", _INSTRUCTION_ENCODED_PAYLOAD_RE),
    )
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for rule, severity, pattern in rules:
            if pattern.search(line):
                findings.append(
                    {
                        "category": 28,
                        "subcategory": "instruction-prompt-injection",
                        "rule": rule,
                        "file": rel,
                        "line": line_no,
                        "severity": severity,
                        "match": line.strip()[:_MAX_MATCH_CHARS],
                    }
                )
    return findings


def _mcp_servers_from_config(data: Any) -> dict[str, Any]:
    """The server map of an MCP config: ``mcpServers`` or ``servers``, at the top level or nested under ``mcp``."""
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
    """The first http(s) URL anywhere in a nested config value, depth-first."""
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
    """Whether the value references an environment variable ($NAME or ${NAME}) instead of holding a secret."""
    stripped = value.strip()
    return bool(re.search(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", stripped))


def _mcp_hardcoded_secret(server_cfg: Any) -> tuple[str, str] | None:
    """(key, "env"|"headers") of the first secret-named value of 8+ characters that is not an env reference."""
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
    """Transport, origin and risk of one MCP server, worst first: hardcoded secret (Critical), remote server
    (High), server fetched from a public registry at start (High), otherwise a local binary (Info)."""
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
    """One classification row per MCP server, plus rows for auto-approved tools, `trust: true` and plain HTTP."""
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
        approved = server_cfg.get("autoApprove")
        approved_tools = (
            [tool for tool in approved if isinstance(tool, str) and tool.strip()] if isinstance(approved, list) else []
        )
        if approved_tools and server_cfg.get("disabled") is not True:
            findings.append(
                {
                    "category": 28,
                    "subcategory": "mcp-auto-approved-tools",
                    "file": rel,
                    "line": None,
                    "server": str(server_name),
                    "severity": "Medium",
                    "match": f"tools run without confirmation: {', '.join(sorted(approved_tools)[:5])}",
                }
            )
        if server_cfg.get("trust") is True:
            findings.append(
                {
                    "category": 28,
                    "subcategory": "mcp-trusted-server",
                    "file": rel,
                    "line": None,
                    "server": str(server_name),
                    "severity": "High",
                    "match": "`trust: true` bypasses every tool-call confirmation for this server",
                }
            )
        url = _first_http_url(server_cfg)
        if isinstance(url, str) and url.lower().startswith("http://"):
            findings.append(
                {
                    "category": 28,
                    "subcategory": "mcp-insecure-transport",
                    "file": rel,
                    "line": None,
                    "server": str(server_name),
                    "transport": classified["transport"],
                    "severity": "High",
                    "match": "remote MCP server uses cleartext HTTP; credentials and tool traffic can be intercepted",
                }
            )
    return findings


# --- Cat 28b: Claude Code permission model (deterministic) -----------------
# The flat `_CAT28_DANGEROUS` regex only ever matched literal `Bash(*)`. The
# scan below parses `permissions.allow` / `defaultMode` structurally so the
# recon template's 7.32 "dangerous permission patterns" table has a real
# producer. Only `allow` is graded: `deny`/`ask` entries are protective, and a
# thin or absent deny-list is hygiene, not an exploitable weakness. The grading
# itself lives in `runtime/agent_config_checks.py`, which the config/IaC catalog uses
# to raise the same signal as a finding.

_CLAUDE_SETTINGS_NAMES = {"settings.json", "settings.local.json"}


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
            classified = classify_permission_rule(entry)
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
# `UserPromptSubmit` was absent from the regex entirely. The scan below walks
# the hook structure and grades the actual `command` bodies through the shared
# graders in `runtime/agent_config_checks.py`.


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
    for event, command in iter_hook_commands(data):
        classified = classify_hook_command(event, command)
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
    """Inventory AI assistant and MCP config files and scan them for risky servers, permissions,
    hooks, agent capabilities and prompt-injection payloads (Cat 28).

    A Claude settings path that is not a regular file is reported instead of followed.
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_path(path: Path) -> None:
        try:
            rel = _rel(path, repo_root)
        except ValueError:
            return
        if rel in seen or _is_excluded(rel, repo_root):
            return
        # A symlink/device in the settings location can hide the effective
        # configuration from both code review and the structured parser below.
        # Inspect it with lstat before Path.is_file() follows or rejects it.
        if _is_claude_settings_path(rel):
            try:
                mode = path.lstat().st_mode
            except OSError:
                mode = None
            if mode is not None and not stat.S_ISREG(mode):
                seen.add(rel)
                findings.append(
                    {
                        "category": 28,
                        "subcategory": "assistant-config-nonregular-file",
                        "file": rel,
                        "line": None,
                        "severity": "Info",
                        "match": "Claude settings path is not a regular file; inspect the effective local configuration",
                    }
                )
                return
        try:
            is_file = path.is_file()
        except OSError:
            return
        if not is_file:
            return
        seen.add(rel)
        findings.extend(_scan_assistant_config_file(path, rel))

    # The same file can be reached by a fixed path, a config directory and the mcp.json search; `seen` keeps
    # the first.
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

    return _category_result(28, "AI Coding Assistant & IDE Agent Configurations", findings)


def _scan_assistant_config_file(path: Path, rel: str) -> list[dict[str, Any]]:
    """The inventory row of one assistant config file, then the findings of every scanner its path selects."""
    try:
        size = path.stat().st_size
    except OSError:
        size = None
    findings: list[dict[str, Any]] = [
        {"category": 28, "subcategory": "assistant-config-present", "file": rel, "line": None, "size": size}
    ]
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
    # Every JSON config is offered to the MCP parser: Gemini and Kiro declare
    # servers inside their settings file, not in a file named `mcp.json`.
    if _is_mcp_config_path(rel) or rel.endswith(".json"):
        findings.extend(_scan_mcp_servers(path, rel))
    if _is_claude_settings_path(rel):
        findings.extend(_scan_claude_permissions(path, rel))
    if _is_claude_settings_path(rel) or _is_claude_hooks_path(rel):
        findings.extend(_scan_hook_commands(path, rel))
    if _is_ai_agent_artifact(rel):
        findings.extend(_scan_agent_artifact(path, rel))
    if _is_ai_instruction_path(rel):
        findings.extend(_scan_instruction_red_flags(path, rel))
    return findings


# ---------------------------------------------------------------------------
# Category 13 — AI / LLM integration (deterministic; replaces the former
# LLM-grep 5-AND rule). Two signal strengths so a single import/framework/
# vector-DB/model-id (STRONG) is enough, while generic tokens (WEAK) only count
# in combination, because they also appear in ML, sensor and game code.
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
            r"|google\.genai|@google/genai|\bsemantic[_-]?kernel\b|\bpydantic[_-]?ai\b"
            r"|\bollama\b|@azure/openai|azure-ai-inference|\bbedrock-runtime\b|ChatCompletion"
            r"|chat\.completions|GenerativeModel|\bInvokeModel\b)"
        ),
    ),
    ("vector-db", "strong", re.compile(r"(?i)(\bchromadb\b|\bpinecone\b|\bweaviate\b|\bqdrant\b|\bmilvus\b)")),
    (
        "agent-framework",
        "strong",
        re.compile(
            r"(?i)(AgentExecutor|ReActAgent|create_react_agent|create_tool_calling_agent"
            r"|\blanggraph\b|\bAgentGraph\b|create_supervisor|\bsmolagents\b|\bstrands\b)"
        ),
    ),
    (
        "agent-memory",
        "strong",
        re.compile(r"(?i)(ConversationBufferMemory|MemorySaver|PostgresSaver|RedisSaver|checkpointer\s*=)"),
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
_CAT13_RUNTIME_ARTIFACT_DIRS = frozenset({".active-tool-calls", ".dispatch-context", ".fragments"})


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
        if any(part in _CAT13_SKIP_DIRS | _CAT13_RUNTIME_ARTIFACT_DIRS for part in rel_path.parts[:-1]):
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
                        # The cap bounds the rows kept, never the signal: a capped hit still counts above.
                        if per_cap.get(subcat, 0) < _CAT13_PER_SUBCAT_CAP:
                            findings.append(
                                {
                                    "category": 13,
                                    "subcategory": subcat,
                                    "strength": strength,
                                    "file": rel,
                                    "line": n,
                                    "match": _clip_line(line).strip(),
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
        return _category_result(13, "AI / LLM Integration", [])

    out = _category_result(13, "AI / LLM Integration", findings)
    if truncated:
        out["truncated"] = True
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
# A new category needs a scan_* function, an entry in run_all's category map and in _DISPATCH below, and a line
# in the module docstring; the three lists must stay in step.


# Cap findings per category and across the aggregate `.recon-patterns.json` the
# recon-scanner agent Reads into its LLM context. A recon pre-pass is a SIGNAL,
# not an exhaustive enumeration — the analyst re-greps on demand — so an
# unbounded findings list (319 KB of `categories` on a mid-size web app,
# ~120k tokens re-read every turn, a major contributor to the multi-million
# cache_read that made the streaming call fragile) only inflates context. The
# true magnitude stays in each category's `count`; strong-strength hits are kept
# ahead of the cap so build_stride_dispatch_manifest still sees them.
_MAX_FINDINGS_PER_CATEGORY = 12
_MAX_FINDINGS_TOTAL = 96
_MIN_FINDINGS_PER_NONEMPTY_CATEGORY = 3

_SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 4,
    "Info": 4,
}


def _finding_order_key(category_id: str, finding: Any) -> tuple[Any, ...]:
    """Order signals without inferring a finding beyond scanner-owned fields."""
    if not isinstance(finding, dict):
        return (9, 1, category_id, "", 0, "")
    severity = _SEVERITY_ORDER.get(str(finding.get("severity") or ""), 8)
    strength = 0 if finding.get("strength") == "strong" else 1
    line = finding.get("line")
    return (
        severity,
        strength,
        category_id,
        str(finding.get("file") or ""),
        line if isinstance(line, int) and not isinstance(line, bool) else 0,
        str(finding.get("subcategory") or ""),
        str(finding.get("match") or finding.get("evidence") or ""),
    )


def _cap_category_findings(categories: dict[str, Any], cap: int, total_cap: int) -> dict[str, Any]:
    """Retain a deterministic, category-diverse risk-ordered signal sample.

    ``count`` is set by the scanners before this runs, so it keeps the true
    pre-cap total. Per-category and aggregate omission metadata records every
    dropped row. The retained rows are signals for semantic recon, not an
    exhaustive scanner export.
    """
    ranked: dict[str, list[Any]] = {}
    original_total = 0
    for category_id, cat in sorted(categories.items(), key=lambda item: int(item[0])):
        if not isinstance(cat, dict):
            continue
        findings = cat.get("findings")
        if not isinstance(findings, list):
            continue
        original_total += len(findings)
        ranked[category_id] = sorted(findings, key=lambda row: _finding_order_key(category_id, row))[:cap]

    retained: dict[str, list[Any]] = {category_id: [] for category_id in ranked}
    for category_id, findings in ranked.items():
        retained[category_id].extend(findings[:_MIN_FINDINGS_PER_NONEMPTY_CATEGORY])

    remaining = [
        (category_id, finding)
        for category_id, findings in ranked.items()
        for finding in findings[_MIN_FINDINGS_PER_NONEMPTY_CATEGORY:]
    ]
    remaining.sort(key=lambda row: _finding_order_key(row[0], row[1]))
    capacity = max(0, total_cap - sum(len(values) for values in retained.values()))
    for category_id, finding in remaining[:capacity]:
        retained[category_id].append(finding)

    retained_total = 0
    for category_id, cat in categories.items():
        findings = cat.get("findings") if isinstance(cat, dict) else None
        if not isinstance(findings, list):
            continue
        kept = sorted(retained.get(category_id, []), key=lambda row: _finding_order_key(category_id, row))
        cat["findings"] = kept
        omitted = len(findings) - len(kept)
        if omitted:
            cat["findings_truncated"] = omitted
        else:
            cat.pop("findings_truncated", None)
        retained_total += len(kept)
    return {
        "max_findings_per_category": cap,
        "max_findings_total": total_cap,
        "minimum_per_nonempty_category": _MIN_FINDINGS_PER_NONEMPTY_CATEGORY,
        "original_findings": original_total,
        "retained_findings": retained_total,
        "omitted_findings": original_total - retained_total,
        "ordering_key": "severity,strength,category,file,line,subcategory,match",
    }


def run_all(
    repo_root: Path,
    include_manifest: bool = False,
) -> dict[str, Any]:
    """Run every category scanner and cap the findings kept per category and in total.

    Uncapped totals stay in each category's `count`; `limits` records the caps and omitted counts.
    """
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
    out["limits"] = _cap_category_findings(
        out["categories"],
        _MAX_FINDINGS_PER_CATEGORY,
        _MAX_FINDINGS_TOTAL,
    )
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
        print(f"analyzers/recon_patterns.py: repo-root not found: {repo_root}", file=sys.stderr)
        return 1

    include_manifest = args.scan_manifest or bool(args.manifest_file)

    if args.command == "all":
        out: dict[str, Any] = run_all(repo_root, include_manifest=include_manifest)
    else:
        if include_manifest:
            print(
                "analyzers/recon_patterns.py: --scan-manifest / --manifest-file requires command 'all'",
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
