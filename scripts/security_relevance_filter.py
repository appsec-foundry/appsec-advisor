#!/usr/bin/env python3
"""
security_relevance_filter.py — classify changed files by security relevance.

Used by the orchestrator during incremental threat modeling to decide whether
dirty components actually need STRIDE re-analysis, or whether the changes are
purely cosmetic / non-security-relevant and the component can be carried forward.

Exit codes:
  0 — at least one file is security-relevant (verdict=relevant)
  1 — all files are non-security-relevant (verdict=irrelevant)
  2 — error (bad args, git failure, etc.)

Output (stdout): JSON with per-file classification and overall verdict.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

# Central scan-excludes (Sprint 1 Item F). Imported lazily-safe: if the
# loader or its YAML is unavailable, fall back to the hardcoded classifier
# below so this filter never hard-fails on a misconfigured plugin install.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from scan_excludes import is_excluded as _scan_is_excluded  # noqa: E402
    from scan_excludes import is_always_included as _scan_is_always_included  # noqa: E402
    _SCAN_EXCLUDES_AVAILABLE = True
except Exception:  # pragma: no cover - defensive
    _SCAN_EXCLUDES_AVAILABLE = False

# ---------------------------------------------------------------------------
# Tier 1: Extension / filename / path classification (no diff content needed)
# ---------------------------------------------------------------------------

# Extensions that are never security-relevant on their own
IRRELEVANT_EXTENSIONS = frozenset({
    ".md", ".txt", ".rst", ".adoc",
    ".css", ".scss", ".sass", ".less", ".styl",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".wav", ".ogg", ".webm",
    ".lock",  # lockfiles are covered by manifest fingerprint, not STRIDE
    ".map",   # source maps
    ".snap",  # Jest snapshots
    ".po", ".pot", ".mo",  # i18n
})

# Exact filenames that are never security-relevant
IRRELEVANT_NAMES = frozenset({
    "LICENSE", "LICENSE.md", "LICENSE.txt",
    "CHANGELOG", "CHANGELOG.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
    ".editorconfig", ".prettierrc", ".prettierrc.json", ".prettierrc.yaml",
    ".prettierignore", ".eslintignore", ".gitignore", ".gitattributes",
    ".browserslistrc", ".nvmrc", ".node-version", ".python-version",
    ".stylelintrc", ".stylelintrc.json",
    "jest.config.js", "jest.config.ts",  # test config, not prod code
    "tsconfig.json",  # type checking config
    ".babelrc", "babel.config.js", "babel.config.json",
    # Claude Code / AI assistant local config — runtime IDE overrides, not source code
    "settings.local.json", "settings.json",
})

# Path-prefix segments whose files are never security-relevant for threat modeling
# (the directory may contain other things, but these prefixes are purely tooling).
IRRELEVANT_PATH_PREFIXES = (
    ".claude/",   # Claude Code IDE settings/hooks (settings*.json, keybindings.json)
    ".vscode/",   # VS Code workspace settings
    ".idea/",     # JetBrains IDE project files
)

# Extensions / names that are ALWAYS security-relevant
ALWAYS_RELEVANT_EXTENSIONS = frozenset({
    ".env", ".pem", ".key", ".crt", ".p12", ".jks",
})

# Manifest / IaC / Dockerfile names — always relevant (reuse from baseline_state)
ALWAYS_RELEVANT_NAMES = frozenset({
    "package.json", "requirements.txt", "Pipfile", "pyproject.toml",
    "go.mod", "Cargo.toml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.json", "Gemfile", "mix.exs",
    "Dockerfile", "Containerfile",
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
})

# Path segments that indicate security-relevant code
RELEVANT_PATH_SEGMENTS = frozenset({
    "auth", "authentication", "authorization",
    "security", "crypto", "encryption",
    "middleware", "interceptor",
    "permissions", "rbac", "acl",
    "session", "oauth", "oidc", "saml",
    "secrets", "vault",
})

# ---------------------------------------------------------------------------
# Tier 2: Diff content patterns (security-relevant keywords in added lines)
# ---------------------------------------------------------------------------

# Patterns are applied against added/modified lines only (lines starting with +)
# Each pattern is a compiled regex for performance
SECURITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Authentication & sessions
    ("auth", re.compile(r"\bauth(?:enticate|orize|entication|orization)?\b", re.I)),
    ("login", re.compile(r"\blogin|logout|sign[_-]?in|sign[_-]?out|sign[_-]?up\b", re.I)),
    ("password", re.compile(r"\bpassword|passwd|credential|bcrypt|argon2|scrypt\b", re.I)),
    ("secret", re.compile(r"\bsecret|api[_-]?key|private[_-]?key|access[_-]?key\b", re.I)),
    ("token", re.compile(r"\btoken|bearer|jwt|refresh[_-]?token|access[_-]?token\b", re.I)),
    ("session", re.compile(r"\bsession|cookie|set[_-]?cookie|httponly|secure\b", re.I)),

    # Cryptography
    ("crypto", re.compile(r"\bencrypt|decrypt|cipher|aes|rsa|hmac|digest\b", re.I)),
    ("hash", re.compile(r"\bhash(?:ing)?|sha[_-]?\d|md5|pbkdf\b", re.I)),
    ("sign", re.compile(r"\b(?:sign|verify)(?:ature)?\b", re.I)),
    ("cert", re.compile(r"\bcert(?:ificate)?|tls|ssl|x509|ca[_-]?cert\b", re.I)),

    # Injection & dangerous sinks
    ("sql", re.compile(r"\bsql|query|SELECT\s|INSERT\s|UPDATE\s|DELETE\s|CREATE\s+TABLE\b", re.I)),
    ("exec", re.compile(r"\bexec|eval|spawn|child_process|subprocess|system\s*\(|popen\b", re.I)),
    ("shell", re.compile(r"\bshell|command[_-]?injection|os\.system|os\.popen\b", re.I)),

    # Input validation & sanitization
    ("sanitize", re.compile(r"\bsaniti[zs]|escap[ei]|purif[yi]|dompurify|bleach\b", re.I)),
    ("validate", re.compile(r"\bvalidat[ei]|whitelist|blacklist|allowlist|denylist\b", re.I)),
    ("filter", re.compile(r"\bfilter[_-]?input|strip[_-]?tags|html[_-]?entit\b", re.I)),

    # Access control
    ("permission", re.compile(r"\bpermission|role|privilege|access[_-]?control\b", re.I)),
    ("rbac", re.compile(r"\brbac|acl|policy|can[_-]?access|is[_-]?authorized\b", re.I)),
    ("admin", re.compile(r"\badmin|superuser|root[_-]?access|elevated\b", re.I)),

    # Web security headers & OWASP
    ("cors", re.compile(r"\bcors|cross[_-]?origin|access[_-]?control[_-]?allow\b", re.I)),
    ("csrf", re.compile(r"\bcsrf|xsrf|anti[_-]?forgery|csrf[_-]?token\b", re.I)),
    ("xss", re.compile(r"\bxss|cross[_-]?site|innerhtml|dangerouslysetinnerhtml\b", re.I)),
    ("redirect", re.compile(r"\bredirect|location\s*=|open[_-]?redirect|url[_-]?redirect\b", re.I)),

    # API & routing (new endpoints = new attack surface)
    ("route", re.compile(
        r"@(?:app\.route|Get|Post|Put|Delete|Patch|Controller|RequestMapping)"
        r"|router\.\s*(?:get|post|put|delete|patch|use)\s*\("
        r"|express\.Router|FastAPI|APIRouter"
        r"|@ApiOperation|@ApiResponse",
        re.I,
    )),

    # Database access
    ("db_access", re.compile(
        r"\.query\s*\(|\.execute\s*\(|\.raw\s*\("
        r"|createQueryBuilder|getRepository"
        r"|prisma\.|mongoose\.|sequelize\.",
        re.I,
    )),

    # File operations (path traversal risk)
    ("file_op", re.compile(
        r"\bupload|download|file[_-]?path|path[_-]?traversal"
        r"|sendFile|readFile|writeFile|unlink\b",
        re.I,
    )),

    # OAuth / SSO protocols
    ("oauth", re.compile(r"\boauth|oidc|openid|saml|sso|identity[_-]?provider\b", re.I)),
]

# ---------------------------------------------------------------------------
# Tier 3: Structural signals
# ---------------------------------------------------------------------------

STRUCTURAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # New dependency imports of security-relevant packages
    ("import_sec_lib", re.compile(
        r"(?:import|require|from)\s+['\"]?"
        r"(?:bcrypt|argon2|jsonwebtoken|passport|helmet|cors|csurf"
        r"|express-session|cookie-parser|crypto|jose|oauth"
        r"|spring-security|django\.contrib\.auth|flask-login"
        r"|authlib|python-jose|pyjwt|cryptography)",
        re.I,
    )),
    # Environment variable references that look security-relevant
    ("env_security", re.compile(
        r"(?:process\.env|os\.environ|os\.getenv|env\[)[.\[('\"]?\s*"
        r"['\"]?(?:SECRET|TOKEN|KEY|PASSWORD|AUTH|JWT|SESSION|DATABASE_URL|REDIS_URL)",
        re.I,
    )),
    # Middleware registration
    ("middleware", re.compile(
        r"\.use\s*\(\s*(?:auth|cors|helmet|csrf|session|passport|rateLimit|limiter)",
        re.I,
    )),
]

# ---------------------------------------------------------------------------
# Tier 1 helpers: path-only classification
# ---------------------------------------------------------------------------


def _is_dockerfile(name: str) -> bool:
    return (
        name == "Dockerfile"
        or name == "Containerfile"
        or name.startswith("Dockerfile.")
        or name.endswith(".Dockerfile")
    )


def _is_iac_file(rel_path: str, name: str, suffix: str) -> bool:
    iac_suffixes = {".tf", ".tfvars"}
    iac_dir_hints = ("k8s/", "kubernetes/", "helm/", "terraform/", "ansible/", ".github/workflows/")
    return (
        suffix in iac_suffixes
        or name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
        or any(hint in rel_path for hint in iac_dir_hints)
    )


def _is_workflow_file(rel_path: str) -> bool:
    return ".github/workflows/" in rel_path


def _is_env_file(name: str) -> bool:
    return name.startswith(".env") and not name.endswith(".example")


def classify_by_path(rel_path: str) -> tuple[bool | None, list[str]]:
    """Classify a file by its path/extension alone.

    Returns:
        (True, reasons)  — definitely relevant
        (False, reasons) — definitely irrelevant
        (None, [])       — undecided, needs diff content analysis

    Ordering rationale: downgradeable Tier-1 signals (manifests, Dockerfile,
    IaC, workflows, security path segments) are checked BEFORE the
    scan-excludes whitelist. ``package.json`` is in both ``ALWAYS_RELEVANT_NAMES``
    and the always-include whitelist; we want it to surface with reason
    ``name:package.json`` (semantic-diff downgradeable) rather than
    ``whitelist:...`` (not downgradeable). The whitelist still wins for
    files that would otherwise be classified as irrelevant — e.g. an
    AsciiDoc file under ``docs/`` that's whitelisted via ``always_include``.
    """
    p = PurePosixPath(rel_path)
    name = p.name
    suffix = p.suffix.lower()

    # --- Tier 1a: downgradeable always-relevant signals (path-only) ---
    # These return reasons with prefixes (name:/iac:/workflow:/path:) that
    # ``_is_tier1_downgradeable`` recognises so a whitespace-only diff can
    # downgrade them to noise in the caller.

    # Always-relevant by exact name
    if name in ALWAYS_RELEVANT_NAMES or _is_dockerfile(name):
        return True, [f"name:{name}"]

    # Always-relevant by extension (env / cert / key — NOT downgradeable;
    # Tier-1b downgrade only applies to ``name:/iac:/workflow:/path:`` reasons).
    if suffix in ALWAYS_RELEVANT_EXTENSIONS or name.startswith(".env"):
        if _is_env_file(name):
            return True, [f"env_file:{name}"]
        if suffix in ALWAYS_RELEVANT_EXTENSIONS:
            return True, [f"ext:{suffix}"]

    # Always-relevant by path (IaC, workflows) — downgradeable
    if _is_iac_file(rel_path, name, suffix):
        return True, [f"iac:{rel_path}"]
    if _is_workflow_file(rel_path):
        return True, [f"workflow:{rel_path}"]

    # Path segments indicating security relevance — downgradeable
    parts_lower = {part.lower() for part in p.parts}
    hits = parts_lower & RELEVANT_PATH_SEGMENTS
    if hits:
        return True, [f"path:{seg}" for seg in sorted(hits)]

    # --- Tier 1b: scan-excludes (whitelist-wins) ---
    # Runs AFTER the downgradeable signals so a file like ``package.json``
    # never falls through to the ``whitelist:`` branch (which would block
    # the semantic-diff downgrade). Now only catches files that ONLY match
    # the whitelist — e.g. AsciiDoc/ADR docs under ``docs/`` directories.
    if _SCAN_EXCLUDES_AVAILABLE:
        try:
            if _scan_is_always_included(rel_path):
                return True, [f"whitelist:{name}"]
            if _scan_is_excluded(rel_path):
                return False, ["scan_excludes"]
        except Exception:
            # Fall through to the hardcoded classifier below.
            pass

    # Irrelevant by path prefix (IDE / tooling directories)
    posix_rel = rel_path.replace("\\", "/")
    for prefix in IRRELEVANT_PATH_PREFIXES:
        if posix_rel.startswith(prefix):
            return False, [f"ide_dir:{prefix.rstrip('/')}"]

    # Irrelevant by extension
    if suffix in IRRELEVANT_EXTENSIONS:
        return False, [f"ext:{suffix}"]

    # Irrelevant by exact name
    if name in IRRELEVANT_NAMES:
        return False, [f"name:{name}"]

    # Test files — generally not security-relevant for threat modeling
    if name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts")):
        return False, ["test_file"]
    if any(part in {"test", "tests", "__tests__", "spec", "specs"} for part in p.parts):
        return False, ["test_dir"]

    return None, []


# ---------------------------------------------------------------------------
# Tier 2+3: Diff content analysis
# ---------------------------------------------------------------------------


def classify_by_diff(diff_text: str) -> tuple[bool, list[str]]:
    """Analyze the diff content of a file for security-relevant changes.

    Only looks at added/modified lines (starting with '+', excluding '+++' header).

    Returns:
        (True, reasons) — security-relevant patterns found
        (False, [])     — no security-relevant patterns in the diff
    """
    reasons: list[str] = []

    added_lines: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append(line[1:])  # strip the leading +

    if not added_lines:
        return False, ["no_added_lines"]

    combined = "\n".join(added_lines)

    # Tier 2: security keyword patterns
    for label, pattern in SECURITY_PATTERNS:
        if pattern.search(combined):
            reasons.append(f"pattern:{label}")

    # Tier 3: structural signals
    for label, pattern in STRUCTURAL_PATTERNS:
        if pattern.search(combined):
            reasons.append(f"structural:{label}")

    if reasons:
        return True, reasons
    return False, []


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def get_diff_for_file(repo_root: str, baseline_sha: str | None, file_path: str) -> str:
    """Get the git diff for a specific file."""
    try:
        # Committed changes since baseline
        parts: list[str] = []
        if baseline_sha:
            result = subprocess.run(
                ["git", "-C", repo_root, "diff", f"{baseline_sha}..HEAD", "--", file_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                parts.append(result.stdout)

        # Uncommitted changes (staged + unstaged)
        result = subprocess.run(
            ["git", "-C", repo_root, "diff", "HEAD", "--", file_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts.append(result.stdout)

        return "\n".join(parts)
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _git_show_blob(repo_root: str, ref: str, file_path: str) -> str | None:
    """Return the file content at the given ref, or None on error / missing."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_root, "show", f"{ref}:{file_path}"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return None


# Security-relevant top-level keys in package.json. Changes outside this
# set (name/version/contributors/repository/license/keywords/description/
# author/homepage/bugs/funding/main/module/browser/files/types/typings/
# private/publishConfig) are treated as metadata noise — they do not
# reshape the threat model.
_PKG_JSON_SEC_KEYS = frozenset({
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "bundledDependencies",
    "bundleDependencies",
    "overrides",
    "resolutions",
    "scripts",
    "engines",
    "type",          # "module" vs "commonjs" — affects loader / sandbox
    "bin",           # CLI entrypoint exposure
    "exports",       # subpath export surface
    "imports",       # subpath import map
    "workspaces",    # monorepo scope expansion
    "config",        # may carry security-sensitive flags
})


def _has_security_relevant_package_json_change(
    before_text: str | None, after_text: str | None
) -> tuple[bool | None, list[str]]:
    """Compare before/after package.json content; return ``(verdict, details)``.

    ``verdict``:
        True   — at least one key in ``_PKG_JSON_SEC_KEYS`` differs
        False  — only metadata keys differ (or both equal)
        None   — cannot decide (parse error, file missing, etc.) — caller
                 must fall back to the conservative whitespace-diff check.

    ``details``: human-readable per-key change descriptions for the
    pre-check banner, e.g. ``["dependencies:+jsdom", "scripts:~start"]``.
    Empty when verdict is False or None.
    """
    if before_text is None or after_text is None:
        return None, []
    try:
        before = json.loads(before_text)
        after = json.loads(after_text)
    except (json.JSONDecodeError, ValueError):
        return None, []
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None, []

    details: list[str] = []
    for key in _PKG_JSON_SEC_KEYS:
        bv = before.get(key)
        av = after.get(key)
        if bv == av:
            continue
        if isinstance(bv, dict) and isinstance(av, dict):
            added = sorted(set(av.keys()) - set(bv.keys()))
            removed = sorted(set(bv.keys()) - set(av.keys()))
            common_diff = sorted(
                k for k in (set(bv.keys()) & set(av.keys())) if bv[k] != av[k]
            )
            parts: list[str] = []
            for k in added[:3]:
                parts.append(f"+{k}")
            for k in removed[:3]:
                parts.append(f"-{k}")
            for k in common_diff[:3]:
                parts.append(f"~{k}")
            extra = (len(added) + len(removed) + len(common_diff)) - len(parts)
            if extra > 0:
                parts.append(f"…+{extra}")
            details.append(f"{key}:{','.join(parts)}" if parts else key)
        else:
            details.append(key)
    return (bool(details), details)


# Dockerfile instruction keywords. A line is considered a real instruction
# iff its first non-whitespace token (case-insensitive) appears here. Lines
# starting with ``#`` (comments) and blank lines are stripped before the
# comparison.
_DOCKERFILE_INSTRUCTIONS = frozenset({
    "FROM", "RUN", "CMD", "LABEL", "EXPOSE", "ENV", "ADD", "COPY",
    "ENTRYPOINT", "VOLUME", "USER", "WORKDIR", "ARG", "ONBUILD",
    "STOPSIGNAL", "HEALTHCHECK", "SHELL", "MAINTAINER",
})


def _normalize_dockerfile(text: str) -> str:
    """Drop comment lines and blank lines; collapse line continuations
    (trailing backslash) into single logical instructions; uppercase the
    instruction keyword. Whitespace inside arguments is preserved so a
    real argument change is still detected.
    """
    out: list[str] = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if pending:
            stripped = pending + " " + stripped
            pending = ""
        if stripped.endswith("\\"):
            pending = stripped[:-1].rstrip()
            continue
        parts = stripped.split(None, 1)
        if parts and parts[0].upper() in _DOCKERFILE_INSTRUCTIONS:
            head = parts[0].upper()
            tail = parts[1] if len(parts) > 1 else ""
            stripped = f"{head} {tail}".rstrip()
        out.append(stripped)
    if pending:
        out.append(pending)
    return "\n".join(out)


def _has_security_relevant_dockerfile_change(
    before_text: str | None, after_text: str | None
) -> tuple[bool | None, list[str]]:
    """Compare normalized Dockerfile content. Comment-only / blank-only
    edits collapse to the same string and return ``(False, [])``. Real
    instruction changes return ``(True, ["RUN", "COPY"])`` listing the
    distinct instruction keywords whose set differs.
    """
    if before_text is None or after_text is None:
        return None, []
    try:
        norm_before = _normalize_dockerfile(before_text)
        norm_after = _normalize_dockerfile(after_text)
    except Exception:
        return None, []
    if norm_before == norm_after:
        return False, []
    # Collect the instruction keywords on diff lines so the banner can
    # show "+RUN, +COPY" instead of just "Dockerfile changed".
    before_lines = set(norm_before.splitlines())
    after_lines = set(norm_after.splitlines())
    added = after_lines - before_lines
    removed = before_lines - after_lines
    instructions: list[str] = []
    for line in list(added)[:5]:
        head = line.split(None, 1)[0] if line else ""
        if head in _DOCKERFILE_INSTRUCTIONS and f"+{head}" not in instructions:
            instructions.append(f"+{head}")
    for line in list(removed)[:5]:
        head = line.split(None, 1)[0] if line else ""
        if head in _DOCKERFILE_INSTRUCTIONS and f"-{head}" not in instructions:
            instructions.append(f"-{head}")
    return True, instructions or ["instruction-change"]


def _whitespace_only_diff(repo_root: str, baseline_sha: str | None, file_path: str) -> bool:
    """True iff ``git diff -w --ignore-blank-lines --ignore-all-space``
    is empty. Conservative on git failure (returns False — caller treats
    file as having a real diff).
    """
    try:
        if baseline_sha:
            result = subprocess.run(
                ["git", "-C", repo_root, "diff",
                 "-w", "--ignore-blank-lines", "--ignore-all-space",
                 f"{baseline_sha}..HEAD", "--", file_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return False
            if result.stdout.strip():
                return False
        result = subprocess.run(
            ["git", "-C", repo_root, "diff",
             "-w", "--ignore-blank-lines", "--ignore-all-space",
             "HEAD", "--", file_path],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return False
        return not result.stdout.strip()
    except (subprocess.TimeoutExpired, OSError):
        return False


def has_semantic_diff(
    repo_root: str, baseline_sha: str | None, file_path: str
) -> tuple[bool, list[str]]:
    """Return ``(is_semantic, details)`` for the file.

    Manifest-aware classification — strips three kinds of noise:

      1. ``package.json`` metadata-only edits (name, version, contributors,
         repository URL, license, keywords, …) — only ``dependencies``,
         ``scripts``, ``engines``, etc. flip the verdict.
      2. ``Dockerfile`` comment-only / blank-line-only edits — only
         instruction-line changes (FROM / RUN / COPY / ENV / …) count.
      3. Pure whitespace / blank-line edits on any text file (catches
         formatter-only diffs the manifest comparators do not see).

    ``details`` lists the specific keys / instruction keywords that
    flipped the verdict (e.g. ``["dependencies:+jsdom"]`` or
    ``["+RUN", "+COPY"]``). Empty when the verdict is False or when no
    structured comparator applies.

    Conservative defaults:
      • git error / file unreadable → ``(True, [])``
      • parse failure on JSON / Dockerfile → fall back to the generic
        whitespace-only check, never silently downgrade.
    """
    name = PurePosixPath(file_path).name

    # Manifest-aware fast paths first — they catch metadata-only edits
    # that the whitespace-diff would otherwise classify as semantic.
    if name == "package.json":
        before = _git_show_blob(repo_root, baseline_sha or "HEAD", file_path)
        try:
            after = (Path(repo_root) / file_path).read_text(encoding="utf-8")
        except OSError:
            after = None
        verdict, details = _has_security_relevant_package_json_change(before, after)
        if verdict is True:
            return True, details
        if verdict is False:
            return False, []
        # verdict is None → fall through.

    elif _is_dockerfile(name):
        before = _git_show_blob(repo_root, baseline_sha or "HEAD", file_path)
        try:
            after = (Path(repo_root) / file_path).read_text(encoding="utf-8")
        except OSError:
            after = None
        verdict, details = _has_security_relevant_dockerfile_change(before, after)
        if verdict is True:
            return True, details
        if verdict is False:
            return False, []
        # verdict is None → fall through.

    # Generic whitespace-only check (catches formatter / blank-line edits
    # on any text file). When the diff is only whitespace, downgrade.
    if _whitespace_only_diff(repo_root, baseline_sha, file_path):
        return False, []
    return True, []


# Reason prefixes whose Tier-1 "relevant" verdict is eligible for a
# semantic-diff downgrade — these are path-only signals (the file
# pattern matches a manifest / IaC / workflow / security-named dir),
# so a whitespace-only edit is genuinely a no-op.
#
# Reason prefixes that are NOT downgradeable:
#   "whitelist:"  → user explicitly opted these in via scan-excludes always_include
#   "env_file:"   → .env files are always security-relevant
#   "ext:.env"    → ditto
#   "ext:.pem|.key|…" → certificate/key material is always relevant
_DOWNGRADEABLE_REASON_PREFIXES = ("name:", "iac:", "workflow:", "path:")


def _is_tier1_downgradeable(reasons: list[str]) -> bool:
    if not reasons:
        return False
    return any(r.startswith(_DOWNGRADEABLE_REASON_PREFIXES) for r in reasons)


def get_changed_files(repo_root: str, baseline_sha: str | None) -> list[str]:
    """Get list of changed files from git diff."""
    files: set[str] = set()
    try:
        if baseline_sha:
            result = subprocess.run(
                ["git", "-C", repo_root, "diff", "--name-only", f"{baseline_sha}..HEAD"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                files.update(f for f in result.stdout.strip().splitlines() if f)

        result = subprocess.run(
            ["git", "-C", repo_root, "diff", "--name-only"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            files.update(f for f in result.stdout.strip().splitlines() if f)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return sorted(files)


# ---------------------------------------------------------------------------
# Main classification logic
# ---------------------------------------------------------------------------


def classify_files(
    repo_root: str,
    baseline_sha: str | None,
    files: list[str],
) -> dict:
    """Classify a list of changed files by security relevance.

    Returns a dict with:
      - verdict: "relevant" or "irrelevant"
      - files: per-file classification
      - summary: human-readable summary
      - relevant_files: list of files classified as relevant
    """
    results: dict[str, dict] = {}
    relevant_files: list[str] = []

    for f in files:
        # Tier 1: path-based
        decision, reasons = classify_by_path(f)

        if decision is True:
            # Tier-1b: semantic-diff downgrade for path-only relevance
            # signals (manifest names, IaC, workflows, security-named
            # path segments). A whitespace-only or blank-line-only diff
            # on a manifest/Dockerfile must NOT trigger STRIDE re-scan.
            # Whitelist-, env-file-, and extension-based hits stay
            # relevant unconditionally.
            if _is_tier1_downgradeable(reasons):
                is_semantic, details = has_semantic_diff(repo_root, baseline_sha, f)
                if not is_semantic:
                    results[f] = {
                        "relevant": False,
                        "reasons": reasons + ["no_semantic_diff"],
                    }
                    continue
                # Append per-key / per-instruction details so the
                # pre-check banner can show WHAT triggered the run.
                merged_reasons = reasons + [f"diff:{d}" for d in details]
                results[f] = {"relevant": True, "reasons": merged_reasons}
                relevant_files.append(f)
                continue
            results[f] = {"relevant": True, "reasons": reasons}
            relevant_files.append(f)
            continue
        if decision is False:
            results[f] = {"relevant": False, "reasons": reasons}
            continue

        # Tier 2+3: need diff content
        diff_text = get_diff_for_file(repo_root, baseline_sha, f)
        if not diff_text:
            # No diff available — conservative: mark as relevant
            results[f] = {"relevant": True, "reasons": ["no_diff_available"]}
            relevant_files.append(f)
            continue

        is_relevant, diff_reasons = classify_by_diff(diff_text)
        if is_relevant:
            results[f] = {"relevant": True, "reasons": diff_reasons}
            relevant_files.append(f)
        else:
            results[f] = {"relevant": False, "reasons": ["no_security_patterns"]}

    total = len(files)
    rel_count = len(relevant_files)
    irrel_count = total - rel_count

    verdict = "relevant" if rel_count > 0 else "irrelevant"

    return {
        "verdict": verdict,
        "files": results,
        "relevant_files": relevant_files,
        "summary": f"{irrel_count}/{total} files irrelevant, {rel_count}/{total} security-relevant",
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="security_relevance_filter.py",
        description="Classify changed files by security relevance for incremental threat modeling.",
    )
    p.add_argument("--repo-root", required=True, help="Path to the repository root")
    p.add_argument("--baseline-sha", default=None, help="Baseline commit SHA for diff")
    p.add_argument("--files", nargs="*", default=None,
                   help="List of changed files (if omitted, computed from git diff)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    repo_root = os.path.abspath(args.repo_root)
    if not os.path.isdir(repo_root):
        print(json.dumps({"error": f"repo root not found: {repo_root}"}), file=sys.stderr)
        return 2

    files = args.files if args.files else get_changed_files(repo_root, args.baseline_sha)
    if not files:
        result = {
            "verdict": "irrelevant",
            "files": {},
            "relevant_files": [],
            "summary": "0/0 files — no changes detected",
        }
        print(json.dumps(result, indent=2))
        return 1

    result = classify_files(repo_root, args.baseline_sha, files)
    print(json.dumps(result, indent=2))

    return 0 if result["verdict"] == "relevant" else 1


if __name__ == "__main__":
    sys.exit(main())
