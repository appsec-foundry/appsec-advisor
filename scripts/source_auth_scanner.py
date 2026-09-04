#!/usr/bin/env python3
"""source_auth_scanner.py — deterministic source-code auth/security scanner.

Runs the rule catalog in `data/source-auth-checks.yaml` against every
matching source file in the repository and emits findings to
`$OUTPUT_DIR/.source-auth-findings.json`. Each finding carries a
counter-pattern-aware verdict so that legitimate ownership-checked code is
NOT flagged.

The same pre-pass also performs a conservative, bounded data-flow check for
direct LLM-output handling. It follows variables assigned from common model
SDK calls and emits only when those values visibly reach a structured-data,
browser-rendering, interpreter, resource, or action sink without the matching
local guard. Multi-file, reflective, or otherwise ambiguous flows remain for
the LLM05/LLM06 STRIDE lens instead of being promoted speculatively.

Counter-pattern scopes:
    line    — only the matched line is searched
    window  — match_line .. match_line + counter_window  (inclusive)
    call    — match_line until balanced close-paren OR counter_window
              lines (whichever comes first)

The scanner is pure-Python, depends only on stdlib + PyYAML, and is
designed to run in well under 30 seconds on a 1000-file repo. It is
INVOKABLE in three ways:

    # Standalone (most common):
    python3 source_auth_scanner.py --repo-root <REPO> --output-dir <OUT>

    # With explicit checks file (override the default):
    python3 source_auth_scanner.py --repo-root <REPO> --output-dir <OUT> \
        --checks <CHECKS_YAML>

    # Dry-run (print findings to stdout, do NOT write sidecar):
    python3 source_auth_scanner.py --repo-root <REPO> --dry-run

Output schema is in `schemas/source-auth-findings.schema.yaml`.

Exit codes
    0  scan completed (regardless of how many findings)
    1  IO / discovery error
    2  usage error
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
from typing import Iterator

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    print("source_auth_scanner: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CHECKS_REL = Path("data") / "source-auth-checks.yaml"

# Additional catalogs run through the SAME engine when `--checks` is not given.
# Rule packs stay separate where their false-positive boundaries differ, while
# sharing the same evidence, sidecar, validation, and merge contract. Missing
# files are skipped silently so an older packaged plugin can still run.
DEFAULT_EXTRA_CHECKS_REL = [
    Path("data") / "crypto-checks.yaml",
    Path("data") / "credential-lifecycle-checks.yaml",
]

# Hard exclusions on top of per-check exclude_file_patterns (universal):
# the scanner never reads anything under these paths even if a check's
# file_patterns matches.
_UNIVERSAL_EXCLUDES = (
    ".git/",
    "node_modules/",
    "dist/",
    "build/",
    "out/",
    ".next/",
    ".nuxt/",
    "coverage/",
    ".cache/",
    ".vscode/",
    ".idea/",
    "vendor/",
    "__pycache__/",
    # Static code snippets stored as DATA and served to the user (e.g. the
    # coding-challenge "fix this vuln" snippets under data/static/codefixes/).
    # They contain intentionally-vulnerable example code but are read via
    # fs.readFile and rendered as text — never require()'d or executed — so
    # their SQL/command literals are inert, not live sinks.
    "codefixes/",
)

# Maximum file size (bytes) — files larger than this are skipped (likely
# minified bundles or generated artifacts).
_MAX_FILE_BYTES = 1_500_000

# How many context lines to include in the evidence_snippet around the
# matched line.
_EVIDENCE_CTX = 1

# Max characters per evidence-snippet line. Over-long lines are trimmed at a
# WORD boundary (never mid-token) so a long source line like a raw SQL query
# does not render as a broken token (e.g. `plain: true` → `plain: tr`). The cap
# is generous because the PDF soft-wraps long code lines; it only guards against
# pathological minified lines.
_EVIDENCE_MAX_LINE = 400


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class Check:
    id: str
    name: str
    description: str
    file_patterns: list[str]
    exclude_file_patterns: list[str]
    pattern: re.Pattern[str]
    counter_scope: str  # line | window | call
    counter_window: int
    counter_patterns: list[re.Pattern[str]]
    required_context_patterns: list[re.Pattern[str]]
    severity_if_violated: str
    cwe: str
    finding_type: str
    breach_vector: str
    rationale: str
    remediation: str


@dataclass
class Finding:
    local_id: str
    check_id: str
    finding_type_id: str
    source_type: str
    file: str
    line: int
    evidence_snippet: str
    title: str
    scenario: str
    severity: str
    cwe: list[str]
    recommended_mitigation_title: str
    breach_vector: str


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def _compile_pattern(p: str, *, name: str, check_id: str) -> re.Pattern[str]:
    try:
        return re.compile(p)
    except re.error as e:
        raise ValueError(f"check {check_id}: invalid regex in {name}: {e}") from e


def load_checks(checks_path: Path) -> list[Check]:
    raw = yaml.safe_load(checks_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "checks" not in raw:
        raise ValueError(f"checks file {checks_path} must be a mapping with a top-level `checks:` key")

    out: list[Check] = []
    for entry in raw["checks"]:
        cid = str(entry.get("id") or "").strip()
        if not cid:
            raise ValueError(f"check is missing id: {entry}")
        try:
            scope = entry.get("counter_scope") or "window"
            if scope not in ("line", "window", "call"):
                raise ValueError(f"check {cid}: counter_scope must be one of line|window|call, got {scope!r}")
            out.append(
                Check(
                    id=cid,
                    name=str(entry["name"]),
                    description=str(entry.get("description") or "").strip(),
                    file_patterns=list(entry.get("file_patterns") or []),
                    exclude_file_patterns=list(entry.get("exclude_file_patterns") or []),
                    pattern=_compile_pattern(entry["pattern"], name="pattern", check_id=cid),
                    counter_scope=scope,
                    counter_window=int(entry.get("counter_window") or 5),
                    counter_patterns=[
                        _compile_pattern(p, name="counter_patterns", check_id=cid)
                        for p in (entry.get("counter_patterns") or [])
                    ],
                    required_context_patterns=[
                        _compile_pattern(p, name="required_context_patterns", check_id=cid)
                        for p in (entry.get("required_context_patterns") or [])
                    ],
                    severity_if_violated=str(entry.get("severity_if_violated") or "Medium"),
                    cwe=str(entry.get("cwe") or "").upper(),
                    finding_type=str(entry.get("finding_type") or ""),
                    breach_vector=str(entry.get("breach_vector") or "Internet User"),
                    rationale=str(entry.get("rationale") or "").strip(),
                    remediation=str(entry.get("remediation") or "").strip(),
                )
            )
        except KeyError as e:
            raise ValueError(f"check {cid}: missing required field {e}") from e
    return out


# ---------------------------------------------------------------------------
# File-system walk
# ---------------------------------------------------------------------------


def _is_universally_excluded(rel_path: str) -> bool:
    for excl in _UNIVERSAL_EXCLUDES:
        if excl in rel_path or rel_path.startswith(excl.rstrip("/")):
            return True
    return False


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Convert a shell glob pattern to a compiled regex.

    Rules:
      `**`          → `.*`  (matches any path including slashes)
      `*`           → `[^/]*`  (matches anything except slash)
      `?`           → `[^/]`
      `{a,b,c}`     → `(?:a|b|c)`  (brace expansion)
      every other char is regex-escaped.

    Pattern `**/foo.ts` matches both `foo.ts` (top-level) AND
    `sub/dir/foo.ts` — this is the cross-shell convention that fnmatch
    + PurePath.match do not give us.
    """

    # 1) handle brace expansion first
    def expand_braces(s: str) -> str:
        out = []
        i = 0
        while i < len(s):
            if s[i] == "{":
                j = s.find("}", i)
                if j == -1:
                    out.append(s[i])
                    i += 1
                    continue
                alts = s[i + 1 : j].split(",")
                out.append("(?:" + "|".join(re.escape(a.strip()) for a in alts) + ")")
                i = j + 1
            else:
                out.append(None)  # placeholder; we re-escape below
                i += 1
        # rebuild — placeholders become the original char
        result = []
        k = 0
        i = 0
        while i < len(s):
            if s[i] == "{":
                j = s.find("}", i)
                if j == -1:
                    result.append(s[i])
                    i += 1
                    continue
                alts = s[i + 1 : j].split(",")
                result.append("(?:" + "|".join(re.escape(a.strip()) for a in alts) + ")")
                i = j + 1
            else:
                result.append(s[i])
                i += 1
        return "".join(result)

    # Convert glob meta to regex tokens.
    expanded = expand_braces(pattern)
    out: list[str] = []
    i = 0
    while i < len(expanded):
        ch = expanded[i]
        if expanded[i : i + 3] == "**/" or expanded[i : i + 3] == "**\\":
            # `**/` consumed greedily: matches "" or "any/path/"
            out.append("(?:.*/)?")
            i += 3
        elif expanded[i : i + 2] == "**":
            out.append(".*")
            i += 2
        elif expanded[i : i + 3] == "(?:":
            # Internal brace-expansion token, not a glob `?` wildcard.
            out.append("(?:")
            i += 3
        elif ch == "*":
            out.append("[^/]*")
            i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch in ("(", ")", "|", "\\"):
            # already-expanded brace tokens; keep regex semantics
            out.append(ch)
            i += 1
        elif ch == "[":
            # Char class — copy verbatim until matching ]
            j = expanded.find("]", i)
            if j == -1:
                out.append(re.escape(ch))
                i += 1
            else:
                out.append(expanded[i : j + 1])
                i = j + 1
        else:
            out.append(re.escape(ch))
            i += 1
    regex = "^" + "".join(out) + "$"
    return re.compile(regex)


_GLOB_CACHE: dict[str, re.Pattern[str]] = {}


def _matches_any_glob(rel_path: str, globs: list[str]) -> bool:
    # Normalize: pathlib gives us posix-style anyway, but be defensive.
    norm = rel_path.replace("\\", "/")
    for g in globs:
        rx = _GLOB_CACHE.get(g)
        if rx is None:
            rx = _glob_to_regex(g)
            _GLOB_CACHE[g] = rx
        if rx.match(norm):
            return True
    return False


def _walk_repo(repo_root: Path) -> Iterator[Path]:
    """Yield every regular file under `repo_root`, skipping common build
    output directories at the directory-prune level so very large dirs do
    not slow the walk down."""
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        # Prune in place
        dirnames[:] = [
            d
            for d in dirnames
            if not (
                d.startswith(".") and d not in {".github", ".claude"}  # keep CI / plugin dirs
            )
            and d
            not in {
                "node_modules",
                "dist",
                "build",
                "out",
                ".next",
                ".nuxt",
                "coverage",
                "vendor",
                "__pycache__",
            }
        ]
        for fn in filenames:
            yield Path(dirpath) / fn


# ---------------------------------------------------------------------------
# Counter-scope helpers
# ---------------------------------------------------------------------------


def _scope_lines_for_call(lines: list[str], start_idx: int, max_window: int) -> list[str]:
    """Return lines from `start_idx` up to the line that closes the call's
    open parenthesis, capped at `max_window` lines."""
    depth = 0
    seen_open = False
    end_idx = start_idx
    for i in range(start_idx, min(len(lines), start_idx + max_window + 1)):
        ln = lines[i]
        for ch in ln:
            if ch == "(":
                depth += 1
                seen_open = True
            elif ch == ")":
                depth -= 1
                if seen_open and depth <= 0:
                    return lines[start_idx : i + 1]
        end_idx = i
    return lines[start_idx : end_idx + 1]


def _counter_match(
    lines: list[str],
    match_line_idx: int,
    check: Check,
) -> bool:
    """True iff ANY counter-pattern matches within the configured scope."""
    if not check.counter_patterns:
        return False

    if check.counter_scope == "line":
        scope_lines = [lines[match_line_idx]]
    elif check.counter_scope == "call":
        scope_lines = _scope_lines_for_call(lines, match_line_idx, check.counter_window)
    else:  # window
        end = min(len(lines), match_line_idx + check.counter_window + 1)
        scope_lines = lines[match_line_idx:end]

    blob = "\n".join(scope_lines)
    for cp in check.counter_patterns:
        if cp.search(blob):
            return True
    return False


def _required_context_matches(
    lines: list[str],
    match_line_idx: int,
    check: Check,
) -> bool:
    """Require local evidence when a syntax token alone is ambiguous.

    A bare MD5 call may serve a cache key, so rules may require an explicit
    security-purpose signal in the same line, call, or forward window. This
    deliberately favours defensible evidence over recall where data-flow
    analysis is unavailable.
    """
    if not check.required_context_patterns:
        return True
    if check.counter_scope == "line":
        scope_lines = [lines[match_line_idx]]
    elif check.counter_scope == "call":
        scope_lines = _scope_lines_for_call(lines, match_line_idx, check.counter_window)
    else:  # window
        end = min(len(lines), match_line_idx + check.counter_window + 1)
        scope_lines = lines[match_line_idx:end]
    blob = "\n".join(scope_lines)
    return any(pattern.search(blob) for pattern in check.required_context_patterns)


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------


def _evidence_snippet(lines: list[str], idx: int) -> str:
    """Capture ±_EVIDENCE_CTX lines around `idx`, trimming each over-long line
    at a WORD boundary (never mid-token) — see ``_EVIDENCE_MAX_LINE``."""
    lo = max(0, idx - _EVIDENCE_CTX)
    hi = min(len(lines), idx + _EVIDENCE_CTX + 1)
    out = []
    for i in range(lo, hi):
        ln = lines[i].rstrip()
        if len(ln) > _EVIDENCE_MAX_LINE:
            cut = ln.rfind(" ", 0, _EVIDENCE_MAX_LINE - 1)
            if cut < _EVIDENCE_MAX_LINE // 2:  # no sensible space → hard cut
                cut = _EVIDENCE_MAX_LINE - 1
            ln = ln[:cut].rstrip() + " …"
        marker = ">>" if i == idx else "  "
        out.append(f"{marker} {i + 1:5}: {ln}")
    return "\n".join(out)


def _source_type_for(file_rel: str) -> str:
    """Derive the schema `source_type` from the file extension."""
    lower = file_rel.lower()
    if lower.endswith(".py"):
        return "python_source"
    if lower.endswith((".java", ".kt")):
        return "java_source"
    if lower.endswith((".ts", ".tsx")):
        return "typescript_source"
    return "nodejs_source"


# ---------------------------------------------------------------------------
# Direct LLM-output flow checks
# ---------------------------------------------------------------------------

# These checks intentionally live in code rather than the single-regex catalog:
# their evidence requires a source assignment, bounded propagation, a concrete
# sink, and a sink-specific counter-signal. A regex-only row cannot preserve
# that producer → consumer relationship without either missing ordinary
# variable indirection or turning every generic ``response`` variable into a
# false positive.
_LLM_OUTPUT_CHECK_IDS = frozenset(
    {
        "INJ-LLM-001",  # structured output consumed without validation
        "INJ-LLM-002",  # model output rendered as active browser content
        "INJ-LLM-003",  # model output passed to SQL/shell/code execution
        "INJ-LLM-004",  # model output selects a URL or filesystem path
        "AUTHZ-LLM-001",  # model output selects an object or tool without authz
    }
)
_LLM_OUTPUT_EXTS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"})
_LLM_OUTPUT_EXCLUDE_GLOBS = [
    "**/*.test.*",
    "**/*.spec.*",
    "**/test/**",
    "**/tests/**",
    "**/__tests__/**",
    "**/__mocks__/**",
    "**/fixtures/**",
]

_LLM_SURFACE_RE = re.compile(
    r"(?i)(\bopenai\b|\banthropic\b|\blangchain\b|\bllama[_-]?index\b|\bollama\b|"
    r"\bbedrock\b|google\.genai|google\.generativeai|GenerativeModel|ChatCompletion|"
    r"chat\.completions|responses\.(?:create|parse|stream)|messages\.create|"
    r"\b(?:llm|language_model|chat_model)\b|streamText\s*\(|generateText\s*\()"
)
_STRONG_LLM_CALL_RE = re.compile(
    r"(?i)(chat\.completions\.(?:create|parse|stream)\s*\(|responses\.(?:create|parse|stream)\s*\(|"
    r"messages\.create\s*\(|generateContent\s*\(|generate_content\s*\(|InvokeModel\s*\(|"
    r"\bconverse\s*\(|streamText\s*\(|generateText\s*\()"
)
_GENERIC_LLM_CALL_RE = re.compile(
    r"(?i)\b(?:llm|model|chat_model|language_model|agent)\s*\.\s*"
    r"(?:invoke|ainvoke|predict|complete|generate|chat|stream)\s*\("
)
_RAW_STRUCTURED_PARSE_RE = re.compile(r"(?i)(?:JSON\.parse|json\.loads)\s*\(")
_HTML_SINK_RE = re.compile(
    r"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\(|"
    r"dangerouslySetInnerHTML|bypassSecurityTrustHtml\s*\(|\bv-html\b|\{@html\b)"
)
_HTML_SANITIZER_RE = re.compile(
    r"(?i)(DOMPurify\.sanitize|sanitizeHtml|sanitize_html|escapeHtml|html\.escape|bleach\.clean)\s*\("
)
_CODE_EXEC_RE = re.compile(
    r"(?i)(?<![\w.])eval\s*\(|new\s+Function\s*\(|"
    r"vm\.runIn(?:New|This)?Context\s*\("
)
_PYTHON_CODE_EXEC_RE = re.compile(r"(?i)(?<![\w.])(?:exec|compile)\s*\(")
_PROCESS_EXEC_RE = re.compile(
    r"(?i)(?:child_process\.)?(?:exec|execSync|execFile|spawn)\s*\(|"
    r"os\.(?:system|popen)\s*\(|subprocess\.(?:run|call|Popen|check_output|check_call)\s*\("
)
_INTERPRETER_ARGV_RE = re.compile(
    r"(?i)['\"](?:[^'\"]*/)?(?:ba|da|z)?sh(?:\.exe)?['\"]|"
    r"['\"](?:[^'\"]*/)?(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|python[0-9.]*(?:\.exe)?|"
    r"node(?:\.exe)?|ruby(?:\.exe)?|perl(?:\.exe)?)['\"]"
)
_INTERPRETER_CODE_FLAG_RE = re.compile(r"(?i)['\"](?:-c|-e|/c|-command|/command)['\"]")
_SQL_EXEC_RE = re.compile(
    r"(?i)\b(?:db|database|sql|cursor|sequelize|connection|pool|queryRunner)\w*\s*\.\s*"
    r"(?:query|execute|exec|raw)\s*\("
)
_URL_SINK_RE = re.compile(
    r"(?i)\b(?:fetch|urlopen|openConnection|requests\.(?:get|post|put|patch|delete|request)|"
    r"axios(?:\.(?:get|post|put|patch|delete|request))?|got(?:\.(?:get|post))?|"
    r"http\.(?:get|request)|https\.(?:get|request))\s*\("
)
_PATH_SINK_RE = re.compile(
    r"(?i)\b(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|"
    r"readdir|unlink|rm|rename)|res\.(?:sendFile|download))\s*\("
)
_PYTHON_PATH_SINK_RE = re.compile(r"(?i)(?<![\w.])(?:open|Path)\s*\(")
_OBJECT_SINK_RE = re.compile(
    r"(?i)\.(?:findByPk|findById|findUnique|findFirst|findOne|update|destroy|delete|deleteOne|"
    r"updateOne|remove)\s*\("
)
_TOOL_SINK_RE = re.compile(
    r"(?i)(?:\b(?:execute|invoke|call|run|dispatch)[_-]?(?:tool|action)\s*\(|"
    r"\btools?\s*\[[^\]]+\]\s*\()"
)

_SCHEMA_VALIDATOR_RE = re.compile(
    r"(?i)(?:\b(?:\w*(?:schema|validator)\w*|zod|joi|yup|ajv|typeAdapter)\s*\.\s*"
    r"(?:parse|validateAsync|validate_json)\s*\(|"
    r"\b(?:jsonschema\.validate|model_validate|model_validate_json)\s*\()"
)
_NAMED_SCHEMA_CALL_RE = re.compile(
    r"(?i)\b(?P<name>(?:[A-Z][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*(?:schema|validator)[A-Za-z0-9_]*))"
    r"\s*\.\s*(?:parse|validateAsync|validate_json|model_validate|model_validate_json)\s*\("
)
_JSONSCHEMA_SCHEMA_NAME_RE = re.compile(
    r"(?i)\bjsonschema\.validate\s*\(\s*(?:instance\s*=\s*)?[^,]+,\s*"
    r"(?:schema\s*=\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
_SCHEMA_TYPE_CONSTRAINT_RE = re.compile(
    r"(?i)(z\.(?:string|number|boolean|date|object)\s*\(|['\"]type['\"]\s*:|"
    r":\s*(?:str|int|float|bool)\b|\bField\s*\()"
)
_SCHEMA_RANGE_OR_FORMAT_RE = re.compile(
    r"(?i)(\.(?:min|max|gte|lte|positive|nonnegative|uuid|regex)\s*\(|"
    r"\b(?:minimum|maximum|minLength|maxLength|pattern|format)\b|\b(?:ge|le|gt|lt)\s*=)"
)
_SCHEMA_CLOSED_RE = re.compile(r"(?i)(\.strict\s*\(|additionalProperties['\"]?\s*:\s*false|extra\s*=\s*['\"]forbid)")
_SCHEMA_ALLOWLIST_RE = re.compile(r"(?i)(z\.enum\s*\(|\bLiteral\s*\[|\boneOf\b|['\"]enum['\"]\s*:)")
_MANUAL_TYPE_RE = re.compile(
    r"(?i)(typeof\b|isinstance\s*\(|Number\.is(?:Integer|Finite)\s*\(|\.is_(?:string|number|integer)\s*\()"
)
_MANUAL_RANGE_RE = re.compile(r"(?i)(?:<=|>=|<|>|\bmin(?:imum)?\b|\bmax(?:imum)?\b|\bge\b|\ble\b)")
_MANUAL_ALLOWLIST_RE = re.compile(
    r"(?i)(?:allowed\w*\s*\.(?:includes|has)\s*\(|\b\w+\s+in\s+allowed\w*|"
    r"allowlist|whitelist|\benum\b|\bLiteral\s*\[)"
)
_URL_GUARD_RE = re.compile(r"(?i)(assertAllowedUrl|validateOutboundUrl|ssrfGuard|assertPublicHttpUrl)")
_PATH_GUARD_RE = re.compile(
    r"(?i)(assertContainedPath|resolveContainedPath|safeJoin|"
    r"startsWith\s*\(\s*(?:base|root)|commonpath\s*\()"
)
_AUTHZ_GUARD_RE = re.compile(
    r"(?i)(authorize|assertAuthorized|requirePermission|assertPermission|requireRole|"
    r"requireOwnership|assertOwnership|ensureOwnership)"
)
_BROAD_AUTHZ_GATE_RE = re.compile(
    r"(?i)(?:requireRole|requirePermission|assertAuthorized|ensureAdmin|requireAdmin)\s*\([^\n]*(?:"
    r"currentUser|current_user|req\.user|principal|identity)"
)
_INLINE_OWNERSHIP_RE = re.compile(
    r"(?i)(?:ownerId|owner_id|tenantId|tenant_id)\s*:\s*"
    r"(?:req\.user|currentUser|current_user|principal|identity)(?:\.[A-Za-z_][A-Za-z0-9_]*)?"
)
_TOOL_ALLOWLIST_RE = re.compile(
    r"(?i)(?:(?:allowedTools?|toolAllowlist|tool_allowlist|allowedActions?|actionAllowlist|"
    r"action_allowlist)\s*\.\s*(?:includes|has)\s*\(|"
    r"assertAllowed(?:Tool|Action)|validate(?:Tool|Action))"
)


def _assignment(line: str) -> tuple[list[str], str] | None:
    """Return direct assignment targets and RHS for common source syntaxes."""
    destructured = re.search(r"^\s*(?:const|let|var)\s*\{(?P<targets>[^}]+)\}\s*=\s*(?P<rhs>.*)", line)
    if destructured:
        targets = []
        for item in destructured.group("targets").split(","):
            candidate = item.split(":")[-1].strip().split("=")[0].strip()
            if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", candidate):
                targets.append(candidate)
        return (targets, destructured.group("rhs")) if targets else None

    scalar = re.search(
        r"^\s*(?:(?:const|let|var|final|String|Object|Map(?:<[^>]+>)?|dict|str|int|float|bool)\s+)?"
        r"(?P<target>\$?[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)*)"
        r"(?:\s*:\s*[^=]+)?\s*(?:=|:=)\s*(?P<rhs>.*)",
        line,
    )
    if not scalar:
        return None
    return [scalar.group("target")], scalar.group("rhs")


def _loop_target(line: str) -> tuple[str, str] | None:
    match = re.search(
        r"(?i)^\s*(?:for\s*\(\s*(?:const|let|var)\s+|for\s+)(?P<target>[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\s+(?:of|in)\s+(?P<rhs>.+?)(?:\)|:)?\s*\{?\s*$",
        line,
    )
    return (match.group("target"), match.group("rhs")) if match else None


def _refs_in(text: str, refs: set[str]) -> set[str]:
    hits: set[str] = set()
    for ref in refs:
        if re.search(rf"(?<![A-Za-z0-9_$]){re.escape(ref)}(?![A-Za-z0-9_$])", text):
            hits.add(ref)
    return hits


def _call_first_argument(statement: str, call_match: re.Match[str]) -> str:
    """Extract a call's first argument without executing or fully parsing code."""
    start = call_match.end()
    depth = 0
    quote: str | None = None
    escaped = False
    out: list[str] = []
    for ch in statement[start:]:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\" and quote:
            out.append(ch)
            escaped = True
            continue
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in {'"', "'", "`"}:
            quote = ch
            out.append(ch)
            continue
        if ch in "([{":
            depth += 1
            out.append(ch)
            continue
        if ch in ")]}":
            if depth == 0:
                break
            depth -= 1
            out.append(ch)
            continue
        if ch == "," and depth == 0:
            break
        out.append(ch)
    return "".join(out).strip()


def _call_arguments(statement: str, call_match: re.Match[str]) -> list[str]:
    """Extract bounded top-level call arguments for sinks with multiple locators."""
    depth = 0
    quote: str | None = None
    escaped = False
    current: list[str] = []
    arguments: list[str] = []
    for ch in statement[call_match.end() :]:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\" and quote:
            current.append(ch)
            escaped = True
            continue
        if quote:
            current.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in {'"', "'", "`"}:
            quote = ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            if depth == 0:
                if current or arguments:
                    arguments.append("".join(current).strip())
                break
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    return arguments


def _call_match_consumes_direct_output(statement: str, call_match: re.Match[str]) -> bool:
    """Return whether the matched call encloses a direct model invocation."""
    matched = call_match.group(0)
    relative_open = matched.find("(")
    if relative_open >= 0:
        open_idx = call_match.start() + relative_open
    else:
        suffix = statement[call_match.end() :]
        opening = re.match(r"\s*\(", suffix)
        if not opening:
            return False
        open_idx = call_match.end() + opening.end() - 1

    depth = 1
    quote: str | None = None
    escaped = False
    body: list[str] = []
    for ch in statement[open_idx + 1 :]:
        if escaped:
            body.append(ch)
            escaped = False
            continue
        if ch == "\\" and quote:
            body.append(ch)
            escaped = True
            continue
        if quote:
            body.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in {'"', "'", "`"}:
            quote = ch
            body.append(ch)
        elif ch == "(":
            depth += 1
            body.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
            body.append(ch)
        else:
            body.append(ch)
    return _direct_llm_call("".join(body), has_surface=True)


def _guard_wraps_direct_output(scope: str, guard_re: re.Pattern[str]) -> bool:
    return any(_call_match_consumes_direct_output(scope, match) for match in guard_re.finditer(scope))


def _forward_statement(lines: list[str], idx: int, limit: int = 6) -> str:
    """Join a bounded forward window for ordinary multi-line call/JSX forms."""
    collected: list[str] = []
    depth = 0
    quote: str | None = None
    escaped = False
    for raw in lines[idx : min(len(lines), idx + limit)]:
        collected.append(raw)
        for ch in raw:
            if escaped:
                escaped = False
                continue
            if ch == "\\" and quote:
                escaped = True
                continue
            if quote:
                if ch == quote:
                    quote = None
                continue
            if ch in {'"', "'", "`"}:
                quote = ch
            elif ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
        stripped = raw.rstrip()
        if depth == 0 and not stripped.endswith(("=", ",", "(", "{", "[")):
            break
    return "\n".join(collected)


def _direct_llm_call(text: str, has_surface: bool) -> bool:
    return bool(_STRONG_LLM_CALL_RE.search(text) or (has_surface and _GENERIC_LLM_CALL_RE.search(text)))


def _html_sanitizes_refs(text: str, refs: set[str]) -> bool:
    for sanitizer in _HTML_SANITIZER_RE.finditer(text):
        if _refs_in(_call_first_argument(text, sanitizer), refs):
            return True
    return False


def _definition_scope(lines: list[str], start: int, limit: int = 24) -> str:
    """Return one bounded schema definition without borrowing nearby constraints."""
    first = lines[start]
    if re.match(r"^\s*class\s+", first):
        base_indent = len(first) - len(first.lstrip())
        end = start + 1
        while end < min(len(lines), start + limit):
            candidate = lines[end]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= base_indent:
                break
            end += 1
        return "\n".join(lines[start:end])

    collected: list[str] = []
    depth = 0
    saw_delimiter = False
    quote: str | None = None
    escaped = False
    for raw in lines[start : min(len(lines), start + limit)]:
        collected.append(raw)
        for ch in raw:
            if escaped:
                escaped = False
                continue
            if ch == "\\" and quote:
                escaped = True
                continue
            if quote:
                if ch == quote:
                    quote = None
                continue
            if ch in {'"', "'", "`"}:
                quote = ch
            elif ch in "([{":
                saw_delimiter = True
                depth += 1
            elif ch in ")]}":
                depth = max(0, depth - 1)
        if saw_delimiter and depth == 0:
            break
        if not saw_delimiter and raw.rstrip().endswith(";"):
            break
    return "\n".join(collected)


def _complete_schema_definition(lines: list[str], validator_name: str | None) -> bool:
    if validator_name:
        escaped_name = re.escape(validator_name)
        definition_re = re.compile(
            rf"^\s*(?:(?:const|let|var|final)\s+)?{escaped_name}(?:\s*:[^=]+)?\s*=|"
            rf"^\s*class\s+{escaped_name}(?:\s*\([^)]*\))?\s*:",
            re.IGNORECASE,
        )
        starts = [idx for idx, line in enumerate(lines) if definition_re.search(line)]
        scope = _definition_scope(lines, starts[0]) if starts else ""
    else:
        scope = "\n".join(lines)
    return bool(
        scope
        and _SCHEMA_TYPE_CONSTRAINT_RE.search(scope)
        and _SCHEMA_RANGE_OR_FORMAT_RE.search(scope)
        and _SCHEMA_CLOSED_RE.search(scope)
        and _SCHEMA_ALLOWLIST_RE.search(scope)
    )


def _schema_name_from_validation(line: str) -> str | None:
    jsonschema = _JSONSCHEMA_SCHEMA_NAME_RE.search(line)
    if jsonschema:
        return jsonschema.group("name")
    named = _NAMED_SCHEMA_CALL_RE.search(line)
    return named.group("name") if named else None


def _structured_validation_present(lines: list[str], idx: int, refs: set[str], parse_statement: str) -> bool:
    validator_name = _schema_name_from_validation(parse_statement)
    if validator_name and _complete_schema_definition(lines, validator_name):
        return True

    manual_type = False
    manual_range = False
    manual_allowlist = False
    first_following_line = idx + len(parse_statement.splitlines())
    for pos in range(first_following_line, min(len(lines), idx + 20)):
        line = lines[pos]
        if not _refs_in(line, refs):
            continue
        validator = _SCHEMA_VALIDATOR_RE.search(line)
        if validator:
            validator_name = _schema_name_from_validation(line)
            if validator_name and _complete_schema_definition(lines, validator_name):
                return True
            continue
        type_hit = bool(_MANUAL_TYPE_RE.search(line))
        range_hit = bool(_MANUAL_RANGE_RE.search(line))
        allowlist_hit = bool(_MANUAL_ALLOWLIST_RE.search(line))
        if type_hit or range_hit or allowlist_hit:
            manual_type = manual_type or type_hit
            manual_range = manual_range or range_hit
            manual_allowlist = manual_allowlist or allowlist_hit
            if manual_type and manual_range and manual_allowlist:
                return True
            continue
        # The first non-validation use makes a later check too late.
        return False
    return manual_type and manual_range and manual_allowlist


def _guard_consumes_refs(scope: str, guard_re: re.Pattern[str], refs: set[str]) -> bool:
    return any(guard_re.search(line) and _refs_in(line, refs) for line in scope.splitlines())


def _authz_guard_present(scope: str, selected_argument: str, refs: set[str], direct_output: bool) -> bool:
    """Require authorization tied to the selected value or an explicit caller gate."""
    tied_guard = _guard_consumes_refs(scope, _AUTHZ_GUARD_RE, refs) if refs else False
    direct_guard = direct_output and _guard_wraps_direct_output(selected_argument, _AUTHZ_GUARD_RE)
    inline_owner_filter = bool(refs and _INLINE_OWNERSHIP_RE.search(selected_argument))
    return tied_guard or direct_guard or inline_owner_filter or bool(_BROAD_AUTHZ_GATE_RE.search(scope))


def _html_sink_payload(statement: str, sink_match: re.Match[str]) -> str:
    matched = sink_match.group(0).rstrip()
    if matched.endswith("("):
        return _call_first_argument(statement, sink_match)
    if matched.endswith("="):
        return statement[sink_match.end() :].split(";", 1)[0]
    return statement[sink_match.end() :]


def _selected_sink_refs(statement: str, sink_match: re.Match[str], refs: set[str], *, is_tool: bool) -> set[str]:
    matched = sink_match.group(0)
    if is_tool and "[" in matched:
        selector = matched.split("[", 1)[1].rsplit("]", 1)[0]
    else:
        selector = _call_first_argument(statement, sink_match)
    return _refs_in(selector, refs)


def _python_fixed_argv(statement: str, process_match: re.Match[str], first_arg: str) -> bool:
    """Recognize a literal executable in a shell-free subprocess argv list."""
    if not process_match.group(0).lower().startswith("subprocess."):
        return False
    if re.search(r"(?i)\bshell\s*=\s*True\b", statement):
        return False
    literal_first_item = re.compile(
        r"""^\s*[\[(]\s*(?:r|u|b|br|rb)?(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*")\s*(?:,|[\])])""",
        re.IGNORECASE,
    )
    return bool(literal_first_item.match(first_arg))


def _fixed_interpreter_executes_model_output(statement: str, refs: set[str], direct_output: bool) -> bool:
    return bool(
        (refs or direct_output)
        and _INTERPRETER_ARGV_RE.search(statement)
        and _INTERPRETER_CODE_FLAG_RE.search(statement)
    )


def _resource_sink_argument(statement: str, sink_match: re.Match[str]) -> str:
    """Select the URL/path-bearing arguments for known multi-argument sinks."""
    arguments = _call_arguments(statement, sink_match)
    sink = sink_match.group(0).lower()
    if "requests.request" in sink:
        named_url = next((arg for arg in arguments if re.match(r"(?i)^\s*url\s*=", arg)), None)
        if named_url is not None:
            return named_url
        return arguments[1] if len(arguments) > 1 else ""
    if "fs.rename" in sink:
        return "\n".join(arguments[:2])
    return arguments[0] if arguments else ""


def _guard_scope_before(lines: list[str], idx: int, column: int, before: int = 14) -> str:
    prior = lines[max(0, idx - before) : idx]
    return "\n".join([*prior, lines[idx][:column]])


def _structured_output_consumed(lines: list[str], idx: int, targets: list[str]) -> bool:
    if not targets:
        return bool(re.search(r"(?i)\b(return|yield|send|json)\b", lines[idx]))
    scope = "\n".join(lines[idx + 1 : min(len(lines), idx + 40)])
    return bool(_refs_in(scope, set(targets)))


def _llm_finding(
    *,
    check_id: str,
    file_rel: str,
    line_idx: int,
    lines: list[str],
    title: str,
    scenario: str,
    severity: str,
    cwe: str,
    finding_type: str,
    remediation: str,
) -> Finding:
    return Finding(
        local_id="",
        check_id=check_id,
        finding_type_id=finding_type,
        source_type=_source_type_for(file_rel),
        file=file_rel,
        line=line_idx + 1,
        evidence_snippet=_evidence_snippet(lines, line_idx),
        title=f"{title} ({file_rel}:{line_idx + 1})",
        scenario=scenario,
        severity=severity,
        cwe=[cwe],
        recommended_mitigation_title=remediation,
        breach_vector="Internet User",
    )


def _scan_llm_output_file(file_abs: Path, file_rel: str) -> list[Finding]:
    """Emit high-confidence findings for direct model-output-to-sink flows."""
    if file_abs.suffix.lower() not in _LLM_OUTPUT_EXTS:
        return []
    if _matches_any_glob(file_rel, _LLM_OUTPUT_EXCLUDE_GLOBS):
        return []
    try:
        if file_abs.stat().st_size > _MAX_FILE_BYTES:
            return []
        text = file_abs.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not text or not _LLM_SURFACE_RE.search(text):
        return []

    lines = text.splitlines()
    tainted: set[str] = set()
    html_sanitized: set[str] = set()
    findings: list[Finding] = []
    emitted: set[tuple[str, int]] = set()

    def emit_once(finding: Finding) -> None:
        key = (finding.check_id, finding.line)
        if key not in emitted:
            emitted.add(key)
            findings.append(finding)

    for idx, line in enumerate(lines):
        statement = _forward_statement(lines, idx)
        assignment = _assignment(line)
        if assignment:
            targets, rhs = assignment
            continuation = "\n".join(statement.splitlines()[1:])
            rhs_scope = "\n".join(part for part in (rhs, continuation) if part)
            rhs_refs = _refs_in(rhs_scope, tainted)
            rhs_has_direct_output = _direct_llm_call(rhs_scope, has_surface=True)
            rhs_is_tainted = bool(rhs_refs or rhs_has_direct_output)
            for target in targets:
                if rhs_is_tainted:
                    tainted.add(target)
                    sanitizes_refs = bool(rhs_refs and _html_sanitizes_refs(rhs_scope, rhs_refs))
                    sanitizes_direct = rhs_has_direct_output and _guard_wraps_direct_output(
                        rhs_scope, _HTML_SANITIZER_RE
                    )
                    if sanitizes_refs or sanitizes_direct:
                        html_sanitized.add(target)
                    else:
                        html_sanitized.discard(target)
                else:
                    tainted.discard(target)
                    html_sanitized.discard(target)

            if _RAW_STRUCTURED_PARSE_RE.search(rhs_scope) and (rhs_refs or rhs_has_direct_output):
                structured_refs = set(targets) | rhs_refs
                if _structured_output_consumed(lines, idx, targets) and not _structured_validation_present(
                    lines, idx, structured_refs, rhs_scope
                ):
                    emit_once(
                        _llm_finding(
                            check_id="INJ-LLM-001",
                            file_rel=file_rel,
                            line_idx=idx,
                            lines=lines,
                            title="Improper LLM Output Validation",
                            scenario=(
                                "Model-generated JSON is parsed and subsequently consumed without a schema or complete "
                                "type, range, and allowlist checks. Prompt-influenced fields can therefore select "
                                "unexpected identifiers, enum values, or numeric bounds."
                            ),
                            severity="Medium",
                            cwe="CWE-20",
                            finding_type="",
                            remediation=(
                                "Validate parsed model output with a closed schema that rejects unknown fields and "
                                "enforces types, enum allowlists, identifier formats, and numeric ranges before use."
                            ),
                        )
                    )

        loop = _loop_target(line)
        if loop and _refs_in(loop[1], tainted):
            tainted.add(loop[0])
            html_sanitized.discard(loop[0])

        statement_refs = _refs_in(statement, tainted)
        statement_has_direct_output = _direct_llm_call(statement, has_surface=True)
        if not statement_refs and not statement_has_direct_output:
            continue

        html_match = _HTML_SINK_RE.search(line)
        if html_match:
            html_payload = _html_sink_payload(statement, html_match)
            sink_refs = _refs_in(html_payload, tainted)
            unsafe_refs = sink_refs - html_sanitized
            direct_html = _direct_llm_call(html_payload, has_surface=True)
            unsafe_direct_html = direct_html and not _guard_wraps_direct_output(html_payload, _HTML_SANITIZER_RE)
            if (unsafe_refs and not _html_sanitizes_refs(html_payload, unsafe_refs)) or unsafe_direct_html:
                emit_once(
                    _llm_finding(
                        check_id="INJ-LLM-002",
                        file_rel=file_rel,
                        line_idx=idx,
                        lines=lines,
                        title="Cross-Site Scripting from LLM Output",
                        scenario=(
                            "Model-controlled text is inserted into an active HTML context without contextual encoding "
                            "or a sanitizer applied to that value, allowing model output to become executable markup."
                        ),
                        severity="High",
                        cwe="CWE-79",
                        finding_type="FT-011",
                        remediation=(
                            "Render model text through framework escaping or sanitize it for the exact HTML context "
                            "immediately before the sink; keep raw HTML disabled for Markdown output."
                        ),
                    )
                )

        execution_kind: tuple[str, str, str, str] | None = None
        code_match = _CODE_EXEC_RE.search(line)
        if code_match is None and file_abs.suffix.lower() == ".py":
            code_match = _PYTHON_CODE_EXEC_RE.search(line)
        if code_match:
            first_arg = _call_first_argument(statement, code_match)
            if _refs_in(first_arg, tainted) or _direct_llm_call(first_arg, has_surface=True):
                execution_kind = ("code", "CWE-94", "FT-020", "Critical")
        else:
            process_match = _PROCESS_EXEC_RE.search(line)
            if process_match:
                first_arg = _call_first_argument(statement, process_match)
                first_arg_is_model_output = bool(
                    _refs_in(first_arg, tainted) or _direct_llm_call(first_arg, has_surface=True)
                )
                shell_enabled = bool(re.search(r"(?i)\bshell\s*[:=]\s*true\b", statement))
                shell_receives_model_output = shell_enabled and bool(statement_refs or statement_has_direct_output)
                interpreter_receives_model_output = _fixed_interpreter_executes_model_output(
                    statement, statement_refs, statement_has_direct_output
                )
                safe_python_argv = _python_fixed_argv(statement, process_match, first_arg)
                if interpreter_receives_model_output or (
                    (first_arg_is_model_output or shell_receives_model_output) and not safe_python_argv
                ):
                    execution_kind = ("process", "CWE-78", "FT-003", "Critical")
            if execution_kind is None:
                sql_match = _SQL_EXEC_RE.search(line)
                if sql_match:
                    first_arg = _call_first_argument(statement, sql_match)
                    if _refs_in(first_arg, tainted) or _direct_llm_call(first_arg, has_surface=True):
                        execution_kind = ("SQL", "CWE-89", "FT-001", "High")
        if execution_kind is not None:
            kind, cwe, finding_type, severity = execution_kind
            emit_once(
                _llm_finding(
                    check_id="INJ-LLM-003",
                    file_rel=file_rel,
                    line_idx=idx,
                    lines=lines,
                    title={
                        "code": "Code Injection from LLM Output",
                        "process": "Command Injection from LLM Output",
                        "SQL": "SQL Injection from LLM Output",
                    }[kind],
                    scenario=(
                        f"Model-controlled output reaches a {kind} interpreter as executable structure rather than "
                        "data. Prompt injection or a compromised model response can therefore alter the operation "
                        "that the application executes."
                    ),
                    severity=severity,
                    cwe=cwe,
                    finding_type=finding_type,
                    remediation=(
                        "Do not execute model output directly. Use fixed operations with bound parameters or a "
                        "shell-free fixed executable, and mediate any model-selected action through a strict allowlist."
                    ),
                )
            )

        resource_sinks = [
            (_URL_SINK_RE, "outbound URL", "CWE-918", "FT-070", _URL_GUARD_RE),
            (_PATH_SINK_RE, "filesystem path", "CWE-22", "FT-060", _PATH_GUARD_RE),
        ]
        if file_abs.suffix.lower() == ".py":
            resource_sinks.append((_PYTHON_PATH_SINK_RE, "filesystem path", "CWE-22", "FT-060", _PATH_GUARD_RE))
        for sink_re, resource_kind, cwe, finding_type, guard_re in resource_sinks:
            sink_match = sink_re.search(line)
            if not sink_match:
                continue
            resource_argument = _resource_sink_argument(statement, sink_match)
            resource_refs = _refs_in(resource_argument, tainted)
            direct_resource = _direct_llm_call(resource_argument, has_surface=True)
            if not resource_refs and not direct_resource:
                continue
            scope = "\n".join([_guard_scope_before(lines, idx, sink_match.start()), resource_argument])
            guarded_refs = resource_refs and _guard_consumes_refs(scope, guard_re, resource_refs)
            guarded_direct = direct_resource and _guard_wraps_direct_output(resource_argument, guard_re)
            if guarded_refs or guarded_direct:
                continue
            emit_once(
                _llm_finding(
                    check_id="INJ-LLM-004",
                    file_rel=file_rel,
                    line_idx=idx,
                    lines=lines,
                    title=(
                        "Server-Side Request Forgery from LLM Output"
                        if cwe == "CWE-918"
                        else "Path Traversal from LLM Output"
                    ),
                    scenario=(
                        f"A model-generated value selects an {resource_kind} without a visible destination/containment "
                        "allowlist. Prompt-influenced output can therefore reach resources outside the caller's "
                        "intended scope."
                    ),
                    severity="High",
                    cwe=cwe,
                    finding_type=finding_type,
                    remediation=(
                        "Validate the model-selected resource with a strict allowlist and canonical containment or "
                        "destination checks before access; do not treat model output as a trusted locator."
                    ),
                )
            )

        object_match = _OBJECT_SINK_RE.search(line)
        tool_match = _TOOL_SINK_RE.search(line)
        selected_match = tool_match or object_match
        if selected_match:
            is_tool = tool_match is not None
            selected_argument = (
                selected_match.group(0).split("[", 1)[1].rsplit("]", 1)[0]
                if is_tool and "[" in selected_match.group(0)
                else _call_first_argument(statement, selected_match)
            )
            scope = "\n".join([_guard_scope_before(lines, idx, selected_match.start()), selected_argument])
            selected_refs = _selected_sink_refs(statement, selected_match, tainted, is_tool=is_tool)
            direct_selection = _direct_llm_call(selected_argument, has_surface=True)
            if not selected_refs and not direct_selection:
                continue
            has_authz = _authz_guard_present(scope, selected_argument, selected_refs, direct_selection)
            has_allowlist = (
                bool(
                    (selected_refs and _guard_consumes_refs(scope, _TOOL_ALLOWLIST_RE, selected_refs))
                    or (direct_selection and _guard_wraps_direct_output(selected_argument, _TOOL_ALLOWLIST_RE))
                )
                if is_tool
                else True
            )
            if not (has_authz and has_allowlist):
                target_kind = "tool/action" if is_tool else "object identifier"
                emit_once(
                    _llm_finding(
                        check_id="AUTHZ-LLM-001",
                        file_rel=file_rel,
                        line_idx=idx,
                        lines=lines,
                        title=(
                            "Missing Authorization for LLM-Selected Action"
                            if is_tool
                            else "Missing Authorization for LLM-Selected Object"
                        ),
                        scenario=(
                            f"A model-generated {target_kind} reaches a protected operation without both a server-side "
                            "authorization/ownership decision and, for dynamic actions, a fixed allowlist. The model can "
                            "therefore direct application authority at a resource the caller may not control."
                        ),
                        severity="High",
                        cwe="CWE-862",
                        finding_type="FT-042",
                        remediation=(
                            "Resolve the model-selected value through an allowlisted server-side mapping, then authorize "
                            "the authenticated caller against the concrete tool, action, object, owner, and tenant."
                        ),
                    )
                )

    return findings


def _title_with_location(check: Check, file: str, line: int) -> str:
    # Mirrors the "<weakness class> — <file[:line]>" convention used by the
    # plugin's threat titles (see feedback_threat_model_finding_titles.md).
    return f"{check.name} — {file}:{line}"


def scan_file(
    file_abs: Path,
    file_rel: str,
    checks: list[Check],
) -> list[Finding]:
    try:
        if file_abs.stat().st_size > _MAX_FILE_BYTES:
            return []
        text = file_abs.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    if not text:
        return []
    lines = text.splitlines()

    findings: list[Finding] = []
    for check in checks:
        if check.exclude_file_patterns and _matches_any_glob(file_rel, check.exclude_file_patterns):
            continue
        if not _matches_any_glob(file_rel, check.file_patterns):
            continue

        for m in check.pattern.finditer(text):
            # Resolve line number: count newlines before the match start.
            line_idx = text.count("\n", 0, m.start())
            if _counter_match(lines, line_idx, check):
                continue
            if not _required_context_matches(lines, line_idx, check):
                continue
            findings.append(
                Finding(
                    local_id="",  # filled in by aggregator
                    check_id=check.id,
                    finding_type_id=check.finding_type,
                    source_type=_source_type_for(file_rel),
                    file=file_rel,
                    line=line_idx + 1,
                    evidence_snippet=_evidence_snippet(lines, line_idx),
                    title=_title_with_location(check, file_rel, line_idx + 1),
                    scenario=check.rationale,
                    severity=check.severity_if_violated,
                    cwe=[check.cwe] if check.cwe else [],
                    recommended_mitigation_title=check.remediation,
                    breach_vector=check.breach_vector,
                )
            )
    return findings


def scan_repo(repo_root: Path, checks: list[Check]) -> list[Finding]:
    findings: list[Finding] = []
    for path in _walk_repo(repo_root):
        try:
            rel = str(path.relative_to(repo_root))
        except ValueError:
            continue
        if _is_universally_excluded(rel):
            continue
        catalog_findings = scan_file(path, rel, checks)
        llm_findings = _scan_llm_output_file(path, rel)
        # Prefer the source-aware LLM finding when a broad catalog rule matched
        # the same sink and CWE. Both rows describe one affected statement and
        # mechanism; keeping both would violate the per-instance finding model.
        specific = {(f.line, tuple(f.cwe)) for f in llm_findings}
        findings.extend(f for f in catalog_findings if (f.line, tuple(f.cwe)) not in specific)
        findings.extend(llm_findings)
    # Assign sequential local IDs (SAF-001, SAF-002, …) deterministically by
    # (file, line, check_id).
    findings.sort(key=lambda f: (f.file, f.line, f.check_id))
    for i, f in enumerate(findings, start=1):
        f.local_id = f"SAF-{i:03d}"
    return findings


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def emit_sidecar(
    output_dir: Path,
    findings: list[Finding],
    checks_run: int,
) -> Path:
    doc = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks_run": checks_run,
        "violations": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    out_path = output_dir / ".source-auth-findings.json"
    tmp = out_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.replace(tmp, out_path)
    return out_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _discover_plugin_root() -> Path | None:
    """Resolve plugin root from CLAUDE_PLUGIN_ROOT or the script location."""
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if env and Path(env).is_dir():
        return Path(env)
    # scripts/ sits directly under plugin root
    here = Path(__file__).resolve().parent.parent
    if (here / "data").is_dir():
        return here
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Deterministic Node.js authorization-pattern scanner",
    )
    ap.add_argument("--repo-root", type=Path, required=True, help="Repository to scan")
    ap.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory for .source-auth-findings.json (omit with --dry-run)",
    )
    ap.add_argument("--checks", type=Path, help="Override checks YAML path")
    ap.add_argument("--dry-run", action="store_true", help="Print findings to stdout, do NOT write sidecar")
    ap.add_argument("--quiet", action="store_true", help="Suppress summary line")
    args = ap.parse_args(argv)

    repo_root: Path = args.repo_root.resolve()
    if not repo_root.is_dir():
        print(f"source_auth_scanner: repo-root {repo_root} is not a directory", file=sys.stderr)
        return 2
    if not args.dry_run and args.output_dir is None:
        print(
            "source_auth_scanner: --output-dir is required unless --dry-run is passed",
            file=sys.stderr,
        )
        return 2

    catalog_paths: list[Path] = []
    if args.checks:
        catalog_paths = [args.checks]
    else:
        plugin_root = _discover_plugin_root()
        if plugin_root is None:
            print(
                "source_auth_scanner: cannot resolve plugin root; pass --checks explicitly",
                file=sys.stderr,
            )
            return 2
        catalog_paths = [plugin_root / DEFAULT_CHECKS_REL]
        # Peer catalogs — run through the same engine; skip if absent.
        catalog_paths += [plugin_root / rel for rel in DEFAULT_EXTRA_CHECKS_REL]
    if not catalog_paths or not catalog_paths[0].is_file():
        print(
            f"source_auth_scanner: checks file {catalog_paths[0] if catalog_paths else '?'} not found", file=sys.stderr
        )
        return 2

    try:
        checks = []
        for cp in catalog_paths:
            if cp.is_file():
                checks.extend(load_checks(cp))
    except (ValueError, KeyError) as e:
        print(f"source_auth_scanner: failed to load checks: {e}", file=sys.stderr)
        return 2

    findings = scan_repo(repo_root, checks)

    if args.dry_run:
        print(json.dumps([asdict(f) for f in findings], indent=2))
        if not args.quiet:
            print(f"\nsource_auth_scanner: {len(findings)} finding(s) across {len(checks)} check(s)", file=sys.stderr)
        return 0

    output_dir: Path = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    sidecar = emit_sidecar(output_dir, findings, checks_run=len(checks))

    # Per-check tally for the summary
    tally: dict[str, int] = {}
    for f in findings:
        tally[f.check_id] = tally.get(f.check_id, 0) + 1

    if not args.quiet:
        print(
            f"source_auth_scanner: wrote {sidecar} ({len(findings)} finding(s); {len(checks)} check(s) run)",
            file=sys.stderr,
        )
        if tally:
            for cid in sorted(tally):
                print(f"  {cid:11} {tally[cid]:3} finding(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
