#!/usr/bin/env python3
"""source_auth_scanner.py — deterministic source-code authorization scanner.

Runs the rule catalog in `data/source-auth-checks.yaml` against every
matching source file in the repository and emits findings to
`$OUTPUT_DIR/.source-auth-findings.json`. Each finding carries a
counter-pattern-aware verdict so that legitimate ownership-checked code is
NOT flagged.

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
# P3 (weakness-class evidence model): the crypto rule pack lives in its own file
# for clarity but is a peer catalog — no separate scanner. Missing files are
# skipped silently, so adding a catalog here is safe.
DEFAULT_EXTRA_CHECKS_REL = [Path("data") / "crypto-checks.yaml"]

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
        findings.extend(scan_file(path, rel, checks))
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
        # Peer catalogs (P3 crypto pack) — run through the same engine; skip if absent.
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
