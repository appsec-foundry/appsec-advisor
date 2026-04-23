#!/usr/bin/env python3
"""
recon_patterns.py — deterministic recon pattern scans (Sprint 3 Item #1).

Replaces four pattern-only categories that the LLM-driven recon-scanner
used to grep for. These are pure regex scans with no judgement involved:

  Cat 11  Exposed Routes — admin/debug/swagger/actuator endpoints
  Cat 14  CI/CD Supply Chain — unpinned GitHub Actions (no SHA ref),
          GitLab CI image directives
  Cat 17  Postinstall Scripts — package.json lifecycle hooks,
          Python setup.py install-time shell, .npmrc ignore-scripts
  Cat 18  Security Headers & CORS — presence of hardening config

The script walks `REPO_ROOT` honouring `data/scan-excludes.yaml`, emits
findings as JSON on stdout, and runs in a single process instead of N
LLM turns. The recon-scanner agent consumes the JSON and skips these
categories in its grep loop.

CLI:
  python3 recon_patterns.py all             --repo-root <path>
  python3 recon_patterns.py exposed-routes  --repo-root <path>
  python3 recon_patterns.py ci-supply-chain --repo-root <path>
  python3 recon_patterns.py postinstall     --repo-root <path>
  python3 recon_patterns.py security-headers --repo-root <path>

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
from typing import Any, Iterable

# Try to load the central exclude policy. Fall back to a minimal built-in
# set if scan_excludes is unavailable — the script must not hard-fail when
# installed in a stripped-down plugin layout.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import scan_excludes
    _SCAN_EXCLUDES = True
except Exception:  # pragma: no cover
    _SCAN_EXCLUDES = False


# ---------------------------------------------------------------------------
# Default fallback excludes when scan_excludes.yaml is unavailable.
# ---------------------------------------------------------------------------
_FALLBACK_DIRS = frozenset({
    "node_modules", "vendor", "dist", "build", "target", "out", "coverage",
    ".next", ".nuxt", "__pycache__", "__tests__", "__mocks__",
    ".git", ".cache", ".venv", "venv",
})

_TEXT_EXT = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".scala", ".groovy",
    ".go", ".rb", ".php", ".cs", ".swift", ".rs", ".c", ".cc", ".cpp", ".h", ".hpp",
    ".yml", ".yaml", ".json", ".toml", ".xml", ".conf", ".cfg", ".ini",
    ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".md", ".adoc",
    ".env", ".npmrc", ".yarnrc",
    # Also match files with no extension when the name suggests code (Dockerfile, Jenkinsfile)
}


# Directories that MUST NEVER be scanned, even when scan_excludes' whitelist
# would otherwise include a file inside them (e.g. `node_modules/foo/package.json`).
# These are dependency/build caches — anything inside is third-party artefact,
# not application source. This is a recon-scanner-specific policy: the shared
# scan_excludes.yaml whitelist is designed for "don't overlook security
# signals" (a committed .env anywhere is interesting), but in the recon pass
# we explicitly want the application surface, not the dependency tree.
_HARD_EXCLUDE_DIRS = frozenset({
    "node_modules",
    "vendor",
    "bower_components",
    ".tox",
    ".gradle",
    ".cache", ".appsec-cache",
    "__pycache__",
    "dist", "build", "target", "out", "coverage",
    ".next", ".nuxt",
    ".git",
    "Pods",
})

# Directory-name glob patterns that are also hard-excluded. Covers python
# virtualenv variants (.venv, venv, .venv-tests, venv_linux, …) and build
# directories whose names carry a profile suffix.
_HARD_EXCLUDE_PATTERNS = (
    ".venv*", "venv", "venv-*", "venv_*",
    "build-*", "dist-*", "target-*",
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


def _is_excluded(rel_path: str) -> bool:
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
        "Dockerfile", "Containerfile", "Jenkinsfile", "Makefile",
        ".gitlab-ci.yml", ".gitlab-ci.yaml", "bitbucket-pipelines.yml",
        "azure-pipelines.yml", "azure-pipelines.yaml", ".travis.yml",
        "renovate.json", ".renovaterc", ".npmrc", ".yarnrc", "package.json",
        "setup.py", "setup.cfg", "pyproject.toml",
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
    for dirpath, dirnames, filenames in os.walk(repo_root):
        # Prune excluded directories up-front for speed
        rel_dir = str(Path(dirpath).relative_to(repo_root)).replace("\\", "/")
        dirnames[:] = [d for d in dirnames if not _is_excluded(
            f"{rel_dir}/{d}" if rel_dir != "." else d
        )]
        for name in filenames:
            rel = str((Path(dirpath) / name).relative_to(repo_root)).replace("\\", "/")
            if _is_excluded(rel):
                continue
            p = Path(dirpath) / name
            if not _should_read(p):
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
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".scala",
    ".go", ".rb", ".php", ".cs", ".swift", ".rs",
}


def scan_exposed_routes(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CAT11_EXTS:
            continue
        for line_no, text in _grep_file(p, _CAT11_PATTERN):
            findings.append({
                "category": 11,
                "file": str(p.relative_to(repo_root)).replace("\\", "/"),
                "line": line_no,
                "match": text.strip(),
            })
    return {"category": 11, "name": "Exposed Routes", "findings": findings, "count": len(findings)}


# ---------------------------------------------------------------------------
# Category 14 — CI/CD supply chain
# ---------------------------------------------------------------------------


# `uses: owner/name@ref` where ref is NOT a 40-char hex SHA.
# Lines typically start with `- uses:` (YAML list item) but may also appear
# as plain `uses:` inside a composite-action step. Match both.
_CAT14_UNPINNED_ACTION = re.compile(
    r"^(?P<indent>\s*-?\s*)uses:\s*(?P<ref>[^\s#@]+@(?P<tag>[^\s#]+))"
)
_SHA40 = re.compile(r"^[0-9a-f]{40}$")

# GitLab CI `image: foo:bar` directive (informational — non-pinned tags)
_CAT14_GITLAB_IMAGE = re.compile(
    r"^\s*image:\s*(?P<image>[^\s#]+)", re.MULTILINE
)


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
                findings.append({
                    "category": 14,
                    "subcategory": "unpinned-github-action",
                    "file": str(p.relative_to(repo_root)).replace("\\", "/"),
                    "line": n,
                    "action": m.group("ref"),
                    "tag": tag,
                    "match": line.strip(),
                })

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
            findings.append({
                "category": 14,
                "subcategory": "gitlab-image",
                "file": candidate,
                "line": line_no,
                "image": m.group("image"),
                "match": text[m.start():m.end()].strip(),
            })

    return {
        "category": 14,
        "name": "CI/CD Supply Chain",
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
                findings.append({
                    "category": 17,
                    "subcategory": "npm-lifecycle",
                    "file": rel,
                    "line": None,
                    "hook": key,
                    "command": str(value),
                })

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
                findings.append({
                    "category": 17,
                    "subcategory": "npmrc-ignore-scripts",
                    "file": ".npmrc",
                    "line": n,
                    "match": line.strip(),
                })
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
            findings.append({
                "category": 17,
                "subcategory": "python-setup-shell",
                "file": rel,
                "line": line_no,
                "match": text.strip(),
            })

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
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".java", ".kt", ".go", ".rb", ".php", ".cs", ".rs",
    ".yml", ".yaml", ".conf", ".toml",
}


def scan_security_headers(repo_root: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in _walk_repo(repo_root):
        if p.suffix.lower() not in _CAT18_EXTS:
            continue
        for line_no, text in _grep_file(p, _CAT18_PATTERN):
            findings.append({
                "category": 18,
                "file": str(p.relative_to(repo_root)).replace("\\", "/"),
                "line": line_no,
                "match": text.strip(),
            })
    return {
        "category": 18,
        "name": "Security Headers & CORS",
        "findings": findings,
        "count": len(findings),
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run_all(
    repo_root: Path,
    include_manifest: bool = False,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "version": 1,
        "repo_root": str(repo_root),
        "categories": {
            "11": scan_exposed_routes(repo_root),
            "14": scan_ci_supply_chain(repo_root),
            "17": scan_postinstall(repo_root),
            "18": scan_security_headers(repo_root),
        },
    }
    if include_manifest:
        manifest: list[str] = []
        # Re-walk once purely to collect the manifest; the per-category
        # scan functions already walked individually above.
        for _ in _walk_repo(repo_root, manifest=manifest):
            pass
        out["scan_manifest"] = sorted(manifest)
        out["scan_manifest_count"] = len(manifest)
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


_DISPATCH = {
    "exposed-routes":   (scan_exposed_routes, "Cat 11"),
    "ci-supply-chain":  (scan_ci_supply_chain, "Cat 14"),
    "postinstall":      (scan_postinstall, "Cat 17"),
    "security-headers": (scan_security_headers, "Cat 18"),
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
