#!/usr/bin/env python3
"""The deterministic supply-chain control producer for §6.11.

What this emits, per repo:

  1. Rows in `$OUTPUT_DIR/.security-controls.json`, under domain
     "Operations Runtime and Supply Chain Controls":
       • "Dependency and build integrity" — one grouped row whose sub-controls
         are "Automated SCA scanning", "Automated dependency updates",
         "Lockfile hygiene", "CI install integrity", "Action pinning",
         "Base image pinning" and "Install scripts". The row's effectiveness is
         the worst of its sub-controls.
       • "Static analysis (SAST)".
     A sub-control whose surface the repository lacks (no Dockerfile, no CI
     install step, no CI action or image reference) is not emitted. One whose
     theme the model already covers with a rule-backed or catalog control
     (data/supply-chain-controls.yaml) is not emitted either; that control
     receives the sub-control's `linked_checks` instead.

  2. For each patch-management sub-control (the three named in
     data/sca-practice-severity.yaml) rated `Missing`, `Partial` or `Weak`, a
     meta-finding in `$OUTPUT_DIR/.sca-practice-findings.json`. The yaml
     builder (model/build_threat_model_yaml.py) allocates MF-NNN ids, and drops
     one whose `linked_checks` a final finding already reports.

Every rating comes from repository files the scan inventory lists
(`analyzers.scan_excludes.repo_inventory`; inside git only committed and
untracked-unignored files, so an ignored lockfile on disk does not count) and,
for CI, from the steps the pipeline actually runs (`_executable_lines`): never
from a comment, a step label, string data, or LLM-authored recon text (FE-2).
Evidence is `file:line`.

`linked_checks` (data/supply-chain-controls.yaml) are resolved to findings by
the yaml builder, after the run has filtered its findings, so a row never
points at a finding the report does not contain.

Detection is **passive**: this script never runs `npm audit`, `pip-audit`,
`snyk` or any package-manager, network or vulnerability-database tool.

A peer emitter (`model/emit_dep_update_activity.py`) consults `git log` over a
90-day window for dep-update commits. When that sidecar reports `active`
cadence the "Automated dependency updates" rating is lifted even without
Dependabot / Renovate config files in the repo.

Idempotent — re-running replaces this producer's rows (including the three
top-level rows of the earlier layout) and the sidecar list. Other rows are
preserved verbatim.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import fnmatch
import functools
import json
import re
import shlex
import sys
from pathlib import Path

import yaml
from analyzers.scan_excludes import RepoInventory, repo_inventory
from shared._supply_chain_config import renovate_configs

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DOMAIN = "Operations Runtime and Supply Chain Controls"

CONTROL_GROUP = "Build pipeline and dependency controls"
CONTROL_SAST = "Static analysis (SAST)"

CONTROL_SCANNING = "Automated SCA scanning"
CONTROL_UPDATES = "Automated dependency updates"
CONTROL_LOCKFILE = "Lockfile hygiene"
CONTROL_CI_INSTALL = "CI install integrity"
CONTROL_ACTION_PINNING = "Action pinning"
CONTROL_BASE_IMAGE = "Base image pinning"
CONTROL_INSTALL_SCRIPTS = "Install scripts"

# The patch-management triple: the meta-findings, the severity policy and the
# §6.13 derived rating (sections-contract `patch_management_derived_rating`).
SCA_CONTROLS = (CONTROL_SCANNING, CONTROL_UPDATES, CONTROL_LOCKFILE)

# A process tool (SCA, dependency updates, SAST) often runs outside the
# repository: a GitHub App, CodeQL default setup, an organization policy. With
# no CI step and no configuration marker in the repository its use is "not
# evidenced" — never Missing, no meta-finding, no downgrade of the row. The
# state is a sub-control without `effectiveness` (that enum has no such value)
# and with this `status`.
NOT_EVIDENCED = "not_evidenced"
NOT_EVIDENCED_NOTE = (
    "Not evidenced in the repository; it may run outside it (GitHub App, default setup, organization policy, agent)."
)

_PLUGIN_ROOT = Path(__file__).resolve().parents[2]

# Top-level rows this producer owns. The triple was emitted as three rows
# before the grouped layout; a re-run on such a sidecar replaces them.
_OWN_ROWS = frozenset({CONTROL_GROUP, CONTROL_SAST, *SCA_CONTROLS})

_RANK = {"Missing": 0, "Unsafe": 0, "Weak": 1, "Partial": 2, "Adequate": 3}

# Detection signatures.

# Tools that count as "blocking" SCA when found in CI workflow YAML.
# Conservative — only well-known dedicated tools and language-native
# audit commands. A repo using a homegrown shell script is not credited.
#
# Every token must describe an *invocation*: a command with its
# subcommand, or a marketplace action reference. A bare tool name is not
# enough — tool names appear in comments, PR templates, and string data,
# and crediting them produced false SCA evidence (see the `grype`
# alternation inside a PR-spam regex, 2026-07).
#
# CodeQL is deliberately absent. `github/codeql-action` is code scanning
# (SAST); dependency scanning is a separate GitHub feature, so a CodeQL
# workflow alone must not be credited as SCA.
_SCA_TOOL_TOKENS = (
    r"\bsnyk\s+test\b",
    r"\bsnyk\s+monitor\b",
    r"\bsnyk/actions\b",
    r"\btrivy\s+fs\b",
    r"\btrivy\s+repo\b",
    r"\baquasecurity/trivy-action\b",
    r"\bgrype\s+\S",
    r"\banchore/scan-action\b",
    r"\bosv-scanner\b",
    r"\bdependency-check\b",
    r"\bactions/dependency-review-action\b",
    r"\bnpm\s+audit\b",
    r"\bpip-audit\b",
    r"\bcargo\s+audit\b",
    r"\bbundle\s+audit\b",
    r"\bcomposer\s+audit\b",
    r"\bdotnet\s+list\s+package\s+--vulnerable\b",
    r"\bgovulncheck\b",
    r"\bmend\b|\bwhitesource\b",
)
_SCA_TOOL_RE = re.compile("|".join(_SCA_TOOL_TOKENS), re.IGNORECASE)

# Static analysis invocations. CodeQL counts only with its `analyze` step:
# `init` alone sets the database up and reports nothing.
_SAST_TOOL_TOKENS = (
    r"\bgithub/codeql-action/analyze\b",
    r"\bsemgrep\s+(?:ci|scan)\b",
    r"\b(?:returntocorp|semgrep)/semgrep-action\b",
    r"\bsonar-scanner\b",
    r"\bsonarsource/sonar(?:qube|cloud)-(?:scan|github)-action\b",
    r"\bbandit\s+-",
    r"\bgosec\s+\S",
    r"(?:^|[\s;&|])brakeman(?:\s|$)",
)
_SAST_TOOL_RE = re.compile("|".join(_SAST_TOOL_TOKENS), re.IGNORECASE)

# GitLab CI templates that run a scanner unless their `<NAME>_DISABLED`
# variable switches it off. Matched on the template file name.
_GITLAB_SCA_TEMPLATES = frozenset({"Auto-DevOps.gitlab-ci.yml", "Dependency-Scanning.gitlab-ci.yml"})
_GITLAB_SAST_TEMPLATES = frozenset({"Auto-DevOps.gitlab-ci.yml", "SAST.gitlab-ci.yml"})
_GITLAB_TEMPLATE_RE = re.compile(r"^\s*(?:-\s*)?template:\s*['\"]?([^'\"\s#]+)")

# A scanner whose failure is discarded cannot block anything.
_SUPPRESSOR_RE = re.compile(r"\|\|\s*true\b|\|\|\s*:|--exit-code[= ]0\b|\|\|\s*exit\s+0\b", re.IGNORECASE)
_ALLOW_FAILURE_RE = re.compile(r"^\s*(?:continue-on-error|allow_failure)\s*:\s*['\"]?true\b", re.IGNORECASE)

# Commands that install strictly from a lockfile / hash set.
_DETERMINISTIC_INSTALL_RE = re.compile(
    "|".join(
        (
            r"\bnpm\s+ci\b",
            r"--frozen-lockfile",
            r"--immutable\b",
            r"--require-hashes",
            r"\bcargo\s+build\s+--locked",
            r"\bdotnet\s+restore\s+--locked",
            r"\bbundle\s+install\s+--frozen",
            r"\bgo\s+mod\s+verify",
            r"--verify-locks",
            r"--strict-checksums",
            r"\buv\s+sync\b[^\n]*--(?:frozen|locked)",
            r"\buv\s+pip\s+sync\b",
            r"\bpip-sync\b",
            r"\bpoetry\s+install\b[^\n]*--sync",
            r"\bpipenv\s+install\b[^\n]*--deploy",
            r"\bpdm\s+sync\b",
            r"\bpdm\s+install\b[^\n]*--frozen-lockfile",
        )
    ),
    re.IGNORECASE,
)

# Commands that resolve versions at install time. `pip install` is mutable
# unless the same command carries --require-hashes.
_MUTABLE_INSTALL_RE = re.compile(
    r"\bnpm\s+(?:install|i)\b|\byarn\s+add\b|\bpnpm\s+add\b"
    r"|\bpip\d?\s+install\b(?![^\n]*--require-hashes)(?![^\n]*-r\s+\S+\.lock)",
    re.IGNORECASE,
)

# A CLI tool installed globally is not part of the product's dependency graph.
_GLOBAL_TOOL_INSTALL_RE = re.compile(r"(?:npm|pnpm|yarn)\s+(?:install|i|add)\s+(?:-g\b|--global\b)", re.IGNORECASE)

# Remote code piped straight into an interpreter. The fetched bytes are never
# pinned or verified, so whoever controls that URL controls the build. Only
# the fetch-into-interpreter forms match; a plain download followed by a
# checksum check does not.
_FETCH_EXEC_RE = re.compile(
    "|".join(
        (
            r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",
            r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python\d?|perl|ruby|node)\b",
            r"(?:source|\.)\s+<\(\s*(?:curl|wget)\b",
            r"(?:ba)?sh\s+<\(\s*(?:curl|wget)\b",
            r"eval\s+[\"'`]?\$\(\s*(?:curl|wget)\b",
            r"(?:python\d?|node|ruby)\s+-[ce]\s+[\"']?\$\(\s*(?:curl|wget)\b",
            r"(?:iex|Invoke-Expression)\b[^\n]*(?:DownloadString|Invoke-WebRequest|iwr)\b",
            r"(?:Invoke-WebRequest|iwr)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b",
        )
    ),
    re.IGNORECASE,
)

# Install-hook variants of the same threat.
_HOOK_EXEC_RE = re.compile(
    _FETCH_EXEC_RE.pattern
    + "|"
    + "|".join(
        (
            r"base64\s+(?:-d|--decode)[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
            r"(?:node|python\d?|ruby|perl)\s+-[ce]\s[^\n]*https?://",
            r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output))\s*\([^)]*https?://",
            r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output))\s*\([^)]*(?:curl|wget)\b",
        )
    ),
    re.IGNORECASE,
)

# Hooks that run on a plain `npm install`; they decide the Partial rating.
# `prepare` is absent: `"prepare": "husky install"` is common and says nothing
# about supply-chain posture. The wider list is scanned only for dangerous
# content.
_INSTALL_HOOK_KEYS = ("preinstall", "install", "postinstall")
_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare", "prebuild", "postpublish")
_SETUP_SHELL_RE = re.compile(r"cmdclass\s*=|os\.system\s*\(|subprocess\.(?:run|call|Popen)")
_IGNORE_SCRIPTS_RE = re.compile(
    r"--ignore-scripts|--no-scripts|npm_config_ignore_scripts|npm\s+config\s+(?:set\s+)?ignore-scripts\s+true"
    r"|onlyBuiltDependencies",
    re.IGNORECASE,
)

_SHA_REF_RE = re.compile(r"[0-9a-fA-F]{40}|sha256:[0-9a-fA-F]{64}")
_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)")
_IMAGE_RE = re.compile(r"^\s*(?:-\s*)?image:\s*['\"]?([^\s'\"#]*)")
_IMAGE_NAME_RE = re.compile(r"^\s*name:\s*['\"]?([^\s'\"#]+)")

# --- Executable-step detection -------------------------------------------
#
# Keys whose value — inline or as a following block scalar / list — is a
# shell command or an action reference.
_EXEC_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?(run|script|before_script|after_script|uses)\s*:\s*(.*)$")

# `with:` opens a non-executable region. An `actions/github-script` step
# keeps JavaScript under `with: script:`; tool names quoted in that
# JavaScript are data, not invocations.
_NON_EXEC_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?(with)\s*:\s*(.*)$")

_COMMENT_RE = re.compile(r"^\s*(?:#|//)")

# A value that only opens a block scalar / list — the command follows on
# the indented lines below.
_BLOCK_OPENERS = frozenset({"", "|", ">", "|-", ">-", "|+", ">+"})

_CI_FILE_GLOBS = (
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
)

# Lockfiles per ecosystem. A repo can have multiple.
_LOCKFILE_PATTERNS = {
    "npm": ("package-lock.json", "npm-shrinkwrap.json"),
    "yarn": ("yarn.lock",),
    "pnpm": ("pnpm-lock.yaml",),
    "pip": ("Pipfile.lock", "poetry.lock", "uv.lock", "requirements.lock"),
    "go": ("go.sum",),
    "gem": ("Gemfile.lock",),
    "composer": ("composer.lock",),
    "cargo": ("Cargo.lock",),
}

# Manifest files that imply a lockfile should exist for the ecosystem.
_MANIFEST_TO_ECOSYSTEM = {
    "package.json": "npm",  # or yarn/pnpm — any of the three is fine
    "requirements.txt": "pip",
    "Pipfile": "pip",
    "pyproject.toml": "pip",
    "go.mod": "go",
    "Gemfile": "gem",
    "composer.json": "composer",
    "Cargo.toml": "cargo",
}

# Directories whose manifests and lockfiles are not the repository's own:
# installed dependencies and build output.
_DEPENDENCY_DIRS = frozenset({"node_modules", ".venv", "venv", "vendor", ".git", "__pycache__", "site-packages"})
_VENDORED_DIRS = _DEPENDENCY_DIRS | {"target", "build", "dist"}

# Asset-tier normalization.
_TIER_RE = re.compile(r"\bT(?:ier\s*)?([1-4])\b", re.IGNORECASE)

# One clause per rating, for the sub-controls outside the patch-management triple.
_REASONS = {
    CONTROL_SCANNING: {"Weak": "A dependency scanner runs in CI, but its failure cannot block the build"},
    CONTROL_CI_INSTALL: {
        "Adequate": "CI installs dependencies only from the lockfile",
        "Partial": "Some CI install steps resolve versions at install time instead of using the lockfile",
        "Missing": "CI installs dependencies by resolving versions at install time",
    },
    CONTROL_ACTION_PINNING: {
        "Adequate": "Every CI action and image reference is pinned to a commit SHA or digest",
        "Partial": "Some CI action or image references use a mutable tag or branch",
        "Missing": "CI action and image references use mutable tags or branches",
    },
    CONTROL_BASE_IMAGE: {
        "Adequate": "Every base image is pinned to a digest",
        "Partial": "Some base images use a version tag instead of a digest",
        "Missing": "Base images use no tag or a mutable tag",
    },
    CONTROL_INSTALL_SCRIPTS: {
        "Adequate": "No install-time hook runs unreviewed code",
        "Partial": "Install-time hooks run without an ignore-scripts policy",
        "Missing": "An install-time hook fetches and executes remote code",
        "Weak": "A build step executes code fetched from an external URL",
    },
    CONTROL_SAST: {
        "Adequate": "Static analysis runs in CI",
        "Missing": "No static analysis tool runs in CI",
    },
}


# ---------------------------------------------------------------------------
# Asset-tier resolution
# ---------------------------------------------------------------------------


def _normalize_tier(raw: str | None) -> str:
    """Normalize 'Tier 1 — Restricted' / 'T1' / 'tier-1' → 'T1'.

    Default to T2 (conservative middle) when unparseable.
    """
    if not raw:
        return "T2"
    m = _TIER_RE.search(raw)
    if not m:
        return "T2"
    return f"T{m.group(1)}"


# ---------------------------------------------------------------------------
# Repository files — deterministic, inventory driven
# ---------------------------------------------------------------------------


def _inventory(repo_root: Path, inventory: RepoInventory | None) -> RepoInventory:
    return inventory if inventory is not None else repo_inventory(repo_root)


def _belongs(inventory: RepoInventory, rel: str) -> bool:
    """A listed file git does not know as untracked; outside git every listed file."""
    return rel in inventory and inventory.is_tracked(rel) is not False


def _repo_files(repo_root: Path, inventory: RepoInventory, match, skip: frozenset[str] = _VENDORED_DIRS) -> list[str]:
    """Repo-relative files whose name satisfies ``match``, outside the ``skip`` directories."""
    out = []
    for rel in inventory.files:
        parts = rel.split("/")
        if any(part in skip for part in parts[:-1]) or not match(parts[-1]):
            continue
        if _belongs(inventory, rel) and (repo_root / rel).is_file():
            out.append(rel)
    return sorted(out)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_ci_files(repo_root: Path, inventory: RepoInventory | None = None) -> list[tuple[Path, str]]:
    inventory = _inventory(repo_root, inventory)
    out: list[tuple[Path, str]] = []
    for glob in _CI_FILE_GLOBS:
        for path in sorted(repo_root.glob(glob)):
            if not path.is_file() or not _belongs(inventory, path.relative_to(repo_root).as_posix()):
                continue
            try:
                out.append((path, path.read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
    return out


def _rel(repo_root: Path, path: Path) -> str:
    return path.relative_to(repo_root).as_posix() if path.is_relative_to(repo_root) else str(path)


def _executable_lines(path: Path, text: str) -> list[tuple[int, str]]:
    """Return the (line number, inspectable text) pairs of a CI definition
    that actually run something.

    A tool name is only evidence when the pipeline invokes it. This filter
    keeps the values of `run` / `script` / `before_script` / `after_script`
    and `uses`, including their block-scalar and list bodies, and drops
    everything else: comments, `name:` labels, `if:` conditions, and any
    `with:` body (where `actions/github-script` keeps JavaScript).

    `Jenkinsfile` is Groovy, not YAML — there is no key structure to walk,
    so every non-comment line stays inspectable.

    Accepted false negative: a scanner shelled out from inside a
    `github-script` body is not credited. Inspecting those bodies is what
    produced the false evidence this filter exists to prevent.
    """
    lines = text.splitlines()
    if path.name == "Jenkinsfile":
        return [(i, line) for i, line in enumerate(lines, start=1) if line.strip() and not _COMMENT_RE.match(line)]

    out: list[tuple[int, str]] = []
    exec_indent: int | None = None
    suppress_indent: int | None = None
    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue  # blank lines are legal inside a block scalar
        leading = len(line) - len(line.lstrip())
        if suppress_indent is not None and leading <= suppress_indent:
            suppress_indent = None
        if exec_indent is not None and leading <= exec_indent:
            exec_indent = None
        if _COMMENT_RE.match(line):
            continue

        non_exec = _NON_EXEC_KEY_RE.match(line)
        if non_exec:
            suppress_indent = non_exec.start(2)
            continue
        if suppress_indent is not None:
            continue

        key = _EXEC_KEY_RE.match(line)
        if key:
            value = key.group(3).strip()
            if value in _BLOCK_OPENERS:
                exec_indent = key.start(2)
            else:
                out.append((i, value))
            continue
        if exec_indent is not None:
            out.append((i, line))
    return out


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def _mapping_keys(lines: list[str], i: int) -> list[str]:
    """The keys of the mapping that holds line ``i``; for a list item, the item's own keys."""
    indent = _indent(lines[i])
    if lines[i].lstrip().startswith("- "):
        stop = next(
            (j for j in range(i + 1, len(lines)) if lines[j].strip() and _indent(lines[j]) <= indent), len(lines)
        )
        return [lines[i].lstrip()[2:]] + [
            lines[j] for j in range(i + 1, stop) if lines[j].strip() and _indent(lines[j]) == indent + 2
        ]
    parent = next((j for j in range(i - 1, -1, -1) if lines[j].strip() and _indent(lines[j]) < indent), -1)
    end = next((j for j in range(i + 1, len(lines)) if lines[j].strip() and _indent(lines[j]) < indent), len(lines))
    keys = [lines[j] for j in range(parent + 1, end) if lines[j].strip() and _indent(lines[j]) == indent]
    if parent >= 0 and lines[parent].lstrip().startswith("- ") and _indent(lines[parent]) + 2 == indent:
        keys.append(lines[parent].lstrip()[2:])  # the item's first key sits on its dash line
    return keys


def _allows_failure(lines: list[str], number: int) -> bool:
    """True when a block around line ``number`` may fail without failing the pipeline.

    Walks from the line to the file root and checks the keys beside each
    enclosing block: `continue-on-error` on a GitHub step or job,
    `allow_failure` on a GitLab job. Another step's or job's setting is not a
    key of an enclosing block and does not count.
    """
    i: int | None = number - 1
    while i is not None:
        if any(_ALLOW_FAILURE_RE.match(key) for key in _mapping_keys(lines, i)):
            return True
        indent = _indent(lines[i])
        i = next((j for j in range(i - 1, -1, -1) if lines[j].strip() and _indent(lines[j]) < indent), None)
    return False


def _gitlab_template_hits(path: Path, text: str, templates: frozenset[str], disabled_variable: str) -> list[int]:
    """Lines of a GitLab CI file that include a scanner template the file does not switch off."""
    if not path.name.startswith(".gitlab-ci."):
        return []
    if re.search(rf"(?m)^\s*{re.escape(disabled_variable)}\s*:\s*['\"]?(?:true|1|yes)\b", text, re.IGNORECASE):
        return []
    hits = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _COMMENT_RE.match(line):
            continue
        match = _GITLAB_TEMPLATE_RE.match(line)
        if match and match.group(1).rsplit("/", 1)[-1] in templates:
            hits.append(i)
    return hits


@functools.lru_cache(maxsize=1)
def _control_table() -> dict[str, dict]:
    return _load_control_table(_PLUGIN_ROOT)


def _marker_hits(repo_root: Path, inventory: RepoInventory, control: str) -> list[str]:
    """`file:1` of every repository file that configures ``control``'s tool outside CI (data/supply-chain-controls.yaml)."""
    markers = (_control_table().get(control) or {}).get("markers") or []
    return [
        f"{rel}:1"
        for rel in sorted(inventory.files)
        if _belongs(inventory, rel) and any(fnmatch.fnmatchcase(rel, marker) for marker in markers)
    ]


# ---------------------------------------------------------------------------
# Classifiers — each returns (effectiveness, ["file:line", ...]); a None
# effectiveness means the repository has no surface for the sub-control, and
# NOT_EVIDENCED that a process tool shows no trace in the repository.
# ---------------------------------------------------------------------------


def classify_sca_scanning(repo_root: Path, inventory: RepoInventory | None = None) -> tuple[str, list[str]]:
    """Return (Adequate|Partial|Weak|Missing, evidence_file_lines).

    Inspected signal: dependency-vulnerability scanners invoked by a CI
    definition — `_SCA_TOOL_RE` matched against executable step values
    only (`_executable_lines`) — and a GitLab CI include of a dependency
    scanning template its `DEPENDENCY_SCANNING_DISABLED` variable does not
    switch off.

    Trigger: at least one matching invocation. `Weak` when every one may
    fail without failing the pipeline (`|| true`, `--exit-code 0`,
    `continue-on-error` / `allow_failure` on its step or job). Otherwise
    `Adequate` when the number of CI files carrying one is at least the
    number of detected package ecosystems, else `Partial`. Without an
    invocation, a configuration marker of a tool that runs outside CI
    (`.snyk`, a Mend config, …) is `Adequate`; nothing at all is
    NOT_EVIDENCED, because such a tool may run outside the repository.

    False-positive exclusions: comments, `name:`/`if:` text, `with:`
    bodies, bare tool names without a subcommand, and CodeQL — none of
    those run a dependency scanner.

    Required evidence: the `<ci file>:<line>` of the invocation itself,
    which is what the control assessment and any meta-finding cite.
    """
    inventory = _inventory(repo_root, inventory)
    live: list[str] = []
    advisory: list[str] = []
    for path, text in _read_ci_files(repo_root, inventory):
        lines = text.splitlines()
        rel = _rel(repo_root, path)
        numbers = [i for i, value in _executable_lines(path, text) if _SCA_TOOL_RE.search(value)]
        numbers += _gitlab_template_hits(path, text, _GITLAB_SCA_TEMPLATES, "DEPENDENCY_SCANNING_DISABLED")
        file_live = [
            i for i in sorted(numbers) if not _SUPPRESSOR_RE.search(lines[i - 1]) and not _allows_failure(lines, i)
        ]
        if file_live:
            live.append(f"{rel}:{file_live[0]}")
        elif numbers:
            advisory.append(f"{rel}:{min(numbers)}")
    if not live:
        if advisory:
            return "Weak", advisory
        markers = _marker_hits(repo_root, inventory, CONTROL_SCANNING)
        return ("Adequate", markers) if markers else (NOT_EVIDENCED, [])
    if len(live) >= max(1, len(_detect_ecosystems(repo_root, inventory))):
        return "Adequate", live
    return "Partial", live


def classify_sast(repo_root: Path, inventory: RepoInventory | None = None) -> tuple[str, list[str]]:
    """Static analysis invoked by a CI definition, or a GitLab SAST template not switched off by `SAST_DISABLED`.

    Same exclusions as `classify_sca_scanning`; a CodeQL `init` step without
    `analyze` is not credited. A configuration marker (`sonar-project.properties`,
    a Semgrep or CodeQL config) is evidence too; nothing at all is NOT_EVIDENCED.
    """
    inventory = _inventory(repo_root, inventory)
    hits = []
    for path, text in _read_ci_files(repo_root, inventory):
        numbers = [i for i, value in _executable_lines(path, text) if _SAST_TOOL_RE.search(value)]
        numbers += _gitlab_template_hits(path, text, _GITLAB_SAST_TEMPLATES, "SAST_DISABLED")
        if numbers:
            hits.append(f"{_rel(repo_root, path)}:{min(numbers)}")
    hits += _marker_hits(repo_root, inventory, CONTROL_SAST)
    return ("Adequate", hits) if hits else (NOT_EVIDENCED, [])


def _load_activity_sidecar(output_dir: Path) -> dict:
    """Load .dep-update-activity.json when present. Graceful degradation
    — model/emit_dep_update_activity.py is a peer emitter and may not have been
    run yet (e.g. in a degraded run); we treat its absence as 'unknown
    cadence' rather than failing."""
    path = output_dir / ".dep-update-activity.json"
    if not path.is_file():
        return {"cadence": "unknown"}
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {"cadence": "unknown"}
    except (json.JSONDecodeError, OSError):
        return {"cadence": "unknown"}


def classify_auto_updates(
    repo_root: Path, output_dir: Path, inventory: RepoInventory | None = None
) -> tuple[str, list[str]]:
    inventory = _inventory(repo_root, inventory)
    evidence: list[str] = []
    dependabot = _marker_hits(repo_root, inventory, CONTROL_UPDATES)
    has_dependabot = bool(dependabot)
    evidence += dependabot[:1]
    active_renovate = [
        f"{rel}:1"
        for rel, cfg in renovate_configs(repo_root)
        if cfg.get("enabled") is not False and _belongs(inventory, rel)
    ] + _package_json_renovate(repo_root, inventory)
    has_renovate = bool(active_renovate)
    evidence += active_renovate[:1]

    # Activity sidecar — when model/emit_dep_update_activity.py ran first, lift
    # the rating out of Missing for repos that patch on a regular cadence
    # even without Dependabot / Renovate config files. Covers (a) Renovate
    # hosted-app mode (no config file in repo), (b) Dependabot
    # security-updates (configured at repo settings, no file), (c) teams
    # with manual but disciplined update PRs.
    activity = _load_activity_sidecar(output_dir)
    cadence = activity.get("cadence", "unknown")
    if activity.get("dep_update_commits"):
        evidence.append(
            f"git-log: {activity['dep_update_commits']} dep-update commit(s) in "
            f"last {activity.get('window_days', 90)} days "
            f"(cadence={cadence})"
        )

    if not has_dependabot and not has_renovate:
        # No config file — fall back to the activity signal. Without it the
        # tool may still run outside the repository (Dependabot security
        # updates, the hosted Renovate app), so the gap is not evidenced.
        if cadence == "active":
            return "Partial", evidence  # patching happens but not automated by config
        return NOT_EVIDENCED, []

    # Config file present. Partial: only one of {Dependabot, Renovate}
    # present AND multiple ecosystems detected. The single-tool case is
    # fine for single-eco repos.
    ecosystems = _detect_ecosystems(repo_root, inventory)
    if len(ecosystems) > 1 and not (has_dependabot and has_renovate):
        if has_dependabot:
            try:
                dependabot_path = repo_root / dependabot[0].rsplit(":", 1)[0]
                cfg = yaml.safe_load(dependabot_path.read_text(encoding="utf-8", errors="replace"))
                covered = {u.get("package-ecosystem") for u in (cfg or {}).get("updates", []) if isinstance(u, dict)}
                eco_alias = {
                    "npm": {"npm", "yarn", "pnpm"},
                    "pip": {"pip"},
                    "gomod": {"go"},
                    "bundler": {"gem"},
                    "composer": {"composer"},
                    "cargo": {"cargo"},
                    "maven": {"maven"},
                    "gradle": {"maven"},
                    "nuget": {"nuget"},
                }
                covered_norm: set[str] = set()
                for c in covered:
                    if c in eco_alias:
                        covered_norm |= eco_alias[c]
                    elif c:
                        covered_norm.add(c)
                if not ecosystems.issubset(covered_norm):
                    return "Partial", evidence
            except (yaml.YAMLError, OSError):
                pass
    return "Adequate", evidence


def _package_json_renovate(repo_root: Path, inventory: RepoInventory) -> list[str]:
    """`package.json:<line>` when the root manifest carries an enabled `renovate` config."""
    if not _belongs(inventory, "package.json"):
        return []
    text = _read(repo_root / "package.json")
    try:
        config = (json.loads(text) or {}).get("renovate")
    except (json.JSONDecodeError, AttributeError):
        return []
    if not isinstance(config, dict) or config.get("enabled") is False:
        return []
    line = next((i for i, row in enumerate(text.splitlines(), 1) if re.search(r'"renovate"\s*:', row)), 1)
    return [f"package.json:{line}"]


def _hashed_requirements(repo_root: Path, inventory: RepoInventory, rel: str, seen: set[str] | None = None) -> bool:
    """True when every requirement in ``rel`` (and the files it includes) is `==`-pinned with a sha256 hash."""
    seen = set() if seen is None else seen
    if rel in seen or not _belongs(inventory, rel):
        return False
    seen.add(rel)
    found = False
    for row in _read(repo_root / rel).replace("\\\n", " ").splitlines():
        row = row.split(" #", 1)[0].strip()
        if not row or row.startswith("#"):
            continue
        include = re.match(r"(?:-r\s*|--requirement[= ]+)(\S+)", row)
        if include:
            target = (Path(rel).parent / include.group(1)).as_posix()
            if target.startswith("../") or not _hashed_requirements(repo_root, inventory, target, seen):
                return False
            found = True
        elif row.startswith(("--index-url", "--extra-index-url", "--trusted-host", "--require-hashes")):
            continue
        elif "==" not in row or not re.search(r"--hash=sha256:[0-9a-fA-F]{64}\b", row) or "*" in row:
            return False
        else:
            found = True
    seen.discard(rel)
    return found


def classify_lockfile_hygiene(repo_root: Path, inventory: RepoInventory | None = None) -> tuple[str, list[str]]:
    """Lockfiles the repository contains for each detected ecosystem.

    Only files the inventory lists count: a lockfile that exists on disk but
    is git-ignored is not part of the repository. Fully hash-pinned pip
    requirements count as the pip lockfile. A Missing rating names the
    settings that exclude lockfiles (`_lockfile_exclusions`).
    """
    inventory = _inventory(repo_root, inventory)
    ecosystems = _detect_ecosystems(repo_root, inventory)
    if not ecosystems:
        # No package manifests detected → not applicable, treat as Adequate
        # (no lockfile expected, no gap to report).
        return "Adequate", []
    evidence: list[str] = []
    missing: list[str] = []
    for eco in sorted(ecosystems):
        names = set(_LOCKFILE_PATTERNS.get(eco, ()))
        if eco == "npm":
            names |= set(_LOCKFILE_PATTERNS["yarn"]) | set(_LOCKFILE_PATTERNS["pnpm"])
        found = _repo_files(repo_root, inventory, lambda name, names=names: name in names)
        if not found and eco == "pip":
            requirements = _repo_files(
                repo_root, inventory, lambda name: name.startswith("requirements") and name.endswith(".txt")
            )
            if requirements and all(_hashed_requirements(repo_root, inventory, rel) for rel in requirements):
                found = requirements
        if found:
            evidence.append(f"{found[0]}:1")
        else:
            missing.append(eco)
    if not missing:
        return "Adequate", evidence
    if len(missing) == len(ecosystems):
        return "Missing", _lockfile_exclusions(repo_root)
    return "Partial", evidence


def _lockfile_exclusions(repo_root: Path) -> list[str]:
    """`file:line` of settings that keep lockfiles out of the repository.

    A missing lockfile is either never generated or deliberately excluded. The
    exclusion is the evidence a reader needs, and without it the §6 narrative has
    no fact to contradict a claim that a lockfile is committed.
    """
    names = {name for patterns in _LOCKFILE_PATTERNS.values() for name in patterns}
    out = []
    for rel, matches in (
        (".gitignore", lambda line: line.strip().lstrip("/") in names),
        (".npmrc", lambda line: re.match(r"\s*package-lock\s*=\s*false\b", line) is not None),
    ):
        try:
            text = (repo_root / rel).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        out += [f"{rel}:{number}" for number, line in enumerate(text.splitlines(), 1) if matches(line)]
    return out


def _detect_ecosystems(repo_root: Path, inventory: RepoInventory | None = None) -> set[str]:
    inventory = _inventory(repo_root, inventory)
    return {
        _MANIFEST_TO_ECOSYSTEM[Path(rel).name]
        for rel in _repo_files(repo_root, inventory, lambda name: name in _MANIFEST_TO_ECOSYSTEM)
    }


def classify_ci_install(repo_root: Path, inventory: RepoInventory | None = None) -> tuple[str | None, list[str]]:
    """Whether CI installs dependencies from the lockfile (`npm ci`, `--frozen-lockfile`, hashes) or resolves them.

    Graded across every executable CI step: one deterministic step beside a
    mutable one is Partial. A global CLI-tool install is not the product's
    dependency graph and does not count. None without any install step.
    """
    deterministic: list[str] = []
    mutable: list[str] = []
    for path, text in _read_ci_files(repo_root, inventory):
        rel = _rel(repo_root, path)
        for i, value in _executable_lines(path, text):
            if _DETERMINISTIC_INSTALL_RE.search(value):
                deterministic.append(f"{rel}:{i}")
            elif not _GLOBAL_TOOL_INSTALL_RE.search(value) and _MUTABLE_INSTALL_RE.search(value):
                mutable.append(f"{rel}:{i}")
    if not deterministic and not mutable:
        return None, []
    if not mutable:
        return "Adequate", deterministic
    return ("Partial" if deterministic else "Missing"), mutable


def classify_action_pinning(repo_root: Path, inventory: RepoInventory | None = None) -> tuple[str | None, list[str]]:
    """CI build inputs pinned by commit SHA or digest.

    GitHub: every `uses:` outside a local `./` action. GitLab: every `image:`
    (inline or its `name:`). A reference is pinned only by a 40-hex commit or
    an `@sha256:` digest; a tag or branch is mutable. None without any reference.
    """
    pinned: list[str] = []
    mutable: list[str] = []
    for path, text in _read_ci_files(repo_root, inventory):
        rel = _rel(repo_root, path)
        lines = text.splitlines()
        gitlab = path.name.startswith(".gitlab-ci.")
        for i, line in enumerate(lines, start=1):
            if _COMMENT_RE.match(line):
                continue
            ref = None
            if gitlab:
                image = _IMAGE_RE.match(line)
                if image:
                    ref = image.group(1)
                    if not ref and i < len(lines) and (name := _IMAGE_NAME_RE.match(lines[i])):
                        ref = name.group(1)
            elif uses := _USES_RE.match(line):
                ref = uses.group(1)
                if ref.startswith("./"):
                    ref = None
            if not ref:
                continue
            revision = ref.rpartition("@")[2] if "@" in ref else ""
            (pinned if _SHA_REF_RE.fullmatch(revision) else mutable).append(f"{rel}:{i}")
    if not pinned and not mutable:
        return None, []
    if not mutable:
        return "Adequate", pinned
    return ("Partial" if pinned else "Missing"), mutable


def _dockerfiles(repo_root: Path, inventory: RepoInventory) -> list[str]:
    # A `build/` directory often holds the image definitions themselves; only dependency trees are skipped.
    return _repo_files(
        repo_root,
        inventory,
        lambda n: n in ("Dockerfile", "Containerfile") or n.startswith("Dockerfile.") or n.endswith(".Dockerfile"),
        _DEPENDENCY_DIRS,
    )


def classify_base_image_pinning(
    repo_root: Path, inventory: RepoInventory | None = None
) -> tuple[str | None, list[str]]:
    """Every `FROM` stage of every Dockerfile pinned to a digest.

    A stage that names an earlier stage of the same file (`FROM builder`) and
    `scratch` are not images. A version tag is Partial, no tag or `latest` is
    Missing. None without any Dockerfile stage.
    """
    inventory = _inventory(repo_root, inventory)
    pinned: list[str] = []
    tagged: list[str] = []
    floating: list[str] = []
    for rel in _dockerfiles(repo_root, inventory):
        aliases: set[str] = set()
        for i, line in enumerate(_read(repo_root / rel).splitlines(), start=1):
            match = re.match(r"(?i)^\s*FROM\s+(.+)", line)
            if not match:
                continue
            try:
                tokens = shlex.split(match.group(1), comments=True)
            except ValueError:
                continue
            while tokens and tokens[0].startswith("--"):
                option = tokens.pop(0)
                if "=" not in option and tokens:
                    tokens.pop(0)
            if not tokens:
                continue
            image = tokens[0]
            if image.lower() not in aliases and image.lower() != "scratch":
                if re.fullmatch(r"\S+@sha256:[0-9a-fA-F]{64}", image):
                    pinned.append(f"{rel}:{i}")
                elif re.search(r":[0-9]", image.rsplit("/", 1)[-1]):
                    tagged.append(f"{rel}:{i}")
                else:
                    floating.append(f"{rel}:{i}")
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                aliases.add(tokens[2].lower())
    if not (pinned or tagged or floating):
        return None, []
    if not tagged and not floating:
        return "Adequate", pinned
    if pinned or not floating:
        return "Partial", tagged + floating
    return "Missing", tagged + floating


def classify_install_scripts(repo_root: Path, inventory: RepoInventory | None = None) -> tuple[str | None, list[str]]:
    """Code that runs at install or build time and can change without review.

    `Weak`: a CI step or Dockerfile line pipes a fetched script into an
    interpreter. `Missing`: a package lifecycle hook or `setup.py` fetches and
    executes code. `Partial`: install hooks run without an ignore-scripts
    policy. None when the repository has no manifest, setup script, CI file or
    Dockerfile to inspect.
    """
    inventory = _inventory(repo_root, inventory)
    ci_files = _read_ci_files(repo_root, inventory)
    dockerfiles = _dockerfiles(repo_root, inventory)
    manifests = _repo_files(repo_root, inventory, lambda n: n == "package.json")
    setups = _repo_files(repo_root, inventory, lambda n: n == "setup.py")
    if not (ci_files or dockerfiles or manifests or setups):
        return None, []

    fetch_exec = []
    for path, text in ci_files:
        rel = _rel(repo_root, path)
        fetch_exec += [f"{rel}:{i}" for i, value in _executable_lines(path, text) if _FETCH_EXEC_RE.search(value)]
    for rel in dockerfiles:
        for i, line in enumerate(_read(repo_root / rel).splitlines(), start=1):
            if not _COMMENT_RE.match(line) and _FETCH_EXEC_RE.search(line):
                fetch_exec.append(f"{rel}:{i}")
    if fetch_exec:
        return "Weak", fetch_exec

    hooks: list[tuple[str, str, str]] = []  # (file:line, hook, command)
    for rel in manifests:
        text = _read(repo_root / rel)
        try:
            scripts = (json.loads(text) or {}).get("scripts")
        except (json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(scripts, dict):
            continue
        lines = text.splitlines()
        for key in _LIFECYCLE_KEYS:
            command = scripts.get(key)
            if isinstance(command, str) and command.strip():
                number = next((i for i, line in enumerate(lines, 1) if re.search(rf'"{key}"\s*:', line)), 1)
                hooks.append((f"{rel}:{number}", key, command))
    for rel in setups:
        for i, line in enumerate(_read(repo_root / rel).splitlines(), start=1):
            if not line.lstrip().startswith("#") and _SETUP_SHELL_RE.search(line):
                hooks.append((f"{rel}:{i}", "setup.py", line.strip()))

    dangerous = [where for where, _key, command in hooks if _HOOK_EXEC_RE.search(command)]
    if dangerous:
        return "Missing", dangerous
    install_hooks = [where for where, key, _command in hooks if key in _INSTALL_HOOK_KEYS or key == "setup.py"]
    if not install_hooks:
        return "Adequate", []
    policy = [
        f".npmrc:{i}"
        for i, line in enumerate(_read(repo_root / ".npmrc").splitlines(), 1)
        if _belongs(inventory, ".npmrc") and re.match(r"(?i)\s*ignore-scripts\s*=\s*true", line)
    ]
    for path, text in ci_files:
        rel = _rel(repo_root, path)
        policy += [f"{rel}:{i}" for i, value in _executable_lines(path, text) if _IGNORE_SCRIPTS_RE.search(value)]
    return ("Adequate", policy) if policy else ("Partial", install_hooks)


# ---------------------------------------------------------------------------
# Sidecar writers
# ---------------------------------------------------------------------------


def _load_existing_security_controls(path: Path) -> dict:
    if not path.is_file():
        return {"schema_version": 1, "security_controls": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"schema_version": 1, "security_controls": []}
        data.setdefault("schema_version", 1)
        data.setdefault("security_controls", [])
        return data
    except (json.JSONDecodeError, OSError):
        return {"schema_version": 1, "security_controls": []}


def _load_control_table(plugin_root: Path) -> dict[str, dict]:
    """data/supply-chain-controls.yaml: sub-control → linked_checks, rule_ids, catalog_names."""
    try:
        data = yaml.safe_load((plugin_root / "data" / "supply-chain-controls.yaml").read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return {str(name): dict(row or {}) for name, row in ((data or {}).get("controls") or {}).items()}


def _covering_control(controls: list[dict], theme: dict) -> dict | None:
    """The model's rule-backed or catalog control for a sub-control's theme, if it has one."""
    rule_ids = set(theme.get("rule_ids") or [])
    names = {str(name).casefold() for name in theme.get("catalog_names") or []}
    for control in controls:
        if not isinstance(control, dict) or control.get("control") in _OWN_ROWS:
            continue
        if control.get("rule_id") in rule_ids or str(control.get("control") or "").casefold() in names:
            return control
    return None


def _upsert_sca_rows(controls: list[dict], rows: list[dict]) -> list[dict]:
    """Replace this producer's rows (current and earlier layout), append the new ones."""
    kept = [c for c in controls if not (isinstance(c, dict) and c.get("control") in _OWN_ROWS)]
    return kept + rows


def _load_severity_policy(plugin_root: Path) -> dict:
    path = plugin_root / "data" / "sca-practice-severity.yaml"
    if not path.is_file():
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return {}


def _severity_for(policy: dict, control: str, tier: str, effectiveness: str) -> str:
    if effectiveness == "Missing":
        block = (policy or {}).get("missing_severity", {})
    elif effectiveness in ("Partial", "Weak"):
        block = (policy or {}).get("partial_severity", {})
    else:
        return "Informational"
    by_tier = block.get(control, {}) if isinstance(block, dict) else {}
    return by_tier.get(tier) or by_tier.get(policy.get("default_tier", "T2"), "Medium")


def _evidence_rows(evidence: list[str]) -> list[dict]:
    rows = []
    for item in evidence or []:
        file, _, line = item.rpartition(":")
        if file and line.isdigit():
            rows.append({"file": file, "line": int(line)})
    return rows


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def run(repo_root: Path, output_dir: Path, asset_tier_raw: str | None, plugin_root: Path) -> int:
    tier = _normalize_tier(asset_tier_raw)
    policy = _load_severity_policy(plugin_root)
    table = _load_control_table(plugin_root)
    inventory = repo_inventory(repo_root)

    ratings = {
        CONTROL_SCANNING: classify_sca_scanning(repo_root, inventory),
        CONTROL_UPDATES: classify_auto_updates(repo_root, output_dir, inventory),
        CONTROL_LOCKFILE: classify_lockfile_hygiene(repo_root, inventory),
        CONTROL_CI_INSTALL: classify_ci_install(repo_root, inventory),
        CONTROL_ACTION_PINNING: classify_action_pinning(repo_root, inventory),
        CONTROL_BASE_IMAGE: classify_base_image_pinning(repo_root, inventory),
        CONTROL_INSTALL_SCRIPTS: classify_install_scripts(repo_root, inventory),
        CONTROL_SAST: classify_sast(repo_root, inventory),
    }

    sc_path = output_dir / ".security-controls.json"
    sc_data = _load_existing_security_controls(sc_path)
    controls = [c for c in sc_data.get("security_controls", []) if isinstance(c, dict)]

    subs = []
    covered = []
    for name, (eff, evidence) in ratings.items():
        if eff is None:
            continue
        theme = table.get(name) or {}
        checks = list(theme.get("linked_checks") or [])
        owner = _covering_control(controls, theme)
        if owner is not None:
            # The model already rates this theme; give that control the findings instead of a second row.
            owner["linked_checks"] = sorted(set(owner.get("linked_checks") or []) | set(checks))
            covered.append(name)
            continue
        if eff == NOT_EVIDENCED:
            subs.append(
                {"title": name, "status": NOT_EVIDENCED, "status_note": NOT_EVIDENCED_NOTE, "linked_checks": checks}
            )
            continue
        subs.append(
            {
                "title": name,
                "effectiveness": eff,
                "assessment": _sub_assessment(name, eff, evidence),
                "status_note": _status_note(_sub_assessment(name, eff, evidence), evidence),
                "evidence": _evidence_rows(evidence),
                "linked_checks": checks,
            }
        )

    rows = []
    rated = [s for s in subs if s.get("effectiveness")]
    if rated:
        present = [s["title"] for s in rated if s["effectiveness"] in ("Adequate", "Partial")]
        gaps = [f"{s['title']} ({s['effectiveness']})" for s in rated if s["effectiveness"] != "Adequate"]
        unknown = [s["title"] for s in subs if not s.get("effectiveness")]
        rows.append(
            {
                "domain": DOMAIN,
                "control": CONTROL_GROUP,
                # A not-evidenced process control may run outside the repository; it never lowers the row.
                "effectiveness": min((s["effectiveness"] for s in rated), key=lambda e: _RANK.get(e, 0)),
                "kind": "lifecycle",
                "group_subcontrols": True,
                # No trailing period: §6 joins the implementations of a section into one sentence.
                "implementation": (
                    f"In place: {', '.join(present)}"
                    if present
                    else "No build pipeline or dependency control is in place in the repository"
                ),
                "status_note": (
                    f"gaps in {', '.join(s['title'] for s in rated if s['effectiveness'] != 'Adequate')}"
                    if gaps
                    else "every rated sub-control is adequate"
                ),
                "assessment": " ".join(
                    part
                    for part in (
                        f"Gaps: {', '.join(gaps)}." if gaps else "Every rated sub-control is adequate.",
                        f"Not evidenced in the repository: {', '.join(unknown)}." if unknown else "",
                    )
                    if part
                ),
                "subcontrols": subs,
                "linked_checks": sorted({check for s in subs for check in s["linked_checks"]}),
                "linked_threats": [],
            }
        )

    sc_data["security_controls"] = _upsert_sca_rows(controls, rows)
    sc_path.write_text(json.dumps(sc_data, indent=2, sort_keys=False), encoding="utf-8")

    # Persist meta-finding rows to .sca-practice-findings.json. The
    # model/build_threat_model_yaml.py aggregator picks these up and merges
    # them into meta_findings[] with deterministic MF-NNN allocation.
    findings: list[dict] = []
    for name in SCA_CONTROLS:
        eff, evidence = ratings[name]
        if eff in {"Missing", "Partial", "Weak"}:
            findings.append(
                {
                    "title": f"{name}: {eff.lower()}",
                    "category": "Insufficient Patch Management",
                    "summary": _missing_finding_summary(name, eff, tier),
                    "evidence": _evidence_rows(evidence),
                    "severity": _severity_for(policy, name, tier, eff),
                    "control": name,
                    "effectiveness": eff,
                    "source": "sca-practice",  # so the aggregator can MF-id it
                    "derived_from": [],  # no T-NNN linkage; this is process-level
                    "linked_checks": list((table.get(name) or {}).get("linked_checks") or []),
                    "asset_tier": tier,
                }
            )

    findings_path = output_dir / ".sca-practice-findings.json"
    findings_path.write_text(
        json.dumps({"schema_version": 1, "findings": findings}, indent=2, sort_keys=False),
        encoding="utf-8",
    )

    summary = " ".join(f"{name}={eff}" for name, (eff, _ev) in ratings.items() if eff)
    print(
        f"emit_sca_practice: tier={tier} {summary}"
        + (f" covered-by-model={','.join(covered)}" if covered else "")
        + f" → {len(findings)} sca-practice finding(s)"
    )
    return 0


def _assessment_text(control: str, effectiveness: str, evidence: list[str]) -> str:
    if effectiveness == "Adequate":
        if evidence:
            return f"{control} present: " + ", ".join(evidence[:3])
        return f"{control} present (no specific evidence captured)"
    if effectiveness == "Partial":
        return (
            f"{control} present but coverage is partial. "
            f"Evidence: {', '.join(evidence[:3]) if evidence else 'none on disk'}. "
            "Expand to all detected ecosystems before treating this control as adequate."
        )
    excluded = f" Excluded by {', '.join(evidence[:3])}." if evidence else ""
    return (
        f"{control} not detected in the repository.{excluded} "
        "Patch-management posture depends on this control being in place — the "
        "team is reactive rather than proactive without it."
    )


def _sub_assessment(control: str, effectiveness: str, evidence: list[str]) -> str:
    """One sentence and its `file:line` evidence; the triple keeps its patch-management wording."""
    reason = (_REASONS.get(control) or {}).get(effectiveness)
    if reason is None:
        return _assessment_text(control, effectiveness, evidence)
    return f"{reason}: {', '.join(evidence[:3])}." if evidence else f"{reason}."


def _status_note(assessment: str, evidence: list[str]) -> str:
    """The assessment's first sentence with its evidence: the grouped row shows one clause per sub-control."""
    note = assessment.split(". ")[0].rstrip(".")
    if evidence and evidence[0] not in note:
        note += f" ({', '.join(evidence[:3])})"
    return note + "."


def _missing_finding_summary(control: str, effectiveness: str, tier: str) -> str:
    state = {"Missing": "missing", "Weak": "advisory only"}.get(effectiveness, "partial")
    return (
        f"Asset tier {tier}: {control} is {state}. The architectural concern is "
        "patch-management maturity — without this signal the team relies on "
        "ad-hoc upgrades after the fact. Address by introducing the control "
        "at the platform level (CI workflow, repo config, or org policy), "
        "not by reacting to individual CVE advisories."
    )


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="Emit supply-chain control rows + MF findings")
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument(
        "--asset-tier", default=None, help='Raw asset-tier string (e.g. "Tier 1 — Restricted" / "T2"). Default: T2.'
    )
    p.add_argument("--plugin-root", default=None, type=Path, help="Override plugin root for severity-policy lookup")
    args = p.parse_args(argv)

    plugin_root = args.plugin_root or Path(__file__).resolve().parents[2]
    if not args.repo_root.is_dir():
        print(f"emit_sca_practice: repo-root not a directory: {args.repo_root}", file=sys.stderr)
        return 2
    if not args.output_dir.is_dir():
        print(f"emit_sca_practice: output-dir not a directory: {args.output_dir}", file=sys.stderr)
        return 2

    return run(args.repo_root, args.output_dir, args.asset_tier, plugin_root)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
