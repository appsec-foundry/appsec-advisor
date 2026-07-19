#!/usr/bin/env python3
"""
assess_supply_chain_controls.py — deterministic supply chain control assessment.

Replaces the LLM reasoning loop for Phase 8's "Operations, Runtime and Supply Chain"
domain by evaluating the 9 rule-based sub-controls directly from recon artifacts.
Saves ~4 orchestrator turns per run (the LLM no longer needs to read recon sections
7.14–7.17, 7.26–7.28, reason through 9 sub-controls, and write the assessment prose).

Sub-controls evaluated (per phase-group-architecture.md §"Operations, Runtime and Supply
Chain — sub-controls"):
  1. CVE scanning
  2. Lockfile pinning
  3. CI install integrity
  4. CI/CD action pinning
  5. Container image hygiene
  6. Dependency confusion
  7. Postinstall scripts
  8. Dependency management (Renovate / Dependabot)
  9. SCA tooling

Output: $OUTPUT_DIR/.supply-chain-assessment.json

Usage:
  python3 assess_supply_chain_controls.py <output_dir> [--repo-root <path>]
  python3 assess_supply_chain_controls.py <output_dir> --report-only   (print JSON, no file write)

Exit codes:
  0   Assessment written (or printed in --report-only mode).
  1   Required input not found (.recon-summary.md missing and no repo-root given).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Effectiveness enum
# ---------------------------------------------------------------------------
ADEQUATE = "Adequate"
PARTIAL = "Partial"
WEAK = "Weak"
MISSING = "Missing"


# ---------------------------------------------------------------------------
# Recon-summary text helpers
# ---------------------------------------------------------------------------


def _load_recon(output_dir: str, repo_root: str | None) -> str:
    """Return recon-summary text, or empty string if unavailable."""
    recon_path = Path(output_dir) / ".recon-summary.md"
    if recon_path.exists():
        return recon_path.read_text(encoding="utf-8", errors="replace")
    # Fallback: scan repo root directly (first-run before recon writes the file).
    return ""


def _has(text: str, *patterns: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


# Directories never worth walking when looking for manifests.
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    "site-packages",
}


def _iter_files(repo_root: str | None, name_match) -> list[Path]:
    """Walk the repo for files whose name satisfies ``name_match``.

    Mirrors the exclusion behaviour of ``recon_patterns._walk_repo`` without
    importing it (this script must stay dependency-free and fast).
    """
    if not repo_root:
        return []
    root = Path(repo_root)
    if not root.is_dir():
        return []
    hits: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS:
                    stack.append(entry)
            elif name_match(entry.name):
                hits.append(entry)
    return hits


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _ci_text(recon: str, repo_root: str | None) -> str:
    """Return recon text plus the raw text of every CI definition in the repo.

    Several sub-controls used to grade on ``recon`` alone, so a terse or absent
    ``.recon-summary.md`` made them report Missing on a repo whose workflows
    plainly ran ``npm ci`` or ``pip-audit``. Reading the CI files directly makes
    those rows agree with the ones that already consult ``repo_root``.
    """
    parts = [recon]
    if repo_root:
        wf_dir = Path(repo_root) / ".github" / "workflows"
        if wf_dir.is_dir():
            for pattern in ("*.yml", "*.yaml"):
                for wf in sorted(wf_dir.glob(pattern)):
                    parts.append(_read(wf))
        for name in (".gitlab-ci.yml", ".gitlab-ci.yaml", "Jenkinsfile", "azure-pipelines.yml"):
            p = Path(repo_root) / name
            if p.is_file():
                parts.append(_read(p))
    return "\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# Sub-control evaluators
# ---------------------------------------------------------------------------


def _eval_lockfile(recon: str, repo_root: str | None) -> dict[str, str]:
    """Lockfile pinning: is a lockfile present and committed?

    Ecosystem-parametric: covers npm/yarn/pnpm, Python (pip/pipenv/poetry/uv),
    Ruby, Rust, Go, PHP, and Java (Gradle ``gradle.lockfile`` /
    ``gradle/verification-metadata.xml``). Maven has no native lockfile, so a
    Maven-only repo cannot satisfy this row via a lockfile (its integrity story
    is graded under CI install integrity / Enforcer instead).
    """
    present = _has(
        recon,
        r"package-lock\.json",
        r"yarn\.lock",
        r"pnpm-lock\.yaml",
        r"Pipfile\.lock",
        r"poetry\.lock",
        r"uv\.lock",
        r"requirements\.lock",
        r"Gemfile\.lock",
        r"Cargo\.lock",
        r"go\.sum",
        r"composer\.lock",
        r"gradle\.lockfile",
        r"verification-metadata\.xml",
    )
    # Check repo root directly when available
    if not present and repo_root:
        lockfiles = [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Pipfile.lock",
            "poetry.lock",
            "uv.lock",
            "requirements.lock",
            "Gemfile.lock",
            "Cargo.lock",
            "go.sum",
            "composer.lock",
            "gradle.lockfile",
            "gradle/verification-metadata.xml",
        ]
        present = any(Path(repo_root, lf).exists() for lf in lockfiles)

    if present:
        return {"effectiveness": ADEQUATE, "reason": "Lockfile present and committed for detected ecosystem(s)."}

    # pip's native integrity story is `pip-compile --generate-hashes`, which
    # produces a fully hashed requirements.txt and no file named *.lock. Without
    # this branch such a repo scored Missing and capped the whole domain at Weak.
    hashed = [
        p
        for p in _iter_files(repo_root, lambda n: n.startswith("requirements") and n.endswith(".txt"))
        if "--hash=sha256:" in _read(p)
    ]
    if hashed:
        return {
            "effectiveness": ADEQUATE,
            "reason": f"Hash-pinned requirements file ({hashed[0].name}) provides lockfile-equivalent integrity.",
        }
    if _has(recon, r"--hash=sha256:"):
        return {
            "effectiveness": ADEQUATE,
            "reason": "Hash-pinned requirements detected — lockfile-equivalent integrity.",
        }
    return {"effectiveness": MISSING, "reason": "No lockfile found for any detected package ecosystem."}


# Commands that install strictly from a lockfile / hash set.
_DETERMINISTIC_INSTALL = (
    r"npm\s+ci\b",
    r"--frozen-lockfile",
    r"--immutable",
    r"--require-hashes",
    r"cargo\s+build\s+--locked",
    r"dotnet\s+restore\s+--locked",
    r"bundle\s+install\s+--frozen",
    r"go\s+mod\s+verify",
    # Java — Gradle dependency locking / verification, Maven strict checksums
    r"--verify-locks",
    r"verification-metadata",
    r"--strict-checksums",
    r"mvn\b[^\n]*\s-C\b",
    # Python — the lockfile-enforcing installers. uv.lock/poetry.lock were already
    # credited by _eval_lockfile; the commands that enforce them were not.
    r"uv\s+sync\b[^\n]*--(?:frozen|locked)",
    r"uv\s+pip\s+sync\b",
    r"\bpip-sync\b",
    r"poetry\s+install\b[^\n]*--sync",
    r"poetry\s+check\b[^\n]*--lock",
    r"pipenv\s+install\b[^\n]*--deploy",
    r"pdm\s+sync\b",
    r"pdm\s+install\b[^\n]*--frozen-lockfile",
)

# Commands that resolve versions at install time.
_MUTABLE_INSTALL = (
    r"npm\s+install\b",
    r"npm\s+i\b",
    r"yarn\s+add\b",
    r"pnpm\s+add\b",
    # `pip install` is mutable unless the same command carries --require-hashes.
    # Checked per-line so a later flag on the same line still counts.
    r"pip\d?\s+install\b(?![^\n]*--require-hashes)",
    r"pip\d?\s+install\b(?![^\n]*-r\s+\S+\.lock)",
)

# Installing a CLI tool globally is not part of the product's dependency graph.
# `npm install -g @redocly/cli` or `pip install ruff` in a lint job must not drag
# an otherwise lockfile-clean repo down to Partial — that is CI tooling noise,
# not a supply-chain integrity gap in what ships.
_GLOBAL_TOOL_INSTALL = re.compile(r"(?:npm|pnpm|yarn)\s+(?:install|i|add)\s+(?:-g\b|--global\b)", re.IGNORECASE)


def _eval_ci_install(recon: str, repo_root: str | None = None) -> dict[str, str]:
    """CI install integrity: does CI use deterministic install flags?

    Graded as a three-state mix (like CI/CD action pinning) rather than
    first-match-wins: a repo where one workflow runs ``npm ci`` and another runs
    ``npm install`` is not fully deterministic and must not score Adequate.
    """
    text = _ci_text(recon, repo_root)
    # Drop global tool installs before looking for mutable project installs.
    project_text = "\n".join(line for line in text.splitlines() if not _GLOBAL_TOOL_INSTALL.search(line))
    deterministic = _has(text, *_DETERMINISTIC_INSTALL)
    mutable = _has(project_text, *_MUTABLE_INSTALL)

    if deterministic and not mutable:
        return {
            "effectiveness": ADEQUATE,
            "reason": "CI uses deterministic install commands (npm ci / --frozen-lockfile / uv sync --frozen / equivalent).",
        }
    if deterministic and mutable:
        return {
            "effectiveness": PARTIAL,
            "reason": "Mix of deterministic and mutable install commands — some steps resolve versions at install time.",
        }
    if mutable:
        return {
            "effectiveness": MISSING,
            "reason": "CI uses mutable install commands (npm install / pip install without hashes).",
        }
    return {"effectiveness": MISSING, "reason": "No CI install step detected."}


def _eval_action_pinning(recon: str, repo_root: str | None) -> dict[str, str]:
    """CI step pinning: are pipeline build inputs pinned by SHA / digest?

    Ecosystem-aware across CI providers:
      - GitHub Actions: ``uses: …@<40-hex>`` / ``@sha256:`` (pinned) vs
        ``@v<N>`` / ``@latest`` (mutable).
      - GitLab CI: ``image: …@sha256:`` (pinned) vs a bare/tagged image
        (mutable). Mirrors ``recon_patterns._CAT14_GITLAB_IMAGE``.

    A repo whose CI lives only in ``.gitlab-ci.yml`` is graded on its image
    digest-pinning instead of returning a false "No GitHub Actions" Missing.
    """
    # Read GitHub workflow files directly when repo root is available
    workflow_text = recon
    gitlab_text = ""
    if repo_root:
        wf_dir = Path(repo_root) / ".github" / "workflows"
        if wf_dir.is_dir():
            parts = []
            for pattern in ("*.yml", "*.yaml"):
                for wf in wf_dir.glob(pattern):
                    try:
                        parts.append(wf.read_text(encoding="utf-8", errors="replace"))
                    except OSError:
                        pass
            if parts:
                workflow_text = "\n".join(parts)
        for name in (".gitlab-ci.yml", ".gitlab-ci.yaml"):
            p = Path(repo_root) / name
            if p.is_file():
                try:
                    gitlab_text += "\n" + p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    pass
    if not gitlab_text:
        gitlab_text = recon

    # --- GitHub Actions ---
    gh_sha = bool(
        re.search(r"uses:\s*\S+@[0-9a-f]{40}", workflow_text) or re.search(r"uses:\s*\S+@sha256:", workflow_text)
    )
    gh_mutable = bool(re.search(r"uses:\s*\S+@v\d", workflow_text) or re.search(r"uses:\s*\S+@latest", workflow_text))
    has_gh = bool(re.search(r"uses:\s*\S+@", workflow_text))

    # --- GitLab CI images ---
    gl_pinned = gl_mutable = False
    has_gl = False
    for m in re.finditer(r"(?m)^\s*image:\s*(?P<image>[^\s#]+)", gitlab_text):
        has_gl = True
        image = m.group("image").strip("'\"")
        if re.search(r"@sha256:[0-9a-f]{64}", image):
            gl_pinned = True
        else:  # bare image, :tag, or :latest — all mutable
            gl_mutable = True

    if not has_gh and not has_gl:
        return {"effectiveness": MISSING, "reason": "No GitHub Actions or GitLab CI pipeline references detected."}

    any_pinned = gh_sha or gl_pinned
    any_mutable = gh_mutable or gl_mutable
    if any_pinned and not any_mutable:
        return {
            "effectiveness": ADEQUATE,
            "reason": "All detected CI steps/images pinned to commit SHA or image digest.",
        }
    if any_pinned and any_mutable:
        return {"effectiveness": PARTIAL, "reason": "Mix of SHA/digest-pinned and mutable-tag CI references."}
    return {"effectiveness": MISSING, "reason": "CI steps/images pinned to mutable tags (@v<N> / @latest / :tag)."}


def _eval_container_hygiene(recon: str, repo_root: str | None) -> dict[str, str]:
    """Container image hygiene: digest-pinned base images.

    Every ``FROM`` in every Dockerfile is graded, not just the first match in
    ``<repo_root>/Dockerfile``: a multi-stage file whose build stage is digest
    pinned but whose runtime stage is ``:latest`` is not adequately pinned, and
    ``Dockerfile.prod`` / subdirectory Dockerfiles are just as deployable as the
    root one. Mirrors ``recon_patterns.scan_container_images``.
    """
    dockerfiles = _iter_files(
        repo_root, lambda n: n == "Dockerfile" or n.startswith("Dockerfile.") or n.endswith(".Dockerfile")
    )
    texts = [_read(p) for p in dockerfiles] or [recon]

    stages: list[str] = []
    for text in texts:
        for m in re.finditer(r"(?im)^\s*FROM\s+(?P<image>[^\s#]+)", text):
            stages.append(m.group("image").strip().strip("\"'"))

    if not stages:
        return {"effectiveness": MISSING, "reason": "No Dockerfile detected."}

    # A stage may reference an earlier stage by alias (FROM build AS runtime);
    # those carry no registry provenance and are not graded.
    aliases = {m.group(1).lower() for text in texts for m in re.finditer(r"(?im)\bAS\s+([A-Za-z0-9_.-]+)", text)}

    pinned = tagged = mutable = 0
    for image in stages:
        if image.lower() in aliases or image.lower() == "scratch":
            continue
        if re.search(r"@sha256:[0-9a-f]{64}", image):
            pinned += 1
        elif re.search(r":[0-9]", image.rsplit("/", 1)[-1]):
            tagged += 1
        else:  # :latest, or no tag at all
            mutable += 1

    if not (pinned or tagged or mutable):
        return {"effectiveness": MISSING, "reason": "No Dockerfile detected."}
    if pinned and not tagged and not mutable:
        return {"effectiveness": ADEQUATE, "reason": f"All {pinned} base image stage(s) pinned to SHA-256 digest."}
    if mutable and not pinned and not tagged:
        return {"effectiveness": MISSING, "reason": "Base image uses :latest tag or no tag."}
    if pinned:
        return {
            "effectiveness": PARTIAL,
            "reason": f"{pinned} digest-pinned stage(s) but {tagged + mutable} on mutable tag(s).",
        }
    if tagged and not mutable:
        return {"effectiveness": PARTIAL, "reason": "Base image pinned to version tag but not digest."}
    return {"effectiveness": MISSING, "reason": "Base image uses :latest tag or no tag."}


_PUBLIC_REGISTRY_HOSTS = ("registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org")

# Well-known public supplemental indexes. Pointing at one of these is routine
# (PyTorch wheels, piwheels, Jetson builds) and is not a confusion setup.
_PUBLIC_EXTRA_INDEXES = (
    "pypi.org",
    "files.pythonhosted.org",
    "download.pytorch.org",
    "piwheels.org",
    "developer.download.nvidia.com",
    "storage.googleapis.com/jax-releases",
    "data.pyg.org",
    "abi.rocm.com",
)


def _is_internal_index(url: str) -> bool:
    """True when a package index URL looks internal rather than public."""
    url = url.strip("\"'")
    if any(host in url for host in _PUBLIC_EXTRA_INDEXES):
        return False
    # Credentials in the URL, an RFC1918/localhost host, or a bare hostname with
    # no public TLD all indicate an internal index.
    return bool(re.match(r"https?://", url)) or url.startswith("${") or "@" in url


def _consumes_internal_packages(recon: str, repo_root: str | None) -> bool:
    """True when the repo plausibly depends on non-public package names.

    Dependency confusion requires an internal name an attacker can publish
    publicly. Evidence: a private/scoped npm package of its own, a declared
    private registry, or a self-hosted registry product in the recon text.
    """
    for pkg_path in _iter_files(repo_root, lambda n: n == "package.json"):
        try:
            data = json.loads(_read(pkg_path))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        if data.get("private") is True or str(data.get("name", "")).startswith("@"):
            return True
        if isinstance(data.get("publishConfig"), dict):
            return True
    npmrc = _read(Path(repo_root) / ".npmrc") if repo_root else ""
    if re.search(r"@[\w-]+:registry\s*=", npmrc):
        return True
    return _has(
        recon,
        r"verdaccio",
        r"artifactory",
        r"\bnexus\b",
        r"codeartifact",
        r"internal.*(?:package|registry)",
        r"private.*(?:package|registry)",
    )


def _eval_dependency_confusion(recon: str, repo_root: str | None) -> dict[str, str]:
    """Dependency confusion: is internal-package resolution pinned to one source?

    Two corrections over the previous npm-shaped heuristic:

    * Pointing ``registry=`` at the *public* registry is the npm default and is
      no protection at all — only a scope-pinned registry or a non-public host
      counts. Merely *consuming* a scoped package (``@types/node``) is likewise
      not a control, so the old ``@\\w+/`` recon match is gone.
    * Python has a real confusion vector of its own: a supplemental index
      (``--extra-index-url`` / ``PIP_EXTRA_INDEX_URL`` / uv
      ``index-strategy = "unsafe-best-match"``) makes pip resolve across two
      sources and take the higher version, which is the exact attack.
    """
    evidence: list[str] = []
    risk: list[str] = []

    # --- npm: .npmrc / .yarnrc.yml ---
    for name in (".npmrc", ".yarnrc.yml"):
        text = _read(Path(repo_root) / name) if repo_root else ""
        if not text and repo_root:
            continue
        if not text:
            text = recon if re.search(r"@[\w-]+:registry", recon) else ""
        if re.search(r"@[\w-]+:registry\s*=", text):
            evidence.append(f"{name} pins a package scope to a dedicated registry")
        for m in re.finditer(r"(?m)^\s*(?:registry|npmRegistryServer)\s*[=:]\s*(?P<url>\S+)", text):
            url = m.group("url").strip("\"'")
            if not any(host in url for host in _PUBLIC_REGISTRY_HOSTS):
                evidence.append(f"{name} routes installs to a non-public registry")

    # --- Python: a *supplemental* index is the confusion vector ---
    #
    # Only when it points somewhere internal. `--extra-index-url
    # https://download.pytorch.org/whl/cpu` is on half the ML repos in existence
    # and is not a confusion setup: the attack needs an internal package name
    # that is also resolvable from the public index.
    py_conf = "\n".join(
        _read(p) for p in _iter_files(repo_root, lambda n: n in {"pip.conf", "pip.ini", ".pypirc", "pyproject.toml"})
    )
    haystack = _ci_text(recon, repo_root) + "\n" + py_conf
    for m in re.finditer(r"(?:--extra-index-url|PIP_EXTRA_INDEX_URL\s*[=:]|extra-index-url\s*=)\s*(\S+)", haystack):
        if _is_internal_index(m.group(1)):
            risk.append(
                "a supplemental internal pip index is configured alongside PyPI, so an internal "
                "package name can also resolve from the public index"
            )
            break
    if _has(haystack, r"index-strategy\s*=\s*[\"']?unsafe-"):
        risk.append("uv index-strategy is set to an unsafe-* mode, which resolves across indexes by version")
    if _has(py_conf, r"(?m)^\s*index-url\s*=") or _has(haystack, r"--index-url", r"PIP_INDEX_URL"):
        if not any(host in haystack for host in _PUBLIC_REGISTRY_HOSTS if "pypi" in host or "pythonhosted" in host):
            evidence.append("pip is pinned to a single non-public index-url")

    # --- Self-hosted registry products (either ecosystem) ---
    if _has(recon, r"verdaccio", r"artifactory", r"\bnexus\b", r"gitlab.*package\s*registry", r"codeartifact"):
        evidence.append("a self-hosted package registry is referenced")

    if risk:
        return {
            "effectiveness": WEAK,
            "reason": "Dependency-confusion exposure: " + "; ".join(risk) + ".",
        }
    if evidence:
        return {"effectiveness": ADEQUATE, "reason": (evidence[0][0].upper() + evidence[0][1:]) + "."}
    # No internal packages means there is no name for an attacker to squat, so
    # the absence of a private registry is not a gap. Reporting Missing here
    # would accuse every repo that simply consumes public dependencies.
    if not _consumes_internal_packages(recon, repo_root):
        return {
            "effectiveness": ADEQUATE,
            "reason": "No internal or private packages detected — dependency confusion does not apply.",
        }
    return {
        "effectiveness": MISSING,
        "reason": "Internal package names are resolved without a scope-pinned or private registry.",
    }


# Hooks that run on a plain `npm install`. These decide the *Partial* rating, so
# the list stays narrow: `prepare` is deliberately absent because `"prepare":
# "husky install"` is on a large share of repos and is not a security posture
# signal — flagging it would be noise.
_INSTALL_HOOK_KEYS = ("preinstall", "install", "postinstall")

# The wider list, kept in sync with recon_patterns._CAT17_NPM_LIFECYCLE_KEYS, is
# scanned only for *content* that is actually dangerous (a `prepare` hook that
# curls a script is a real finding regardless of how common the key is).
_LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare", "prebuild", "postpublish")


# Remote code piped straight into an interpreter. The fetched bytes are never
# pinned or verified, so whoever controls that URL (or can MITM it) controls the
# build. Deliberately narrow: only the fetch-into-interpreter forms match, so a
# plain `curl -o artifact.tgz` followed by a checksum check is not flagged.
_FETCH_EXEC_PATTERNS = (
    # curl/wget piped to a shell or interpreter
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:python\d?|perl|ruby|node)\b",
    # process substitution / command substitution into an interpreter
    r"(?:source|\.)\s+<\(\s*(?:curl|wget)\b",
    r"(?:ba)?sh\s+<\(\s*(?:curl|wget)\b",
    r"eval\s+[\"'`]?\$\(\s*(?:curl|wget)\b",
    r"(?:python\d?|node|ruby)\s+-[ce]\s+[\"']?\$\(\s*(?:curl|wget)\b",
    # PowerShell download-and-execute
    r"(?:iex|Invoke-Expression)\b[^\n]*(?:DownloadString|Invoke-WebRequest|iwr)\b",
    r"(?:Invoke-WebRequest|iwr)\b[^\n]*\|\s*(?:iex|Invoke-Expression)\b",
)


# Install-hook variants of the same threat: code obtained at install time and
# handed to an interpreter. Narrower than "mentions a URL" on purpose.
_HOOK_EXEC_PATTERNS = _FETCH_EXEC_PATTERNS + (
    r"base64\s+(?:-d|--decode)[^\n]*\|\s*(?:sudo\s+)?(?:ba)?sh\b",
    r"(?:node|python\d?|ruby|perl)\s+-[ce]\s[^\n]*https?://",
    # setup.py shelling out to a network fetch during install
    r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output))\s*\([^)]*https?://",
    r"(?:os\.system|subprocess\.(?:run|call|Popen|check_output))\s*\([^)]*(?:curl|wget)\b",
)


def _eval_fetch_and_execute(recon: str, repo_root: str | None) -> list[tuple[str, str]]:
    """Find build/install steps that execute code fetched from an external URL.

    Returns ``(location, matched line)`` pairs. This is the highest-severity
    supply-chain pattern the scorecard looks for: unlike an unpinned dependency,
    the fetched payload is not recorded anywhere, so a change at the far end is
    both silent and unreviewable.
    """
    hits: list[tuple[str, str]] = []

    def _scan(label: str, text: str) -> None:
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or len(stripped) > 500:
                continue
            if any(re.search(p, stripped, re.IGNORECASE) for p in _FETCH_EXEC_PATTERNS):
                hits.append((label, stripped[:120]))
                return  # one hit per location is enough to make the point

    if repo_root:
        wf_dir = Path(repo_root) / ".github" / "workflows"
        if wf_dir.is_dir():
            for pattern in ("*.yml", "*.yaml"):
                for wf in sorted(wf_dir.glob(pattern)):
                    _scan(f".github/workflows/{wf.name}", _read(wf))
        for name in (".gitlab-ci.yml", ".gitlab-ci.yaml", "Jenkinsfile", "azure-pipelines.yml"):
            p = Path(repo_root) / name
            if p.is_file():
                _scan(name, _read(p))
        for df in _iter_files(repo_root, lambda n: n == "Dockerfile" or n.startswith("Dockerfile.")):
            rel = str(df.relative_to(Path(repo_root))).replace("\\", "/")
            _scan(rel, _read(df))
    if not hits:
        _scan("recon summary", recon)
    return hits


def _eval_postinstall(recon: str, repo_root: str | None) -> dict[str, str]:
    """Install-time code execution: does arbitrary code run when the project is
    installed or built, and can its source change without review?

    Covers three surfaces that share one threat and one remediation:
    package-manager lifecycle hooks (every ``package.json`` in the repo, not just
    the root one — ``npm install`` executes workspace hooks too), ``setup.py``
    shell escapes, and build steps that pipe a remote script into a shell.
    """
    hooks: list[tuple[str, str, str]] = []  # (relative file, hook name, command)
    for pkg_path in _iter_files(repo_root, lambda n: n == "package.json"):
        try:
            data = json.loads(_read(pkg_path))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
        rel = str(pkg_path.relative_to(Path(repo_root))).replace("\\", "/") if repo_root else pkg_path.name
        for key in _LIFECYCLE_KEYS:
            value = scripts.get(key)
            if isinstance(value, str) and value.strip():
                hooks.append((rel, key, value))

    # Python: install-time shell escape in setup.py (recon Cat 17
    # `python-setup-shell`), which the scorecard previously ignored entirely.
    py_shell = re.compile(r"(cmdclass\s*=|os\.system\s*\(|subprocess\.(?:run|call|Popen))")
    for setup_py in _iter_files(repo_root, lambda n: n == "setup.py"):
        rel = str(setup_py.relative_to(Path(repo_root))).replace("\\", "/") if repo_root else setup_py.name
        for line in _read(setup_py).splitlines():
            if py_shell.search(line):
                # Record the matched line itself, so the content classifier below
                # can tell a benign `cmdclass=BuildExt` from a shell-out that
                # fetches over the network at install time.
                hooks.append((rel, "setup.py", line.strip()))
                break

    # --ignore-scripts, read from the repo rather than trusted to recon prose.
    npmrc = _read(Path(repo_root) / ".npmrc") if repo_root else ""
    ignore_scripts = bool(re.search(r"(?m)^\s*ignore-scripts\s*=\s*true", npmrc, re.IGNORECASE)) or _has(
        _ci_text(recon, repo_root),
        r"--ignore-scripts",
        r"--no-scripts",
        r"npm_config_ignore_scripts",
        r"npm\s+config\s+(?:set\s+)?ignore-scripts\s+true",
        # pnpm's allowlist: only the named packages may run build scripts.
        r"onlyBuiltDependencies",
    )

    # Highest-severity case: code fetched from a URL and executed, in a build
    # step or a lifecycle hook. The payload is unpinned and unreviewable.
    fetch_exec = _eval_fetch_and_execute(recon, repo_root)
    if fetch_exec:
        where, line = fetch_exec[0]
        extra = f" (+{len(fetch_exec) - 1} more location(s))" if len(fetch_exec) > 1 else ""
        return {
            "effectiveness": WEAK,
            "reason": (
                f"{where} executes code fetched from an external URL at build time{extra}: {line!r} — "
                "the fetched payload is unpinned and unverified, so whoever controls that URL controls the build."
            ),
        }

    # A hook that fetches and executes code at install time is the real finding —
    # any lifecycle key qualifies, however routine that key normally is. Matched
    # against execution vectors only: a hook named `node scripts/fetch-assets.js`
    # or one echoing a docs URL is not a finding.
    dangerous = [h for h in hooks if any(re.search(p, h[2], re.IGNORECASE) for p in _HOOK_EXEC_PATTERNS)]
    if dangerous:
        rel, key, cmd = dangerous[0]
        # Not neutralised by --ignore-scripts in CI, because developer machines
        # still run it on a plain `npm install`.
        return {
            "effectiveness": MISSING,
            "reason": f"{rel} `{key}` hook fetches and executes code at install time: {cmd[:80]!r}",
        }

    # Everything below grades the *policy*, so only genuine install-time hooks
    # count — a `prepare` running husky says nothing about supply-chain posture.
    install_hooks = [h for h in hooks if h[1] in _INSTALL_HOOK_KEYS or h[1] == "setup.py"]
    if not install_hooks:
        return {"effectiveness": ADEQUATE, "reason": "No install-time lifecycle hooks with risky content detected."}
    if ignore_scripts:
        return {
            "effectiveness": ADEQUATE,
            "reason": f"{len(install_hooks)} install hook(s) present but ignore-scripts is configured.",
        }
    return {
        "effectiveness": PARTIAL,
        "reason": f"{len(install_hooks)} install hook(s) present (build tasks only); no ignore-scripts policy.",
    }


# Marker file -> Dependabot `package-ecosystem` value, for coverage comparison.
_ECOSYSTEM_MARKERS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "pyproject.toml": "pip",
    "Pipfile": "pip",
    "go.mod": "gomod",
    "Cargo.toml": "cargo",
    "Gemfile": "bundler",
    "composer.json": "composer",
    "pom.xml": "maven",
}


def _detected_ecosystems(repo_root: str | None) -> set[str]:
    """Package ecosystems the repo actually depends on.

    Deliberately excludes ``github-actions`` and ``docker``: both are graded by
    their own rows (CI/CD action pinning, Container image hygiene), and counting
    them here too would report the same gap twice and downgrade almost every
    repo for not listing them in dependabot.yml.
    """
    return {_ECOSYSTEM_MARKERS[p.name] for p in _iter_files(repo_root, lambda n: n in _ECOSYSTEM_MARKERS)}


def _eval_dep_management(recon: str, repo_root: str | None) -> dict[str, str]:
    """Dependency management: Renovate or Dependabot configured *and* covering
    the ecosystems the repo actually uses.

    Previously this row could only ever return Partial or Missing, which made
    the all-Adequate branch of ``_derive_overall`` unreachable — no repo, however
    well hardened, could score Adequate for the domain. Coverage is now measured
    against the manifests present rather than asserted in prose.
    """
    renovate_text = ""
    dependabot_text = ""
    if repo_root:
        for rel in ("renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".github/renovate.json"):
            renovate_text += _read(Path(repo_root) / rel)
        for rel in (".github/dependabot.yml", ".github/dependabot.yaml"):
            dependabot_text += _read(Path(repo_root) / rel)

    renovate = bool(renovate_text.strip())
    dependabot = bool(dependabot_text.strip())
    if not renovate and not dependabot:
        # Fall back to recon prose only when the repo itself is unavailable.
        renovate = _has(recon, r"renovate", r"renovatebot")
        dependabot = _has(recon, r"dependabot")
        if renovate or dependabot:
            tool = "Renovate" if renovate else "Dependabot"
            return {
                "effectiveness": PARTIAL,
                "reason": f"{tool} referenced in recon but its configuration could not be read to confirm coverage.",
            }
        return {"effectiveness": MISSING, "reason": "No Renovate or Dependabot configuration detected."}

    tool = "Renovate" if renovate else "Dependabot"
    detected = _detected_ecosystems(repo_root)

    if dependabot:
        configured = {m.group(1) for m in re.finditer(r"package-ecosystem\s*:\s*[\"']?([\w-]+)", dependabot_text)}
    else:
        # Renovate auto-detects every ecosystem unless explicitly restricted.
        configured = set() if re.search(r"\"enabledManagers\"", renovate_text) else detected

    uncovered = detected - configured
    # Install cooldown (minimumReleaseAge / minimumReleaseAgeGate) is the control
    # that blocks a freshly-published malicious version from being auto-merged.
    cooldown = _has(renovate_text + dependabot_text, r"minimumReleaseAge", r"cooldown")

    if uncovered:
        return {
            "effectiveness": PARTIAL,
            "reason": f"{tool} configured but does not cover: {', '.join(sorted(uncovered))}.",
        }
    # A missing install cooldown is a hardening opportunity, not a vulnerability
    # — it is noted in the reason but does not downgrade the row.
    if not cooldown:
        return {
            "effectiveness": ADEQUATE,
            "reason": (
                f"{tool} covers all detected ecosystems. Consider an install cooldown "
                "(minimumReleaseAge / cooldown) to blunt freshly-published malicious versions."
            ),
        }
    return {
        "effectiveness": ADEQUATE,
        "reason": f"{tool} covers all detected ecosystems and enforces an install cooldown.",
    }


# Scanners that exit non-zero on findings by default — no threshold flag needed.
_FAIL_CLOSED_BY_DEFAULT = (
    r"npm\s+audit\b",
    r"pnpm\s+audit\b",
    r"yarn\s+audit\b",
    r"snyk\s+test\b",
    r"pip-audit\b",
    r"osv-scanner\b",
    r"safety\s+(?:check|scan)\b",
    r"cargo\s+audit\b",
    r"govulncheck\b",
    r"actions/dependency-review-action",
)

_SCANNER_ANY = _FAIL_CLOSED_BY_DEFAULT + (
    r"trivy\b",
    r"grype\b",
    r"OWASP.*dependency",
    r"dependency.check\b",
)


def _eval_cve_scanning(recon: str, repo_root: str | None = None) -> dict[str, str]:
    """CVE scanning: SCA tool in CI with a blocking policy.

    Two grading corrections:

    * Most scanners (``npm audit``, ``pip-audit``, ``osv-scanner``, ``snyk test``)
      already exit non-zero on findings, so requiring an explicit threshold flag
      under-graded a correctly blocking pipeline to Partial.
    * ``|| true`` and ``continue-on-error: true`` deliberately neutralise that
      exit code and were not detected at all, so a knowingly advisory gate scored
      Adequate. This is the direction that produces a falsely reassuring report,
      so a detected suppressor downgrades regardless of the flags present.
    """
    text = _ci_text(recon, repo_root)

    advisory = _has(text, *_SCANNER_ANY)
    if not advisory:
        return {"effectiveness": MISSING, "reason": "No SCA/CVE scanning tool detected in CI or manifests."}

    # Suppressors, checked on the scanner's own line (or the step around it).
    suppressed = None
    for line in text.splitlines():
        if _has(line, *_SCANNER_ANY) and _has(
            line, r"\|\|\s*true", r"\|\|\s*:", r"--exit-code[= ]0", r"\|\|\s*exit\s+0"
        ):
            suppressed = "the scanner's exit code is discarded (`|| true` / `--exit-code 0`)"
            break
    if suppressed is None and _has(text, r"continue-on-error\s*:\s*true"):
        # Only meaningful if it sits in a block that also runs a scanner.
        for block in re.split(r"\n\s*-\s+(?=name:|uses:|run:)", text):
            if _has(block, *_SCANNER_ANY) and _has(block, r"continue-on-error\s*:\s*true"):
                suppressed = "the scanning step sets `continue-on-error: true`"
                break
    if suppressed:
        return {
            "effectiveness": WEAK,
            "reason": f"SCA tool runs in CI but {suppressed} — findings cannot block a merge.",
        }

    explicit_threshold = _has(
        text,
        r"npm\s+audit[^\n]*--audit-level[= ](?:moderate|high|critical)",
        r"snyk\s+test[^\n]*--severity-threshold",
        r"trivy[^\n]*--exit-code\s+[1-9]",
        r"grype[^\n]*--fail-on",
        r"osv-scanner[^\n]*--fail",
        r"pip-audit[^\n]*--fail-on",
    )
    if explicit_threshold or _has(text, *_FAIL_CLOSED_BY_DEFAULT):
        return {
            "effectiveness": ADEQUATE,
            "reason": "SCA tool runs in CI and fails the build on findings.",
        }
    return {
        "effectiveness": PARTIAL,
        "reason": "SCA tool present but advisory-only (no blocking exit code configured).",
    }


def _eval_sca_tooling(recon: str, repo_root: str | None = None) -> dict[str, str]:
    """SCA tooling: dedicated SCA tool vs. native audit only."""
    text = _ci_text(recon, repo_root)
    dedicated = _has(
        text,
        r"snyk\b",
        r"trivy\b",
        r"grype\b",
        r"osv-scanner\b",
        r"OWASP.*dependency.check",
        r"dependency.check\b",
        r"syft\b",
        r"actions/dependency-review-action",
        r"govulncheck\b",
    )
    native_only = _has(text, r"npm\s+audit\b", r"pip-audit\b", r"cargo\s+audit\b", r"safety\s+(?:check|scan)\b")
    if dedicated:
        return {
            "effectiveness": ADEQUATE,
            "reason": "Dedicated SCA tool (Snyk/Trivy/Grype/OSV-Scanner or equivalent) detected.",
        }
    if native_only:
        return {
            "effectiveness": PARTIAL,
            "reason": "Only native audit commands (npm audit / pip-audit) detected — no dedicated SCA tool.",
        }
    return {"effectiveness": MISSING, "reason": "No SCA tooling detected in CI or manifests."}


# ---------------------------------------------------------------------------
# Overall domain rating derivation
# ---------------------------------------------------------------------------

_EFFECTIVENESS_RANK = {ADEQUATE: 3, PARTIAL: 2, WEAK: 1, MISSING: 0}


def _derive_overall(sub_controls: list[dict[str, Any]]) -> tuple[str, str]:
    ratings = [sc["effectiveness"] for sc in sub_controls]
    # Weak is now reachable per-row (a suppressed SCA gate, an unsafe index
    # strategy) and represents an actively counter-productive control, so it
    # caps the domain exactly as Missing does.
    if any(r in (MISSING, WEAK) for r in ratings):
        worst = WEAK
    elif all(r == ADEQUATE for r in ratings):
        worst = ADEQUATE
    else:
        worst = PARTIAL

    missing_names = [sc["name"] for sc in sub_controls if sc["effectiveness"] == MISSING]
    weak_names = [sc["name"] for sc in sub_controls if sc["effectiveness"] == WEAK]
    partial_names = [sc["name"] for sc in sub_controls if sc["effectiveness"] == PARTIAL]

    clauses = []
    if missing_names:
        clauses.append(f"Missing controls: {', '.join(missing_names)}.")
    if weak_names:
        clauses.append(f"Weak: {', '.join(weak_names)}.")
    if partial_names:
        clauses.append(f"Partial: {', '.join(partial_names)}.")
    reason = " ".join(clauses) if clauses else "All supply chain sub-controls rated Adequate."
    return worst, reason


# ---------------------------------------------------------------------------
# Main assessment
# ---------------------------------------------------------------------------


def assess(output_dir: str, repo_root: str | None) -> dict[str, Any]:
    recon = _load_recon(output_dir, repo_root)

    sub_controls = [
        {"name": "CVE scanning", **_eval_cve_scanning(recon, repo_root)},
        {"name": "Lockfile pinning", **_eval_lockfile(recon, repo_root)},
        {"name": "CI install integrity", **_eval_ci_install(recon, repo_root)},
        {"name": "CI/CD action pinning", **_eval_action_pinning(recon, repo_root)},
        {"name": "Container image hygiene", **_eval_container_hygiene(recon, repo_root)},
        {"name": "Dependency confusion", **_eval_dependency_confusion(recon, repo_root)},
        {"name": "Postinstall scripts", **_eval_postinstall(recon, repo_root)},
        {"name": "Dependency management", **_eval_dep_management(recon, repo_root)},
        {"name": "SCA tooling", **_eval_sca_tooling(recon, repo_root)},
    ]

    overall_effectiveness, overall_reason = _derive_overall(sub_controls)

    return {
        "schema_version": 1,
        "domain": "Operations, Runtime and Supply Chain Controls",
        "sub_controls": sub_controls,
        "overall_effectiveness": overall_effectiveness,
        "overall_reason": overall_reason,
        "source": "deterministic:assess_supply_chain_controls.py",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Deterministic supply chain control assessment for Phase 8")
    parser.add_argument("output_dir", help="Assessment output directory (docs/security)")
    parser.add_argument("--repo-root", default=None, help="Repository root (optional, improves detection)")
    parser.add_argument("--report-only", action="store_true", help="Print JSON to stdout instead of writing file")
    args = parser.parse_args()

    result = assess(args.output_dir, args.repo_root)
    payload = json.dumps(result, indent=2)

    if args.report_only:
        print(payload)
        return

    out_path = Path(args.output_dir) / ".supply-chain-assessment.json"
    try:
        out_path.write_text(payload + "\n", encoding="utf-8")
        print(
            f"assess_supply_chain_controls: wrote {out_path} "
            f"(overall={result['overall_effectiveness']}, "
            f"{sum(1 for sc in result['sub_controls'] if sc['effectiveness'] == 'Missing')} missing / "
            f"{sum(1 for sc in result['sub_controls'] if sc['effectiveness'] == 'Adequate')} adequate)"
        )
    except OSError as exc:
        print(f"assess_supply_chain_controls: write failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
