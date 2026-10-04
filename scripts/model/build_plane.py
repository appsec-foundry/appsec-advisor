#!/usr/bin/env python3
"""Whether a component belongs to the build plane rather than the running system.

Figure 1a draws the running system and leaves the build plane to Figure 1b; the
§2.2 container diagram follows the same split. Every consumer asks this module,
so a component cannot be runtime in one figure and build in another (RA-28).

The answer is about placement only. Whether a build-time actor can exploit a
finding stays with data/actor-attribution-rules.yaml.

A component is build-plane when one of its deployment zones names the build
(a zone token ``ci``, ``cicd``, ``build`` or ``pipeline``), or when its paths
cite at least one CI definition and otherwise only build-neutral files:
container build files, compose files, package manifests, lockfiles and build
scripts. Any other path, application source above all, keeps the component in
the runtime. A Dockerfile alone never makes a component build-plane, because
the same file defines the runtime image.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from typing import Any

BUILD_ZONE_TOKENS = frozenset({"ci", "cicd", "build", "pipeline"})

# CI definition files of the systems deployment_inventory.scan_ci recognises.
CI_DEFINITION_PATTERNS = (
    ".github/workflows/*",
    ".github/workflows/**",
    ".gitlab-ci.yml",
    ".gitlab-ci.yaml",
    "Jenkinsfile",
    ".circleci/*",
    ".circleci/**",
    "azure-pipelines.yml",
    "azure-pipelines.yaml",
    "bitbucket-pipelines.yml",
    ".travis.yml",
)

# Files a build component may cite besides its CI definitions.
BUILD_NEUTRAL_PATTERNS = (
    "Dockerfile",
    "Dockerfile.*",
    "*.dockerfile",
    "docker-compose*.yml",
    "docker-compose*.yaml",
    "compose*.yml",
    "compose*.yaml",
    ".dockerignore",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".npmrc",
    "requirements*.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "uv.lock",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "gradle.lockfile",
    "Makefile",
    ".github/dependabot.yml",
    ".github/dependabot.yaml",
    "renovate.json",
)


def _normalized(path: Any) -> str:
    text = str(path or "").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("/")


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch(path, pattern) or ("/" not in pattern and fnmatch(name, pattern)) for pattern in patterns)


def is_ci_definition(path: Any) -> bool:
    """True when ``path`` (a file or a glob) names a CI definition."""
    return _matches(_normalized(path), CI_DEFINITION_PATTERNS)


def _zone_names_build(zone: Any) -> bool:
    return bool(BUILD_ZONE_TOKENS & set(re.split(r"[^a-z0-9]+", str(zone or "").lower())))


def is_build_component(component: dict[str, Any]) -> bool:
    """True when ``component`` belongs to the build plane; see the module docstring."""
    if not isinstance(component, dict):
        return False
    if any(_zone_names_build(zone) for zone in component.get("deployment_zones") or []):
        return True
    paths = [_normalized(path) for path in component.get("paths") or [] if _normalized(path)]
    if not any(is_ci_definition(path) for path in paths):
        return False
    return all(is_ci_definition(path) or _matches(path, BUILD_NEUTRAL_PATTERNS) for path in paths)


def build_component_ids(components: list[dict[str, Any]]) -> set[str]:
    """IDs of the build-plane components of a model."""
    return {c["id"] for c in components or [] if isinstance(c, dict) and c.get("id") and is_build_component(c)}
