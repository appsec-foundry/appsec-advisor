#!/usr/bin/env python3
"""Manifest parser — enumerate (ecosystem, package, version, file:line) tuples
across the ecosystems appsec-advisor targets.

Used by:
  - scripts/emit_known_bad_libs.py    (Proposal 2 — known-bad-libs match)

Design choices:
  - Manifest-only (no lockfile walk). The architectural choice is the
    direct dep; lockfile-aware matching blurs back toward SCA-tool
    territory (see sca.md §11 open-question resolution: manifest-only).
  - Best-effort parsing — malformed manifests yield empty lists, never
    raise. Threat-modeling pipeline must degrade gracefully.
  - Tuple keying — `(ecosystem, package)` is the unique identity. Names
    collide across ecosystems (npm `request` vs python `requests`).
  - Line numbers are best-effort: for JSON (package.json, composer.json)
    we substring-scan; for line-oriented formats (requirements.txt,
    Gemfile, etc.) we report the literal line.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator


@dataclass(frozen=True)
class Dep:
    ecosystem: str           # one of: npm, pip, go, maven, gem, composer, cargo, nuget
    package: str             # canonical package name
    version: str | None      # raw pin (may include ^/~/>= prefixes); None if unpinned
    manifest: str            # repo-relative path of the manifest
    line: int                # 1-based line number in the manifest (best effort)


_NPM_MANIFEST_NAMES = ("package.json",)
_PIP_MANIFEST_NAMES = ("requirements.txt", "requirements-dev.txt", "requirements-test.txt", "pyproject.toml", "setup.py", "Pipfile")
_GO_MANIFEST_NAMES = ("go.mod",)
_MAVEN_MANIFEST_NAMES = ("pom.xml", "build.gradle", "build.gradle.kts")
_GEM_MANIFEST_NAMES = ("Gemfile",)
_COMPOSER_MANIFEST_NAMES = ("composer.json",)
_CARGO_MANIFEST_NAMES = ("Cargo.toml",)
_NUGET_MANIFEST_NAMES = ("packages.config",)  # *.csproj parsed too — see below


def discover_manifests(repo_root: Path) -> list[Path]:
    """Walk repo_root and return all manifest files. Skips common vendor
    dirs (node_modules, .venv, vendor/, target/, build/).
    """
    skip = {"node_modules", ".venv", "venv", "vendor", "target", "build", "dist", ".git", ".tox", "__pycache__"}
    all_names = (
        _NPM_MANIFEST_NAMES + _PIP_MANIFEST_NAMES + _GO_MANIFEST_NAMES
        + _MAVEN_MANIFEST_NAMES + _GEM_MANIFEST_NAMES + _COMPOSER_MANIFEST_NAMES
        + _CARGO_MANIFEST_NAMES + _NUGET_MANIFEST_NAMES
    )
    out: list[Path] = []
    for p in repo_root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip for part in p.parts):
            continue
        if p.name in all_names or p.suffix == ".csproj":
            out.append(p)
    return out


def parse_manifest(path: Path, repo_root: Path) -> list[Dep]:
    """Dispatch to the per-ecosystem parser. Never raises — malformed
    manifests yield an empty list and the caller treats it as no deps.
    """
    rel = str(path.relative_to(repo_root)) if path.is_relative_to(repo_root) else str(path)
    try:
        if path.name == "package.json":
            return _parse_package_json(path, rel)
        if path.name in {"requirements.txt", "requirements-dev.txt", "requirements-test.txt"}:
            return _parse_requirements_txt(path, rel)
        if path.name == "pyproject.toml":
            return _parse_pyproject_toml(path, rel)
        if path.name == "Pipfile":
            return _parse_pipfile(path, rel)
        if path.name == "setup.py":
            return _parse_setup_py(path, rel)
        if path.name == "go.mod":
            return _parse_go_mod(path, rel)
        if path.name == "pom.xml":
            return _parse_pom_xml(path, rel)
        if path.name in {"build.gradle", "build.gradle.kts"}:
            return _parse_build_gradle(path, rel)
        if path.name == "Gemfile":
            return _parse_gemfile(path, rel)
        if path.name == "composer.json":
            return _parse_composer_json(path, rel)
        if path.name == "Cargo.toml":
            return _parse_cargo_toml(path, rel)
        if path.suffix == ".csproj":
            return _parse_csproj(path, rel)
        if path.name == "packages.config":
            return _parse_packages_config(path, rel)
    except (OSError, json.JSONDecodeError, ValueError):
        # Best-effort; surface nothing rather than crashing the pipeline.
        return []
    return []


def enumerate_deps(repo_root: Path) -> Iterator[Dep]:
    for m in discover_manifests(repo_root):
        for dep in parse_manifest(m, repo_root):
            yield dep


# ---------------------------------------------------------------------------
# Per-ecosystem parsers — each returns list[Dep] or [] on parse error.
# Line numbers are 1-based; when not derivable we report line 1.
# ---------------------------------------------------------------------------


def _find_line_for_key(text: str, key: str) -> int:
    """For JSON-ish text, find the 1-based line containing `"<key>"`."""
    needle = f'"{key}"'
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return 1


def _parse_package_json(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    out: list[Dep] = []
    for block in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for pkg, ver in (data.get(block) or {}).items():
            out.append(Dep("npm", pkg, ver, rel, _find_line_for_key(text, pkg)))
    return out


_REQ_PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~]=?\s*[^\s;#]+)?")


def _parse_requirements_txt(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line_clean = line.split("#", 1)[0].strip()
        if not line_clean or line_clean.startswith("-"):
            continue
        m = _REQ_PIN_RE.match(line_clean)
        if not m:
            continue
        out.append(Dep("pip", m.group(1), (m.group(2) or "").strip() or None, rel, i))
    return out


def _parse_pyproject_toml(path: Path, rel: str) -> list[Dep]:
    # Minimal TOML scan — avoids requiring tomllib presence assumptions.
    # We grep dependencies lists; full TOML parse is intentionally out of
    # scope for a known-bad match (lossy is OK, we just want package names).
    out: list[Dep] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    in_deps = False
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            in_deps = "dependencies" in line.lower() or line in ("[tool.poetry.dependencies]", "[tool.poetry.dev-dependencies]", "[project.dependencies]")
            continue
        if in_deps and "=" in line and not line.startswith("#"):
            name = line.split("=", 1)[0].strip().strip('"').strip("'")
            if name and name not in ("python",):
                ver = line.split("=", 1)[1].strip()
                out.append(Dep("pip", name, ver or None, rel, i))
        # PEP-621 list-of-strings form: dependencies = ["foo>=1.0", "bar"]
        if "dependencies" in line and "=" in line and "[" in line:
            for chunk in re.findall(r'"([^"]+)"', raw):
                m = _REQ_PIN_RE.match(chunk)
                if m:
                    out.append(Dep("pip", m.group(1), (m.group(2) or "").strip() or None, rel, i))
    return out


def _parse_pipfile(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    in_deps = False
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if line in ("[packages]", "[dev-packages]"):
            in_deps = True
            continue
        if line.startswith("["):
            in_deps = False
            continue
        if in_deps and "=" in line:
            name = line.split("=", 1)[0].strip()
            ver = line.split("=", 1)[1].strip()
            if name:
                out.append(Dep("pip", name, ver or None, rel, i))
    return out


_SETUP_PY_REQ_RE = re.compile(r"install_requires\s*=\s*\[([^\]]*)\]", re.DOTALL)


def _parse_setup_py(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    m = _SETUP_PY_REQ_RE.search(text)
    if not m:
        return []
    body = m.group(1)
    start_line = text[: m.start()].count("\n") + 1
    out: list[Dep] = []
    for chunk in re.findall(r'["\']([^"\']+)["\']', body):
        rm = _REQ_PIN_RE.match(chunk)
        if rm:
            out.append(Dep("pip", rm.group(1), (rm.group(2) or "").strip() or None, rel, start_line))
    return out


_GO_REQUIRE_LINE_RE = re.compile(r"^\s*(\S+)\s+(\S+)")


def _parse_go_mod(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    in_require_block = False
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        s = raw.strip()
        if s.startswith("require ("):
            in_require_block = True
            continue
        if in_require_block and s == ")":
            in_require_block = False
            continue
        if s.startswith("require ") and not s.startswith("require ("):
            body = s[len("require "):].strip()
            m = _GO_REQUIRE_LINE_RE.match(body)
            if m:
                out.append(Dep("go", m.group(1), m.group(2), rel, i))
            continue
        if in_require_block:
            m = _GO_REQUIRE_LINE_RE.match(s)
            if m and not s.startswith("//"):
                out.append(Dep("go", m.group(1), m.group(2), rel, i))
    return out


_POM_DEP_RE = re.compile(
    r"<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?",
    re.DOTALL,
)


def _parse_pom_xml(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Dep] = []
    for m in _POM_DEP_RE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        pkg = f"{m.group(1).strip()}:{m.group(2).strip()}"
        out.append(Dep("maven", pkg, (m.group(3) or "").strip() or None, rel, line))
    return out


_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compile|testImplementation|runtimeOnly)\s*[(]?\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


def _parse_build_gradle(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in _GRADLE_DEP_RE.finditer(text):
        coord = m.group(1)
        parts = coord.split(":")
        if len(parts) >= 2:
            pkg = f"{parts[0]}:{parts[1]}"
            ver = parts[2] if len(parts) >= 3 else None
            line = text[: m.start()].count("\n") + 1
            out.append(Dep("maven", pkg, ver, rel, line))
    return out


_GEMFILE_LINE_RE = re.compile(r"""\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""")


def _parse_gemfile(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if raw.strip().startswith("#"):
            continue
        m = _GEMFILE_LINE_RE.match(raw)
        if m:
            out.append(Dep("gem", m.group(1), m.group(2), rel, i))
    return out


def _parse_composer_json(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    out: list[Dep] = []
    for block in ("require", "require-dev"):
        for pkg, ver in (data.get(block) or {}).items():
            if pkg.startswith("php") or pkg.startswith("ext-"):
                continue
            out.append(Dep("composer", pkg, str(ver), rel, _find_line_for_key(text, pkg)))
    return out


_CARGO_DEP_LINE_RE = re.compile(r"""^\s*([A-Za-z0-9_\-]+)\s*=\s*(.+)$""")


def _parse_cargo_toml(path: Path, rel: str) -> list[Dep]:
    out: list[Dep] = []
    in_deps = False
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = raw.strip()
        if line.startswith("["):
            in_deps = line in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]")
            continue
        if in_deps and "=" in line and not line.startswith("#"):
            m = _CARGO_DEP_LINE_RE.match(line)
            if m:
                out.append(Dep("cargo", m.group(1), m.group(2), rel, i))
    return out


_CSPROJ_DEP_RE = re.compile(r'<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?')


def _parse_csproj(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Dep] = []
    for m in _CSPROJ_DEP_RE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        out.append(Dep("nuget", m.group(1), m.group(2), rel, line))
    return out


_PACKAGES_CONFIG_RE = re.compile(r'<package\s+id="([^"]+)"(?:\s+version="([^"]+)")?')


def _parse_packages_config(path: Path, rel: str) -> list[Dep]:
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[Dep] = []
    for m in _PACKAGES_CONFIG_RE.finditer(text):
        line = text[: m.start()].count("\n") + 1
        out.append(Dep("nuget", m.group(1), m.group(2), rel, line))
    return out
