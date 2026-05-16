"""Polyglot project-manifest readers for infobox enrichment.

Extracted move-only from ``compose_threat_model.py`` (Phase A2 of
``docs/refactoring-plan.md``). No behavior change — these functions are
the same code at the same call signature, just relocated to keep
``compose_threat_model.py`` from sprawling further. All eight readers
take a ``ctx`` whose only required attribute is ``output_dir: Path``
(duck-typed to avoid a circular import with ``compose_threat_model``).

Public surface used by ``compose_threat_model._render_infobox``:

    read_project_manifest(ctx)   -> dict
    read_readme_description(ctx) -> str | None
    read_readme_tags(ctx)        -> list[str] | None
    read_license_file(ctx)       -> str | None
    format_author(author)        -> str | None
    derive_homepage(remote, pkg) -> str | None
    derive_runtime(pkg)          -> str | None
    extract_repo_url(repo)       -> str | None
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from compose_threat_model import RenderContext  # pragma: no cover

__all__ = [
    "read_package_json",
    "read_project_manifest",
    "read_readme_description",
    "read_readme_tags",
    "read_license_file",
    "format_author",
    "derive_homepage",
    "derive_runtime",
    "extract_repo_url",
]


def _repo_root_candidates(ctx: RenderContext) -> list[Path]:
    """Possible repo roots. Usually `OUTPUT_DIR.parent.parent` (when output
    is at `<repo>/docs/security/`), but we try a few levels up to be
    defensive about non-standard layouts."""
    try:
        p = ctx.output_dir
    except Exception:
        return []
    return [
        p.parent.parent,  # <repo>/docs/security → <repo>
        p.parent,  # <repo>/docs → might hold the manifest
        p,  # output dir itself, unlikely but cheap
    ]


def read_package_json(ctx: RenderContext) -> dict[str, Any]:
    """Read package.json from the repository root for infobox enrichment."""
    for candidate in _repo_root_candidates(ctx):
        p = candidate / "package.json"
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
    return {}


def read_project_manifest(ctx: RenderContext) -> dict[str, Any]:
    """Polyglot project-metadata reader.

    Returns a dict with a normalised shape that mirrors package.json's:
      { name, version, description, author, license, repository,
        homepage, keywords, runtime }
    Missing fields are omitted (caller uses `.get()` with fallbacks).

    Tries manifests in order of fidelity: package.json (full native support)
    → pyproject.toml → Cargo.toml → go.mod → pom.xml → build.gradle.
    Falls back to README.md for a description when no manifest listed one.
    """
    pkg = read_package_json(ctx)
    if pkg:
        return pkg

    data = _read_pyproject_toml(ctx)
    if data:
        data.setdefault("description", read_readme_description(ctx))
        return data

    data = _read_cargo_toml(ctx)
    if data:
        data.setdefault("description", read_readme_description(ctx))
        return data

    data = _read_go_mod(ctx)
    if data:
        data.setdefault("description", read_readme_description(ctx))
        return data

    data = _read_pom_xml(ctx)
    if data:
        data.setdefault("description", read_readme_description(ctx))
        return data

    data = _read_gradle(ctx)
    if data:
        data.setdefault("description", read_readme_description(ctx))
        return data

    desc = read_readme_description(ctx)
    return {"description": desc} if desc else {}


def _read_pyproject_toml(ctx: RenderContext) -> dict[str, Any]:
    """PEP 621 [project] block."""
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return {}
    for root in _repo_root_candidates(ctx):
        p = root / "pyproject.toml"
        if not p.is_file():
            continue
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        proj = data.get("project") or {}
        if not proj:
            proj = (data.get("tool") or {}).get("poetry") or {}
        if not proj:
            continue
        authors = proj.get("authors") or []
        author = None
        if authors:
            first = authors[0]
            if isinstance(first, str):
                author = first
            elif isinstance(first, dict):
                name = first.get("name") or ""
                email = first.get("email") or ""
                author = f"{name} ({email})" if email else name
        license_ = proj.get("license")
        if isinstance(license_, dict):
            license_ = license_.get("text") or license_.get("file")
        urls = proj.get("urls") or {}
        runtime_parts: list[str] = []
        reqs = proj.get("requires-python")
        if reqs:
            runtime_parts.append(f"Python {reqs}")
        deps = proj.get("dependencies") or []
        for d in deps[:5]:
            if isinstance(d, str):
                name = re.split(r"[<>=~! ]", d, 1)[0].strip()
                if name:
                    runtime_parts.append(name)
        return {
            "name": proj.get("name"),
            "version": proj.get("version"),
            "description": proj.get("description"),
            "author": author,
            "license": license_,
            "repository": urls.get("Repository") or urls.get("Source"),
            "homepage": urls.get("Homepage"),
            "keywords": proj.get("keywords"),
            "runtime": ", ".join(runtime_parts) or None,
        }
    return {}


def _read_cargo_toml(ctx: RenderContext) -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            return {}
    for root in _repo_root_candidates(ctx):
        p = root / "Cargo.toml"
        if not p.is_file():
            continue
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        pkg = data.get("package") or {}
        if not pkg:
            continue
        authors = pkg.get("authors") or []
        author = authors[0] if authors else None
        rust_ver = pkg.get("rust-version")
        runtime = f"Rust {rust_ver}" if rust_ver else "Rust (Cargo)"
        return {
            "name": pkg.get("name"),
            "version": pkg.get("version"),
            "description": pkg.get("description"),
            "author": author,
            "license": pkg.get("license"),
            "repository": pkg.get("repository"),
            "homepage": pkg.get("homepage"),
            "keywords": pkg.get("keywords"),
            "runtime": runtime,
        }
    return {}


def _read_go_mod(ctx: RenderContext) -> dict[str, Any]:
    for root in _repo_root_candidates(ctx):
        p = root / "go.mod"
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        module_match = re.search(r"^module\s+(\S+)", text, re.MULTILINE)
        go_match = re.search(r"^go\s+(\S+)", text, re.MULTILINE)
        if not module_match:
            continue
        name = module_match.group(1).strip()
        return {
            "name": name.rsplit("/", 1)[-1],
            "repository": name if name.startswith("github.com") else None,
            "runtime": f"Go {go_match.group(1)}" if go_match else "Go",
        }
    return {}


def _read_pom_xml(ctx: RenderContext) -> dict[str, Any]:
    """Maven pom.xml — best-effort regex extraction (xml.etree avoids having
    to pull in lxml, but namespace-aware parsing via ElementTree works)."""
    for root in _repo_root_candidates(ctx):
        p = root / "pom.xml"
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        text_ns = re.sub(r'\sxmlns="[^"]+"', "", text, count=1)
        try:
            import xml.etree.ElementTree as ET

            root_el = ET.fromstring(text_ns)
        except ET.ParseError:
            continue

        def find_text(path: str) -> str | None:
            el = root_el.find(path)
            return (el.text or "").strip() if el is not None and el.text else None

        name = find_text("name") or find_text("artifactId")
        version = find_text("version")
        description = find_text("description")
        url = find_text("url")
        licenses = root_el.findall("licenses/license/name")
        license_ = licenses[0].text if licenses and licenses[0].text else None
        developers = root_el.findall("developers/developer/name")
        author = developers[0].text if developers and developers[0].text else None
        scm_url = find_text("scm/url")
        java_ver = find_text("properties/java.version") or find_text("properties/maven.compiler.source")
        deps = []
        for dep in root_el.findall("dependencies/dependency/artifactId")[:5]:
            if dep.text:
                deps.append(dep.text)
        runtime_parts: list[str] = []
        if java_ver:
            runtime_parts.append(f"Java {java_ver}")
        runtime_parts.extend(deps)
        return {
            "name": name,
            "version": version,
            "description": description,
            "author": author,
            "license": license_,
            "repository": scm_url or url,
            "homepage": url,
            "runtime": ", ".join(runtime_parts) or None,
        }
    return {}


def _read_gradle(ctx: RenderContext) -> dict[str, Any]:
    """Gradle / Kotlin Gradle build — regex-based because a full Groovy/KTS
    parser is out of scope. Extracts what's commonly declarative.

    Returns a dict with the normalised shape expected by the infobox:
      {name, version, description, author, license, homepage, runtime, keywords}.
    License / homepage / keywords are filled from sibling files (LICENSE,
    git remote, README frontmatter) because Gradle itself rarely declares
    them.
    """
    for root in _repo_root_candidates(ctx):
        for filename in ("build.gradle", "build.gradle.kts"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                continue
            settings_path = root / ("settings.gradle.kts" if filename.endswith(".kts") else "settings.gradle")
            settings_text = ""
            if settings_path.is_file():
                try:
                    settings_text = settings_path.read_text(encoding="utf-8")
                except OSError:
                    settings_text = ""

            def first(pattern: str, haystack: str, flags: int = re.MULTILINE) -> str | None:
                m = re.search(pattern, haystack, flags)
                return m.group(1).strip() if m else None

            name = first(r'rootProject\.name\s*=\s*[\'"]([^\'"]+)[\'"]', settings_text) or first(
                r'archivesBaseName\s*=\s*[\'"]([^\'"]+)[\'"]', text
            )
            version = first(r'^\s*version\s*=\s*[\'"]([^\'"]+)[\'"]', text)
            group = first(r'^\s*group\s*=\s*[\'"]([^\'"]+)[\'"]', text)
            description = first(r'description\s*=\s*[\'"]([^\'"]+)[\'"]', text, flags=0)
            java_ver = first(r'sourceCompatibility\s*=\s*[\'"]?([\d.]+)', text, flags=0) or first(
                r"JavaVersion\.VERSION_([\d_]+)", text, flags=0
            )
            spring_boot = first(
                r"id\s*\(?\s*[\'\"]org\.springframework\.boot[\'\"]\s*\)?\s*version\s*[\'\"]([^\'\"]+)",
                text,
                flags=0,
            )
            runtime_parts: list[str] = []
            if java_ver:
                runtime_parts.append(f"Java {java_ver.replace('_', '.')}")
            if spring_boot:
                runtime_parts.append(f"Spring Boot {spring_boot}")
            impl_deps = re.findall(
                r"\b(?:implementation|compile|api)\s*\(?\s*[\'\"]([^\'\"]+):[^\'\"]+:[^\'\"]+[\'\"]",
                text,
            )
            libs: list[str] = []
            for d in impl_deps[:6]:
                libs.append(d.split(":")[-1])
            runtime_parts.extend(libs[:3])
            return {
                "name": name,
                "version": version,
                "author": group,
                "description": description,
                "runtime": ", ".join(runtime_parts) or None,
            }
    return {}


def read_readme_description(ctx: RenderContext) -> str | None:
    """Extract a one-line description from README.md — the first non-empty
    paragraph after the H1 title, capped at ~200 chars.

    Used as the last-resort description when a manifest doesn't carry one.
    """
    for root in _repo_root_candidates(ctx):
        for filename in ("README.md", "README.rst", "Readme.md", "readme.md"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            text = re.sub(r"^---\n.*?\n---\n", "", text, count=1, flags=re.DOTALL)
            lines = text.splitlines()
            start = 0
            for i, line in enumerate(lines):
                if re.match(r"^#\s+\S", line):
                    start = i + 1
                    break
            for line in lines[start:]:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith(("#", "<!", "!", "[!", "<img", "[![", "```", ">", "|")):
                    continue
                stripped = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", stripped)
                stripped = re.sub(r"\*\*?([^*]+)\*\*?", r"\1", stripped)
                stripped = re.sub(r"`([^`]+)`", r"\1", stripped)
                if len(stripped) > 250:
                    stripped = stripped[:247].rstrip() + "…"
                return stripped
    return None


def format_author(author: Any) -> str | None:
    """package.json 'author' may be a string ('Name <email> (url)') or an object.
    Gradle/Maven pass plain strings (groupId), pyproject may pass a list/dict.
    """
    if not author:
        return None
    if isinstance(author, str):
        return author.strip() or None
    if isinstance(author, dict):
        name = author.get("name") or ""
        email = f" ({author['email']})" if author.get("email") else ""
        return (name + email) if name else None
    if isinstance(author, list) and author:
        return format_author(author[0])
    return None


def read_license_file(ctx: RenderContext) -> str | None:
    """Parse a LICENSE file at the repo root and infer the SPDX identifier.

    Returns a short label like 'MIT', 'Apache-2.0', 'GPL-3.0', 'BSD-3-Clause',
    or the first non-empty line of the file when no well-known SPDX pattern
    matches. Used as a fallback when the project manifest does not declare
    a license (common for Gradle, Maven, Go, and hand-rolled builds).
    """
    for root in _repo_root_candidates(ctx):
        for filename in (
            "LICENSE",
            "LICENSE.md",
            "LICENSE.txt",
            "LICENCE",
            "LICENCE.md",
            "LICENCE.txt",
            "COPYING",
            "COPYING.md",
        ):
            p = root / filename
            if not p.is_file():
                continue
            try:
                head = p.read_text(encoding="utf-8", errors="ignore")[:2000]
            except OSError:
                continue
            tests: list[tuple[str, str]] = [
                (r"\bApache License,?\s+Version\s+2\.0\b", "Apache-2.0"),
                (r"\bMozilla Public License\s+Version\s+2\.0\b", "MPL-2.0"),
                (r"\bGNU AFFERO GENERAL PUBLIC LICENSE\b", "AGPL-3.0"),
                (r"\bGNU LESSER GENERAL PUBLIC LICENSE\b", "LGPL-3.0"),
                (r"\bGNU GENERAL PUBLIC LICENSE[\s\S]{0,50}?Version\s+3", "GPL-3.0"),
                (r"\bGNU GENERAL PUBLIC LICENSE[\s\S]{0,50}?Version\s+2", "GPL-2.0"),
                (r"\bBSD 3-Clause\b|New BSD License", "BSD-3-Clause"),
                (r"\bBSD 2-Clause\b|Simplified BSD", "BSD-2-Clause"),
                (r"\bISC License\b", "ISC"),
                (r"\bThe Unlicense\b", "Unlicense"),
                (
                    r"Permission is hereby granted, free of charge[\s\S]{0,200}"
                    r'THE SOFTWARE IS PROVIDED "AS IS"',
                    "MIT",
                ),
                (r"\bMIT License\b", "MIT"),
            ]
            for pat, spdx in tests:
                if re.search(pat, head, flags=re.IGNORECASE):
                    return spdx
            for line in head.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "<!")):
                    return line[:80]
    return None


def derive_homepage(remote_url: str | None, pkg: dict[str, Any]) -> str | None:
    """Infer a project homepage.

    Order of preference:
      1. Explicit pkg['homepage'] (package.json, pyproject urls.Homepage, etc.)
      2. git remote URL, normalised (strip .git) — the repo is usually a
         reasonable fallback homepage for OSS projects.
    """
    if pkg and pkg.get("homepage"):
        return pkg["homepage"]
    if not remote_url:
        return None
    url = remote_url.strip()
    url = re.sub(r"^git\+", "", url)
    url = re.sub(r"\.git/?$", "", url)
    m = re.match(r"^git@([^:]+):(.+)$", url)
    if m:
        url = f"https://{m.group(1)}/{m.group(2)}"
    return url or None


def read_readme_tags(ctx: RenderContext) -> list[str] | None:
    """Read topics/tags from README frontmatter or `.github/topics` manifest.

    Sources (first match wins):
      1. README.md YAML frontmatter with `tags:` or `topics:` (list).
      2. `.github/topics` or `.github/repo-topics.yml` (newline- or yaml-list).
      3. Heuristic: capitalised stand-alone words inside the first README
         paragraph that look like tech keywords (Java, Spring, Docker, OWASP,
         …) — only used when the project is obviously OSS-adjacent and other
         sources were silent.
    """
    for root in _repo_root_candidates(ctx):
        for filename in ("README.md", "Readme.md", "readme.md"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            fm = re.match(r"^---\s*\n([\s\S]*?)\n---\s*\n", text)
            if fm:
                try:
                    import yaml as _yaml

                    data = _yaml.safe_load(fm.group(1)) or {}
                    for key in ("tags", "topics", "keywords"):
                        v = data.get(key)
                        if isinstance(v, list) and v:
                            return [str(x) for x in v][:8]
                        if isinstance(v, str) and v.strip():
                            return [s.strip() for s in re.split(r"[,\s]+", v) if s.strip()][:8]
                except Exception:
                    pass
            break
        for filename in (".github/topics", ".github/repo-topics.yml", ".github/repo-topics.yaml"):
            p = root / filename
            if not p.is_file():
                continue
            try:
                raw = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            parts = [ln.strip().lstrip("- ") for ln in raw.splitlines() if ln.strip()]
            parts = [p for p in parts if p and not p.startswith("#")]
            if parts:
                return parts[:8]
    return None


def extract_repo_url(repo: Any) -> str | None:
    """package.json 'repository' may be a string or {type, url}."""
    if not repo:
        return None
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict) and repo.get("url"):
        url = repo["url"]
        url = re.sub(r"^git\+", "", url)
        url = re.sub(r"\.git/?$", "", url)
        return url
    return None


def derive_runtime(pkg: dict[str, Any]) -> str | None:
    """Synthesise a Runtime line from package.json engines + key dependencies."""
    if not pkg:
        return None
    parts: list[str] = []
    engines = pkg.get("engines") or {}
    if engines.get("node"):
        parts.append(f"`Node.js` {engines['node']}")
    deps = pkg.get("dependencies") or {}
    for key, label in [
        ("express", "Express"),
        ("angular", "Angular"),
        ("@angular/core", "Angular"),
        ("react", "React"),
        ("vue", "Vue"),
        ("next", "Next.js"),
    ]:
        if deps.get(key):
            v = deps[key].lstrip("^~>=<")
            parts.append(f"{label} {v.split('.')[0]}")
            break
    return ", ".join(parts) if parts else None
