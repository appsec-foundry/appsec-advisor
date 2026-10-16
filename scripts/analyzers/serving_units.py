"""Serving units: deployable code that answers requests or runs in a browser.

A component inventory that omits the unit serving a repository's routes, or
its client application, loses every finding, asset and flow behind it while
still looking complete. This scanner names those units from static signals so
inventory finalization can require a component for each of them.

Signals, per manifest root (the nearest directory holding a package or build
manifest, else the repository root):

* ``http-api``   route registrations from ``analyzers/route_inventory.py``;
  its entry files are the registering files, most routes first.
* ``client-app`` a ``package.json`` declaring a browser UI framework; its
  entry files are the runtime source files below that root.

Test, fixture, example, documentation, mock, vendored and build-output paths
never form or feed a unit. Languages without a route extractor (Go, Ruby,
PHP) yield no ``http-api`` unit; their coverage stays with discovery alone.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from shared._path_guard import is_safe_to_read

_MANIFESTS = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "requirements.txt",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "go.mod",
        "Gemfile",
        "composer.json",
    }
)
# Packages that only exist to render a browser UI. Meta-frameworks that also
# serve requests (Next.js, Nuxt) still declare one of these.
_CLIENT_FRAMEWORKS = ("@angular/core", "react-dom", "vue", "svelte", "solid-js", "preact")
_NON_RUNTIME_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "e2e",
        "cypress",
        "fixture",
        "fixtures",
        "testdata",
        "example",
        "examples",
        "sample",
        "samples",
        "doc",
        "docs",
        "mock",
        "mocks",
        "__mocks__",
        "stories",
        ".storybook",
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".git",
    }
)
_TEST_FILE_RE = re.compile(r"\.(?:spec|test|stories)\.[a-z]+$|(?:^|/)test_[^/]*\.py$|_test\.(?:py|go)$")
_TOOLING_FILE_RE = re.compile(r"\.config\.[a-z]+$|(?:^|/)(?:test-setup|setup-?tests?)\.[a-z]+$")
_CODE_EXTS = frozenset(
    {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".py", ".java", ".kt", ".cs"}
)
_ENTRY_NAME_RE = re.compile(r"(?:^|/)(?:main|index|app|server)\.[a-z]+$")
_MAX_MANIFEST_BYTES = 1_000_000
_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[2] / "schemas" / "architecture-serving-units.schema.json").read_text(
        encoding="utf-8"
    )
)
MAX_UNITS = _SCHEMA["properties"]["limits"]["properties"]["max_units"]["const"]
MAX_ENTRY_FILES = _SCHEMA["properties"]["limits"]["properties"]["max_entry_files"]["const"]


def is_runtime_path(rel: str) -> bool:
    """False for test, fixture, example, documentation, vendored or built files."""
    return not (set(rel.split("/")[:-1]) & _NON_RUNTIME_SEGMENTS or _TEST_FILE_RE.search(rel))


def _files(repo_root: Path) -> list[str]:
    found = []
    for directory, subdirectories, names in os.walk(repo_root):
        subdirectories[:] = sorted(d for d in subdirectories if d not in _NON_RUNTIME_SEGMENTS)
        base = Path(directory).relative_to(repo_root).as_posix()
        found.extend(name if base == "." else f"{base}/{name}" for name in names)
    return sorted(found)


def _manifest_root(rel: str, roots: list[str]) -> str:
    """The deepest manifest root holding ``rel``; ``""`` is the repository root."""
    return max((r for r in roots if r == "" or rel.startswith(r + "/")), key=len, default="")


def _client_framework(repo_root: Path, manifest: str) -> str | None:
    path = repo_root / manifest
    try:
        if not is_safe_to_read(path, repo_root) or path.stat().st_size > _MAX_MANIFEST_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    declared = set()
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        if isinstance(data.get(key), dict):
            declared.update(data[key])
    return next((name for name in _CLIENT_FRAMEWORKS if name in declared), None)


def scan(repo_root: Path, routes: list[dict]) -> list[dict]:
    """Every serving unit with its complete entry-file list, in a stable order.

    ``routes`` are the rows of the route inventory of the same ``repo_root``.
    """
    repo_root = Path(repo_root)
    files = [f for f in _files(repo_root) if is_runtime_path(f)]
    manifests = [f for f in files if f.rsplit("/", 1)[-1] in _MANIFESTS]
    roots = sorted({m.rsplit("/", 1)[0] if "/" in m else "" for m in manifests})
    units = []
    registrations: dict[str, dict[str, int]] = {}
    frameworks: dict[str, set[str]] = {}
    for route in routes:
        rel = route.get("handler_file")
        if not isinstance(rel, str) or not is_runtime_path(rel):
            continue
        root = _manifest_root(rel, roots)
        counts = registrations.setdefault(root, {})
        counts[rel] = counts.get(rel, 0) + 1
        if route.get("framework"):
            frameworks.setdefault(root, set()).add(str(route["framework"]))
    for root, counts in sorted(registrations.items()):
        units.append(
            {
                "id": f"http-api:{root or '.'}",
                "kind": "http-api",
                "root": root,
                "framework": ", ".join(sorted(frameworks.get(root, ()))) or None,
                "entry_files": sorted(counts, key=lambda rel: (-counts[rel], rel)),
            }
        )
    for manifest in manifests:
        if not manifest.endswith("package.json"):
            continue
        framework = _client_framework(repo_root, manifest)
        if framework is None:
            continue
        root = manifest.rsplit("/", 1)[0] if "/" in manifest else ""
        # A nested manifest root is its own unit, never this app's source.
        sources = [
            f
            for f in files
            if Path(f).suffix in _CODE_EXTS and _manifest_root(f, roots) == root and not _TOOLING_FILE_RE.search(f)
        ]
        # Files beside the manifest are build tooling when the app has a source tree.
        depth = root.count("/") + 1 if root else 0
        if any(f.count("/") > depth for f in sources):
            sources = [f for f in sources if f.count("/") > depth]
        if not sources:
            continue
        sources.sort(key=lambda rel: (not _ENTRY_NAME_RE.search(rel), rel.count("/"), rel))
        units.append(
            {
                "id": f"client-app:{root or '.'}",
                "kind": "client-app",
                "root": root,
                "framework": framework,
                "entry_files": sources,
            }
        )
    return units


def project(units: list[dict]) -> dict:
    """The bounded, schema-checked view a model receives.

    Coverage during discovery needs one listed entry file. A path the contract
    rejects is left out, never shortened; a unit left without a listable entry
    file is omitted here and still enforced by component finalization.
    """
    from jsonschema import Draft202012Validator  # noqa: PLC0415

    item = _SCHEMA["properties"]["units"]["items"]["properties"]
    path_ok = Draft202012Validator(item["entry_files"]["items"]).is_valid
    shown = []
    for unit in units:
        files = [rel for rel in unit["entry_files"] if path_ok(rel)]
        if not files or len(unit["root"]) > item["root"]["maxLength"]:
            continue
        if len(shown) == MAX_UNITS:
            break
        shown.append(
            {
                **{key: unit[key] for key in ("id", "kind", "root", "framework")},
                "entry_files": files[:MAX_ENTRY_FILES],
                "omitted_entry_files": len(unit["entry_files"]) - min(len(files), MAX_ENTRY_FILES),
            }
        )
    projected = {
        "schema_version": 1,
        "limits": {
            "max_units": MAX_UNITS,
            "max_entry_files": MAX_ENTRY_FILES,
            "omitted_units": len(units) - len(shown),
        },
        "units": shown,
    }
    Draft202012Validator(_SCHEMA).validate(projected)
    return projected


# An http-api unit needs an application component; a client may be modelled as
# a client or, for server-rendered applications, as an application component.
_CARRIER_TIERS = {"http-api": {"application"}, "client-app": {"client", "application"}}


def _owns(component: dict, rel: str) -> bool:
    from orchestrator.build_stride_dispatch_manifest import _path_owns  # noqa: PLC0415

    paths = [p for p in component.get("paths") or [] if isinstance(p, str)]
    return rel in paths or _path_owns(paths, rel)


def carriers(unit: dict, components: list[dict]) -> list[dict]:
    """Components of an eligible tier that list one of the unit's entry files."""
    tiers = _CARRIER_TIERS[unit["kind"]]
    return [c for c in components if c.get("tier") in tiers and any(_owns(c, rel) for rel in unit["entry_files"])]


def uncovered(units: list[dict], components: list[dict]) -> list[dict]:
    return [unit for unit in units if not carriers(unit, components)]


def describe(units: list[dict]) -> str:
    """A bounded, controller-authored reason naming each uncovered unit."""
    rows = [
        f"{u['kind']} at {u['root'] or 'repository root'} (entry files: {', '.join(u['entry_files'][:3])})"
        for u in units[:MAX_UNITS]
    ]
    return "; ".join(rows)


def adopt(units: list[dict], components: list[dict], repo_root: Path, routes: list[dict]) -> int:
    """Give each unit's carrier the unit's code no eligible component lists; return additions.

    An http-api carrier receives the resolved handler module of every route it
    registers. A client-app carrier receives the app's runtime source files.
    Files another eligible component lists stay with it.
    """
    from analyzers.handler_resolver import HandlerResolver  # noqa: PLC0415

    eligible = [c for c in components if c.get("tier") in {"client", "application"}]
    added = 0

    def give(owner: dict, rel: str) -> None:
        nonlocal added
        if not is_runtime_path(rel) or any(_owns(c, rel) for c in eligible):
            return
        owner["paths"] = [*owner.get("paths", []), rel]
        added += 1

    resolver = None
    for unit in units:
        found = carriers(unit, components)
        if not found:
            continue
        if unit["kind"] == "client-app":
            for rel in unit["entry_files"]:
                give(found[0], rel)
            continue
        resolver = resolver or HandlerResolver(repo_root)
        for route in routes:
            registering = route.get("handler_file")
            owner = next((c for c in found if registering in unit["entry_files"] and _owns(c, registering)), None)
            if owner is None:
                continue
            module = resolver.handler_module(route)
            if module:
                give(owner, module)
    return added
