"""Record that access to an embedded database engine has no authentication layer.

An embedded engine (SQLite, MarsDB, NeDB, LokiJS) runs inside the application
process and offers no login of its own. When the architecture producer left the
receiving authentication of a flow into such a store open, the controller-owned
handoff records ``none`` and cites the engine's instantiation lines. A data
component is linked to an engine only through its declared framework, its paths,
or the evidence of a flow into it; names never link it. Producer values stay.
PouchDB is excluded because it can synchronize with an authenticated remote.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path

from reclassify_components import _glob_to_regex
from recon_patterns import _walk_repo

MAX_FILES = 20000
MAX_FILE_BYTES = 1_000_000
MAX_EVIDENCE = 8
EVIDENCE_WINDOW = 5  # A flow citing the constructor call links its option lines too.
_NETWORK_ENGINE = re.compile(
    r"postgres|mysql|mariadb|mssql|sql ?server|oracle|mongo|redis|cassandra|dynamo|elastic|couch|neo4j|cockroach|"
    r"firestore|cosmos",
    re.I,
)
_SOURCE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".rb", ".php"}
_NON_RUNTIME = re.compile(
    r"(?:^|/)(?:tests?|__tests__|fixtures?|examples?|docs?|samples?|mocks?)(?:/|$)|(?:\.test|\.spec|_test|Test)\.", re.I
)
_COMMENT = re.compile(r"^\s*(?://|#|\*|/\*)")
_NAMES = {"sqlite": "SQLite", "marsdb": "MarsDB", "nedb": "NeDB", "lokijs": "LokiJS"}
# (engine, package, constructor after the imported identifier)
_IMPORTED = (
    ("marsdb", "marsdb", r"\.Collection"),
    ("nedb", "nedb", ""),
    ("nedb", "@seald-io/nedb", ""),
    ("lokijs", "lokijs", ""),
    ("sqlite", "sqlite3", r"\.Database"),
    ("sqlite", "better-sqlite3", ""),
)
_LITERAL = (
    re.compile(r"\bdialect\s*:\s*['\"]sqlite['\"]"),
    re.compile(r"\bclient\s*:\s*['\"](?:sqlite3?|better-sqlite3)['\"]"),
    re.compile(r"\bsqlite3\.connect\s*\("),
    re.compile(r"['\"]jdbc:sqlite:"),
    re.compile(r"\bsql\.Open\s*\(\s*\"sqlite3?\""),
)


@dataclass(frozen=True, order=True)
class Site:
    file: str
    line: int
    engine: str


def _sites_in(text: str, rel: str) -> list[Site]:
    patterns = [("sqlite", pattern) for pattern in _LITERAL]
    for engine, package, constructor in _IMPORTED:
        imported = re.search(
            r"(?:import\s+(?:\*\s+as\s+)?|(?:const|let|var)\s+)([A-Za-z_$][\w$]*)\s*(?:from\s*|=\s*require\(\s*)['\"]"
            + re.escape(package)
            + r"['\"]",
            text,
        )
        if imported:
            patterns.append((engine, re.compile(r"\bnew\s+" + re.escape(imported[1]) + constructor + r"\s*\(")))
    sites = []
    for number, line in enumerate(text.splitlines(), 1):
        if _COMMENT.match(line):
            continue
        sites.extend(Site(rel, number, engine) for engine, pattern in patterns if pattern.search(line))
    return sites


def instantiation_sites(repo_root: Path) -> list[Site]:
    """Runtime source lines that open an embedded engine; tests and docs excluded."""
    root = repo_root.resolve()
    sites, count = set(), 0
    for path in _walk_repo(root):
        rel = path.relative_to(root).as_posix()
        if path.suffix not in _SOURCE_EXT or _NON_RUNTIME.search(rel):
            continue
        if not path.is_file() or not path.resolve().is_relative_to(root) or path.stat().st_size > MAX_FILE_BYTES:
            continue
        count += 1
        if count > MAX_FILES:
            break
        sites.update(_sites_in(path.read_text(encoding="utf-8", errors="replace"), rel))
    return sorted(sites)


def _owns(patterns: list, file: str) -> bool:
    return any(isinstance(p, str) and _glob_to_regex(p).fullmatch(file) for p in patterns)


def _linked_sites(component: dict, flows: list[dict], sites: list[Site]) -> list[Site]:
    framework = str(component.get("framework") or "").lower()
    if _NETWORK_ENGINE.search(framework):
        return []
    cited = [
        (e.get("file"), e.get("line"))
        for f in flows
        if f.get("to") == component.get("id")
        for e in f.get("evidence") or []
        if isinstance(e, dict) and isinstance(e.get("line"), int)
    ]
    return [
        site
        for site in sites
        if site.engine in framework
        or _owns(component.get("paths") or [], site.file)
        or any(file == site.file and abs(line - site.line) <= EVIDENCE_WINDOW for file, line in cited)
    ]


def record_embedded_access(repo_root: Path, components: list[dict], document: dict) -> dict:
    """Return the flow document with ``none`` on open accesses to embedded stores."""
    result = copy.deepcopy(document)
    flows = [f for f in result.get("data_flows") or [] if isinstance(f, dict)]
    stores = [c for c in components if isinstance(c, dict) and c.get("tier") == "data" and c.get("id")]
    if not stores:
        return result
    sites = instantiation_sites(repo_root)
    for store in stores:
        linked = _linked_sites(store, flows, sites)
        if not linked:
            continue
        engines = " and ".join(sorted({_NAMES[site.engine] for site in linked}))
        authentication = {
            "scheme": "none",
            "scope": f"Embedded {engines} engine inside the application process; the engine has no login of its own.",
            "evidence": [{"file": site.file, "line": site.line} for site in linked[:MAX_EVIDENCE]],
        }
        for flow in flows:
            if flow.get("to") == store["id"] and not flow.get("authentication"):
                flow["authentication"] = copy.deepcopy(authentication)
    return result
