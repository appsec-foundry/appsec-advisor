"""Extract an ORM model and raw-query relationship map from JS/TS sources.

Scans JavaScript/TypeScript application files (tests, builds and vendored
code excluded) with regex heuristics and no LLM calls. Import patterns detect
Sequelize, Mongoose, TypeORM and Prisma; model definitions are extracted for
Sequelize, Mongoose (`mongoose.model("Name", ...)`) and TypeORM only, and
associations for Sequelize only. Route consumers are read only from
`<REPO_ROOT>/routes/**/*.ts`.

Output (JSON):
    {
      "version": 1,
      "generated_at": "<iso-8601>",
      "orm_detected": ["mongoose", "prisma", "sequelize", "typeorm"],  # sorted subset; [] when none
      "models": {
        "<model_name>": {
          "model_file": "<repo-relative path>",
          "associations": ["<model_name>", ...],
          "raw_query_callers": [{"file": ..., "line": ..., "snippet": ...}],
          "route_consumers": ["<routes/*.ts path>", ...]
        }
      },
      "raw_query_routes": [{"file": ..., "line": ..., "snippet": ...}],
      "note": "..."  # only when no ORM is detected; models and raw_query_routes are then empty
    }

`raw_query_routes` lists every raw-query call site in any scanned file.
`raw_query_callers` holds the subset in `routes/*.ts` whose snippet names the
model. A `routes/*.ts` file is a route consumer of every model whose name it
contains as a word.

`scripts/orchestrator/orchestration_controller.py` runs it best-effort with
`--output $OUTPUT_DIR/.fragments/data-relations.json`.

CLI:
    analyzers/extract_data_relations.py <REPO_ROOT> [--output FILE] [--quiet]

Without --output the file is written to
<REPO_ROOT>/docs/security/.fragments/data-relations.json.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))


import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Patterns for ORM detection + model extraction
# ---------------------------------------------------------------------------

# Sequelize
SEQUELIZE_DETECT = re.compile(r"from\s+['\"]sequelize['\"]|require\(['\"]sequelize['\"]\)")
SEQUELIZE_MODEL_DEFINE = re.compile(
    r"sequelize\.define\(\s*['\"](\w+)['\"]"
    r"|class\s+(\w+)\s+extends\s+Model"
    r"|@Table.*?\n\s*(?:export\s+)?class\s+(\w+)\s+extends\s+Model"
)
SEQUELIZE_RAW_QUERY = re.compile(r"sequelize\.query\(|sequelize\.literal\(|Sequelize\.literal\(")
SEQUELIZE_ASSOC = re.compile(r"\.(hasMany|belongsTo|hasOne|belongsToMany)\(\s*(?:models\.)?(\w+)")

# Mongoose
MONGOOSE_DETECT = re.compile(r"from\s+['\"]mongoose['\"]|require\(['\"]mongoose['\"]\)")
MONGOOSE_MODEL_DEFINE = re.compile(r"mongoose\.model\(\s*['\"](\w+)['\"]|new\s+mongoose\.Schema\(")

# TypeORM
TYPEORM_DETECT = re.compile(r"from\s+['\"]typeorm['\"]|require\(['\"]typeorm['\"]\)")
TYPEORM_ENTITY = re.compile(r"@Entity\(.*?\)\s*(?:export\s+)?class\s+(\w+)", re.DOTALL)

# Prisma
PRISMA_DETECT = re.compile(r"from\s+['\"]@prisma/client['\"]|prisma\.")

# Find raw-query indicators across any ORM
RAW_SQL_INDICATORS = re.compile(
    r"\.query\(\s*[`'\"]"  # connection.query("SELECT ...")
    r"|raw\s*\(\s*[`'\"]"  # knex.raw("DROP ...")
    r"|sequelize\.literal\("
    r"|Sequelize\.literal\("
    r"|\$queryRaw|prisma\..*\$queryRaw"
)


@dataclass
class ModelInfo:
    name: str
    model_file: str
    associations: list[str] = field(default_factory=list)
    raw_query_callers: list[dict] = field(default_factory=list)
    route_consumers: list[str] = field(default_factory=list)


def detect_orms(repo_root: Path, files: list[Path]) -> list[str]:
    """Scan source files for ORM imports — return list of detected ORM names."""
    detected = set()
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if SEQUELIZE_DETECT.search(text):
            detected.add("sequelize")
        if MONGOOSE_DETECT.search(text):
            detected.add("mongoose")
        if TYPEORM_DETECT.search(text):
            detected.add("typeorm")
        if PRISMA_DETECT.search(text):
            detected.add("prisma")
    return sorted(detected) or ["none"]


def find_models(repo_root: Path, source_files: list[Path]) -> dict[str, ModelInfo]:
    """Locate ORM model definitions. Returns name → ModelInfo (with file)."""
    models: dict[str, ModelInfo] = {}
    for f in source_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(repo_root))
        # Sequelize patterns
        for m in SEQUELIZE_MODEL_DEFINE.finditer(text):
            name = next((g for g in m.groups() if g), None)
            if name:
                models.setdefault(name, ModelInfo(name=name, model_file=rel))
        # Mongoose
        for m in MONGOOSE_MODEL_DEFINE.finditer(text):
            name = m.group(1)
            if name:
                models.setdefault(name, ModelInfo(name=name, model_file=rel))
        # TypeORM
        for m in TYPEORM_ENTITY.finditer(text):
            name = m.group(1)
            if name:
                models.setdefault(name, ModelInfo(name=name, model_file=rel))
        # Sequelize associations (later) — store on the calling model later.
    return models


def collect_raw_queries(repo_root: Path, source_files: list[Path]) -> list[dict]:
    """Find all raw SQL/ORM queries across source files."""
    out: list[dict] = []
    for f in source_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(repo_root))
        for m in RAW_SQL_INDICATORS.finditer(text):
            line_num = text[: m.start()].count("\n") + 1
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            if line_end == -1:
                line_end = len(text)
            snippet = text[line_start:line_end].strip()[:120]
            out.append({"file": rel, "line": line_num, "snippet": snippet})
    return out


def collect_associations(repo_root: Path, source_files: list[Path], models: dict[str, ModelInfo]) -> None:
    """Populate .associations[] for each ModelInfo (Sequelize-style)."""
    for f in source_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(repo_root))
        # Find the model defined IN this file (heuristic: rel == m.model_file)
        owners = [m for m in models.values() if m.model_file == rel]
        if not owners:
            continue
        for owner in owners:
            for assoc in SEQUELIZE_ASSOC.finditer(text):
                target = assoc.group(2)
                if target and target != owner.name and target not in owner.associations:
                    owner.associations.append(target)


def link_routes_to_models(
    repo_root: Path,
    routes_dir: Path,
    models: dict[str, ModelInfo],
    raw_queries: list[dict],
) -> None:
    """Heuristic: a route file mentioning a model name is a "consumer". Plus
    raw-query calls within routes/ get attached to the route side.
    """
    if not routes_dir.is_dir():
        return
    for f in sorted(routes_dir.rglob("*.ts")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(f.relative_to(repo_root))
        for name, info in models.items():
            # Heuristic: name appears as identifier (capitalized usage) in route file
            if re.search(rf"\b{re.escape(name)}\b", text):
                if rel not in info.route_consumers:
                    info.route_consumers.append(rel)
        # Attach raw-query call sites to model.raw_query_callers when the
        # query mentions a known model name.
        for q in raw_queries:
            if q["file"] != rel:
                continue
            snippet_low = q["snippet"].lower()
            for name, info in models.items():
                if name.lower() in snippet_low:
                    callers = info.raw_query_callers
                    if not any(c["file"] == rel and c["line"] == q["line"] for c in callers):
                        callers.append(q)


def gather_source_files(repo_root: Path) -> list[Path]:
    """Walk repo, collect TypeScript/JavaScript application source. Excludes
    node_modules, dist/, build/, tests via the standard exclude set."""
    exclude_dirs = {
        "node_modules",
        "dist",
        "build",
        "target",
        "out",
        "coverage",
        ".git",
        ".venv",
        "venv",
        "tests",
        "test",
        "__tests__",
        "__mocks__",
        ".next",
        ".nuxt",
        "vendor",
        "Pods",
        "third_party",
    }
    out: list[Path] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(seg in exclude_dirs for seg in path.parts):
            continue
        if path.suffix not in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
            continue
        if any(path.name.endswith(s) for s in (".min.js", ".d.ts", ".test.ts", ".spec.ts")):
            continue
        out.append(path)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("repo_root", type=Path)
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON path. Default: <REPO_ROOT>/docs/security/.fragments/data-relations.json",
    )
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    repo_root: Path = args.repo_root.resolve()
    if not repo_root.is_dir():
        print(f"Error: not a directory: {repo_root}", file=sys.stderr)
        return 2

    output_path = args.output or (repo_root / "docs" / "security" / ".fragments" / "data-relations.json")

    src_files = gather_source_files(repo_root)
    if not args.quiet:
        print(f"Scanning {len(src_files)} source files...", file=sys.stderr)

    orms = detect_orms(repo_root, src_files)
    if orms == ["none"]:
        result = {
            "version": 1,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "orm_detected": [],
            "models": {},
            "raw_query_routes": [],
            "note": "no ORM patterns detected — data-layer STRIDE will use default discovery",
        }
    else:
        models = find_models(repo_root, src_files)
        raw_queries = collect_raw_queries(repo_root, src_files)
        collect_associations(repo_root, src_files, models)
        link_routes_to_models(repo_root, repo_root / "routes", models, raw_queries)

        result = {
            "version": 1,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "orm_detected": orms,
            "models": {
                name: {
                    "model_file": info.model_file,
                    "associations": info.associations,
                    "raw_query_callers": info.raw_query_callers,
                    "route_consumers": info.route_consumers,
                }
                for name, info in sorted(models.items())
            },
            "raw_query_routes": raw_queries,
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True))
    if not args.quiet:
        print(f"  ORMs detected: {orms}", file=sys.stderr)
        print(f"  Models: {len(result.get('models', {}))}", file=sys.stderr)
        print(f"  Raw-query call sites: {len(result.get('raw_query_routes', []))}", file=sys.stderr)
        print(f"  Wrote {output_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
