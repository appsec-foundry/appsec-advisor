#!/usr/bin/env python3
"""mass_assignment_scanner.py — entity-aware two-pass mass-assignment detector.

Closes the one mass-assignment case a single-line regex cannot express: a Spring
write handler that binds a request body directly to a *privileged persistence
entity* (`@RequestBody AppUser` where `AppUser` is an `@Entity` carrying a
`role`/`admin`/… field declared in another file). The JS/TS (`AUTHZ-003/004`) and
Python (`AUTHZ-101/102`) mass-assignment cases are already covered by the
single-regex `source_auth_scanner.py`; this scanner is Java/Spring only (Phase 1).

Two passes (see data/mass-assignment-signatures.yaml):
    Pass 1  discover PRIV_ENTITIES = {TypeName -> {file, privileged_fields}}
            — a type is privileged iff it carries an entity signal (@Entity /
              @Table / @Document) AND declares >=1 privileged field that is not
              neutralised by a field suppressor (@JsonIgnore / READ_ONLY).
    Pass 2  flag write handlers (@Post/Put/PatchMapping) that bind a PRIV_ENTITIES
            type via @RequestBody / @ModelAttribute. Binding a non-entity DTO is
            the safe pattern and is not flagged (the core FP guard).

Output `$OUTPUT_DIR/.mass-assignment-findings.json` reuses the source-auth
findings schema (schemas/source-auth-findings.schema.yaml), so
`merge_threats.py:_load_source_auth_findings` ingests it with a single extra
load line — same mechanism as `.authz-confirm-findings.json`.

    python3 mass_assignment_scanner.py --repo-root <REPO> --output-dir <OUT>
    python3 mass_assignment_scanner.py --repo-root <REPO> --dry-run

Exit codes: 0 completed · 1 IO/discovery error · 2 usage error.
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
    print("mass_assignment_scanner: PyYAML is required (pip install pyyaml)", file=sys.stderr)
    sys.exit(1)

DEFAULT_CATALOG_REL = Path("data") / "mass-assignment-signatures.yaml"

# Directories never worth reading (build output, deps, tests live elsewhere).
_EXCLUDE_DIRS = {
    ".git",
    "node_modules",
    "target",
    "build",
    "out",
    "dist",
    "bin",
    ".gradle",
    ".idea",
    ".mvn",
    "__pycache__",
}
# Path fragments that mark test / generated sources — excluded even mid-tree.
_EXCLUDE_FRAGMENTS = ("/test/", "/tests/", "/generated/")
_MAX_FILE_BYTES = 1_500_000
_EVIDENCE_CTX = 1
_EVIDENCE_MAX_LINE = 400


@dataclass
class Catalog:
    check_id: str
    finding_type: str
    cwe: str
    severity: str
    severity_ownership: str
    breach_vector: str
    privileged_fields: set[str]
    ownership_fields: set[str]
    entity_signals: list[str]
    field_suppressors: list[re.Pattern[str]]
    write_mapping: re.Pattern[str]
    bind: re.Pattern[str]
    admin_guard: re.Pattern[str]


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


@dataclass
class Entity:
    name: str
    file: str
    fields: list[str]
    has_vertical: bool  # >=1 vertical privilege field (role/admin/…) vs ownership-only


# Severity bands, low → high. An admin guard steps a finding down one band.
_BANDS = ["Low", "Medium", "High", "Critical"]


def _step_down(severity: str) -> str:
    try:
        i = _BANDS.index(severity)
    except ValueError:
        return severity
    return _BANDS[max(0, i - 1)]


# ---------------------------------------------------------------------------
# Catalog loading
# ---------------------------------------------------------------------------


def _norm(identifier: str) -> str:
    """Normalise a field identifier for privileged-vocab comparison:
    lowercase and strip underscores so isAdmin / is_admin / admin collapse."""
    return identifier.replace("_", "").lower()


def load_catalog(path: Path) -> Catalog:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"catalog {path} must be a mapping")
    try:
        return Catalog(
            check_id=str(raw["check_id"]),
            finding_type=str(raw["finding_type"]),
            cwe=str(raw["cwe"]).upper(),
            severity=str(raw.get("severity") or "High"),
            severity_ownership=str(raw.get("severity_ownership") or "Medium"),
            breach_vector=str(raw.get("breach_vector") or "Internet User"),
            privileged_fields={_norm(f) for f in raw["privileged_fields"]},
            ownership_fields={_norm(f) for f in (raw.get("ownership_fields") or [])},
            entity_signals=[str(s) for s in raw["entity_signals"]],
            field_suppressors=[re.compile(p) for p in (raw.get("field_suppressors") or [])],
            write_mapping=re.compile(raw["write_mapping"]),
            bind=re.compile(raw["bind"]),
            admin_guard=re.compile(raw["admin_guard"], re.IGNORECASE),
        )
    except KeyError as e:
        raise ValueError(f"catalog {path}: missing required key {e}") from e


# ---------------------------------------------------------------------------
# File-system walk (Java only)
# ---------------------------------------------------------------------------


def _walk_java(repo_root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn.endswith((".java", ".kt")):
                yield Path(dirpath) / fn


def _rel(path: Path, root: Path) -> str | None:
    try:
        rel = str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return None
    if any(frag in f"/{rel}" for frag in _EXCLUDE_FRAGMENTS):
        return None
    return rel


def _read(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Pass 1 — privileged-entity discovery
# ---------------------------------------------------------------------------

_CLASS_RE = re.compile(r"\b(?:public\s+|final\s+|abstract\s+|sealed\s+)*class\s+([A-Za-z_$][\w$]*)")
# A Java field declaration: modifiers, a type, then the field name. Deliberately
# loose on the type (may carry generics) but anchored on a name followed by ; = or ,.
_FIELD_RE = re.compile(
    r"\b(?:private|protected|public)\s+(?:final\s+|static\s+|transient\s+|volatile\s+)*"
    r"[\w.<>\[\],\s]+?\b([A-Za-z_$][\w$]*)\s*[;=]"
)


def discover_entities(file_rel: str, text: str, cat: Catalog) -> list[Entity]:
    """Return the privileged entities declared in this file. Only files carrying
    an entity signal are considered; per-file single primary entity is assumed
    (the common case — one @Entity class per .java file)."""
    if not any(sig in text for sig in cat.entity_signals):
        return []

    lines = text.splitlines()
    m = _CLASS_RE.search(text)
    if not m:
        return []
    entity_name = m.group(1)

    priv_fields: list[str] = []
    has_vertical = False
    for fm in _FIELD_RE.finditer(text):
        field_name = fm.group(1)
        norm = _norm(field_name)
        is_vertical = norm in cat.privileged_fields
        is_ownership = norm in cat.ownership_fields
        if not (is_vertical or is_ownership):
            continue
        # Suppressor check: any field-suppressor annotation in the 3 lines above.
        line_idx = text.count("\n", 0, fm.start())
        window = "\n".join(lines[max(0, line_idx - 3) : line_idx + 1])
        if any(sup.search(window) for sup in cat.field_suppressors):
            continue
        priv_fields.append(field_name)
        has_vertical = has_vertical or is_vertical

    if not priv_fields:
        return []
    return [Entity(name=entity_name, file=file_rel, fields=priv_fields, has_vertical=has_vertical)]


# ---------------------------------------------------------------------------
# Pass 2 — unsafe binding sink
# ---------------------------------------------------------------------------

_BIND_BACK_WINDOW = 8  # lines to look back from a @RequestBody param for the mapping


def _evidence_snippet(lines: list[str], idx: int) -> str:
    lo = max(0, idx - _EVIDENCE_CTX)
    hi = min(len(lines), idx + _EVIDENCE_CTX + 1)
    out = []
    for i in range(lo, hi):
        ln = lines[i].rstrip()
        if len(ln) > _EVIDENCE_MAX_LINE:
            cut = ln.rfind(" ", 0, _EVIDENCE_MAX_LINE - 1)
            if cut < _EVIDENCE_MAX_LINE // 2:
                cut = _EVIDENCE_MAX_LINE - 1
            ln = ln[:cut].rstrip() + " …"
        marker = ">>" if i == idx else "  "
        out.append(f"{marker} {i + 1:5}: {ln}")
    return "\n".join(out)


def find_sinks(
    file_rel: str,
    text: str,
    cat: Catalog,
    entities: dict[str, Entity],
) -> list[Finding]:
    lines = text.splitlines()
    # Class-declaration annotation block (5 lines above the class decl) — a
    # controller-wide @PreAuthorize("hasRole('ADMIN')") guards every handler.
    class_guard_block = ""
    cm = _CLASS_RE.search(text)
    if cm:
        class_idx = text.count("\n", 0, cm.start())
        class_guard_block = "\n".join(lines[max(0, class_idx - 5) : class_idx + 1])

    findings: list[Finding] = []
    for m in cat.bind.finditer(text):
        bound_type = m.group(1)
        entity = entities.get(bound_type)
        if entity is None:
            continue  # binding a non-entity DTO is the safe pattern — skip
        line_idx = text.count("\n", 0, m.start())
        back = "\n".join(lines[max(0, line_idx - _BIND_BACK_WINDOW) : line_idx + 1])
        if not cat.write_mapping.search(back):
            continue  # a bind without a write-mapping is not a state-changing sink

        # Base severity by field tier: vertical privilege (role/admin) is
        # self-promotion → High; ownership/tenant/financial only is horizontal
        # tampering → Medium.
        base_severity = cat.severity if entity.has_vertical else cat.severity_ownership

        # Admin-guard downgrade: a method- or class-level admin authz annotation
        # means a normal user cannot reach the sink → step severity down one band.
        guarded = bool(cat.admin_guard.search(back) or cat.admin_guard.search(class_guard_block))
        severity = _step_down(base_severity) if guarded else base_severity

        fields = ", ".join(entity.fields)
        harm = (
            "set privileged field(s) they must not control (mass assignment / self-promotion)"
            if entity.has_vertical
            else "overwrite ownership / tenant / financial field(s) on the record (horizontal authorization tampering)"
        )
        guard_note = (
            " An authorization guard restricts the endpoint to admins, so this is "
            "not exploitable by a normal user — but the writable surface is still "
            "not isolated by a DTO/allowlist (defence-in-depth weakness)."
            if guarded
            else ""
        )
        scenario = (
            f"Write handler binds the request body directly to the privileged "
            f"entity `{bound_type}` (declared in `{entity.file}`) via "
            f"@RequestBody/@ModelAttribute, letting the caller {harm} via field(s) "
            f"[{fields}]. No field allowlist or DTO isolates the writable surface.{guard_note}"
        )
        guard_label = " (admin-guarded)" if guarded else ""
        title = f"Mass assignment{guard_label} — request body bound to entity {bound_type} — {file_rel}:{line_idx + 1}"

        findings.append(
            Finding(
                local_id="",
                check_id=cat.check_id,
                finding_type_id=cat.finding_type,
                source_type="java_source",
                file=file_rel,
                line=line_idx + 1,
                evidence_snippet=_evidence_snippet(lines, line_idx),
                title=title,
                scenario=scenario,
                severity=severity,
                cwe=[cat.cwe] if cat.cwe else [],
                recommended_mitigation_title=(
                    f"Bind {bound_type} through a request DTO exposing only the "
                    f"user-editable fields, or mark [{fields}] @JsonIgnore / "
                    f"read-only; never persist privileged fields copied from the body."
                ),
                breach_vector=cat.breach_vector,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def scan_repo(repo_root: Path, cat: Catalog) -> list[Finding]:
    files: list[tuple[str, str]] = []
    for path in _walk_java(repo_root):
        rel = _rel(path, repo_root)
        if rel is None:
            continue
        text = _read(path)
        if text:
            files.append((rel, text))

    # Pass 1
    entities: dict[str, Entity] = {}
    for rel, text in files:
        for ent in discover_entities(rel, text, cat):
            entities.setdefault(ent.name, ent)

    # Pass 2
    findings: list[Finding] = []
    if entities:
        for rel, text in files:
            findings.extend(find_sinks(rel, text, cat, entities))

    findings.sort(key=lambda f: (f.file, f.line))
    for i, f in enumerate(findings, start=1):
        f.local_id = f"SAF-{i:03d}"
    return findings


def emit_sidecar(output_dir: Path, findings: list[Finding]) -> Path:
    doc = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checks_run": 1,
        "violations": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    out_path = output_dir / ".mass-assignment-findings.json"
    tmp = out_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    os.replace(tmp, out_path)
    return out_path


def _discover_plugin_root() -> Path | None:
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if env and Path(env).is_dir():
        return Path(env)
    here = Path(__file__).resolve().parent.parent
    if (here / "data").is_dir():
        return here
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Entity-aware two-pass mass-assignment scanner (Java/Spring)")
    ap.add_argument("--repo-root", type=Path, required=True, help="Repository to scan")
    ap.add_argument(
        "--output-dir", type=Path, help="Output dir for .mass-assignment-findings.json (omit with --dry-run)"
    )
    ap.add_argument("--catalog", type=Path, help="Override signatures YAML path")
    ap.add_argument("--dry-run", action="store_true", help="Print findings to stdout, do NOT write sidecar")
    ap.add_argument("--quiet", action="store_true", help="Suppress summary line")
    args = ap.parse_args(argv)

    repo_root: Path = args.repo_root.resolve()
    if not repo_root.is_dir():
        print(f"mass_assignment_scanner: repo-root {repo_root} is not a directory", file=sys.stderr)
        return 2
    if not args.dry_run and args.output_dir is None:
        print("mass_assignment_scanner: --output-dir is required unless --dry-run is passed", file=sys.stderr)
        return 2

    if args.catalog:
        catalog_path = args.catalog
    else:
        plugin_root = _discover_plugin_root()
        if plugin_root is None:
            print("mass_assignment_scanner: cannot resolve plugin root; pass --catalog explicitly", file=sys.stderr)
            return 2
        catalog_path = plugin_root / DEFAULT_CATALOG_REL
    if not catalog_path.is_file():
        print(f"mass_assignment_scanner: catalog {catalog_path} not found", file=sys.stderr)
        return 2

    try:
        cat = load_catalog(catalog_path)
    except (ValueError, re.error) as e:
        print(f"mass_assignment_scanner: failed to load catalog: {e}", file=sys.stderr)
        return 2

    findings = scan_repo(repo_root, cat)

    if args.dry_run:
        print(json.dumps([asdict(f) for f in findings], indent=2))
        if not args.quiet:
            print(f"\nmass_assignment_scanner: {len(findings)} finding(s)", file=sys.stderr)
        return 0

    output_dir: Path = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    sidecar = emit_sidecar(output_dir, findings)
    if not args.quiet:
        print(f"mass_assignment_scanner: wrote {sidecar} ({len(findings)} finding(s))", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
