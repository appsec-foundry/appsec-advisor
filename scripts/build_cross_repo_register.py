#!/usr/bin/env python3
"""
build_cross_repo_register.py — single source of truth for cross-repo deps.

Replaces three implicit data flows that previously diverged:

1. ``appsec-context-resolver`` Sub-step A — declared deps from
   ``docs/related-repos.yaml`` (now loaded by ``load_related_repos.py``).
2. ``appsec-context-resolver`` Sub-step B — filesystem-sibling + git
   submodule discovery (metadata only).
3. ``appsec-recon-scanner`` Category 25 — code-grep-based SCM-sibling /
   SaaS detection (metadata only).

This script consumes the structured outputs of (1) and (3) and probes the
filesystem for (2), then emits a unified register at
``<OUTPUT_DIR>/.cross-repo-register.json`` that conforms to
``schemas/cross-repo-register.schema.json``.

Downstream consumers (``slice_cross_repo_for_component.py``,
``coverage_checks.check_cross_repo``, Phase 11 §5/§7 renderers) read the
register instead of re-parsing rendered Markdown or duplicating the discovery
logic.

Deduplication rule: when the same name appears in multiple sources, the
declared entry wins. Sibling/submodule outranks recon for the same name.

CLI usage::

    python3 build_cross_repo_register.py \\
        --repo-root <REPO_ROOT> \\
        --output    <PATH>                    # writes JSON
        [--declared-json <PATH>]              # load_related_repos.py output (optional)
        [--recon-summary <PATH>]              # .recon-summary.md (optional)
        [--workspace-root <PATH>]             # default: parent of REPO_ROOT
        [--max-siblings N]                    # default: 8
        [--skip-sibling-discovery]            # honour B0 skip-on-no-signal
        [--no-validate]                       # disable schema validation
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from configparser import ConfigParser, MissingSectionHeaderError
from pathlib import Path
from typing import Any

import yaml

try:
    import jsonschema  # type: ignore
except ImportError:  # pragma: no cover
    jsonschema = None  # noqa: N816


_HERE = Path(__file__).resolve().parent
_DEFAULT_SCHEMA = _HERE.parent / "schemas" / "cross-repo-register.schema.json"

_DEFAULT_MAX_SIBLINGS = 8
_DEFAULT_TM_REL_PATH = Path("docs") / "security" / "threat-model.yaml"


def _should_skip_sibling_discovery(
    repo_root: Path,
    workspace_root: Path,
    *,
    has_declared: bool,
) -> tuple[bool, str]:
    """Replicate the B0-skip rule from the previous Bash flow.

    Skip sibling discovery when the workspace gives no signal that cross-repo
    work is relevant. Without this guard a standalone single-repo scan from
    e.g. ``~/projects/myrepo`` would list every unrelated directory in
    ``~/projects`` as a "missing" upstream and pollute the report with
    spurious CWE-1059 gap-threats.

    The conditions ALL have to hold for the skip:
      1. No declared cross-repo deps (``docs/related-repos.yaml`` not loaded).
      2. No ``.gitmodules`` at REPO_ROOT.
      3. The workspace root looks like a generic home / root directory
         (``$HOME`` or ``/``) **OR** contains at most one sibling directory
         (only the repo itself).

    Returns (skip, reason).
    """
    if has_declared:
        return False, ""
    if (repo_root / ".gitmodules").is_file():
        return False, ""

    home = os.environ.get("HOME")
    ws_str = str(workspace_root)
    if home and ws_str == home:
        return True, f"workspace_root is $HOME ({home})"
    if ws_str == "/":
        return True, "workspace_root is /"

    try:
        sibling_count = sum(
            1 for p in workspace_root.iterdir()
            if p.is_dir() and not p.name.startswith(".")
        )
    except OSError:
        return False, ""
    if sibling_count <= 1:
        return True, f"workspace has {sibling_count} non-hidden directory"

    return False, ""


# ---------------------------------------------------------------------------
# Sibling / submodule discovery
# ---------------------------------------------------------------------------


def _read_threat_model_meta(tm_path: Path) -> dict[str, Any]:
    """Return shallow metadata + threat counts from a sibling TM (no findings)."""
    try:
        text = tm_path.read_text(encoding="utf-8")
    except OSError as exc:
        return {"status": "unavailable", "fetch_detail": f"unavailable: {exc}"}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        return {"status": "unavailable", "fetch_detail": f"unavailable: yaml: {exc}"}
    if not isinstance(data, dict):
        return {"status": "unavailable", "fetch_detail": "unavailable: not a mapping"}

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    git = meta.get("git") if isinstance(meta.get("git"), dict) else {}
    threats: list[dict[str, Any]] = []
    if isinstance(data.get("threats"), list):
        threats = [t for t in data["threats"] if isinstance(t, dict)]
    else:
        for cat in data.get("threat_categories", []) or []:
            if isinstance(cat, dict):
                for f in cat.get("findings", []) or []:
                    if isinstance(f, dict):
                        threats.append(f)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "open": 0}
    for t in threats:
        sev = str(t.get("severity", "")).strip().title()
        if sev in counts:
            counts[sev.lower()] += 1
        if str(t.get("status", "")).lower() == "open":
            counts["open"] += 1
    components = [
        c.get("name") for c in (data.get("components") or [])
        if isinstance(c, dict) and isinstance(c.get("name"), str)
    ]
    return {
        "status": "found",
        "path": str(tm_path),
        "ref_kind": "absolute",
        "generated": meta.get("generated"),
        "commit_sha": git.get("commit_sha"),
        "components": components,
        "threats_total": len(threats),
        "threats_critical": counts["critical"],
        "threats_high": counts["high"],
        "threats_open": counts["open"],
    }


def _discover_siblings(
    repo_root: Path,
    workspace_root: Path,
    *,
    max_siblings: int,
    declared_names: set[str],
) -> list[dict[str, Any]]:
    if not workspace_root.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    current_name = repo_root.name
    try:
        candidates = sorted(p for p in workspace_root.iterdir() if p.is_dir())
    except OSError:
        return []
    for sibling in candidates:
        if sibling.name == current_name:
            continue
        if sibling.name in declared_names:
            continue
        if len(entries) >= max_siblings:
            break
        tm_path = sibling / _DEFAULT_TM_REL_PATH
        if tm_path.is_file():
            tm_meta = _read_threat_model_meta(tm_path)
            entries.append({
                "name": sibling.name,
                "source": "sibling",
                "interface": None,
                "type": None,
                "discovery_hint": str(sibling),
                "threat_model": tm_meta,
                "interface_findings": None,
            })
        else:
            entries.append({
                "name": sibling.name,
                "source": "sibling",
                "interface": None,
                "type": None,
                "discovery_hint": str(sibling),
                "threat_model": {"status": "missing", "path": None},
                "interface_findings": None,
            })
    return entries


def _discover_submodules(
    repo_root: Path, *, declared_names: set[str],
) -> list[dict[str, Any]]:
    gm = repo_root / ".gitmodules"
    if not gm.is_file():
        return []
    parser = ConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(gm.read_text(encoding="utf-8"))
    except (MissingSectionHeaderError, OSError):
        return []
    out: list[dict[str, Any]] = []
    for section in parser.sections():
        if not parser.has_option(section, "path"):
            continue
        subpath = parser.get(section, "path").strip()
        if not subpath:
            continue
        # Section names are typically `submodule "name"`; fall back to subpath basename.
        m = re.match(r'submodule\s+"(.+)"', section)
        name = m.group(1) if m else Path(subpath).name
        if name in declared_names:
            continue
        tm_path = repo_root / subpath / _DEFAULT_TM_REL_PATH
        if tm_path.is_file():
            tm_meta = _read_threat_model_meta(tm_path)
        else:
            tm_meta = {"status": "missing", "path": None}
        out.append({
            "name": name,
            "source": "submodule",
            "interface": None,
            "type": None,
            "discovery_hint": subpath,
            "threat_model": tm_meta,
            "interface_findings": None,
        })
    return out


# ---------------------------------------------------------------------------
# Recon-summary parsing (Category 25)
# ---------------------------------------------------------------------------


_RECON_25_HEADING_RE = re.compile(
    r"^#{1,6}\s*(?:7\.|Section\s+7\.)?25\b.*$", re.MULTILINE | re.IGNORECASE,
)


def _extract_recon_25(recon_md: str) -> str:
    m = _RECON_25_HEADING_RE.search(recon_md)
    if not m:
        return ""
    tail = recon_md[m.end():]
    next_section = re.search(r"^#{1,6}\s+", tail, re.MULTILINE)
    end = m.end() + (next_section.start() if next_section else len(tail))
    return recon_md[m.start():end]


_RECON_ROW_NAME_RE = re.compile(r"\*\*([A-Za-z0-9_.\-]+)\*\*")


def _parse_recon_25(recon_md: str) -> list[dict[str, Any]]:
    """Best-effort parse for recon Section 7.25 dependencies. The recon
    scanner renders this section as a mix of tables and bullet lists, so the
    parser is liberal: any line with name=, **NAME**, or a leading bullet
    that introduces a known name pattern contributes one entry.
    """
    section = _extract_recon_25(recon_md)
    if not section:
        return []

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    # Match table rows: | name | type | source | interface | repo_hint | confidence |
    for row in section.splitlines():
        if not row.startswith("|"):
            continue
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        if cells[0].lower() in ("name", "dependency", "service", "") or cells[0].startswith("---"):
            continue
        name = cells[0].replace("*", "").replace("`", "").strip()
        if not name or name in seen or name.lower() in ("name", "—", "-"):
            continue
        dep_type = cells[1].lower() if len(cells) > 1 else ""
        if dep_type not in ("scm-sibling", "saas", "scm sibling", "sibling", "third-party"):
            continue
        interface = None
        if len(cells) >= 4:
            iface_cell = cells[3].replace("`", "").strip()
            interface = iface_cell or None
        hint = cells[2].strip() if len(cells) > 2 else None
        seen.add(name)
        out.append({
            "name": name,
            "source": "recon",
            "interface": interface,
            "type": "saas" if dep_type == "saas" else "scm-sibling",
            "discovery_hint": hint,
            "threat_model": {
                "status": "n/a" if dep_type == "saas" else "missing",
                "path": None,
            },
            "interface_findings": None,
        })

    # Also match `* **name** — type: saas | interface: …` bullet style if no rows.
    if not out:
        for line in section.splitlines():
            if not line.strip().startswith(("- ", "* ")):
                continue
            m = _RECON_ROW_NAME_RE.search(line)
            if not m:
                continue
            name = m.group(1)
            if name in seen:
                continue
            dep_type = "saas" if re.search(r"\bsaas\b", line, re.IGNORECASE) else "scm-sibling"
            iface_m = re.search(r"interface[:=]\s*([^|;,]+)", line, re.IGNORECASE)
            interface = iface_m.group(1).strip() if iface_m else None
            seen.add(name)
            out.append({
                "name": name,
                "source": "recon",
                "interface": interface,
                "type": dep_type,
                "discovery_hint": None,
                "threat_model": {
                    "status": "n/a" if dep_type == "saas" else "missing",
                    "path": None,
                },
                "interface_findings": None,
            })
    return out


# ---------------------------------------------------------------------------
# Declared entries (output of load_related_repos.py)
# ---------------------------------------------------------------------------


def _normalise_declared(declared_json: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for rec in declared_json.get("related", []):
        tm = dict(rec.get("threat_model") or {})
        # The loader records status verbatim; pass through.
        out.append({
            "name": rec.get("name", ""),
            "source": "declared",
            "interface": rec.get("interface"),
            "type": None,
            "discovery_hint": None,
            "threat_model": tm,
            "interface_findings": rec.get("interface_findings"),
        })
    return out


# ---------------------------------------------------------------------------
# Merge / dedup
# ---------------------------------------------------------------------------

_SOURCE_PRIORITY = {"declared": 0, "submodule": 1, "sibling": 2, "recon": 3}


def _merge(
    declared: list[dict[str, Any]],
    submodules: list[dict[str, Any]],
    siblings: list[dict[str, Any]],
    recon: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_name: dict[str, dict[str, Any]] = {}
    for batch in (declared, submodules, siblings, recon):
        for entry in batch:
            name = entry["name"]
            if name not in by_name:
                by_name[name] = entry
                continue
            existing = by_name[name]
            ex_prio = _SOURCE_PRIORITY.get(existing["source"], 99)
            new_prio = _SOURCE_PRIORITY.get(entry["source"], 99)
            if new_prio < ex_prio:
                by_name[name] = entry
    # Stable order: declared first (in input order), then submodule, sibling, recon
    ordered: list[dict[str, Any]] = []
    for src in ("declared", "submodule", "sibling", "recon"):
        for entry in (declared, submodules, siblings, recon)[
            ("declared", "submodule", "sibling", "recon").index(src)
        ]:
            if by_name.get(entry["name"]) is entry:
                ordered.append(entry)
    return ordered


# ---------------------------------------------------------------------------
# Build / validate / emit
# ---------------------------------------------------------------------------


def build(
    repo_root: Path,
    *,
    declared_json_path: Path | None,
    recon_summary_path: Path | None,
    workspace_root: Path | None = None,
    max_siblings: int = _DEFAULT_MAX_SIBLINGS,
    skip_sibling_discovery: bool = False,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    # Resolve repo_root so .parent picks the actual workspace dir even when
    # the caller passed a relative path like "." (whose .parent is "." itself).
    repo_root = repo_root.resolve()

    declared: list[dict[str, Any]] = []
    declared_json: dict[str, Any] | None = None
    if declared_json_path and declared_json_path.is_file():
        try:
            declared_json = json.loads(declared_json_path.read_text(encoding="utf-8"))
            declared = _normalise_declared(declared_json)
        except (json.JSONDecodeError, OSError):
            declared_json = None

    declared_names = {e["name"] for e in declared}

    submodules = _discover_submodules(repo_root, declared_names=declared_names)

    ws_root = workspace_root or repo_root.parent
    skip_reason = ""
    if skip_sibling_discovery:
        siblings: list[dict[str, Any]] = []
        skip_reason = "skip_sibling_discovery=True"
    else:
        auto_skip, auto_reason = _should_skip_sibling_discovery(
            repo_root, ws_root, has_declared=bool(declared),
        )
        if auto_skip:
            siblings = []
            skip_sibling_discovery = True
            skip_reason = f"auto-skip ({auto_reason})"
        else:
            siblings = _discover_siblings(
                repo_root, ws_root,
                max_siblings=max_siblings,
                declared_names=declared_names,
            )

    recon: list[dict[str, Any]] = []
    if recon_summary_path and recon_summary_path.is_file():
        try:
            recon = _parse_recon_25(recon_summary_path.read_text(encoding="utf-8"))
        except OSError:
            recon = []

    merged = _merge(declared, submodules, siblings, recon)

    sources_used = sorted({e["source"] for e in merged})
    now = now or _dt.datetime.now(tz=_dt.timezone.utc)

    return {
        "meta": {
            "register_version": 1,
            "generated_at": now.isoformat(),
            "repo_root": str(repo_root),
            "sources": sources_used,
            "skipped_sibling_discovery": bool(skip_sibling_discovery),
            "skip_reason": skip_reason or None,
            "declared_present": declared_json is not None,
            "recon_summary_present": bool(recon_summary_path and recon_summary_path.is_file()),
        },
        "entries": merged,
    }


def _validate(register: dict[str, Any], schema_path: Path = _DEFAULT_SCHEMA) -> list[str]:
    if jsonschema is None:
        return []
    if not schema_path.is_file():
        return [f"schema not found: {schema_path}"]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(v.iter_errors(register), key=lambda e: list(e.absolute_path))
    ]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    p.add_argument("--repo-root", required=True, type=Path)
    p.add_argument("--output", required=True, help="destination JSON path, or '-' for stdout")
    p.add_argument("--declared-json", type=Path, default=None)
    p.add_argument("--recon-summary", type=Path, default=None)
    p.add_argument("--workspace-root", type=Path, default=None)
    p.add_argument("--max-siblings", type=int, default=_DEFAULT_MAX_SIBLINGS)
    p.add_argument("--skip-sibling-discovery", action="store_true")
    p.add_argument("--no-validate", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    register = build(
        args.repo_root,
        declared_json_path=args.declared_json,
        recon_summary_path=args.recon_summary,
        workspace_root=args.workspace_root,
        max_siblings=args.max_siblings,
        skip_sibling_discovery=args.skip_sibling_discovery,
    )
    if not args.no_validate:
        errors = _validate(register)
        if errors:
            print("cross-repo register failed schema validation:", file=sys.stderr)
            for e in errors:
                print(f"  · {e}", file=sys.stderr)
            return 2
    rendered = json.dumps(register, indent=2, sort_keys=False)
    if args.output == "-":
        print(rendered)
    else:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
