#!/usr/bin/env python3
"""
coverage_checks.py — deterministic Phase 9 coverage checks (Sprint 2 Item #6).

Replaces the LLM-driven Coverage Check A (OWASP Top 10) and Check D
(Cross-repo boundary) with set-membership logic. Emits a JSON report of
coverage gaps that the orchestrator injects as `source: coverage-gap`
threats during Phase 9 merge — no LLM judgement involved.

Checks covered:
  A  OWASP Top 10 (2021)  — every OWASP 2021 category must have ≥ 1 threat.
     Missing → one gap-threat per missing category, STRIDE and default-risk
     pre-set from the category metadata in data/owasp-top10-cwes.yaml.
  D  Cross-repo boundary  — every declared/discovered cross-repo dependency
     whose threat_model is `missing` must have ≥ 1 threat referencing the
     interface. Missing → one gap-threat per uncovered boundary.

Not covered (remain LLM-driven in the orchestrator):
  B  Business logic        — requires judgement on workflow semantics.
  C  OWASP LLM Top 10     — conditional + domain-specific judgement.

CLI usage:
  python3 coverage_checks.py owasp --output-dir <dir>
  python3 coverage_checks.py cross-repo --output-dir <dir>
  python3 coverage_checks.py all --output-dir <dir>

Inputs (all optional — absence is classified, not an error):
  $OUTPUT_DIR/.threats-merged.json          (Check A)
  $OUTPUT_DIR/.threat-modeling-context.md   (Check D)

Output: JSON on stdout, exit code 0 (gaps found OR clean), 1 (hard error).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("coverage_checks.py: PyYAML is required", file=sys.stderr)
    sys.exit(1)


_HERE = Path(__file__).resolve().parent
_DEFAULT_OWASP_YAML = _HERE.parent / "data" / "owasp-top10-cwes.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _plugin_data_file(env_var: str, default: Path, filename: str) -> Path:
    """Resolve a data-file path: env var > $CLAUDE_PLUGIN_ROOT/data > default."""
    override = os.environ.get(env_var)
    if override:
        return Path(override)
    plugin_root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if plugin_root:
        cand = Path(plugin_root) / "data" / filename
        if cand.is_file():
            return cand
    return default


def _load_owasp_mapping(path: Path | None = None) -> list[dict[str, Any]]:
    path = path or _plugin_data_file("OWASP_TOP10_YAML", _DEFAULT_OWASP_YAML, "owasp-top10-cwes.yaml")
    if not path.is_file():
        raise FileNotFoundError(f"OWASP mapping file missing: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "categories" not in data:
        raise ValueError(f"{path}: missing 'categories' top-level key")
    if data.get("version") != 1:
        raise ValueError(f"{path}: unsupported version {data.get('version')!r}")
    return data["categories"]


def _parse_cwe(value: Any) -> int | None:
    """Parse a CWE identifier in any common form. Returns None if unparseable.

    Accepts: 79, "79", "CWE-79", "cwe-79", "CWE-79 (...)", etc.
    """
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        m = re.search(r"(?:CWE[-_\s]?)?(\d{1,5})", value.strip(), re.IGNORECASE)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    return None


# ---------------------------------------------------------------------------
# Check A — OWASP Top 10
# ---------------------------------------------------------------------------


def check_owasp_top10(
    threats: list[dict[str, Any]],
    mapping: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return a report of OWASP 2021 categories lacking coverage."""
    mapping = mapping or _load_owasp_mapping()

    # Collect CWEs present in any threat (with or without duplicates — we only
    # care about set membership).
    present_cwes: set[int] = set()
    for t in threats:
        cwe = _parse_cwe(t.get("cwe"))
        if cwe is not None:
            present_cwes.add(cwe)

    covered: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []

    for cat in mapping:
        cat_cwes = set(cat.get("cwes", []))
        overlap = sorted(cat_cwes & present_cwes)
        entry = {
            "id": cat["id"],
            "name": cat["name"],
            "stride": cat["stride"],
            "default_risk": cat["default_risk"],
            "covered_by_cwes": overlap,
        }
        if overlap:
            covered.append(entry)
        else:
            # Suggest a gap threat for the orchestrator to inject.
            primary_cwe = cat_cwes and sorted(cat_cwes)[0] or None
            entry["suggested_threat"] = {
                "component_id": None,  # component-agnostic; orchestrator may re-scope
                "stride": cat["stride"],
                "risk": cat["default_risk"],
                "likelihood": "Medium",
                "impact": cat["default_risk"],
                "title": f"{cat['name']} — no threats identified (OWASP {cat['id']} coverage gap)",
                "scenario": (
                    f"The STRIDE analysis produced no threat matching OWASP {cat['id']} "
                    f"({cat['name']}). Either the codebase genuinely lacks this class "
                    f"of exposure, or a relevant threat was missed. Review the affected "
                    f"surfaces and confirm. Suggested CWE: CWE-{primary_cwe}."
                ),
                "cwe": f"CWE-{primary_cwe}" if primary_cwe else None,
                "source": "coverage-gap",
                "coverage_category": cat["id"],
            }
            missing.append(entry)

    return {
        "check": "owasp-top10",
        "total_categories": len(mapping),
        "covered_count": len(covered),
        "missing_count": len(missing),
        "covered": covered,
        "missing": missing,
    }


# ---------------------------------------------------------------------------
# Check D — Cross-repo boundary coverage
# ---------------------------------------------------------------------------


# Parse the "Cross-Repository Dependency Threat Models" section of
# .threat-modeling-context.md and extract every dependency row, classifying
# each as found / missing / outdated / unavailable.

_CROSS_REPO_HEADING_RE = re.compile(r"^##+\s+Cross-Repository", re.MULTILINE)
_TABLE_ROW_RE = re.compile(r"^\|\s*([^|]+?)\s*\|")
# Status cell candidates (columns vary slightly between declared/discovered)
_STATUS_MISSING_SIGNALS = (
    "✗ missing",
    "✗ not found",
    "✗ unavailable",
    "missing",
    "not found",
    "unavailable",
)
_STATUS_FOUND_SIGNALS = ("✓ found", "found", "outdated", "⚠ outdated")


def _extract_cross_repo_section(context_md: str) -> str:
    """Return the slice of context_md starting at the Cross-Repository heading
    and ending at the next top-level section (## ...) or end-of-file."""
    m = _CROSS_REPO_HEADING_RE.search(context_md)
    if not m:
        return ""
    start = m.start()
    # Find the next top-level heading after this one
    tail = context_md[m.end() :]
    next_section = re.search(r"^##[^#]", tail, re.MULTILINE)
    end = m.end() + (next_section.start() if next_section else len(tail))
    return context_md[start:end]


def _row_status(row: str) -> str | None:
    """Classify a table row as 'missing', 'found', or None (not a data row)."""
    if row.startswith("|---") or row.startswith("| ---"):
        return None
    lower = row.lower()
    for sig in _STATUS_MISSING_SIGNALS:
        if sig in lower:
            return "missing"
    for sig in _STATUS_FOUND_SIGNALS:
        if sig in lower:
            return "found"
    return None


def _extract_row_cells(row: str) -> list[str]:
    # Strip the leading and trailing pipes then split.
    stripped = row.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    parts = [c.strip() for c in stripped[1:-1].split("|")]
    return parts


def parse_cross_repo_deps(context_md: str) -> list[dict[str, Any]]:
    """Extract cross-repo dependencies from the context Markdown file.

    Returns a list of dicts:
        {name, interface (or None), status: found|missing, source: declared|discovered}
    """
    section = _extract_cross_repo_section(context_md)
    if not section:
        return []

    deps: list[dict[str, Any]] = []
    current_source = "declared"

    for line in section.splitlines():
        low = line.lower()
        if "auto-discovered" in low or "discovered siblings" in low:
            current_source = "discovered"
        if not line.startswith("|"):
            continue

        status = _row_status(line)
        if status is None:
            continue
        cells = _extract_row_cells(line)
        if len(cells) < 2:
            continue
        name_cell = cells[0]
        # Skip header rows (table header cell often contains "Dependency" or "|")
        if name_cell.lower() in ("dependency", ""):
            continue
        interface = cells[1] if len(cells) >= 2 else None
        # When the second cell is the "Source" column (sibling/submodule) for
        # auto-discovered tables, treat interface as None.
        if interface and interface.lower() in ("sibling", "submodule", "source"):
            interface = None
        if interface in ("—", "-", ""):
            interface = None

        deps.append(
            {
                "name": name_cell,
                "interface": interface,
                "status": status,
                "source": current_source,
            }
        )

    return deps


def _deps_from_register(register_path: Path) -> tuple[list[dict[str, Any]], bool]:
    """Load deps from a structured cross-repo register. Returns (deps, present).

    Each dep matches the shape that ``parse_cross_repo_deps`` returns from
    the Markdown path (``name``, ``interface``, ``status``, ``source``) so the
    downstream check is source-agnostic. Status normalisation:

      ``not found`` / ``unavailable`` / ``missing`` / ``n/a`` → ``missing``
      ``found`` / ``outdated``                                → ``found``
    """
    if not register_path.is_file():
        return [], False
    try:
        register = json.loads(register_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return [], False
    deps: list[dict[str, Any]] = []
    for entry in register.get("entries", []):
        tm_status = (entry.get("threat_model") or {}).get("status", "").lower()
        if tm_status in ("found", "outdated"):
            status = "found"
        elif tm_status == "n/a":
            # SaaS deps cannot have a project threat model; do not raise as gaps.
            continue
        else:
            status = "missing"
        deps.append(
            {
                "name": entry.get("name", ""),
                "interface": entry.get("interface"),
                "status": status,
                "source": "declared" if entry.get("source") == "declared" else "discovered",
            }
        )
    return deps, True


def check_cross_repo(
    context_md_path: Path,
    threats: list[dict[str, Any]],
    *,
    register_path: Path | None = None,
) -> dict[str, Any]:
    """Check that every cross-repo dependency with status=missing has at least
    one threat referencing it (by dependency name substring in title/scenario,
    or by interface name substring).

    Prefers the structured cross-repo register at ``register_path`` when
    available. Falls back to parsing the rendered Markdown at
    ``context_md_path`` so existing assessments still produce a check result.
    The fallback path is the source of historical compatibility — new
    pipelines should always pass ``register_path``.
    """
    deps: list[dict[str, Any]] = []
    register_used = False

    if register_path is not None:
        deps, register_used = _deps_from_register(register_path)

    if not register_used:
        if not context_md_path.is_file():
            return {
                "check": "cross-repo-boundary",
                "context_file_present": False,
                "register_used": False,
                "total_deps": 0,
                "missing_tm_count": 0,
                "uncovered_boundaries": [],
                "covered_boundaries": [],
            }
        text = context_md_path.read_text(encoding="utf-8")
        deps = parse_cross_repo_deps(text)

    missing_tm = [d for d in deps if d["status"] == "missing"]

    if not missing_tm:
        return {
            "check": "cross-repo-boundary",
            "context_file_present": True,
            "register_used": register_used,
            "total_deps": len(deps),
            "missing_tm_count": 0,
            "uncovered_boundaries": [],
            "covered_boundaries": [],
        }

    # Build an O(1) searchable corpus of threat titles + scenarios.
    corpus = []
    for t in threats:
        pieces = [
            str(t.get("title", "")),
            str(t.get("scenario", "")),
            str(t.get("component_name", "")),
            str(t.get("component_id", "")),
        ]
        corpus.append(" ".join(pieces).lower())

    uncovered: list[dict[str, Any]] = []
    covered: list[dict[str, Any]] = []

    for dep in missing_tm:
        name_l = dep["name"].lower()
        iface_l = (dep["interface"] or "").lower()
        hit = False
        for threat_text in corpus:
            if name_l and name_l in threat_text:
                hit = True
                break
            if iface_l and iface_l in threat_text:
                hit = True
                break
        if hit:
            covered.append(dep)
        else:
            # PII/auth interfaces → Medium; otherwise Low per the
            # Phase 9 D spec in phase-group-threats.md.
            iface = dep["interface"] or ""
            sensitive = any(
                kw in iface.lower()
                for kw in ("auth", "token", "jwt", "oauth", "pii", "payment", "credential", "session")
            )
            risk = "Medium" if sensitive else "Low"
            uncovered.append(
                {
                    **dep,
                    "suggested_threat": {
                        "component_id": None,
                        "stride": "Information Disclosure",
                        "risk": risk,
                        "likelihood": "Medium",
                        "impact": risk,
                        "title": (f"Unanalyzed trust boundary to `{dep['name']}` — no upstream threat model"),
                        "scenario": (
                            f"Data from `{dep['name']}` crosses an unanalyzed trust boundary — "
                            f"no threat model exists for the upstream service to validate its "
                            f"security posture. Treat data crossing this boundary as partially "
                            f"untrusted until a threat model exists for `{dep['name']}`."
                        ),
                        "cwe": "CWE-1059",  # Insufficient Technical Documentation
                        "source": "coverage-gap",
                        "coverage_category": "cross-repo-boundary",
                    },
                }
            )

    return {
        "check": "cross-repo-boundary",
        "context_file_present": True,
        "register_used": register_used,
        "total_deps": len(deps),
        "missing_tm_count": len(missing_tm),
        "covered_boundaries": covered,
        "uncovered_boundaries": uncovered,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _load_merged_threats(output_dir: Path) -> list[dict[str, Any]]:
    path = output_dir / ".threats-merged.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data.get("threats", []) if isinstance(data, dict) else []


def run_all(output_dir: Path) -> dict[str, Any]:
    threats = _load_merged_threats(output_dir)
    owasp = check_owasp_top10(threats)
    register_path = output_dir / ".cross-repo-register.json"
    cross = check_cross_repo(
        output_dir / ".threat-modeling-context.md",
        threats,
        register_path=register_path if register_path.is_file() else None,
    )
    return {
        "version": 1,
        "threats_evaluated": len(threats),
        "owasp": owasp,
        "cross_repo": cross,
        "gap_count": owasp["missing_count"] + len(cross["uncovered_boundaries"]),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="coverage_checks.py", description=__doc__)
    p.add_argument("command", choices=["owasp", "cross-repo", "all"])
    p.add_argument(
        "--output-dir",
        required=True,
        help="assessment output dir containing .threats-merged.json and .threat-modeling-context.md",
    )
    args = p.parse_args(argv)

    output_dir = Path(args.output_dir)
    if not output_dir.is_dir():
        print(f"coverage_checks.py: output dir not found: {output_dir}", file=sys.stderr)
        return 1

    threats = _load_merged_threats(output_dir)

    try:
        if args.command == "owasp":
            out: dict[str, Any] = check_owasp_top10(threats)
        elif args.command == "cross-repo":
            reg = output_dir / ".cross-repo-register.json"
            out = check_cross_repo(
                output_dir / ".threat-modeling-context.md",
                threats,
                register_path=reg if reg.is_file() else None,
            )
        else:
            out = run_all(output_dir)
    except (FileNotFoundError, ValueError) as e:
        print(f"coverage_checks.py: {e}", file=sys.stderr)
        return 1

    json.dump(out, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
