#!/usr/bin/env python3
"""
aggregate_threat_summary.py — deterministic aggregator for threat-model
portfolio summaries.
Reads finished ``threat-model.yaml`` files from one or more repositories and
produces:

* a structured JSON document conforming to
  ``schemas/threat-summary.schema.json`` (stable contract)
* a rendered Markdown report (the historical default — same sections as the
  prompt-only skill, but deterministic).

The aggregator does **not** perform threat analysis or recon — it consumes
artifacts that ``/appsec-advisor:create-threat-model`` has already produced.

CLI usage::

    python3 aggregate_threat_summary.py \\
        --repo <PATH>... \\
        --format md|json|both \\
        [--min-severity low|medium|high|critical]   # default: medium
        [--open-only]                                # default: include all
        [--output <PATH>]                            # default: stdout
        [--dry-run]

Cross-repo attack-chain candidates are heuristic by definition — the
authoritative chain analysis happens during ``create-threat-model`` itself.
Heuristic matches in this script use the upstream repo's ``related-repos.yaml``
when present, plus a substring match between upstream component names and
downstream trust-boundary text.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import io
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

try:
    import jsonschema  # type: ignore
except ImportError:  # pragma: no cover
    jsonschema = None  # noqa: N816


_HERE = Path(__file__).resolve().parent
_DEFAULT_SCHEMA = _HERE.parent / "schemas" / "threat-summary.schema.json"

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_SEVERITY_MIN_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_DEFAULT_OUTDATED_DAYS = 90


# ---------------------------------------------------------------------------
# Per-repo loading
# ---------------------------------------------------------------------------


def _locate_threat_model(repo: Path) -> Path | None:
    cand = [
        repo / "docs" / "security" / "threat-model.yaml",
        repo / "threat-model.yaml",
    ]
    for p in cand:
        if p.is_file():
            return p
    return None


def _extract_threats(tm: dict[str, Any]) -> list[dict[str, Any]]:
    if isinstance(tm.get("threats"), list):
        return [t for t in tm["threats"] if isinstance(t, dict)]
    out: list[dict[str, Any]] = []
    for cat in tm.get("threat_categories", []) or []:
        if isinstance(cat, dict):
            for f in cat.get("findings", []) or []:
                if isinstance(f, dict):
                    out.append(f)
    return out


def _normalise_severity(s: Any) -> str:
    out = str(s or "").strip().title()
    return out if out in _SEVERITY_ORDER else ""


def _passes_filter(t: dict[str, Any], min_severity: str, open_only: bool) -> bool:
    sev = _normalise_severity(t.get("severity"))
    if not sev or _SEVERITY_ORDER[sev] > _SEVERITY_MIN_RANK[min_severity]:
        return False
    if open_only and str(t.get("status", "")).lower() != "open":
        return False
    return True


def load_repo(
    repo: Path,
    *,
    min_severity: str,
    open_only: bool,
    outdated_days: int = _DEFAULT_OUTDATED_DAYS,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    name = repo.name or str(repo)
    tm_path = _locate_threat_model(repo)
    if tm_path is None:
        return {
            "name": name,
            "path": str(repo),
            "threat_model_path": None,
            "loaded": False,
            "skip_reason": "no threat-model.yaml found",
            "generated": None,
            "commit_sha": None,
            "outdated": False,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_status": {"open": 0, "mitigated": 0, "accepted": 0, "false_positive": 0},
            "findings_total": 0,
            "findings_after_filter": 0,
            "controls_missing": 0,
            "_threats": [],
            "_mitigations": [],
            "_trust_boundaries": [],
        }

    try:
        tm = yaml.safe_load(tm_path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError) as exc:
        return {
            "name": name,
            "path": str(repo),
            "threat_model_path": str(tm_path),
            "loaded": False,
            "skip_reason": f"unreadable threat-model.yaml: {exc}",
            "generated": None,
            "commit_sha": None,
            "outdated": False,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "by_status": {"open": 0, "mitigated": 0, "accepted": 0, "false_positive": 0},
            "findings_total": 0,
            "findings_after_filter": 0,
            "controls_missing": 0,
            "_threats": [],
            "_mitigations": [],
            "_trust_boundaries": [],
        }

    meta = tm.get("meta") if isinstance(tm.get("meta"), dict) else {}
    generated = meta.get("generated")
    git = meta.get("git") if isinstance(meta.get("git"), dict) else {}

    outdated = False
    if generated:
        try:
            ts = _dt.datetime.fromisoformat(str(generated).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=_dt.timezone.utc)
            delta = (now or _dt.datetime.now(tz=_dt.timezone.utc)) - ts
            outdated = delta.days > outdated_days
        except (ValueError, TypeError):
            outdated = False

    all_threats = _extract_threats(tm)
    by_severity = Counter()
    by_status = Counter()
    for t in all_threats:
        sev = _normalise_severity(t.get("severity"))
        if sev:
            by_severity[sev.lower()] += 1
        st = str(t.get("status", "")).lower().replace("-", "_")
        if st:
            by_status[st] += 1

    filtered = [t for t in all_threats if _passes_filter(t, min_severity, open_only)]

    controls = tm.get("security_controls") or []
    controls_missing = sum(
        1 for c in controls if isinstance(c, dict) and str(c.get("effectiveness", "")).lower() == "missing"
    )

    trust_boundaries = tm.get("trust_boundaries") or []

    return {
        "name": name,
        "path": str(repo),
        "threat_model_path": str(tm_path),
        "loaded": True,
        "skip_reason": None,
        "generated": str(generated) if generated else None,
        "commit_sha": git.get("commit_sha"),
        "outdated": outdated,
        "by_severity": {
            "critical": by_severity["critical"],
            "high": by_severity["high"],
            "medium": by_severity["medium"],
            "low": by_severity["low"],
        },
        "by_status": {
            "open": by_status.get("open", 0),
            "mitigated": by_status.get("mitigated", 0),
            "accepted": by_status.get("accepted", 0),
            "false_positive": by_status.get("false_positive", 0),
        },
        "findings_total": len(all_threats),
        "findings_after_filter": len(filtered),
        "controls_missing": controls_missing,
        # Private fields (underscored) carried through to the consolidator,
        # stripped before final emission.
        "_threats": filtered,
        "_mitigations": tm.get("mitigations") or [],
        "_trust_boundaries": [tb for tb in trust_boundaries if isinstance(tb, dict)],
        "_related_repos": _load_related_repos(repo),
    }


def _load_related_repos(repo: Path) -> list[dict[str, Any]]:
    p = repo / "docs" / "related-repos.yaml"
    if not p.is_file():
        return []
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    return [r for r in data.get("related", []) if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# Cross-repo analysis
# ---------------------------------------------------------------------------


def _shared_cwes(repos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cwe_to_repos: dict[str, set[str]] = defaultdict(set)
    cwe_to_count: Counter = Counter()
    for r in repos:
        if not r.get("loaded"):
            continue
        for t in r["_threats"]:
            cwe = str(t.get("cwe") or "").strip()
            if not cwe:
                continue
            cwe_to_repos[cwe].add(r["name"])
            cwe_to_count[cwe] += 1
    out = []
    for cwe, repo_set in cwe_to_repos.items():
        if len(repo_set) >= 2:
            out.append(
                {
                    "cwe": cwe,
                    "repos": sorted(repo_set),
                    "finding_count": cwe_to_count[cwe],
                }
            )
    out.sort(key=lambda e: (-e["finding_count"], e["cwe"]))
    return out


def _chain_candidates(repos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Heuristic upstream → downstream chains.

    A chain candidate exists when:
      * repo B declares repo A in ``related-repos.yaml`` (B depends on A),
      * repo A has an open Critical/High finding,
      * A's finding component name appears in B's trust-boundary text or in
        the declared interface text of B's related-repos entry for A.
    """
    by_name = {r["name"]: r for r in repos if r.get("loaded")}
    out: list[dict[str, Any]] = []
    for downstream in by_name.values():
        for rel in downstream["_related_repos"]:
            upstream_name = str(rel.get("name") or "").strip()
            interface = str(rel.get("interface") or "").strip().lower()
            if not upstream_name or upstream_name not in by_name:
                continue
            upstream = by_name[upstream_name]
            tb_text = " ".join(
                str(tb.get("description") or tb.get("name") or "") for tb in downstream["_trust_boundaries"]
            ).lower()
            for t in upstream["_threats"]:
                if _normalise_severity(t.get("severity")) not in ("Critical", "High"):
                    continue
                component = str(t.get("component") or t.get("component_name") or "").strip()
                if not component:
                    continue
                cmp_l = component.lower()
                match_reason = None
                if cmp_l and (cmp_l in tb_text or (interface and cmp_l in interface)):
                    match_reason = "component name appears in downstream trust boundary"
                elif interface and interface in tb_text:
                    match_reason = "declared interface appears in downstream trust boundary"
                if match_reason:
                    out.append(
                        {
                            "upstream_repo": upstream_name,
                            "upstream_finding_id": str(t.get("id") or t.get("threat_id") or ""),
                            "upstream_component": component,
                            "upstream_severity": _normalise_severity(t.get("severity")),
                            "downstream_repo": downstream["name"],
                            "match_reason": match_reason,
                        }
                    )
    # Stable order + cap at 5 to match the documented skill behaviour.
    out.sort(key=lambda c: (c["downstream_repo"], c["upstream_repo"], c["upstream_finding_id"]))
    return out[:5]


def _shared_mitigations(repos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cwe_to_repos: dict[str, set[str]] = defaultdict(set)
    cwe_to_titles: dict[str, set[str]] = defaultdict(set)
    for r in repos:
        if not r.get("loaded"):
            continue
        for m in r["_mitigations"]:
            if not isinstance(m, dict):
                continue
            title = str(m.get("title") or "")
            cwes = m.get("addresses_cwes") or m.get("cwes") or []
            for cwe in cwes:
                cwe_to_repos[str(cwe)].add(r["name"])
                if title:
                    cwe_to_titles[str(cwe)].add(title)
    out = []
    for cwe, repo_set in cwe_to_repos.items():
        if len(repo_set) >= 2:
            out.append(
                {
                    "cwe": cwe,
                    "repos": sorted(repo_set),
                    "mitigation_titles": sorted(cwe_to_titles[cwe]),
                }
            )
    out.sort(key=lambda e: e["cwe"])
    return out


def _consolidate_findings(
    repos: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in repos:
        if not r.get("loaded"):
            continue
        for t in r["_threats"]:
            sev = _normalise_severity(t.get("severity"))
            if not sev:
                continue
            out.append(
                {
                    "repo": r["name"],
                    "id": str(t.get("id") or t.get("threat_id") or ""),
                    "title": str(t.get("title") or t.get("summary") or ""),
                    "severity": sev,
                    "stride": str(t.get("stride") or ""),
                    "cwe": str(t.get("cwe") or ""),
                    "status": str(t.get("status") or ""),
                    "component": str(t.get("component") or t.get("component_name") or ""),
                }
            )
    out.sort(key=lambda f: (_SEVERITY_ORDER[f["severity"]], f["repo"], f["id"]))
    return out


# ---------------------------------------------------------------------------
# Top-level aggregator
# ---------------------------------------------------------------------------


def aggregate(
    repos: list[Path],
    *,
    min_severity: str = "medium",
    open_only: bool = False,
    now: _dt.datetime | None = None,
) -> dict[str, Any]:
    if min_severity not in _SEVERITY_MIN_RANK:
        raise ValueError(f"min_severity must be one of {sorted(_SEVERITY_MIN_RANK)}")

    loaded = [load_repo(r, min_severity=min_severity, open_only=open_only, now=now) for r in repos]

    result: dict[str, Any] = {
        "meta": {
            "aggregator_version": 1,
            "generated_at": (now or _dt.datetime.now(tz=_dt.timezone.utc)).isoformat(),
            "filter": {"min_severity": min_severity, "open_only": open_only},
        },
        "repos": [],
        "consolidated_findings": _consolidate_findings(loaded),
        "shared_cwes": _shared_cwes(loaded),
        "chain_candidates": _chain_candidates(loaded),
        "shared_mitigations": _shared_mitigations(loaded),
    }
    for r in loaded:
        public = {k: v for k, v in r.items() if not k.startswith("_")}
        result["repos"].append(public)
    return result


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def validate(payload: dict[str, Any], schema_path: Path = _DEFAULT_SCHEMA) -> list[str]:
    if jsonschema is None:
        return []
    if not schema_path.is_file():
        return [f"schema not found: {schema_path}"]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    v = jsonschema.Draft202012Validator(schema)
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in sorted(v.iter_errors(payload), key=lambda e: list(e.absolute_path))
    ]


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------


def render_markdown(summary: dict[str, Any]) -> str:
    buf = io.StringIO()
    w = buf.write
    meta = summary["meta"]
    repos = summary["repos"]

    loaded = [r for r in repos if r["loaded"]]
    skipped = [r for r in repos if not r["loaded"]]
    totals = Counter()
    for r in loaded:
        for k, v in r["by_severity"].items():
            totals[k] += v

    w("# Threat Summary\n")
    w("<!-- generated by aggregate_threat_summary.py -->\n\n")
    w("| Field | Value |\n|-------|-------|\n")
    w(f"| Generated | {meta['generated_at']} |\n")
    w(f"| Repos | {len(repos)} ({len(loaded)} loaded, {len(skipped)} skipped) |\n")
    w(
        f"| Filter | severity ≥ {meta['filter']['min_severity']}, "
        f"open-only: {'yes' if meta['filter']['open_only'] else 'no'} |\n"
    )
    w(
        f"| Findings included | {len(summary['consolidated_findings'])} "
        f"(Critical: {totals['critical']}, High: {totals['high']}, "
        f"Medium: {totals['medium']}, Low: {totals['low']}) |\n\n"
    )

    w("## Risk Overview\n\n")
    w("| Repo | Critical | High | Medium | Low | Open | Mitigated | Controls Missing | Last Analysed |\n")
    w("|------|----------|------|--------|-----|------|-----------|------------------|----------------|\n")
    for r in repos:
        if not r["loaded"]:
            w(f"| {r['name']} | — | — | — | — | — | — | — | _skipped: {r['skip_reason']}_ |\n")
            continue
        bs = r["by_severity"]
        bst = r["by_status"]
        gen = r["generated"] or "—"
        if r["outdated"]:
            gen += " ⚠"
        w(
            f"| {r['name']} | {bs['critical']} | {bs['high']} | {bs['medium']} | "
            f"{bs['low']} | {bst['open']} | {bst['mitigated']} | "
            f"{r['controls_missing']} | {gen} |\n"
        )

    if summary["shared_cwes"]:
        w("\n## Systemic Weaknesses (Shared CWEs)\n\n")
        w("| CWE | Affected Repos | Total Findings |\n")
        w("|-----|----------------|----------------|\n")
        for entry in summary["shared_cwes"][:10]:
            w(f"| {entry['cwe']} | {', '.join(entry['repos'])} | {entry['finding_count']} |\n")

    if summary["chain_candidates"]:
        w("\n## Cross-Repo Attack Chain Candidates\n\n")
        w("> _Heuristic — not confirmed by STRIDE analysis. Review each candidate manually._\n\n")
        for c in summary["chain_candidates"]:
            w(
                f"- **{c['upstream_finding_id']}** ({c['upstream_severity']}) "
                f"in `{c['upstream_repo']}::{c['upstream_component']}` may propagate "
                f"to `{c['downstream_repo']}` — {c['match_reason']}.\n"
            )

    if summary["shared_mitigations"]:
        w("\n## Shared Mitigation Candidates\n\n")
        w("| CWE | Repos | Sample Mitigation Titles |\n")
        w("|-----|-------|--------------------------|\n")
        for entry in summary["shared_mitigations"]:
            titles = "; ".join(entry["mitigation_titles"][:3]) or "—"
            w(f"| {entry['cwe']} | {', '.join(entry['repos'])} | {titles} |\n")

    w("\n## Consolidated Finding Register\n\n")
    if not summary["consolidated_findings"]:
        w("_No findings matched the filter._\n")
    else:
        w("| Repo | ID | Title | Severity | STRIDE | CWE | Status | Component |\n")
        w("|------|----|-------|----------|--------|-----|--------|-----------|\n")
        for f in summary["consolidated_findings"]:
            w(
                f"| {f['repo']} | {f['id']} | {f['title']} | {f['severity']} | "
                f"{f['stride']} | {f['cwe']} | {f['status']} | {f['component']} |\n"
            )

    return buf.getvalue()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0] if __doc__ else None)
    p.add_argument(
        "--repo", action="append", default=[], required=False, help="repository path (may be repeated; default: cwd)"
    )
    p.add_argument("--format", choices=["md", "json", "both"], default="md")
    p.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="medium")
    p.add_argument("--open-only", action="store_true")
    p.add_argument("--output", default=None, help="output file (md) or directory (both) — default stdout")
    p.add_argument("--dry-run", action="store_true", help="print summary to console only, do not write files")
    p.add_argument("--no-validate", action="store_true")
    return p.parse_args(argv)


def _resolve_repos(args: argparse.Namespace) -> list[Path]:
    if args.repo:
        return [Path(r).resolve() for r in args.repo]
    return [Path.cwd().resolve()]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    repos = _resolve_repos(args)
    summary = aggregate(
        repos,
        min_severity=args.min_severity,
        open_only=args.open_only,
    )
    if not args.no_validate:
        errs = validate(summary)
        if errs:
            print("aggregate_threat_summary: schema validation failed:", file=sys.stderr)
            for e in errs:
                print(f"  · {e}", file=sys.stderr)
            return 2

    rendered_md = render_markdown(summary)
    rendered_json = json.dumps(summary, indent=2, sort_keys=False)

    if args.dry_run or args.output is None:
        if args.format in ("md", "both"):
            sys.stdout.write(rendered_md)
        if args.format in ("json", "both"):
            sys.stdout.write(rendered_json + "\n")
        return 0

    out_path = Path(args.output)
    if args.format == "md":
        out_path.write_text(rendered_md, encoding="utf-8")
    elif args.format == "json":
        out_path.write_text(rendered_json + "\n", encoding="utf-8")
    else:  # both
        if out_path.is_dir() or args.output.endswith("/"):
            out_path.mkdir(parents=True, exist_ok=True)
            (out_path / "threat-summary.md").write_text(rendered_md, encoding="utf-8")
            (out_path / "threat-summary.json").write_text(rendered_json + "\n", encoding="utf-8")
        else:
            # If user gave a file, write md to it and json next to it.
            out_path.write_text(rendered_md, encoding="utf-8")
            out_path.with_suffix(".json").write_text(rendered_json + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
