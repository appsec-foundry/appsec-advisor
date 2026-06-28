#!/usr/bin/env python3
"""Render a human-facing overview of an existing ``threat-model.yaml``.

Powers ``/appsec-advisor:show-threat-model``. Read-only: it parses the
committed semantic model and prints a compact at-a-glance summary —
project + scan identity, severity breakdown, top-Critical findings,
mitigation/control counts, and the report path. No LLM judgement, no
network, no writes; output is byte-stable for a given input.

Freshness is NOT computed here. The skill obtains the freshness verdict
from ``threat_model_health.py --json`` (which wraps
``baseline_state.py check-changes`` + ``dirty-set`` — the SAME change
detection that decides whether an incremental scan is needed) and pipes
that JSON in via ``--health-json``. Folding it here keeps the final
rendered block deterministic instead of LLM-assembled.

Usage:
    summarize_threat_model.py --output-dir PATH [--repo-root PATH]
        [--all] [--json] [--health-json PATH|-]

Flags:
    --output-dir PATH    Directory holding ``threat-model.yaml``.
    --repo-root PATH     Repo root (only used for the header path display).
    --all                List every threat grouped by severity, not just
                         the top Critical findings.
    --json               Emit the structured summary as JSON.
    --health-json PATH   Read a ``threat_model_health.py --json`` payload
                         (``-`` for stdin) and fold its freshness verdict
                         into the rendered Status line.

Exit codes:
    0  threat model present, summary rendered
    1  no threat model found at <output-dir>/threat-model.yaml
    2  error (unreadable / unparseable YAML)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


# ---------------------------------------------------------------------------
# Field extraction (defensive — shapes vary across schema/fixture versions)
# ---------------------------------------------------------------------------


def _severity_label(threat: dict | None) -> str:
    """Canonical severity for a threat; mirrors render_completion_summary."""
    if not threat:
        return ""
    raw = (threat.get("severity") or threat.get("risk") or "").strip()
    label = raw[:1].upper() + raw[1:].lower() if raw else ""
    return label if label in _SEVERITY_ORDER else raw


def _threat_title(threat: dict | None) -> str:
    if not threat:
        return ""
    title = (threat.get("title") or threat.get("name") or "").strip()
    if title:
        return title
    scenario = (threat.get("scenario") or threat.get("description") or "").strip()
    return scenario[:80].rstrip()


def _threat_id(threat: dict) -> str:
    return (threat.get("t_id") or threat.get("id") or "").strip()


def _project(data: dict) -> dict:
    """Return {name, version} tolerating top-level or meta-nested project."""
    candidates = [data.get("project"), (data.get("meta") or {}).get("project")]
    name, version = "", ""
    for cand in candidates:
        if isinstance(cand, dict):
            name = name or (cand.get("name") or "").strip()
            version = version or (cand.get("version") or "").strip()
        elif isinstance(cand, str) and cand.strip():
            name = name or cand.strip()
    return {"name": name or "(unnamed project)", "version": version}


def _short_sha(sha: str) -> str:
    return (sha or "").strip()[:7]


def _severity_counts(threats: list) -> dict:
    counts = {k: 0 for k in _SEVERITY_ORDER}
    for t in threats:
        label = _severity_label(t)
        if label in counts:
            counts[label] += 1
    return counts


def build_summary(data: dict, output_dir: Path) -> dict:
    """Reduce raw YAML to the structured summary the renderer consumes."""
    meta = data.get("meta") or {}
    git = meta.get("git") or {}
    threats = [t for t in (data.get("threats") or []) if isinstance(t, dict)]
    components = data.get("components") or []
    mitigations = data.get("mitigations") or []
    controls = data.get("security_controls") or []

    counts = _severity_counts(threats)

    def _sort_key(t: dict) -> tuple:
        return (_SEVERITY_ORDER.get(_severity_label(t), 9), _threat_id(t))

    threats_sorted = sorted(threats, key=_sort_key)
    criticals = [t for t in threats_sorted if _severity_label(t) == "Critical"]

    proj = _project(data)
    return {
        "project": proj,
        "scan": {
            "generated": meta.get("generated", ""),
            "commit_sha": _short_sha(git.get("commit_sha", "")),
            "branch": git.get("branch", ""),
            "model": meta.get("model", ""),
            "assessment_depth": meta.get("assessment_depth", ""),
            "mode": meta.get("mode", ""),
        },
        "totals": {
            "threats": len(threats),
            "components": len(components),
            "mitigations": len(mitigations),
            "controls": len(controls),
        },
        "severity_counts": counts,
        "criticals": [
            {
                "id": _threat_id(t),
                "title": _threat_title(t),
                "component": (t.get("component") or "").strip(),
                "vektor": (t.get("vektor") or "").strip(),
            }
            for t in criticals
        ],
        "threats_by_severity": [
            {
                "id": _threat_id(t),
                "title": _threat_title(t),
                "severity": _severity_label(t),
                "component": (t.get("component") or "").strip(),
                "vektor": (t.get("vektor") or "").strip(),
            }
            for t in threats_sorted
        ],
        "report": str(output_dir / "threat-model.md"),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_VERDICT_ICON = {"FRESH": "✓", "STALE": "⚠", "NO_MODEL": "✗", "UNKNOWN": "?"}
_RECOMMEND_TEXT = {
    "noop": "no re-scan needed — model is up to date",
    "incremental": "next /appsec-advisor:create-threat-model runs incremental",
    "full": "re-scan recommended: /appsec-advisor:create-threat-model --full",
    "rebuild": "rebuild recommended: /appsec-advisor:create-threat-model --rebuild",
    "none": "",
}


def _bar(count: int, peak: int, width: int = 24) -> str:
    if peak <= 0 or count <= 0:
        return ""
    filled = max(1, round(count / peak * width))
    return "█" * filled


def render_status_line(freshness: dict) -> list[str]:
    verdict = (freshness.get("verdict") or "UNKNOWN").strip()
    icon = _VERDICT_ICON.get(verdict, "?")
    reason = (freshness.get("reason") or "").strip()
    head = f"Status     {icon} {verdict}"
    if reason:
        head += f" — {reason}"
    out = [head]
    rec = _RECOMMEND_TEXT.get((freshness.get("recommend") or "none").strip(), "")
    if rec:
        out.append(f"           {rec}")
    return out


def render_text(summary: dict, freshness: dict | None, show_all: bool) -> str:
    proj = summary["project"]
    scan = summary["scan"]
    totals = summary["totals"]
    counts = summary["severity_counts"]
    buf: list[str] = []

    name = proj["name"]
    if proj["version"]:
        name += f" ({proj['version']})"
    buf.append(f"Threat Model — {name}")

    # Scan identity line — only non-empty fields.
    bits = []
    if scan["generated"]:
        bits.append(scan["generated"][:10])
    if scan["commit_sha"]:
        sha = f"commit {scan['commit_sha']}"
        if scan["branch"]:
            sha += f" ({scan['branch']})"
        bits.append(sha)
    if scan["model"]:
        bits.append(f"model {scan['model']}")
    if scan["assessment_depth"]:
        depth = f"depth {scan['assessment_depth']}"
        if scan["mode"]:
            depth += f" ({scan['mode']})"
        bits.append(depth)
    if bits:
        buf.append("Scanned    " + " · ".join(bits))
    buf.append("")

    if freshness is not None:
        buf.extend(render_status_line(freshness))
        buf.append("")

    buf.append(f"Findings   {totals['threats']} threats across {totals['components']} components")
    peak = max(counts.values()) if counts else 0
    for sev in ("Critical", "High", "Medium", "Low", "Informational"):
        n = counts.get(sev, 0)
        if sev == "Informational" and n == 0:
            continue
        buf.append(f"  {sev:<13} {n:>3}   {_bar(n, peak)}")
    buf.append("")

    if show_all:
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            group = [t for t in summary["threats_by_severity"] if t["severity"] == sev]
            if not group:
                continue
            buf.append(f"{sev} ({len(group)})")
            for t in group:
                buf.append(_threat_row(t))
            buf.append("")
    else:
        crit = summary["criticals"]
        if crit:
            buf.append(f"Top Critical ({len(crit)})")
            for t in crit:
                buf.append(_threat_row(t))
            buf.append("")

    buf.append(f"Mitigations {totals['mitigations']} defined · Controls {totals['controls']} in place")
    buf.append(f"Report     {summary['report']}")
    return "\n".join(buf) + "\n"


def _threat_row(t: dict) -> str:
    tid = t.get("id", "")
    title = t.get("title", "")
    comp = t.get("component", "")
    vektor = t.get("vektor", "")
    row = f"  {tid:<7} {title}"
    tail = "   ".join(x for x in (comp, vektor) if x)
    if tail:
        row += f"   [{tail}]"
    return row


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_health(arg: str | None) -> dict | None:
    """Return the ``freshness`` sub-object from a health --json payload."""
    if not arg:
        return None
    try:
        raw = sys.stdin.read() if arg == "-" else Path(arg).read_text(encoding="utf-8")
        payload = json.loads(raw) if raw.strip() else {}
    except (OSError, json.JSONDecodeError):
        return None
    fresh = payload.get("freshness")
    return fresh if isinstance(fresh, dict) else None


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="summarize_threat_model.py", description=__doc__)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--repo-root", default=None)
    p.add_argument("--all", action="store_true", help="List every threat grouped by severity.")
    p.add_argument("--json", action="store_true", help="Emit structured JSON.")
    p.add_argument("--health-json", default=None, help="health --json payload path, or '-' for stdin.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    output_dir = Path(args.output_dir).resolve()
    yaml_path = output_dir / "threat-model.yaml"

    if not yaml_path.is_file():
        msg = {
            "verdict": "NO_MODEL",
            "output_dir": str(output_dir),
        }
        if args.json:
            print(json.dumps(msg, indent=2, sort_keys=True))
        else:
            print(f"No threat model found at {yaml_path}.")
            print("Run /appsec-advisor:create-threat-model to generate one.")
        return 1

    try:
        import yaml as _yaml

        data = _yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 — surface any parse failure as exit 2
        print(f"Error: could not parse {yaml_path}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print(f"Error: {yaml_path} is not a mapping.", file=sys.stderr)
        return 2

    summary = build_summary(data, output_dir)
    freshness = _load_health(args.health_json)

    if args.json:
        payload = dict(summary)
        if freshness is not None:
            payload["freshness"] = freshness
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(summary, freshness, args.all), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
