#!/usr/bin/env python3
"""Console summaries for run-headless.sh — requirements intake and findings.

Two deterministic, read-only summaries printed by ``run-headless.sh`` so they
appear in every mode (default progress and ``--verbose`` raw):

  requirements <yaml>   one-line intake: how many requirements + blueprints
                        were read, and the source name(s) if present. Printed
                        once near the top when a run is requirements-checked.

  findings <yaml>       the Critical/High threats from a finished
                        ``threat-model.yaml``. Printed after the run.

Both fail soft: a missing/unparseable file prints nothing and exits 0 so the
wrapper script is never disrupted.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover - PyYAML is a hard dep elsewhere
    yaml = None


def _load(path: str):
    if yaml is None:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, yaml.YAMLError):
        return None


def _summarize_requirements(path: str) -> int:
    data = _load(path)
    if not data:
        return 0
    categories = data.get("categories") or []
    req_count = sum(len(c.get("requirements") or []) for c in categories if isinstance(c, dict))
    bp_count = len(data.get("blueprints") or [])
    if not req_count and not bp_count:
        return 0

    # Prefer the named sources (sources_meta[].title); fall back to the
    # top-level description so a name is shown whenever one exists.
    names = [s.get("title") for s in (data.get("sources_meta") or []) if isinstance(s, dict) and s.get("title")]
    name_str = ", ".join(names) if names else (data.get("description") or "")
    name_str = name_str.strip().replace("\n", " ")
    if len(name_str) > 80:
        name_str = name_str[:77] + "…"

    line = f"  Requirements read: {req_count} requirements, {bp_count} blueprints"
    if name_str:
        line += f" — {name_str}"
    print(line)
    return 0


_SEV_MARK = {"Critical": "🔴", "High": "🟠"}


def _severity(threat: dict) -> str:
    for key in ("effective_severity", "risk", "severity"):
        val = threat.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def _summarize_findings(path: str) -> int:
    data = _load(path)
    if not data:
        return 0
    threats = data.get("threats") or []
    buckets: dict[str, list[tuple[str, str]]] = {"Critical": [], "High": []}
    for t in threats:
        if not isinstance(t, dict):
            continue
        sev = _severity(t)
        if sev in buckets:
            buckets[sev].append((t.get("id") or t.get("local_id") or "?", (t.get("title") or "").strip()))
    crit, high = buckets["Critical"], buckets["High"]
    if not crit and not high:
        return 0

    print("")
    print(f"  Findings — Critical: {len(crit)}, High: {len(high)}")
    for sev in ("Critical", "High"):
        for tid, title in buckets[sev]:
            if len(title) > 90:
                title = title[:87] + "…"
            print(f"    {_SEV_MARK[sev]} {tid:<7} {title}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("requirements", "findings"):
        print("usage: run_summary.py {requirements|findings} <yaml-path>", file=sys.stderr)
        return 2
    mode, path = argv[1], argv[2]
    if not Path(path).is_file():
        return 0  # fail soft — nothing to summarize
    if mode == "requirements":
        return _summarize_requirements(path)
    return _summarize_findings(path)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
