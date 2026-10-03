#!/usr/bin/env python3
"""Cross-artifact invariants of a finished threat-model run.

Each gate in the pipeline checks one artifact against its own contract. These
checks compare artifacts against each other and against the target repository,
which is where defects survive every green gate. Every check takes a run's
output directory, so it works on a frozen fixture and on a fresh run alike.

Invariants (each check returns a list of violation strings, empty = holds):

  untracked_evidence      no reported finding cites a file outside the target's
                          tracked/visible inventory, except explicit absence
                          findings
  confirmed_needs_verified a reported finding is confirmed-exploitable only with
                          verified or verified-prior evidence
  component_paths         every evidence file of a reported finding matches its
                          component's path globs (or the finding is system-wide)
  unique_identity         no two reported findings share file|line|cwe-family
  boundaries_represented  every catalogued trust boundary appears in a §2
                          diagram or a rendered figure
  architect_refuted       architect coverage does not count findings excluded as
                          refuted by evidence verification as unresolved

Usage: run_invariants.py <output_dir> [--repo-root <target>]
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzers.architect_review_runtime import review_coverage  # noqa: E402
from model.merge_threats import _CWE_FAMILY  # noqa: E402
from model.reclassify_components import _build_matcher  # noqa: E402

SYSTEM_WIDE = "system-wide"
_VERIFIED = {"verified", "verified-prior"}
_TB_ID = re.compile(r"\btb-\d+\b")
_MERMAID = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)


def _load_yaml(output_dir: Path) -> dict:
    return yaml.safe_load((output_dir / "threat-model.yaml").read_text(encoding="utf-8")) or {}


def _norm(path: str) -> str:
    path = (path or "").strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _evidence(threat: dict) -> list[dict]:
    ev = threat.get("evidence")
    if isinstance(ev, dict):
        return [ev]
    return [e for e in ev or [] if isinstance(e, dict)]


def _is_absence(threat: dict) -> bool:
    if "expected_file_absent" in (threat.get("evidence_flags") or []):
        return True
    return any(e.get("kind") == "absence" for e in _evidence(threat))


def tracked_files(repo_root: Path) -> set[str]:
    """Tracked plus untracked-but-not-ignored files of the target repository."""
    out = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-co", "--exclude-standard", "-z"],
        check=True,
        capture_output=True,
    ).stdout
    return {_norm(p) for p in out.decode("utf-8").split("\0") if p}


def untracked_evidence(output_dir: Path, tracked: set[str]) -> list[str]:
    out = []
    for t in _load_yaml(output_dir).get("threats") or []:
        if _is_absence(t):
            continue
        for e in _evidence(t):
            f = _norm(e.get("file") or "")
            if f and f not in tracked:
                out.append(f"{t.get('id')}: evidence file {f!r} is not in the target inventory")
    return out


def confirmed_needs_verified(output_dir: Path) -> list[str]:
    return [
        f"{t.get('id')}: confirmed-exploitable with evidence_check={t.get('evidence_check')!r}"
        for t in _load_yaml(output_dir).get("threats") or []
        if t.get("evidence_tier") == "confirmed-exploitable" and t.get("evidence_check") not in _VERIFIED
    ]


def component_paths(output_dir: Path) -> list[str]:
    data = _load_yaml(output_dir)
    matchers = dict(_build_matcher(c) for c in data.get("components") or [] if isinstance(c, dict))
    out = []
    for t in data.get("threats") or []:
        cid = t.get("component")
        if cid == SYSTEM_WIDE or _is_absence(t):
            continue
        pats = matchers.get(cid)
        if pats is None:
            out.append(f"{t.get('id')}: component {cid!r} is not a modelled component")
            continue
        for e in _evidence(t):
            f = _norm(e.get("file") or "")
            if f and not any(p.search(f) for p in pats):
                out.append(f"{t.get('id')}: {f!r} does not match the paths of component {cid!r}")
    return out


def unique_identity(output_dir: Path) -> list[str]:
    seen: dict[str, str] = {}
    out = []
    for t in _load_yaml(output_dir).get("threats") or []:
        cwe = (t.get("cwe") or "").strip().upper()
        family = _CWE_FAMILY.get(cwe, cwe)
        keys = set()
        for e in _evidence(t):
            line = e.get("line")
            f = _norm(e.get("file") or "")
            if f and isinstance(line, int) and line > 1:
                keys.add(f"{f}|{line}|{family}")
        for key in sorted(keys):
            other = seen.setdefault(key, t.get("id"))
            if other != t.get("id"):
                out.append(f"{other} and {t.get('id')} share identity {key}")
    return out


def _section_two(markdown: str) -> str:
    match = re.search(r"^## 2\..*?(?=^## (?!2\.)|\Z)", markdown, re.MULTILINE | re.DOTALL)
    return match.group(0) if match else ""


def _named_boundaries(output_dir: Path) -> set[str]:
    """Boundary ids named inside §2 mermaid blocks or a rendered figure; captions do not count."""
    md_path = output_dir / "threat-model.md"
    texts = [svg.read_text(encoding="utf-8") for svg in output_dir.glob("threat-model.figure*.svg")]
    if md_path.is_file():
        texts += _MERMAID.findall(_section_two(md_path.read_text(encoding="utf-8")))
    return {tb for text in texts for tb in _TB_ID.findall(text)}


def boundaries_represented(output_dir: Path) -> list[str]:
    catalog = [b.get("id") for b in _load_yaml(output_dir).get("trust_boundaries") or [] if b.get("id")]
    drawn = _named_boundaries(output_dir)
    if catalog and not drawn:
        return [f"no §2 diagram or figure names any trust boundary ({', '.join(catalog)})"]
    return [f"{tb}: not represented in any §2 diagram or figure" for tb in catalog if tb not in drawn]


def architect_refuted(output_dir: Path) -> list[str]:
    path = output_dir / ".architect-review.json"
    if not path.is_file():
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    without = copy.deepcopy(value)
    outcomes = without["application"]["outcomes"]
    without["application"]["outcomes"] = [
        r for r in outcomes if not (r.get("reason") == "refuted" and r.get("status") != "accepted")
    ]
    counted = review_coverage(value)["unresolved_or_unreviewed"]
    expected = review_coverage(without)["unresolved_or_unreviewed"]
    if counted == expected:
        return []
    return [f"unresolved_or_unreviewed={counted} counts {counted - expected} refuted exclusion(s)"]


def run_all(output_dir: Path, tracked: set[str] | None) -> dict[str, list[str]]:
    results = {
        "confirmed_needs_verified": confirmed_needs_verified(output_dir),
        "component_paths": component_paths(output_dir),
        "unique_identity": unique_identity(output_dir),
        "boundaries_represented": boundaries_represented(output_dir),
        "architect_refuted": architect_refuted(output_dir),
    }
    if tracked is not None:
        results["untracked_evidence"] = untracked_evidence(output_dir, tracked)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--repo-root", type=Path, help="target repository; enables untracked_evidence")
    args = parser.parse_args(argv)
    tracked = tracked_files(args.repo_root) if args.repo_root else None
    results = run_all(args.output_dir, tracked)
    for name, violations in results.items():
        print(f"{'FAIL' if violations else 'ok  '} {name} ({len(violations)})")
        for v in violations:
            print(f"     {v}")
    return 1 if any(results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
