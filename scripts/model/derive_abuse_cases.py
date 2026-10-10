#!/usr/bin/env python3
"""Bound the input and admit the output of model-derived business abuse cases.

At thorough depth one deriver agent proposes up to three application-specific
business abuse cases (decision AC-12). This script owns both deterministic
ends of that dispatch:

* ``context`` writes the deriver's bounded input: validated components,
  actors, assets, the confirmed business use case, and the titles of the cases
  already active. It carries no source code.
* ``admit`` validates the deriver's proposals as open descriptive cases,
  drops proposals beyond the limit or with a title an active case already
  uses, assigns ``MODEL-AC-NNN`` ids, and writes the admitted cases to
  ``.derived-abuse-cases.yaml``, which the matcher loads like a repository
  case file.

Proposals are untrusted model output: every admitted case passes the same
schema as a repository case and stays a hypothesis until verified.
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
from pathlib import Path

import yaml

import model.resolve_abuse_cases as rac
from model.match_abuse_cases import DERIVED_CASE_FILE

CONTEXT_REL = Path(".dispatch-context") / "abuse-cases" / "deriver.json"
OUTPUT_FILE = ".abuse-case-deriver-output.json"
MAX_COMPONENTS = 30
MAX_ACTORS = 15
MAX_ASSETS = 20
MAX_ACTIVE_TITLES = 64
_TEXT = 300
_PROPOSAL_FIELDS = ("title", "check", "exclusions", "open_questions", "finding")


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _text(value: object, limit: int = _TEXT) -> str:
    return " ".join(str(value or "").split())[:limit]


def _title_key(title: object) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(title or "").casefold()).strip()


def _config(output_dir: Path) -> dict:
    return _load_json(output_dir / ".skill-config.json")


def _active_cases(output_dir: Path, cfg: dict) -> list[dict]:
    """The cases this run loads before derivation, as the matcher resolves them."""
    profile_path = cfg.get("org_profile_path")
    profile, profile_dir = None, None
    if isinstance(profile_path, str) and profile_path:
        profile = rac._load_yaml(Path(profile_path))
        profile_dir = Path(profile_path).parent
    repo_root = Path(cfg["repo_root"]) if cfg.get("repo_root") else None
    cases, _errors, _rejected = rac.resolve_abuse_case_sources(profile, profile_dir, rac.PLUGIN_ROOT, repo_root)
    return cases


def _use_case(output_dir: Path, cfg: dict) -> str:
    from contexts import load_business_context
    from contexts.business_use_case import confirmed_use_case

    repo_root = Path(cfg.get("repo_root") or output_dir)
    path = load_business_context.effective_source(repo_root, output_dir)
    if path is None:
        return ""
    try:
        return confirmed_use_case(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""


def build_context(output_dir: Path) -> dict:
    cfg = _config(output_dir)
    components = (_load_json(output_dir / ".components.json").get("components") or [])[:MAX_COMPONENTS]
    actors = (_load_json(output_dir / ".actors-resolved.json").get("resolved_actors") or [])[:MAX_ACTORS]
    assets = (_load_json(output_dir / ".assets.json").get("assets") or [])[:MAX_ASSETS]
    active = _active_cases(output_dir, cfg)
    return {
        "schema_version": 1,
        "max_cases": rac.load_limits()["descriptive_candidates_derived"],
        "use_case": _text(_use_case(output_dir, cfg), 600) or None,
        "components": [
            {
                "id": _text(c.get("id"), 80),
                "name": _text(c.get("name"), 120),
                "description": _text(c.get("description")),
            }
            for c in components
            if isinstance(c, dict) and c.get("id")
        ],
        "actors": [
            {
                "id": _text(a.get("id"), 40),
                "label": _text(a.get("label"), 120),
                "description": _text(a.get("description")),
            }
            for a in actors
            if isinstance(a, dict) and a.get("id")
        ],
        "assets": [
            {
                "id": _text(a.get("id"), 40),
                "name": _text(a.get("name"), 160),
                "classification": _text(a.get("classification"), 40),
            }
            for a in assets
            if isinstance(a, dict) and a.get("id")
        ],
        "active_case_titles": [_text(c.get("title"), 160) for c in active if c.get("title")][:MAX_ACTIVE_TITLES],
    }


def write_context(output_dir: Path) -> Path:
    target = output_dir / CONTEXT_REL
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_context(output_dir), indent=2) + "\n", encoding="utf-8")
    return target


def admit(output_dir: Path) -> dict:
    """Validate the deriver's proposals and write the admitted cases.

    Returns ``{"admitted": [...ids], "dropped": [{"title", "reason"}]}``. An
    absent or unreadable output admits nothing; derivation is optional work.
    """
    limit = rac.load_limits()["descriptive_candidates_derived"]
    raw = _load_json(output_dir / OUTPUT_FILE).get("cases")
    proposals = raw if isinstance(raw, list) else []
    taken = {_title_key(c.get("title")) for c in _active_cases(output_dir, _config(output_dir))}
    schema = rac._load_schema()
    admitted: list[dict] = []
    dropped: list[dict] = []
    for proposal in proposals:
        title = _text(proposal.get("title"), 160) if isinstance(proposal, dict) else ""
        if len(admitted) >= limit:
            dropped.append({"title": title, "reason": f"exceeds the limit of {limit} derived cases"})
            continue
        if not isinstance(proposal, dict):
            dropped.append({"title": "", "reason": "not an object"})
            continue
        if not proposal.get("check"):
            dropped.append({"title": title, "reason": "a derived case must state check"})
            continue
        if _title_key(title) in taken:
            dropped.append({"title": title, "reason": "duplicates the title of an active case"})
            continue
        case = {
            "id": f"MODEL-AC-{len(admitted) + 1:03d}",
            "kind": "descriptive",
            **{key: proposal[key] for key in _PROPOSAL_FIELDS if key in proposal},
        }
        if isinstance(case.get("finding"), dict):
            # The model classifies; it does not rate. Severity stays the default.
            case["finding"] = {k: v for k, v in case["finding"].items() if k != "severity"}
        errors = rac._schema_errors({"schema_version": 2, "abuse_cases": [case]}, schema, OUTPUT_FILE)
        if errors:
            dropped.append({"title": title, "reason": rac._reason(errors)})
            continue
        taken.add(_title_key(title))
        admitted.append(case)
    target = output_dir / DERIVED_CASE_FILE
    if admitted:
        target.write_text(
            yaml.safe_dump({"schema_version": 2, "abuse_cases": admitted}, sort_keys=False), encoding="utf-8"
        )
    elif target.exists():
        target.unlink()
    return {"admitted": [case["id"] for case in admitted], "dropped": dropped}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Context and admission for model-derived abuse cases.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("context", "admit"):
        sub.add_parser(name).add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.cmd == "context":
        print(write_context(args.output_dir))
    else:
        print(json.dumps(admit(args.output_dir)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
