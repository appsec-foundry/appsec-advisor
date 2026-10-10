#!/usr/bin/env python3
"""model/abuse_case_hypothesis.py — turn selected abuse cases into an analyst hypothesis check.

The Threat Analyst checks one hypothesis against named paths at a revision.
This module builds both from abuse cases, so a user can check single cases
without a full assessment:

* the cases come from the same sources a threat-model run loads (plugin,
  organization profile, repository, explicit files), and an unknown ID is an
  error rather than a guess;
* the hypothesis text is assembled deterministically from each case's title,
  goal, and steps, or its one-sentence check, and states whether the check runs
  with or without a threat model;
* the paths are files at the selected revision that match a technical step's
  code sink patterns or a business case's path patterns. The model never
  chooses them, and a case that locates no file needs paths from the user.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import re
from pathlib import Path, PurePosixPath

from contexts.build_analyst_snapshot import _blobs, _commit, _tree

from model import match_abuse_cases as matcher
from model import resolve_abuse_cases as resolver

MAX_PATHS = 20  # analyst-request scope/paths maxItems
MAX_HYPOTHESIS_CHARS = 20000
MAX_SCAN_BYTES = 512 * 1024


class AbuseCaseError(Exception):
    """The selected cases cannot be turned into a hypothesis check."""


def load_cases(
    repo_root: Path, org_profile: Path | None, no_org_profile: bool, plugin_root: Path = resolver.PLUGIN_ROOT
) -> tuple[list[dict], dict[str, str]]:
    """Active cases and their origins, resolved with the profile a run would use."""
    from runtime.resolve_org_profile import discover_active_profile

    profile_path = org_profile
    if profile_path is None:
        profile_path, _source = discover_active_profile(None, no_org_profile, plugin_root)
    profile = resolver._load_yaml(profile_path) if profile_path else None
    origins: dict[str, str] = {}
    cases, errors, _rejected = resolver.resolve_abuse_case_sources(
        profile, profile_path.parent if profile_path else None, plugin_root, repo_root, origins=origins
    )
    if errors:
        raise AbuseCaseError("; ".join(errors))
    return cases, origins


def select_cases(cases: list[dict], ids: list[str]) -> list[dict]:
    by_id = {str(c.get("id")): c for c in cases}
    unknown = [cid for cid in ids if cid not in by_id]
    if unknown:
        raise AbuseCaseError(
            f"unknown abuse case ID(s): {', '.join(unknown)}; list them with /appsec-advisor:abuse-cases"
        )
    return [by_id[cid] for cid in dict.fromkeys(ids)]


def _one_line(value: object) -> str:
    return " ".join(str(value or "").split())


def hypothesis_text(cases: list[dict], origins: dict[str, str], with_threat_model: bool) -> str:
    """The hypothesis the analyst checks: every selected case, then the model context."""
    parts = []
    for case in cases:
        cid = str(case["id"])
        kind = "business case" if matcher.is_descriptive(case) else "technical attack chain"
        origin = resolver._ORIGIN_LABEL.get(origins.get(cid, ""), "unknown origin")
        lines = [f"Abuse case {cid} ({kind}, {origin}): {_one_line(case.get('title'))}."]
        if matcher.is_descriptive(case):
            lines += [f"- {_one_line(step)}" for step in resolver.descriptive_steps(case)]
            lines += [f"- Out of scope: {_one_line(item)}" for item in case.get("exclusions") or []]
        else:
            if case.get("goal"):
                lines.append(f"Attacker goal: {_one_line(case['goal'])}")
            for step in case.get("chain") or []:
                lines.append(
                    f"- Step {step.get('step')}: {_one_line(step.get('label'))}. {_one_line(step.get('description'))}"
                )
        parts.append("\n".join(lines))
    parts.append(
        "This check uses the supplied threat model as context."
        if with_threat_model
        else "This check runs without a threat model, against the selected source only."
    )
    text = "\n\n".join(parts)
    if len(text) > MAX_HYPOTHESIS_CHARS:
        raise AbuseCaseError("the selected abuse cases exceed the hypothesis size limit; check fewer at a time")
    return text


def _runtime_sources(tree: dict[str, tuple[str, str]]) -> dict[str, str]:
    """Runtime source files of the revision: path -> blob id."""
    return {
        path: oid
        for path, (mode, oid) in tree.items()
        if mode.startswith("100")
        and PurePosixPath(path).suffix.lower() in matcher._DESCRIPTIVE_SOURCE_SUFFIXES
        and matcher._is_runtime_surface_evidence(path)
        and not matcher.scan_excludes.is_excluded(path)
    }


def locate_paths(repo_root: Path, revision: str, cases: list[dict]) -> list[str]:
    """Files at ``revision`` that each case's own patterns point to, capped at MAX_PATHS."""
    tree = _tree(repo_root, _commit(repo_root, revision))
    sources = _runtime_sources(tree)
    found: list[str] = []
    sinks: list[re.Pattern] = []
    for case in cases:
        if matcher.is_descriptive(case):
            patterns = [
                p
                for p in (
                    matcher._safe_repo_glob(v) for v in (case.get("scope_qualifier") or {}).get("path_patterns") or []
                )
                if p
            ]
            if patterns:
                found += [p for p in sorted(sources) if matcher._path_pattern_matches(Path(p), patterns)]
        else:
            for step in case.get("chain") or []:
                raw = (step.get("probe") or {}).get("sink_patterns") or []
                sinks += matcher._compile([p for p in raw if matcher._is_code_sink_pattern(p)])
    if sinks:
        sizes_ok = [p for p in sorted(sources) if p not in found]
        blobs = _blobs(repo_root, [sources[p] for p in sizes_ok])
        for path in sizes_ok:
            content = blobs[sources[path]]
            if len(content) > MAX_SCAN_BYTES:
                continue
            text = content.decode("utf-8", "ignore")
            if any(rx.search(text) for rx in sinks):
                found.append(path)
    return list(dict.fromkeys(found))[:MAX_PATHS]


def build(
    repo_root: Path,
    revision: str,
    case_ids: list[str],
    user_paths: list[str],
    with_threat_model: bool,
    org_profile: Path | None = None,
    no_org_profile: bool = False,
) -> tuple[str, list[str]]:
    """Return (hypothesis, paths) for the selected cases."""
    cases, origins = load_cases(repo_root, org_profile, no_org_profile)
    selected = select_cases(cases, case_ids)
    paths = list(dict.fromkeys(user_paths))
    if len(paths) < MAX_PATHS:
        paths += [p for p in locate_paths(repo_root, revision, selected) if p not in paths]
    if not paths:
        raise AbuseCaseError(
            "no file at this revision matches the selected abuse cases; name the files or directories with --path"
        )
    return hypothesis_text(selected, origins, with_threat_model), paths[:MAX_PATHS]
