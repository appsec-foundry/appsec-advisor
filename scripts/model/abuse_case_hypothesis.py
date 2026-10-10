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
  chooses them, and a case that locates no file needs paths from the user;
* with a threat model, the case's previous outcome and the findings it is
  linked to, or that share a step's CWE, come first: their files lead the
  path list, and the hypothesis names them as context, not as proof.
"""

from __future__ import annotations

# Direct CLI execution must resolve the same packages as imports from scripts/.
import sys as _sys
from pathlib import Path as _Path

if not __package__:
    _sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))

import re
from pathlib import Path, PurePosixPath

import yaml
from contexts.build_analyst_snapshot import _blobs, _commit, _tree

from model import match_abuse_cases as matcher
from model import resolve_abuse_cases as resolver

MAX_PATHS = 20  # analyst-request scope/paths maxItems
MAX_HYPOTHESIS_CHARS = 20000
MAX_SCAN_BYTES = 512 * 1024
MAX_MODEL_BYTES = 2 * 1024 * 1024
MAX_LINKED_FINDINGS = 8
MAX_FIELD_CHARS = 200


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


def _clip(value: object) -> str:
    text = _one_line(value)
    return text if len(text) <= MAX_FIELD_CHARS else text[: MAX_FIELD_CHARS - 1] + "…"


def _display_id(raw: str) -> str:
    """The report anchor of a threat id: ``T-NNN`` is shown as ``F-NNN``."""
    return "F-" + raw[2:] if raw.startswith("T-") else raw


def _case_cwes(case: dict) -> set[str]:
    blocks = [case.get("finding") or {}] + [step.get("finding") or {} for step in case.get("chain") or []]
    return {str(b.get("cwe")).upper() for b in blocks if isinstance(b, dict) and b.get("cwe")}


def model_links(model_path: Path, cases: list[dict]) -> dict[str, dict]:
    """Per case: its previous outcome in the threat model and the findings tied to it.

    The model is untrusted input: it is read bounded, every string is clipped
    to one line, and a file it names is used only when it exists at the
    checked revision. An unreadable model yields no links.
    """
    try:
        if model_path.stat().st_size > MAX_MODEL_BYTES:
            return {}
        data = yaml.safe_load(model_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError):
        return {}
    if not isinstance(data, dict):
        return {}
    threats = [t for t in data.get("threats") or [] if isinstance(t, dict) and t.get("id")]
    by_id = {}
    for t in threats:
        by_id[str(t["id"])] = t
        by_id[_display_id(str(t["id"]))] = t
    analysis = data.get("abuse_case_analysis") if isinstance(data.get("abuse_case_analysis"), dict) else {}
    recorded = {str(c.get("id")): c for c in analysis.get("cases") or [] if isinstance(c, dict)}
    links: dict[str, dict] = {}
    for case in cases:
        cid = str(case["id"])
        prior = recorded.get(cid) or {}
        linked = [by_id[str(i)] for i in prior.get("matched_finding_ids") or [] if str(i) in by_id]
        cwes = _case_cwes(case)
        linked += [t for t in threats if str(t.get("cwe") or "").upper() in cwes and t not in linked]
        findings = []
        for t in linked[:MAX_LINKED_FINDINGS]:
            evidence = t.get("evidence") if isinstance(t.get("evidence"), list) else []
            first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
            file = matcher._safe_repo_glob(first.get("file"))
            line = first.get("line") if type(first.get("line")) is int else None
            findings.append(
                {"id": _display_id(str(t["id"])), "title": _clip(t.get("title")), "file": file, "line": line}
            )
        questions = [q for q in prior.get("open_questions") or [] if isinstance(q, str) and q.strip()]
        links[cid] = {
            "verdict": _clip(prior.get("chain_verdict")) if prior else "",
            "findings": findings,
            "question": _clip(questions[0]) if questions else "",
        }
    return links


def _model_lines(link: dict) -> list[str]:
    lines = []
    if link.get("verdict"):
        lines.append(f"Previous threat-model result for this case: {link['verdict']}.")
    for f in link.get("findings", []):
        where = f" ({f['file']}" + (f":{f['line']}" if f["line"] else "") + ")" if f["file"] else ""
        lines.append(f"- Related threat-model finding {f['id']}: {f['title']}{where}")
    if link.get("question"):
        lines.append(f"Open question recorded in the threat model: {link['question']}")
    return lines


def hypothesis_text(
    cases: list[dict], origins: dict[str, str], with_threat_model: bool, links: dict[str, dict] | None = None
) -> str:
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
        lines += _model_lines((links or {}).get(cid, {}))
        parts.append("\n".join(lines))
    parts.append(
        "This check uses the supplied threat model as context; a finding it records is a lead to check in the code, not proof."
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


def locate_paths(repo_root: Path, revision: str, cases: list[dict], preferred: list[str] = ()) -> list[str]:
    """Files at ``revision`` for the cases, capped at MAX_PATHS.

    Each source of files is one group: the ``preferred`` files from the
    threat model, each technical step with its files ranked by how many lines
    match its code sinks, and each business case's path patterns. The groups
    take turns, so the cap never fills with one step's matches while another
    step gets no file.
    """
    tree = _tree(repo_root, _commit(repo_root, revision))
    sources = _runtime_sources(tree)
    groups: list[list[str]] = [[p for p in preferred if p in tree and tree[p][0].startswith("100")]]
    step_sinks: list[list[re.Pattern]] = []
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
                groups.append([p for p in sorted(sources) if matcher._path_pattern_matches(Path(p), patterns)])
        else:
            for step in case.get("chain") or []:
                raw = (step.get("probe") or {}).get("sink_patterns") or []
                compiled = matcher._compile([p for p in raw if matcher._is_code_sink_pattern(p)])
                if compiled:
                    step_sinks.append(compiled)
    if step_sinks:
        texts = {}
        blobs = _blobs(repo_root, [sources[p] for p in sorted(sources)])
        for path in sorted(sources):
            content = blobs[sources[path]]
            if len(content) <= MAX_SCAN_BYTES:
                texts[path] = content.decode("utf-8", "ignore").splitlines()
        for sinks in step_sinks:
            hits = {
                path: sum(1 for line in lines if any(rx.search(line) for rx in sinks)) for path, lines in texts.items()
            }
            groups.append(sorted((p for p, n in hits.items() if n), key=lambda p: (-hits[p], p)))
    found: list[str] = []
    for rank in range(max((len(g) for g in groups), default=0)):
        for group in groups:
            if rank < len(group) and group[rank] not in found:
                found.append(group[rank])
    return found[:MAX_PATHS]


def build(
    repo_root: Path,
    revision: str,
    case_ids: list[str],
    user_paths: list[str],
    with_threat_model: bool,
    org_profile: Path | None = None,
    no_org_profile: bool = False,
    threat_model_path: Path | None = None,
) -> tuple[str, list[str], str]:
    """Return (hypothesis, paths, summary) for the selected cases.

    The summary is the plain scope a user sees before the check runs: each
    case with its kind and origin, what the threat model records about it,
    and the files.
    """
    cases, origins = load_cases(repo_root, org_profile, no_org_profile)
    selected = select_cases(cases, case_ids)
    links = model_links(threat_model_path, selected) if threat_model_path else {}
    preferred = [f["file"] for link in links.values() for f in link["findings"] if f["file"]]
    paths = list(dict.fromkeys(user_paths))
    if len(paths) < MAX_PATHS:
        paths += [p for p in locate_paths(repo_root, revision, selected, preferred) if p not in paths]
    if not paths:
        raise AbuseCaseError(
            "no file at this revision matches the selected abuse cases; name the files or directories with --path"
        )
    paths = paths[:MAX_PATHS]
    hypothesis = hypothesis_text(selected, origins, with_threat_model, links)
    return hypothesis, paths, _summary(selected, origins, links, revision, paths)


def _summary(cases: list[dict], origins: dict[str, str], links: dict, revision: str, paths: list[str]) -> str:
    lines = ["ABUSE-CASE CHECK"]
    for case in cases:
        cid = str(case["id"])
        kind = "business case" if matcher.is_descriptive(case) else "technical attack chain"
        origin = resolver._ORIGIN_LABEL.get(origins.get(cid, ""), "unknown origin")
        lines.append(f"  {cid}  {_one_line(case.get('title'))}  ({kind}, {origin})")
        if matcher.is_descriptive(case):
            lines += [f"    Checks: {_clip(step)}" for step in resolver.descriptive_steps(case)[:3]]
        else:
            if case.get("goal"):
                lines.append(f"    Goal: {_clip(case['goal'])}")
            lines += [
                f"    Step {step.get('step')}: {_clip(step.get('label'))}" for step in (case.get("chain") or [])[:6]
            ]
        link = links.get(cid) or {}
        if link.get("verdict"):
            lines.append(f"    previously: {link['verdict']}")
        if link.get("findings"):
            lines.append("    related findings: " + ", ".join(f["id"] for f in link["findings"]))
    lines.append(f"  Revision: {revision}")
    lines.append(f"  Files ({len(paths)}):")
    lines += [f"    {p}" for p in paths]
    return "\n".join(lines)
