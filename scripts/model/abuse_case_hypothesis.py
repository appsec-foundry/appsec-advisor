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
from contexts.build_analyst_snapshot import _blobs, _commit, _redact_secrets, _tree, rejection_reason
from contexts.resolve_analyst_catalog import load_limits

from model import match_abuse_cases as matcher
from model import resolve_abuse_cases as resolver

MAX_PATHS = 20  # analyst-request scope/paths maxItems
MAX_STEPS = 10  # analyst-response hypothesis_assessment/steps maxItems
MAX_HYPOTHESIS_CHARS = 20000
MAX_SCAN_BYTES = 512 * 1024
MAX_MODEL_BYTES = 2 * 1024 * 1024
MAX_LINKED_FINDINGS = 8
MAX_CONTROLS = 8
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
    derived = [cid for cid in unknown if cid.startswith("MODEL-AC-")]
    if derived:
        raise AbuseCaseError(
            f"{', '.join(derived)}: a model-derived case is checked from the threat model that records it; "
            "run without --isolated"
        )
    if unknown:
        raise AbuseCaseError(
            f"unknown abuse case ID(s): {', '.join(unknown)}; list them with /appsec-advisor:abuse-cases"
        )
    unrecorded = [cid for cid in ids if cid.startswith("MODEL-AC-") and not by_id[cid].get("check")]
    if unrecorded:
        raise AbuseCaseError(
            f"{', '.join(unrecorded)}: this threat model does not record the derived check; a new thorough run checks it"
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


def load_model(model_path: Path) -> dict | None:
    """The threat model as untrusted data, read bounded; ``None`` when unreadable or invalid.

    A single-repository model must pass the output validation the analyst
    context applies, so the hypothesis never cites a model the report marks
    invalid. A combined model is returned as is, and ``build`` refuses it.
    """
    from shared.assessment_sources import is_portable_model
    from validators.validate_intermediate import validate_threat_model_output

    try:
        if model_path.stat().st_size > MAX_MODEL_BYTES:
            return None
        data = yaml.safe_load(model_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    if not is_portable_model(data) and not validate_threat_model_output(data)[0]:
        return None
    return data


def _records(data: dict, key: str) -> list[dict]:
    return [r for r in data.get(key) or [] if isinstance(r, dict)]


def model_links(data: dict, cases: list[dict]) -> dict[str, dict]:
    """Per case: its previous outcome and the findings tied to it, with what the
    model recorded about each: evidence status, controls in place, mitigations.

    Every string is clipped to one line. A finding the case only shares a CWE
    with is kept only when its evidence is runtime code, so a CI or
    documentation finding of the same weakness class does not steer the check.
    """
    threats = [t for t in _records(data, "threats") if t.get("id")]
    by_id = {}
    for t in threats:
        by_id[str(t["id"])] = t
        by_id[_display_id(str(t["id"]))] = t
    mitigations = {str(m.get("id")): m for m in _records(data, "mitigations")}
    analysis = data.get("abuse_case_analysis") if isinstance(data.get("abuse_case_analysis"), dict) else {}
    recorded = {str(c.get("id")): c for c in analysis.get("cases") or [] if isinstance(c, dict)}
    links: dict[str, dict] = {}
    for case in cases:
        cid = str(case["id"])
        prior = recorded.get(cid) or {}
        linked = [(by_id[str(i)], True) for i in prior.get("matched_finding_ids") or [] if str(i) in by_id]
        cwes = _case_cwes(case)
        linked += [
            (t, False) for t in threats if str(t.get("cwe") or "").upper() in cwes and t not in [x for x, _ in linked]
        ]
        findings = []
        for t, explicit in linked:
            evidence = t.get("evidence") if isinstance(t.get("evidence"), list) else []
            first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
            file = matcher._safe_repo_glob(first.get("file"))
            if not explicit and not (file and matcher._is_runtime_surface_evidence(file)):
                continue
            line = first.get("line") if type(first.get("line")) is int else None
            fixes = [_clip(mitigations[m].get("title")) for m in t.get("mitigation_ids") or [] if m in mitigations]
            findings.append(
                {
                    "id": _display_id(str(t["id"])),
                    "title": _clip(t.get("title")),
                    "file": file,
                    "line": line,
                    "status": _clip(t.get("evidence_check")),
                    "controls": _clip(t.get("controls_in_place")),
                    "fixes": fixes[:2],
                }
            )
            if len(findings) >= MAX_LINKED_FINDINGS:
                break
        questions = [q for q in prior.get("open_questions") or [] if isinstance(q, str) and q.strip()]
        links[cid] = {
            "verdict": _clip(prior.get("chain_verdict")) if prior else "",
            "findings": findings,
            "question": _clip(questions[0]) if questions else "",
        }
    return links


def model_controls(data: dict, paths: list[str]) -> list[dict]:
    """Security controls the threat model assessed whose implementation or
    assessment cites one of the checked files."""
    found = []
    for c in _records(data, "security_controls"):
        cited = f"{c.get('implementation') or ''} {c.get('assessment') or ''}"
        if any(re.search(rf"(?<![\w/.-]){re.escape(p)}(?![\w/.-])", cited) for p in paths):
            found.append(
                {
                    "control": _clip(c.get("control")),
                    "effectiveness": _clip(c.get("effectiveness")),
                    "assessment": _clip(c.get("assessment")),
                }
            )
        if len(found) >= MAX_CONTROLS:
            break
    return found


def model_recommendation(cases: list[dict]) -> list[str]:
    """Why a threat model would sharpen this check, one reason per case that needs it.

    A technical chain with more than one step usually spans components whose
    findings only a threat model links. A business case that locates code
    through routes or scanner rules depends on data only a threat-model run
    collects; without it, only its path patterns apply.
    """
    reasons = []
    for case in cases:
        cid = str(case["id"])
        if matcher.is_descriptive(case):
            qualifier = case.get("scope_qualifier") or {}
            if qualifier.get("route_patterns") or qualifier.get("detector_rules"):
                reasons.append(
                    f"{cid} finds code through routes and scanner results that only a threat-model run collects"
                )
        elif len(case.get("chain") or []) > 1:
            reasons.append(f"{cid} has {len(case['chain'])} steps; a threat model links the findings across them")
    return reasons


def numbered_steps(cases: list[dict]) -> dict[str, list[tuple[int, dict]]]:
    """Per technical case its chain steps, numbered across all selected cases.

    The analyst answers each ``- Step N:`` line once by its number, so two
    chains checked together must not both declare a step 1.
    """
    numbered: dict[str, list[tuple[int, dict]]] = {}
    n = 0
    for case in cases:
        if matcher.is_descriptive(case):
            continue
        steps = [s for s in case.get("chain") or [] if isinstance(s, dict)]
        numbered[str(case["id"])] = [(n + i, step) for i, step in enumerate(steps, start=1)]
        n += len(steps)
    if n > MAX_STEPS:
        raise AbuseCaseError(
            f"the selected abuse cases have {n} chain steps, more than the {MAX_STEPS} one check rates; "
            "check fewer at a time"
        )
    return numbered


def _model_lines(link: dict) -> list[str]:
    lines = []
    if link.get("verdict"):
        lines.append(f"Previous threat-model result for this case: {link['verdict']}.")
    for f in link.get("findings", []):
        where = f" ({f['file']}" + (f":{f['line']}" if f["line"] else "") + ")" if f["file"] else ""
        lines.append(f"- Related threat-model finding {f['id']}: {f['title']}{where}")
        if f.get("status"):
            lines.append(f"  Evidence status in the model: {f['status']}.")
        if f.get("controls"):
            lines.append(f"  Controls recorded: {f['controls']}")
        if f.get("fixes"):
            lines.append(f"  Planned mitigation: {'; '.join(f['fixes'])}")
    if link.get("question"):
        lines.append(f"Open question recorded in the threat model: {link['question']}")
    return lines


def hypothesis_text(
    cases: list[dict],
    origins: dict[str, str],
    with_threat_model: bool,
    links: dict[str, dict] | None = None,
    controls: list[dict] | None = None,
) -> str:
    """The hypothesis the analyst checks: every selected case, then the model context."""
    parts = []
    numbered = numbered_steps(cases)
    several = len(numbered) > 1
    for case in cases:
        cid = str(case["id"])
        kind = "business abuse case" if matcher.is_descriptive(case) else "technical abuse case"
        origin = resolver._ORIGIN_LABEL.get(origins.get(cid, ""), "unknown origin")
        lines = [f"Abuse case {cid} ({kind}, {origin}): {_one_line(case.get('title'))}."]
        if matcher.is_descriptive(case):
            lines += [f"- {_one_line(step)}" for step in resolver.descriptive_steps(case)]
            lines += [f"- Out of scope: {_one_line(item)}" for item in case.get("exclusions") or []]
        else:
            if case.get("goal"):
                lines.append(f"Attacker goal: {_one_line(case['goal'])}")
            for n, step in numbered.get(cid, []):
                owner = f"{cid}: " if several else ""
                lines.append(f"- Step {n}: {owner}{_one_line(step.get('label'))}. {_one_line(step.get('description'))}")
        lines += _model_lines((links or {}).get(cid, {}))
        parts.append("\n".join(lines))
    if controls:
        parts.append(
            "\n".join(
                ["Security controls the threat model assessed in the checked files:"]
                + [f"- {c['control']} ({c['effectiveness']}): {c['assessment']}" for c in controls]
            )
        )
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


def locate_paths(
    repo_root: Path, revision: str, cases: list[dict], preferred: list[str] = (), limit: int | None = MAX_PATHS
) -> list[str]:
    """Files at ``revision`` for the cases, capped at ``limit``.

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
    return found[:limit]


def admissible_paths(
    repo_root: Path, revision: str, user_paths: list[str], candidates: list[str], max_kept: int
) -> tuple[list[str], list[str]]:
    """Split located files into those the snapshot admits whole and those it would exclude.

    The controller ends a check as incomplete when a named path is not
    admitted. A file the plugin located, not the user, is therefore left out
    beforehand when the snapshot would exclude it: a sensitive name, binary
    content, an unredactable secret, or the per-file and per-job size limits,
    counted after the files the user named. At most ``max_kept`` files are kept.
    """
    limits = load_limits()
    tree = _tree(repo_root, _commit(repo_root, revision))
    blobs = {path: oid for path, (mode, oid) in tree.items() if mode.startswith("100")}
    named = sorted({q for p in user_paths for q in blobs if q == p or q.startswith(p.rstrip("/") + "/")})
    contents = _blobs(repo_root, sorted({blobs[q] for q in named}))
    total = sum(len(contents[blobs[q]]) for q in named if not rejection_reason(q, contents[blobs[q]], limits))
    count = len(named)
    kept: list[str] = []
    skipped: list[str] = []
    for path in candidates:
        if len(kept) >= max_kept:
            break
        content = _blobs(repo_root, [blobs[path]])[blobs[path]] if path in blobs else None
        if content is not None and not rejection_reason(path, content, limits):
            content = _redact_secrets(content)[0]
        if (
            content is None
            or rejection_reason(path, content, limits)
            or total + len(content) > limits["job_kib"] * 1024
            or count >= limits["admitted_files"]
        ):
            skipped.append(path)
            continue
        kept.append(path)
        total += len(content)
        count += 1
    return kept, skipped


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
    data = load_model(threat_model_path) if threat_model_path else None
    from shared.assessment_sources import is_portable_model, single_repository_only

    if is_portable_model(data):
        # Its finding files belong to several checkouts, not to this repository.
        raise AbuseCaseError(
            single_repository_only("an abuse-case check", "Run it with --isolated or a single-repository model")
        )
    # A model-derived case exists only in the threat model that records it.
    for case in resolver.derived_cases(data):
        if case["id"] not in origins:
            cases.append(case)
            origins[case["id"]] = "derived"
    selected = select_cases(cases, case_ids)
    links = model_links(data, selected) if data else {}
    preferred = [f["file"] for link in links.values() for f in link["findings"] if f["file"]]
    paths = list(dict.fromkeys(user_paths))
    skipped: list[str] = []
    if len(paths) < MAX_PATHS:
        located = [p for p in locate_paths(repo_root, revision, selected, preferred, None) if p not in paths]
        located, skipped = admissible_paths(repo_root, revision, paths, located, MAX_PATHS - len(paths))
        paths += located
    if not paths:
        raise AbuseCaseError(
            "no file at this revision matches the selected abuse cases; name the files or directories with --path"
        )
    paths = paths[:MAX_PATHS]
    controls = model_controls(data, paths) if data else []
    # An unreadable or invalid model is not context, and the hypothesis says so.
    unusable = threat_model_path is not None and data is None
    hypothesis = hypothesis_text(selected, origins, with_threat_model and not unusable, links, controls)
    summary = _summary(selected, origins, links, revision, paths)
    if unusable:
        summary += f"\n  Threat model: {threat_model_path.name} is unreadable or invalid and is not used"
    if skipped:
        summary += f"\n  Not added, beyond the analyst's file limits: {len(skipped)} located file(s)"
    if controls:
        summary += "\n  Assessed controls in these files: " + ", ".join(
            f"{c['control']} ({c['effectiveness']})" for c in controls
        )
    reasons = [] if with_threat_model else model_recommendation(selected)
    if reasons:
        summary += "\n  Recommendation: create a threat model first with /appsec-advisor:create-threat-model"
        summary += "".join(f"\n    {r}" for r in reasons)
    return hypothesis, paths, summary


def _summary(cases: list[dict], origins: dict[str, str], links: dict, revision: str, paths: list[str]) -> str:
    lines = ["ABUSE-CASE CHECK"]
    numbered = numbered_steps(cases)
    for case in cases:
        cid = str(case["id"])
        kind = "business abuse case" if matcher.is_descriptive(case) else "technical abuse case"
        origin = resolver._ORIGIN_LABEL.get(origins.get(cid, ""), "unknown origin")
        lines.append(f"  {cid}  {_one_line(case.get('title'))}  ({kind}, {origin})")
        if matcher.is_descriptive(case):
            lines += [f"    Checks: {_clip(step)}" for step in resolver.descriptive_steps(case)[:3]]
        else:
            if case.get("goal"):
                lines.append(f"    Goal: {_clip(case['goal'])}")
            lines += [f"    Step {n}: {_clip(step.get('label'))}" for n, step in numbered.get(cid, [])]
        link = links.get(cid) or {}
        if link.get("verdict"):
            lines.append(f"    previously: {link['verdict']}")
        if link.get("findings"):
            lines.append("    related findings: " + ", ".join(f["id"] for f in link["findings"]))
    lines.append(f"  Revision: {revision}")
    lines.append(f"  Files ({len(paths)}):")
    lines += [f"    {p}" for p in paths]
    return "\n".join(lines)
