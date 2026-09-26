#!/usr/bin/env python3
"""Select the open questions shared by the report and completion summary.

Selection is deterministic and presentation-neutral. Callers supply the anchors
their output can deliver, then render the returned references in their own
reference style. This keeps the console and Management Summary on one rule set without
letting either renderer infer questions from prose.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import _severity_rollup
import yaml
from _shared_sources import DESIGN_LEVEL_SOURCES

CONSOLE_HEADER = "Open questions for the team:"
REPORT_HEADING = "### Open Questions for the Team"
REPORT_INTRO = (
    "The code cannot answer these questions; the people who own the business and the deployment can. "
    "Each question states under it what its answer changes."
)
# Naming an asset does not answer its criticality. Only an explicit, sourced
# answer projected by the control analyst settles that question for its scope.
ASSET_CRITICALITY_IMPACT = (
    "The answer weights the impact rating and fix order of every finding that reaches these assets; recorded "
    "with the asset name and concrete harm in `docs/business-context.md`, the next full run applies it."
)
_CRITICAL_CLASSIFICATIONS = {"Restricted": 0, "Confidential": 1}
_UNSAFE_NAME_CHARS_RE = re.compile(r"[\x00-\x1f\x7f\[\]()<>`*_?#|\\]")
_AUTHENTICATED_ACCESS = {"authenticated-user-session", "authenticated-session"}
_AUTHENTICATED_POSITIONS = {"authenticated-user-authority", "authenticated-user"}
_BYPASS_CWES = {"CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-303", "CWE-304", "CWE-305", "CWE-306", "CWE-1390"}
_BYPASS_VIA_INJECTION_CWES = {"CWE-89", "CWE-564", "CWE-943"}
_AUTH_CONTEXT_RE = re.compile(r"\b(login|log-in|sign-?in|authentication|authenticate|credential)\b", re.I)
REGISTRATION_QUESTION = "Can anyone create an account for {component}, or does onboarding require approval?"
REGISTRATION_IMPACT = (
    "Public onboarding can give an outsider the ordinary account these findings require; approval-gated "
    "onboarding adds a prerequisite. The answer does not establish privileged access or prove a control."
)

# The reference tail a rendered report bullet ends with: the optional weakness
# link, the finding links, their optional `(unproven)` marker and an optional
# `+N more` remainder — nothing else. A question's own parenthetical ("(support,
# admin bulk operations)") never matches because every element must be an id link.
_REPORT_REF_TAIL_RE = re.compile(
    r"\((?=\[[WF]-\d)"
    r"(?:\[W-\d{3,}\]\(#w-\d{3,}\)(?:: )?)?"
    r"(?:\[F-\d{3,}\]\(#f-\d{3,}\)(?: \(unproven\))?"
    r"(?:, \[F-\d{3,}\]\(#f-\d{3,}\)(?: \(unproven\))?)*)?"
    r"(?: ?\+\d+ more)?\)$"
)


def is_report_question_line(line: str) -> bool:
    """True for a rendered Open-Questions bullet: question first, references last.

    The finding-ref enrichment passes key on this to leave the block's ids bare.
    It tests the bullet's own shape, so a separator rewrite elsewhere in the
    rendering tail cannot silently turn the guard off.
    """
    return line.startswith("- ") and bool(_REPORT_REF_TAIL_RE.search(line.rstrip()))


def _mechanism_field(field: str, plugin_root: Optional[Path]) -> dict[str, str]:
    root = plugin_root or Path(__file__).resolve().parent.parent
    try:
        data = yaml.safe_load((root / "data" / "weakness-classes.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    guidance = data.get("mechanism_guidance") or {}
    return {
        str(key): str(entry[field]).strip()
        for key, entry in guidance.items()
        if isinstance(entry, dict) and str(entry.get(field) or "").strip()
    }


def mechanism_team_questions(plugin_root: Optional[Path] = None) -> dict[str, str]:
    """Return the explicit team question for each registered mechanism."""
    return _mechanism_field("team_question", plugin_root)


def mechanism_decision_impacts(plugin_root: Optional[Path] = None) -> dict[str, str]:
    """Return what each mechanism's answer decides, keyed like the questions.

    A question without its consequence reads as conversation. Pairing both keeps
    the selector presentation-neutral: callers render the impact in their own
    style or drop it, but neither renderer has to infer it from the question.
    """
    return _mechanism_field("decision_impact", plugin_root)


def visible_anchor_ids(report_text: str) -> set[str]:
    """Return delivered finding and weakness anchors outside opaque Markdown."""
    visible = re.sub(r"(?ms)^ {0,3}(`{3,}|~{3,})[^\n]*\n.*?^ {0,3}\1[^\n]*$", "", report_text)
    visible = re.sub(r"(?s)<!--.*?-->", "", visible)
    visible = re.sub(r"(?s)(`+).*?\1", "", visible)
    return set(re.findall(r"<a\s+id=[\"']([fw]-\d{3,})[\"']\s*>\s*</a>", visible))


def model_anchor_ids(yaml_data: dict) -> set[str]:
    """Return anchors the validated composer emits for this canonical model."""
    anchors = {
        _severity_rollup.display_id(str(threat.get("id") or threat.get("t_id") or "")).lower()
        for threat in _severity_rollup.register_threats(yaml_data)
        if re.fullmatch(r"[TF]-\d{3,}", str(threat.get("id") or threat.get("t_id") or ""))
    }
    anchors.update(
        str(weakness.get("id") or "").lower()
        for weakness in yaml_data.get("weaknesses") or []
        if isinstance(weakness, dict) and re.fullmatch(r"W-\d{3,}", str(weakness.get("id") or ""))
    )
    return anchors


def select_open_questions(
    yaml_data: dict,
    available_anchors: set[str],
    *,
    team_questions: Optional[dict[str, str]] = None,
    decision_impacts: Optional[dict[str, str]] = None,
) -> dict[str, list[dict]]:
    """Select up to three questions only the team can answer.

    The sources are undeclared criticality of the classified assets the
    findings reach, unresolved verified abuse-case investigations, registered
    weakness mechanisms with an explicit question, and the few mechanism
    signals intentionally handled outside the weakness register. Only
    Medium-or-higher findings with evidence and a delivered anchor participate.
    Verifying an individual finding is triage work, never a team question.
    Every selected topic carries the `impact` its answer decides, so a renderer
    never has to infer the consequence from the wording.
    """
    if team_questions is None:
        team_questions = mechanism_team_questions()
    if decision_impacts is None:
        decision_impacts = mechanism_decision_impacts()
    anchors = {str(anchor).lower() for anchor in available_anchors}
    candidates: list[dict] = []
    for threat in _severity_rollup.register_threats(yaml_data):
        raw_id = str(threat.get("id") or threat.get("t_id") or "")
        if not re.fullmatch(r"[TF]-\d{3,}", raw_id):
            continue
        finding_id = _severity_rollup.display_id(raw_id)
        rank = _severity_rollup.SEVERITY_ORDER.get(_severity_rollup.register_severity(threat), 99)
        evidence = threat.get("evidence")
        locations = evidence if isinstance(evidence, list) else [evidence]
        if (
            finding_id.lower() not in anchors
            or rank > 2
            or not any(isinstance(location, dict) and location.get("file") for location in locations)
            or str(threat.get("source") or "") in DESIGN_LEVEL_SOURCES
            or str(threat.get("status") or threat.get("_status") or "").lower()
            in {"pass", "passed", "resolved", "mitigated", "false_positive", "dormant"}
        ):
            continue
        cwe = threat.get("cwe")
        cwes = {str(value) for value in cwe} if isinstance(cwe, list) else {str(cwe)}
        title = str(threat.get("title") or "")
        context = " ".join(str(threat.get(field) or "") for field in ("title", "evidence_summary"))
        build_time = any(
            isinstance(location, dict)
            and re.search(
                r"(?:^|/)(?:Dockerfile(?:\.[^/]+)?|Jenkinsfile)$|"
                r"^\.github/workflows/|^\.gitlab-ci\.ya?ml$",
                str(location.get("file") or ""),
            )
            for location in locations
        )
        actor_ids = threat.get("actor_ids")
        candidates.append(
            {
                "id": finding_id,
                "rank": rank,
                "cwes": cwes,
                "title": title,
                "context": context,
                "build_time": build_time,
                "actor_ids": {str(value) for value in actor_ids} if isinstance(actor_ids, list) else set(),
                "component": str(threat.get("component") or threat.get("component_id") or ""),
                "unproven": threat.get("evidence_tier") != "confirmed-exploitable"
                or threat.get("evidence_check") not in {"verified", "verified-prior"},
            }
        )
    candidates.sort(key=lambda item: (item["rank"], int(item["id"][2:])))
    by_id = {item["id"]: item for item in candidates}
    component_names = {
        str(component.get("id")): " ".join(
            _UNSAFE_NAME_CHARS_RE.sub("", str(component.get("name") or component.get("id"))).split()
        )[:100]
        for component in yaml_data.get("components") or []
        if isinstance(component, dict) and component.get("id")
    }

    def subject(items: list[dict]) -> str:
        """Name the components the cited findings sit in, so the question has a concrete subject."""
        names = list(
            dict.fromkeys(component_names[i["component"]] for i in items if component_names.get(i["component"]))
        )
        if not names:
            return "this application"
        return " or ".join(names[:2]) + (" and other components" if len(names) > 2 else "")

    def matching(cwes: set[str], pattern: str = "", *, title_only: bool = False) -> list[dict]:
        return [
            item
            for item in candidates
            if item["cwes"] & cwes
            and (not pattern or re.search(pattern, item["title"] if title_only else item["context"], re.I))
        ]

    topics: list[dict] = []
    authenticated_actors = {
        str(actor.get("id"))
        for actor in yaml_data.get("actors") or []
        if isinstance(actor, dict)
        and actor.get("id")
        and "privileged-user-authority" not in (actor.get("trust_positions") or [])
        and (
            set(actor.get("access") or []) & _AUTHENTICATED_ACCESS
            or set(actor.get("trust_positions") or []) & _AUTHENTICATED_POSITIONS
        )
    }
    # Only verified bypasses can settle onboarding through a verified chain.
    # A neighboring bypass is not evidence that another route needs no account.
    gated = [item for item in candidates if item["actor_ids"] and item["actor_ids"] <= authenticated_actors]
    bypass = [
        item
        for item in candidates
        if not item["unproven"]
        and not item["actor_ids"] & authenticated_actors
        and (
            item["cwes"] & _BYPASS_CWES
            or (item["cwes"] & _BYPASS_VIA_INJECTION_CWES and _AUTH_CONTEXT_RE.search(item["context"]))
        )
    ]
    # Sharing a component does not prove that a bypass reaches another route.
    # Suppress onboarding only for a verified chain containing both findings.
    analysis = yaml_data.get("abuse_case_analysis") or {}
    verified_chains = [
        set(case.get("matched_finding_ids") or [])
        for case in analysis.get("cases", [])
        if analysis.get("status") == "completed"
        and case.get("chain_verdict") == "fully_viable"
        and case.get("verification_complete")
        and not case.get("unverified_steps")
    ]
    gated = [
        item
        for item in gated
        if not any(item["id"] in chain and any(other["id"] in chain for other in bypass) for chain in verified_chains)
    ]

    trace = yaml_data.get("business_context_trace") or {}
    answers = trace.get("answered_questions", []) if trace.get("status") == "applied" else []

    def answered(topic: str, component: str, asset_name: str = "") -> bool:
        return bool(component) and any(
            row.get("topic") == topic
            and row.get("component_id") == component
            and row.get("asset_name", "") == asset_name
            for row in answers
            if isinstance(row, dict)
        )

    gated = [item for item in gated if not answered("account-onboarding", item["component"])]
    registration = (yaml_data.get("meta") or {}).get("open_registration_resolution") or {}
    # `not-established` means no signal was found, not that onboarding is closed.
    # While an authenticated actor carries findings of its own, how someone gets
    # an account decides whether that actor is reachable at all, so an unsettled
    # resolution is asked rather than assumed (VulnerableApp, 2026-09-20).
    # A confirmed bypass settles it the other way: the attacker needs no account,
    # so how accounts are issued no longer changes any rating.
    registration_open = bool(gated) and (
        (registration.get("disputed") is True and registration.get("evidence"))
        or (str(registration.get("reason") or "") == "not-established" and authenticated_actors)
    )
    if registration_open:
        topics.append(
            {
                "rank": -1,
                "order": -1,
                "question": REGISTRATION_QUESTION.format(component=subject(gated)),
                "impact": REGISTRATION_IMPACT,
                "refs": gated[:2],
                "hidden": max(0, len(gated) - 2),
                "reach": len(gated),
                "weakness_id": "",
            }
        )

    data_tier = {
        str(component.get("id"))
        for component in yaml_data.get("components") or []
        if isinstance(component, dict) and component.get("tier") == "data"
    }
    exposed: list[tuple[bool, int, int, str]] = []
    for asset in yaml_data.get("assets") or []:
        if not isinstance(asset, dict) or asset.get("classification") not in _CRITICAL_CLASSIFICATIONS:
            continue
        linked = {_severity_rollup.display_id(str(value)) for value in asset.get("linked_threats") or []}
        reached = [by_id[fid] for fid in sorted(linked & by_id.keys())]
        if reached and all(answered("asset-criticality", item["component"], asset.get("name")) for item in reached):
            continue
        name = " ".join(_UNSAFE_NAME_CHARS_RE.sub("", str(asset.get("name") or "")).split())[:60].strip()
        reach = len(linked & by_id.keys())
        # Data held in a data store is what the business owns; keys and tokens
        # that only protect it follow its criticality, so they rank behind it.
        persisted = any(
            isinstance(ref, dict) and ref.get("relation") == "stored" and ref.get("component_id") in data_tier
            for ref in asset.get("component_refs") or []
        )
        if name and reach:
            exposed.append((not persisted, _CRITICAL_CLASSIFICATIONS[asset["classification"]], -reach, name))
    names = list(dict.fromkeys(entry[-1] for entry in sorted(exposed)))[:3]
    if names:
        listed = names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]
        topics.append(
            {
                "rank": -2,
                "order": -2,
                "question": f"How critical are {listed} to the business, "
                "and what harm would their disclosure, manipulation or unavailability cause?",
                "impact": ASSET_CRITICALITY_IMPACT,
                "refs": [],
                "hidden": 0,
                "reach": 0,
                "weakness_id": "",
            }
        )

    def add(
        question: str,
        *groups: list[dict],
        impact: str = "",
        priority: int | None = None,
        limit: int = 2,
        weakness_id: str = "",
        topic: str = "",
    ) -> None:
        if not impact.strip():
            return
        groups = tuple([item for item in group if not answered(topic, item["component"])] for group in groups)
        refs: list[dict] = []
        seen: set[str] = set()
        for offset in range(limit):
            for group in groups:
                if offset < len(group) and group[offset]["id"] not in seen:
                    refs.append(group[offset])
                    seen.add(group[offset]["id"])
        if not refs:
            return
        distinct_count = len({item["id"] for group in groups for item in group})
        topics.append(
            {
                "rank": min(item["rank"] for item in refs),
                "order": len(topics) if priority is None else priority,
                "question": question,
                "impact": impact,
                "refs": refs[:limit],
                "hidden": distinct_count - min(len(refs), limit),
                # How many findings the answer settles. Two questions at the same
                # severity are not equally worth asking: the one that resolves six
                # findings outranks the one that resolves one.
                "reach": distinct_count,
                "weakness_id": weakness_id if weakness_id.lower() in anchors else "",
            }
        )

    analysis = yaml_data.get("abuse_case_analysis") or {}
    for case in analysis.get("cases", []) if analysis.get("status") == "completed" else []:
        if (
            case.get("chain_verdict") != "inconclusive"
            or not case.get("verification_complete")
            or case.get("unverified_steps")
            or any(isinstance(step, dict) and step.get("verdict") == "refuted" for step in case.get("steps") or [])
        ):
            continue
        unresolved = [
            by_id[step["finding_id"]]
            for step in case.get("steps") or []
            if step.get("verdict") == "inconclusive" and not step.get("unverified") and step.get("finding_id") in by_id
        ]
        related = [by_id[fid] for fid in case.get("matched_finding_ids") or [] if fid in by_id]
        if (
            unresolved
            and len({item["id"] for item in unresolved + related}) >= 2
            and not all(answered("attack-path-connection", item["component"]) for item in unresolved + related)
        ):
            add(
                f"Which production data or identities connect these attack paths through {subject(unresolved + related)}?",
                unresolved,
                related,
                impact=(
                    "Shared production data or identities identify a chain to verify; the answer alone cannot "
                    "confirm exploitation or raise a finding's rating."
                ),
                priority=-1,
            )

    weaknesses = [item for item in yaml_data.get("weaknesses") or [] if isinstance(item, dict)]
    for weakness in sorted(weaknesses, key=lambda item: str(item.get("id") or "")):
        weakness_id = str(weakness.get("id") or "")
        question = team_questions.get(str(weakness.get("mechanism_id") or ""))
        if not question or not re.fullmatch(r"W-\d{3,}", weakness_id):
            continue
        instance_ids = {
            _severity_rollup.display_id(str(instance.get("id") or ""))
            for instance in weakness.get("instances") or []
            if isinstance(instance, dict)
        }
        related = [
            item
            for item in candidates
            if item["id"] in instance_ids and not answered(str(weakness.get("mechanism_id")), item["component"])
        ]
        if not related:
            continue
        question = question.replace("{component}", subject(related))
        add(
            question,
            related,
            impact=decision_impacts.get(str(weakness.get("mechanism_id") or ""), ""),
            limit=3,
            weakness_id=weakness_id,
        )

    execution = [
        item
        for item in matching({"CWE-77", "CWE-78", "CWE-94", "CWE-95"})
        if not item["build_time"] and not answered("process-reach", item["component"])
    ]
    if execution:
        runs = "commands" if all(item["cwes"] & {"CWE-77", "CWE-78"} for item in execution) else "code"
        add(
            f"If an attacker runs {runs} in {subject(execution)}, "
            "which other services, secrets or credentials can that process reach?",
            execution,
            impact=(
                "Every reachable service or credential extends this from one component to a wider compromise "
                "and raises the priority of isolating that process; an isolated process contains it."
            ),
        )
    else:
        requests = [item for item in matching({"CWE-918"}) if not answered("server-request-reach", item["component"])]
        add(
            f"Which internal services or infrastructure credentials can server-side requests from {subject(requests)} reach?",
            requests,
            impact=(
                "Reachable metadata endpoints or internal admin APIs turn this into credential theft; a "
                "restricted egress path limits the reachable targets and informs containment."
            ),
        )
    model_tools = [
        item
        for item in matching({"CWE-1427", "CWE-20", "CWE-863", "CWE-862"}, r"\b(llm|prompt injection|language model)\b")
        if re.search(r"\b(tool|tools|tool-calling|agent|actions?)\b", item["context"], re.I)
        # App-owned action lists and checks belong to source analysis. Ask only
        # when the finding actually identifies tools/actions supplied remotely.
        and re.search(r"\b(?:external|remote)\s+(?:tools?|actions?|mcp)\b", item["context"], re.I)
        and not answered("model-actions", item["component"])
    ]
    add(
        f"Which production actions are enabled for the model in {subject(model_tools)} outside this repository?",
        model_tools,
        impact=(
            "The enabled production actions bound the business impact of model misuse and identify which "
            "authorization boundaries the analysis must verify."
        ),
    )

    selected: list[dict] = []
    used: set[str] = set()
    questions: set[str] = set()
    # Severity first, then how many findings the answer settles: at equal severity
    # the question that resolves more of the register is the one worth the cap.
    ordering = sorted(
        topics,
        key=lambda item: (item["rank"], -item["reach"], item["order"], tuple(r["id"] for r in item["refs"])),
    )
    for topic in ordering:
        if topic["question"] in questions or (topic["refs"] and all(item["id"] in used for item in topic["refs"])):
            continue
        selected.append(topic)
        questions.add(topic["question"])
        used.update(item["id"] for item in topic["refs"])
        if len(selected) == 3:
            break

    return {"questions": selected}
