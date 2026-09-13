#!/usr/bin/env python3
"""Select the open questions shared by the report and completion summary.

Selection is deterministic and presentation-neutral. Callers supply the anchors
their output can deliver, then render the returned references in their own link
style. This keeps the console and Management Summary on one rule set without
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
    "The code cannot settle these points. They depend on deployment or business decisions and are the input for "
    "a manual threat-modeling session."
)
UNVERIFIED_QUESTION = (
    "Unverified evidence: confirm or rule out what the code alone could not establish before scheduling the fix."
)


def mechanism_team_questions(plugin_root: Optional[Path] = None) -> dict[str, str]:
    """Return the explicit team question for each registered mechanism."""
    root = plugin_root or Path(__file__).resolve().parent.parent
    try:
        data = yaml.safe_load((root / "data" / "weakness-classes.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    guidance = data.get("mechanism_guidance") or {}
    return {
        str(key): str(entry["team_question"]).strip()
        for key, entry in guidance.items()
        if isinstance(entry, dict) and str(entry.get("team_question") or "").strip()
    }


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
) -> dict[str, list[dict]]:
    """Select up to three team questions and the optional verification line.

    The sources are unresolved verified abuse-case investigations, registered
    weakness mechanisms with an explicit question, and the few mechanism
    signals intentionally handled outside the weakness register. Only
    Medium-or-higher findings with evidence and a delivered anchor participate.
    """
    if team_questions is None:
        team_questions = mechanism_team_questions()
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
        candidates.append(
            {
                "id": finding_id,
                "rank": rank,
                "cwes": cwes,
                "title": title,
                "context": context,
                "build_time": build_time,
                "unproven": threat.get("evidence_tier") != "confirmed-exploitable"
                or threat.get("evidence_check") not in {"verified", "verified-prior"},
                "unverified": threat.get("evidence_check") not in {"verified", "verified-prior"},
            }
        )
    candidates.sort(key=lambda item: (item["rank"], int(item["id"][2:])))
    by_id = {item["id"]: item for item in candidates}

    def matching(cwes: set[str], pattern: str = "", *, title_only: bool = False) -> list[dict]:
        return [
            item
            for item in candidates
            if item["cwes"] & cwes
            and (not pattern or re.search(pattern, item["title"] if title_only else item["context"], re.I))
        ]

    topics: list[dict] = []

    def add(
        question: str,
        *groups: list[dict],
        priority: int | None = None,
        limit: int = 2,
        weakness_id: str = "",
    ) -> None:
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
                "refs": refs[:limit],
                "hidden": distinct_count - min(len(refs), limit),
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
        if unresolved and len({item["id"] for item in unresolved + related}) >= 2:
            add(
                "Unproven attack chain: what would confirm or rule out this combination in the deployed system?",
                unresolved,
                related,
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
        add(
            question,
            [item for item in candidates if item["id"] in instance_ids],
            limit=3,
            weakness_id=weakness_id,
        )

    execution = [item for item in matching({"CWE-77", "CWE-78", "CWE-94", "CWE-95"}) if not item["build_time"]]
    if execution:
        mechanism = (
            "Command execution" if all(item["cwes"] & {"CWE-77", "CWE-78"} for item in execution) else "Code execution"
        )
        add(f"{mechanism}: could a takeover reach other services or shared credentials?", execution)
    else:
        add(
            "Server-side requests: could these reach internal services or infrastructure credentials?",
            matching({"CWE-918"}),
        )
    model_tools = [
        item
        for item in matching({"CWE-1427", "CWE-20", "CWE-863", "CWE-862"}, r"\b(llm|prompt injection|language model)\b")
        if re.search(r"\b(tool|tools|tool-calling|agent|actions?)\b", item["context"], re.I)
    ]
    add("Model-controlled actions: which business decisions need authorization outside the assistant?", model_tools)

    selected: list[dict] = []
    used: set[str] = set()
    questions: set[str] = set()
    for topic in sorted(topics, key=lambda item: (item["rank"], item["order"], tuple(r["id"] for r in item["refs"]))):
        if topic["question"] in questions or all(item["id"] in used for item in topic["refs"]):
            continue
        selected.append(topic)
        questions.add(topic["question"])
        used.update(item["id"] for item in topic["refs"])
        if len(selected) == 3:
            break

    return {
        "questions": selected,
        "unverified": [item for item in candidates if item["unverified"]],
    }
