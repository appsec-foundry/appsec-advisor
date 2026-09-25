"""Give a confirmed privileged actor its own legitimate role before boundary assessment.

The architecture analyst models legitimate roles as external entities. When
actor discovery confirmed a privileged actor with code evidence (an admin
guard, a role check) but no modelled role carries privileged access, the
privileged role would vanish inside a regular one and Figure 1 would show no
administrator (RA-11). This step adds that role from the actor's own file/line
evidence and, when a regular role already uses a client, the same interaction
for the privileged role. It never renames, merges or removes authored roles.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path

from actor_presentation import actor_group
from reclassify_components import _glob_to_regex
from reconcile_role_access import system_proven_anonymous
from validate_evidence_lines import _resolve_evidence_file
from validate_fragment import repository_evidence_errors

ENTITY_ID = "ext-privileged-role"
MAX_EVIDENCE = 4
_LOCATION = re.compile(r"(?<![\w./-])([\w.-][\w./-]*\.[A-Za-z0-9]+):(\d+)\b")


def _repository_path(repo_root: Path, cited: str) -> str:
    """Resolve a citation that dropped leading directories (`app.guard.ts`) to its one repository file."""
    found = _resolve_evidence_file(repo_root, cited)
    if not found:
        return cited
    relative = found.resolve().relative_to(repo_root.resolve()).as_posix()
    return relative if relative == cited or relative.endswith("/" + cited) else cited


def _confirmed_privileged(resolved: dict) -> list[tuple[dict, dict]]:
    """Confirmed, active privileged actors with their discovery row, by ID."""
    confirmed = {row.get("id"): row for row in resolved.get("confirmed_relevant") or [] if isinstance(row, dict)}
    rows = []
    for actor in sorted(resolved.get("resolved_actors") or [], key=lambda a: str(a.get("id"))):
        if actor_group(actor) != "internet-priv-user" or (actor.get("_provenance") or {}).get("active") is False:
            continue
        row = confirmed.get(actor.get("id"))
        if row and row.get("confidence") != "low":
            rows.append((actor, row))
    return rows


def unevidenced_privileged_actors(document: dict, resolved: dict, repo_root: Path) -> list[str]:
    """Confirmed privileged actors that still have no role because no cited location resolved."""
    if any(
        e.get("kind") == "legitimate-role" and e.get("access") == "internet-priv-user"
        for e in document.get("external_entities") or []
    ):
        return []
    return (
        [actor["id"] for actor, _ in _confirmed_privileged(resolved)]
        if not privileged_evidence(resolved, repo_root)
        else []
    )


def privileged_evidence(resolved: dict, repo_root: Path) -> tuple[str, list[dict]] | None:
    """Return the first confirmed, active privileged actor with contained file/line evidence."""
    for actor, row in _confirmed_privileged(resolved):
        locations: list[dict] = []
        for file, line in _LOCATION.findall(str(row.get("relevance_evidence") or "")):
            location = {"file": _repository_path(repo_root, file), "line": int(line)}
            # A file header (package, import, comment) names a file, not the access check.
            if location not in locations and not repository_evidence_errors(
                [location], repo_root, require_line=True, require_code=True, allow_imports=False
            ):
                locations.append(location)
        if locations:
            return actor["id"], locations[:MAX_EVIDENCE]
    return None


def _owns(component: dict, file: str) -> bool:
    return any(
        _glob_to_regex(pattern).fullmatch(file)
        or (not re.search(r"[*?\[]", pattern) and file.startswith(pattern.rstrip("/") + "/"))
        for pattern in component.get("paths") or []
    )


def _interaction_template(document: dict, components: list[dict], evidence: list[dict]) -> dict | None:
    """A regular role's client interaction, preferring the client that holds the privileged evidence."""
    roles = {e.get("id") for e in document.get("external_entities") or [] if e.get("kind") == "legitimate-role"}
    uses = sorted(
        (
            f
            for f in document.get("data_flows") or []
            if f.get("interaction") and f.get("from") == "external" and f.get("from_entity") in roles
        ),
        key=lambda f: f["id"],
    )
    owners = {c.get("id") for c in components for row in evidence if _owns(c, row["file"])}
    return next((f for f in uses if f.get("to") in owners), uses[0] if uses else None)


def reconcile(repo_root: Path, components: list[dict], document: dict, resolved: dict) -> tuple[dict, dict | None]:
    """Return the data-flow document and a receipt when a privileged role was added."""
    result = copy.deepcopy(document)
    entities = result.setdefault("external_entities", [])
    if any(e.get("kind") == "legitimate-role" and e.get("access") == "internet-priv-user" for e in entities):
        return result, None
    # Elevated rights need an authenticated session; a system nobody logs into has no reachable admin role.
    if system_proven_anonymous(result, components):
        return result, None
    found = privileged_evidence(resolved, repo_root)
    if not found:
        return result, None
    actor_id, evidence = found
    taken = {e.get("id") for e in entities}
    entity_id = next(
        candidate
        for candidate in (ENTITY_ID, *(f"{ENTITY_ID}-{n}" for n in range(2, len(taken) + 3)))
        if candidate not in taken
    )
    template = _interaction_template(result, components, evidence)
    entities.append(
        {
            "id": entity_id,
            "name": "Admin",
            "kind": "legitimate-role",
            "access": "internet-priv-user",
            "description": "Application role with elevated rights, evidenced by its access check.",
            "evidence": evidence,
        }
    )
    flow_id = None
    if template:
        # An interaction cites the client it uses; a server-side access check stays on the role only.
        target = next((c for c in components if c.get("id") == template["to"]), {})
        flow_evidence = [row for row in evidence if _owns(target, row["file"])] or template.get("evidence") or evidence
        flows = result.setdefault("data_flows", [])
        flow_id = f"df-{max(int(f['id'][3:]) for f in flows) + 1:03d}"
        flows.append(
            {
                "id": flow_id,
                "from": "external",
                "from_entity": entity_id,
                "to": template["to"],
                "label": "Privileged use",
                "protocol": template["protocol"],
                "data_classification": template["data_classification"],
                "direction": template["direction"],
                "interaction": True,
                "evidence": flow_evidence,
                "provenance": "recon",
            }
        )
    return result, {"actor_id": actor_id, "entity_id": entity_id, "flow_id": flow_id}
