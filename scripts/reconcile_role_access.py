"""Withdraw an authenticated access class the role's own flows disprove, unless the owner declared it.

The architecture analyst classifies a legitimate role as `internet-user` or
`internet-priv-user`, and Figure 1 names the role after that class. Code that
merely contains a login (a training scenario, a demo, a library) is not an
access gate, yet it tempts that classification. This step reads the model the
analyst wrote: a role whose requests reach the system without authentication
(`none` on at least one own flow) and whose whole request path authenticates
nowhere is anonymous, whatever the class claims. `unknown` proves nothing, so
a path that is only unknown is left as authored.

Access control outside the repository (ingress SSO, VPN, authenticating proxy)
is invisible to the code, so the owner may declare roles under
`legitimate_roles` in `.appsec/actors.yaml`. A declared role replaces the
modelled role with its id, or is added, and is never withdrawn.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path

AUTHENTICATED_ACCESS = ("internet-user", "internet-priv-user")
DECLARATION_FILE = ".appsec/actors.yaml"
_UNPROVEN = frozenset({"none", "unknown"})


def _scheme(flow: dict) -> str:
    return (flow.get("authentication") or {}).get("scheme") or "unknown"


def _counted(flow: dict, data_tier: set) -> bool:
    """A request hop: store access and outbound integrations carry service credentials, not the caller's."""
    return not flow.get("interaction") and flow.get("to") not in data_tier and flow.get("to") != "external"


def _flows(document: dict) -> list[dict]:
    return [f for f in document.get("data_flows") or [] if isinstance(f, dict)]


def _data_tier(components: list) -> set:
    return {c.get("id") for c in components or [] if isinstance(c, dict) and c.get("tier") == "data"}


def _roles(document: dict) -> list[dict]:
    return [
        e for e in document.get("external_entities") or [] if isinstance(e, dict) and e.get("kind") == "legitimate-role"
    ]


def request_path(entity_id: str, flows: list[dict], data_tier: set) -> tuple[list[dict], list[dict]]:
    """(the role's own request hops, every hop reachable behind them, including through a used client)."""
    own = [f for f in flows if f.get("from") == "external" and f.get("from_entity") == entity_id]
    direct = [f for f in own if _counted(f, data_tier)]
    reached = {f.get("to") for f in own if f.get("to") not in data_tier and f.get("to") != "external"}
    path: list[dict] = []
    frontier = set(reached)
    while frontier:
        hops = [f for f in flows if f.get("from") in frontier and _counted(f, data_tier) and f not in path]
        path.extend(hops)
        frontier = {f.get("to") for f in hops} - reached
        reached |= frontier
    return direct, path


def proven_anonymous(entity_id: str, flows: list[dict], data_tier: set) -> bool:
    direct, path = request_path(entity_id, flows, data_tier)
    if any(_scheme(f) not in _UNPROVEN for f in (*direct, *path)):
        return False
    return any(_scheme(f) == "none" for f in direct)


def system_proven_anonymous(document: dict, components: list) -> bool:
    """No request hop authenticates, no owner declared a login, and some role demonstrably reaches the system."""
    roles = _roles(document)
    if any(r.get("declared") and r.get("access") in AUTHENTICATED_ACCESS for r in roles):
        return False
    flows = _flows(document)
    data_tier = _data_tier(components)
    if any(_counted(f, data_tier) and _scheme(f) not in _UNPROVEN for f in flows):
        return False
    return any(proven_anonymous(r.get("id"), flows, data_tier) for r in roles)


def _declaration_line(lines: list[str], role_id: str) -> int:
    pattern = re.compile(r"^\s*(?:-\s*)?id:\s*[\"']?" + re.escape(role_id) + r"[\"']?\s*(?:#.*)?$")
    return next((n for n, text in enumerate(lines, 1) if pattern.match(text)), 0) or next(
        (n for n, text in enumerate(lines, 1) if role_id in text), 1
    )


def declared_roles(repo_root: Path) -> list[dict]:
    """Owner-declared legitimate roles with the declaration line as their evidence."""
    path = Path(repo_root) / DECLARATION_FILE
    if not path.is_file():
        return []
    import yaml
    from validate_intermediate import validate_actors_repo

    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    valid, errors = validate_actors_repo(data)
    if not valid:
        raise ValueError(f"invalid {DECLARATION_FILE}: {'; '.join(errors[:3])}")
    lines = text.splitlines()
    roles = []
    for row in data.get("legitimate_roles") or []:
        declared = {"source": DECLARATION_FILE}
        if row.get("authentication"):
            declared["authentication"] = row["authentication"]
        roles.append(
            {
                "id": row["id"],
                "name": row["name"],
                "kind": "legitimate-role",
                "access": row["access"],
                "description": row["description"],
                "evidence": [{"file": DECLARATION_FILE, "line": _declaration_line(lines, row["id"])}],
                "declared": declared,
            }
        )
    return roles


def apply_declared(document: dict, declared: list[dict]) -> tuple[dict, list[dict]]:
    """Return the document with declared roles applied and one receipt per role (replaced or added)."""
    result = copy.deepcopy(document)
    entities = result.setdefault("external_entities", [])
    by_id = {e.get("id"): e for e in entities if isinstance(e, dict)}
    receipts = []
    for role in declared:
        existing = by_id.get(role["id"])
        if existing is not None and existing.get("kind") != "legitimate-role":
            raise ValueError(f"{DECLARATION_FILE}: {role['id']} names a modelled {existing.get('kind')}, not a role")
        if existing is None:
            entities.append(copy.deepcopy(role))
            receipts.append({"entity_id": role["id"], "action": "added", "access": role["access"]})
            continue
        evidence = [row for row in existing.get("evidence") or [] if row not in role["evidence"]]
        existing.update(copy.deepcopy(role))
        existing["evidence"] = (role["evidence"] + evidence)[:8]
        receipts.append({"entity_id": role["id"], "action": "replaced", "access": role["access"]})
    return result, receipts


def reconcile(document: dict, components: list) -> tuple[dict, list[dict]]:
    """Return the data-flow document and one receipt per withdrawn access class."""
    result = copy.deepcopy(document)
    flows = _flows(result)
    data_tier = _data_tier(components)
    changes = []
    for entity in _roles(result):
        if entity.get("declared"):
            continue
        if entity.get("access") in AUTHENTICATED_ACCESS and proven_anonymous(entity.get("id"), flows, data_tier):
            changes.append({"entity_id": entity["id"], "from": entity["access"], "to": "internet-anon"})
            entity["access"] = "internet-anon"
    return result, changes
