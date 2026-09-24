"""Keep finding attribution within the access each actor group can use.

STRIDE analysts attribute a finding to resolved actors. A detection or audit
gap (``no_attacker_cwes``) has no attacker and keeps none. An attribution to an
access group that needs a specific foothold (a build pipeline, repository,
data-store or production access) stays only when the finding shows that
foothold; a finding in a request handler of an internet-exposed component
keeps an internet actor; a finding left without any actor gains the first valid
one. Of several internet actors only the least privileged stays: a finding a
regular account can exploit never names the privileged user as its attacker
(``superseded``). An inactive actor (disabled, or an opt-in class nobody enabled) never keeps
an attribution. The rules live in ``data/actor-attribution-rules.yaml`` and read only
component zones and tiers, CWEs, evidence paths, the deterministic route
inventory and the actors' declared access; never names or prose. The check
runs once after the merge so every report surface projects the same
attribution.
"""

from __future__ import annotations

import fnmatch
import json
import re
from functools import cache
from pathlib import Path

import yaml
from actor_presentation import actor_group
from emit_threat_vektors import _CWE_VEKTOR
from route_inventory import route_authenticated

RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "actor-attribution-rules.yaml"
# Setup files register every route; their name identifies no handler.
_GENERIC_STEMS = {"app", "index", "main", "server", "routes", "router", "urls", "views"}


@cache
def load_rules() -> dict:
    return yaml.safe_load(RULES_PATH.read_text(encoding="utf-8"))


def _cwe(value: object) -> str | None:
    match = re.search(r"(\d+)", str(value or ""))
    return f"CWE-{int(match[1])}" if match else None


def _finding_cwes(threat: dict) -> set[str]:
    values = threat.get("cwe")
    values = values if isinstance(values, list) else [values]
    return {cwe for cwe in map(_cwe, values) if cwe}


def _evidence_files(threat: dict) -> list[str]:
    rows = threat.get("evidence")
    rows = rows if isinstance(rows, list) else [rows]
    rows = [*rows, *(threat.get("instances") or [])]
    files = [str(row["file"]).removeprefix("./") for row in rows if isinstance(row, dict) and row.get("file")]
    return list(dict.fromkeys(files))


def _components(threat: dict) -> list[str]:
    ids = [
        threat.get("component_id") or threat.get("component"),
        *(threat.get("merged_from") or []),
        *(row.get("component_id") for row in threat.get("instances") or [] if isinstance(row, dict)),
    ]
    return list(dict.fromkeys(cid for cid in ids if isinstance(cid, str) and cid))


def _path_matches(path: str, patterns: list[str]) -> bool:
    name = path.rsplit("/", 1)[-1]
    for pattern in patterns:
        if "/" in pattern:
            if fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path, "*/" + pattern):
                return True
        elif fnmatch.fnmatchcase(name, pattern):
            return True
    return False


def _active(actor: dict) -> bool:
    return actor.get("active", (actor.get("_provenance") or {}).get("active", True)) is not False


class _Inventory:
    """Component zones and tiers plus route registrations for one merged model."""

    def __init__(self, components: list[dict], routes: dict | None):
        rows = [c for c in components if isinstance(c, dict) and c.get("id")]
        self.zones = {c["id"]: {str(z) for z in c.get("deployment_zones") or []} for c in rows}
        self.tiers = {c["id"]: str(c.get("tier") or "") for c in rows}
        self.routes = [r for r in (routes or {}).get("routes") or [] if isinstance(r, dict)]
        self.root = Path(str((routes or {}).get("repo_root") or "")).resolve() if routes else None
        self._lines: dict[str, list[str]] = {}

    def finding_zones(self, threat: dict) -> set[str]:
        return set().union(*(self.zones.get(cid, set()) for cid in _components(threat)))

    def registration_line(self, route: dict) -> str:
        """The source line that registers a route, read only inside the inventory's repository root."""
        file, line = route.get("handler_file"), route.get("handler_line")
        if not self.root or not isinstance(file, str) or not isinstance(line, int):
            return ""
        if file not in self._lines:
            path = (self.root / file).resolve()
            try:
                inside = path.is_relative_to(self.root) and path.is_file()
                self._lines[file] = path.read_text(encoding="utf-8", errors="replace").splitlines() if inside else []
            except OSError:
                self._lines[file] = []
        lines = self._lines[file]
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def handler_routes(self, threat: dict) -> list[dict]:
        """Routes whose handler is an evidence file: declared there, resolved to it through imports, or called by its file name where registered."""
        linked = []
        for file in _evidence_files(threat):
            stem = Path(file).stem
            call = (
                re.compile(rf"\b{re.escape(stem)}\s*\(")
                if len(stem) > 3 and stem.lower() not in _GENERIC_STEMS
                else None
            )
            for route in self.routes:
                if (
                    route.get("handler_file") == file
                    or route.get("handler_module") == file
                    or (call and call.search(self.registration_line(route)))
                ):
                    if route not in linked:
                        linked.append(route)
        return linked


def _valid(threat: dict, actor: dict, inventory: _Inventory) -> bool:
    """Apply the group's rule; an unrestricted group is always valid."""
    rules = load_rules()
    rule = rules["restricted_groups"].get(actor_group(actor))
    if rule is None:
        return True
    zones = inventory.finding_zones(threat)
    if zones & set(rule.get("component_zones") or []):
        return True
    if rule.get("component_zones_from_actor_access") and zones & set(actor.get("access") or []):
        return True
    if any(inventory.tiers.get(cid) in (rule.get("component_tiers") or []) for cid in _components(threat)):
        return True
    cwes = _finding_cwes(threat)
    if cwes & set(rule.get("cwes") or []):
        return True
    if rule.get("repository_content") and any(_CWE_VEKTOR.get(cwe) == "repo-read" for cwe in cwes):
        return True
    patterns = [p for key in rule.get("evidence_paths") or [] for p in rules["evidence_paths"][key]]
    return any(_path_matches(path, patterns) for path in _evidence_files(threat))


def _ordered(actors: list[dict], groups: list[str]) -> list[dict]:
    order = {group: index for index, group in enumerate(groups)}
    return sorted(
        (a for a in actors if _active(a) and actor_group(a) in order),
        key=lambda a: (order[actor_group(a)], a["id"]),
    )


def _route_actor(threat: dict, actors: list[dict], inventory: _Inventory) -> str | None:
    """The internet actor a request handler on an exposed component must keep."""
    rules = load_rules()
    component = threat.get("component_id") or threat.get("component")
    if not inventory.zones.get(component, set()) & set(rules["exposed_zones"]):
        return None
    routes = inventory.handler_routes(threat)
    if not routes:
        return None
    authenticated = all(route_authenticated(route) for route in routes)
    internet = rules["internet_groups"]
    preferred = ["internet-user", *internet] if authenticated else internet
    candidates = _ordered(actors, list(dict.fromkeys(preferred)))
    return candidates[0]["id"] if candidates else None


def _fallback(threat: dict, actors: list[dict], inventory: _Inventory) -> str | None:
    """The first active actor whose attribution is valid and whose access reaches the finding."""
    restricted = load_rules()["restricted_groups"]
    zones = inventory.finding_zones(threat)
    for actor in _ordered(actors, load_rules()["fallback_order"]):
        if actor_group(actor) in restricted:
            if _valid(threat, actor, inventory):
                return actor["id"]
        elif zones & set(actor.get("access") or []):
            return actor["id"]
    return None


def reconcile_attribution(
    threats: list[dict], components: list[dict], actors: list[dict], routes: dict | None = None
) -> list[dict]:
    """Correct attributions in place and return one record per changed finding."""
    inventory = _Inventory(components, routes)
    by_id = {a["id"]: a for a in actors if isinstance(a, dict) and a.get("id")}
    internet = set(load_rules()["internet_groups"])
    no_attacker = set(load_rules().get("no_attacker_cwes") or [])
    corrections = []
    for threat in threats:
        ids = [aid for aid in threat.get("actor_ids") or [] if isinstance(aid, str)]
        attackerless = bool(_finding_cwes(threat) & no_attacker)
        removed = [
            aid
            for aid in ids
            if attackerless or (aid in by_id and (not _active(by_id[aid]) or not _valid(threat, by_id[aid], inventory)))
        ]
        kept = [aid for aid in ids if aid not in removed]
        added = []
        if not attackerless:
            kept_internet = [aid for aid in kept if aid in by_id and actor_group(by_id[aid]) in internet]
            route_actor = _route_actor(threat, list(by_id.values()), inventory)
            if not kept_internet:
                added += [route_actor] if route_actor else []
            elif route_actor and actor_group(by_id[route_actor]) != "internet-anon":
                # Every linked route authenticates, so no anonymous request reaches the handler.
                anonymous = [aid for aid in kept_internet if actor_group(by_id[aid]) == "internet-anon"]
                if anonymous:
                    removed += anonymous
                    kept = [aid for aid in kept if aid not in anonymous]
                    added += [route_actor] if route_actor not in kept else []
        if not attackerless and not kept and not added:
            fallback = _fallback(threat, list(by_id.values()), inventory)
            added += [fallback] if fallback else []
        superseded = _superseded(kept + added, by_id)
        if not removed and not added and not superseded:
            continue
        threat["actor_ids"] = [aid for aid in kept + added if aid not in superseded]
        if threat.get("primary_actor") not in threat["actor_ids"]:
            threat["primary_actor"] = threat["actor_ids"][0] if threat["actor_ids"] else None
        correction = {
            "finding": threat.get("t_id") or threat.get("id"),
            "removed": removed,
            "added": added,
            "actor_ids": threat["actor_ids"],
        }
        if superseded:
            correction["superseded"] = superseded
        corrections.append(correction)
    return corrections


def reconcile_output_dir(out_dir: Path, threats: list[dict]) -> list[dict]:
    """Apply the rules against the run's component registry, resolved actors and route inventory.

    Called after the merge and again for findings whose provisional scanner
    owner was resolved later: a guessed component has no zones, so a route
    finding would otherwise never gain its internet actor.
    """

    def read(name: str) -> dict:
        try:
            data = json.loads((out_dir / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    components = read(".components.json").get("components") or []
    actors = read(".actors-resolved.json").get("resolved_actors") or []
    if not components or not actors:
        return []
    return reconcile_attribution(threats, components, actors, read(".route-inventory.json") or None)


def merge_corrections(existing: list[dict], new: list[dict]) -> list[dict]:
    """One record per finding; a later pass replaces the finding's current attribution."""
    merged = {row.get("finding"): dict(row) for row in existing or [] if isinstance(row, dict)}
    for row in new:
        prior = merged.get(row["finding"])
        if prior is None:
            merged[row["finding"]] = row
            continue
        for key in ("removed", "added", "superseded"):
            values = list(dict.fromkeys([*(prior.get(key) or []), *(row.get(key) or [])]))
            if values or key != "superseded":
                prior[key] = values
        prior["actor_ids"] = row["actor_ids"]
    return list(merged.values())


def _superseded(ids: list[str], by_id: dict[str, dict]) -> list[str]:
    """Internet actors above the least privileged one that can already exploit the finding.

    `internet_groups` is ordered by privilege; a higher group adds no capability,
    so it would only surface as a second attacker for the same finding.
    """
    order = {group: index for index, group in enumerate(load_rules()["internet_groups"])}
    ranks = {aid: order[actor_group(by_id[aid])] for aid in ids if aid in by_id and actor_group(by_id[aid]) in order}
    return [aid for aid, rank in ranks.items() if rank > min(ranks.values())] if ranks else []
