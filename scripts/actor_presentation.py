"""Project explicit finding attribution onto bounded overview access groups.

Roles never create diagram nodes. Each path retains its number while separate
access groups retain their own finding subset. No projection mutates analysis
data or infers an actor from a role's name, access, or capabilities.
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path

import yaml
from detect_open_registration import overview_actor_slug


@cache
def default_groups() -> dict[str, str]:
    data = yaml.safe_load((Path(__file__).resolve().parent.parent / "data/actor-id-to-heatmap-slug.yaml").read_text())
    return data["mappings"]


@cache
def _posture_labels() -> dict[str, dict]:
    data = yaml.safe_load((Path(__file__).resolve().parent.parent / "data/posture-actor-labels.yaml").read_text())
    return data["actors"]


@cache
def display_groups() -> frozenset[str]:
    return frozenset(_posture_labels())


# Names for access groups without an entry in data/posture-actor-labels.yaml.
FALLBACK_ACTOR_LABELS = {
    "internet-anon": "Anonymous Internet Attacker",
    "internet-user": "Authenticated Internet Attacker",
    "internet-priv-user": "Privileged User",
    "repo-read": "Source-Code Reader",
    "supply-chain": "Supply-Chain Attacker",
    "build-time": "Supply-Chain / Build Attacker",
    "malicious-insider": "Malicious Insider",
    "insider": "Malicious Insider",
    "developer": "Developer",
    "b2b-partner": "B2B Partner",
}


def attacker_display(slug: str | None, meta: dict | None, labels: dict | None = None) -> tuple[str, str]:
    """Name and subtitle of an attacker access group, identical in every figure, table and legend.

    The slug is projected through the canonical reach equivalence first, so a
    self-registered user or a public-source reader carries the name of the
    group it is drawn in. `labels` overrides the plugin label vocabulary.
    """
    meta = meta or {}
    slug = overview_actor_slug((slug or "internet-anon").strip(), meta)
    if slug == "internet-anon" and meta.get("open_user_registration") is True:
        return "Internet Attacker", "can self-register a regular account"
    entry = (_posture_labels() if labels is None else labels).get(slug) or {}
    return entry.get("label") or FALLBACK_ACTOR_LABELS.get(slug) or slug, entry.get("default_subtitle") or ""


def actor_group(actor: dict) -> str | None:
    """Use declared presentation metadata, or the plugin's default ID map."""
    slug = actor.get("heatmap_slug")
    if not slug:
        aid = str(actor.get("id") or "")
        match = re.fullmatch(r"ACT-D-(\d+)", aid)
        slug = default_groups().get(f"ACT-D-{int(match[1]):02d}") if match else None
    return slug if slug in display_groups() else None


def finding_group(actor: dict, threat: dict) -> str | None:
    """An insider reading committed repository content needs only repository read access (RA-10)."""
    slug = actor_group(actor)
    return "repo-read" if slug == "insider" and threat.get("vektor") == "repo-read" else slug


def export_actors(resolution: dict) -> list[dict]:
    """Keep the validated actor inventory readable after runtime cleanup."""
    return [
        {
            "id": a["id"],
            "label": a["label"],
            "access": a["access"],
            "trust_positions": a.get("trust_positions", []),
            "heatmap_slug": actor_group(a),
            "active": a.get("_provenance", {}).get("active", True),
            "origin": a.get("_provenance", {}).get("layer") or actor_origin(a),
        }
        for a in resolution.get("resolved_actors", [])
    ]


def actor_origin(actor: dict) -> str:
    """Preserve layer provenance, with the contracted ID namespace as fallback."""
    if actor.get("origin"):
        return actor["origin"]
    prefix = str(actor.get("id") or "").split("-")
    return {"R": "repo", "E": "enterprise", "X": "discovery"}.get(prefix[1] if len(prefix) > 1 else "", "plugin")


def inventory_actors(model: dict) -> list[dict]:
    """Show declared roles, plus active automatic roles with finding attribution.

    The discovery catalogue is analysis input, not a list of report conclusions.
    Unused default/discovered personas must not return through the detail table.
    """
    linked = {aid for threat in model.get("threats", []) for aid in threat.get("actor_ids") or []}
    return [
        actor
        for actor in model.get("actors", [])
        if actor_origin(actor) in {"repo", "enterprise"} or (actor.get("active", True) and actor["id"] in linked)
    ]


def finding_id(value: object) -> str:
    value = str(value or "").upper()
    return "F-" + value[2:] if re.fullmatch(r"[FT]-\d+", value) else value


def attributed_actors(model: dict, threat: dict) -> list[dict]:
    ids = set(threat.get("actor_ids") or [])
    # A primary actor must also belong to the finding's explicit actor set.
    actors = [a for a in model.get("actors", []) if a.get("active", True) and a["id"] in ids]
    return sorted(actors, key=lambda a: (a["id"] != threat.get("primary_actor"), a["id"]))


def path_groups(model: dict, path: dict, default: str = "internet-anon") -> list[dict]:
    """Return access groups and only the findings attributed to each group.

    Unattributed legacy findings retain the authored category. Missing custom
    mappings do not invent authenticated access. Victim categories retain their
    separate interaction meaning and are never inferred as attacker privileges.
    """
    threats = {finding_id(t.get("id") or t.get("t_id")): t for t in model.get("threats", [])}
    groups: dict[str, dict] = {}
    fallback = path.get("actor") or default
    for ref in path.get("findings") or []:
        threat = threats.get(finding_id(ref), {})
        actors = attributed_actors(model, threat)
        pairs = [(finding_group(a, threat), a["id"]) for a in actors if actor_group(a)]
        if not pairs:
            pairs = [(fallback, None)]
        for slug, aid in pairs:
            group = groups.setdefault(slug, {"actor": slug, "findings": [], "actor_ids": []})
            if ref not in group["findings"]:
                group["findings"].append(ref)
            if aid and aid not in group["actor_ids"]:
                group["actor_ids"].append(aid)
    return list(groups.values()) or [{"actor": fallback, "findings": [], "actor_ids": []}]


def projected_paths(model: dict, paths: dict, taxonomy: dict):
    """Yield numbered in-memory views; never persist an expanded fragment."""
    classes = {c["id"]: c for c in taxonomy.get("classes", [])}
    for number, path in enumerate(paths.get("attack_paths", []), 1):
        default = classes.get(path.get("class"), {}).get("default_actor") or "internet-anon"
        for group in path_groups(model, path, default):
            yield number, {**path, **group, "_victim_required": (path.get("actor") or default) == "victim-required"}


def represented_role_counts(model: dict, paths: dict, taxonomy: dict) -> dict[str, int]:
    roles: dict[str, set[str]] = {}
    for _, path in projected_paths(model, paths, taxonomy):
        raw = path["actor"]
        slug = overview_actor_slug("internet-anon" if raw == "victim-required" else raw, model.get("meta", {}))
        roles.setdefault(slug, set()).update(path["actor_ids"])
    return {slug: len(ids) for slug, ids in roles.items() if ids}
