#!/usr/bin/env python3
"""Resolve open registration before actor reach equivalence.

Supporting recon evidence or a registration POST establishes openness.
Generic account routes additionally need AUTHZ-008 at the same source location.
Management and role-gated routes never supply this signal. Unresolved
candidates remain separate actors and produce a team question.

The emitter preserves canonical actor resolution and operator pins. Its
fallback uses the same resolver for runs without actor resolution.
"""

from __future__ import annotations

import json
import re
import sys
from functools import cache
from pathlib import Path

import yaml
from _path_guard import is_safe_to_read
from jsonschema import Draft202012Validator

# Patterns that mark a route as user-registration. Case-insensitive.
# Anchored loosely — `/api/v2/users` should match `/users`.
_REGISTRATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bregister\b", re.IGNORECASE),
    re.compile(r"\bsign[-_]?up\b", re.IGNORECASE),
    re.compile(r"/sign[-_]?up\b", re.IGNORECASE),
    re.compile(r"/users?\s*$", re.IGNORECASE),  # POST /users, /api/users
    re.compile(r"/accounts?\s*$", re.IGNORECASE),
    re.compile(r"/users?/create", re.IGNORECASE),
    re.compile(r"/auth/(register|signup)\b", re.IGNORECASE),
]


def _is_registration_entry(entry_point: str) -> bool:
    if not entry_point:
        return False
    # Strip the HTTP method prefix if present so the regex sees the URL.
    parts = entry_point.split(None, 1)
    url = parts[1] if len(parts) == 2 else entry_point
    # Only consider POST (or unspecified method).
    method = (parts[0] if len(parts) == 2 else "").upper()
    if method and method != "POST":
        return False
    return any(p.search(url) for p in _REGISTRATION_PATTERNS)


# authz_signal values from route_inventory.py that denote an explicit role
# gate (decorator / middleware). Their presence on a `/users`-shaped POST is
# the signal that the route is an *admin* create-user endpoint, not public
# self-registration — so it must NOT count as open registration. Anything
# else ("unknown", "none", absent) is treated as no role gate.
_AUTHZ_GATE_SIGNALS = {"present", "decorator_present", "middleware_present"}
_EXPLICIT_REGISTRATION = re.compile(r"(?:^|/)(?:register|sign[-_]?up)(?:/|$)", re.I)


def _registration_candidate(route: dict) -> bool:
    """An account-shaped POST without an observed management or role gate."""
    if str(route.get("method", "")).upper() != "POST":
        return False
    if not _is_registration_entry(str(route.get("path", "") or "")):
        return False
    if route.get("management_surface"):
        return False
    if str(route.get("authz_signal", "") or "") in _AUTHZ_GATE_SIGNALS:
        return False
    return True


def _location(file, line) -> dict | None:
    """Accept only explicit repository-relative file/line identities."""
    if (
        not isinstance(file, str)
        or not file
        or file.startswith("/")
        or "\\" in file
        or any(part in {"", ".", ".."} for part in file.split("/"))
        or ":" in file
        or not isinstance(line, int)
        or isinstance(line, bool)
        or line < 1
    ):
        return None
    return {"file": file, "line": line}


def resolve_open_registration(signal_doc: dict, routes: list, source_auth_findings: list) -> dict:
    """Combine validated inputs without mutating the recon document.

    Authentication middleware presence is not itself proof of a login gate.
    Explicit registration semantics or an exact missing-auth finding
    disambiguates a POST; a generic user endpoint alone remains disputed.
    This is an access prerequisite, not a finding or a severity adjustment.
    """
    signal = (signal_doc.get("signal_evidence") or {}).get("has_open_self_registration") or {}
    recon_locations = [
        location
        for row in signal.get("locations") or []
        if isinstance(row, dict)
        if (location := _location(row.get("file"), row.get("line"))) is not None
    ]

    def result(opened, disputed, reason, evidence):
        unique = {(row["file"], row["line"]): row for row in evidence}
        return {
            "open": opened,
            "disputed": disputed,
            "reason": reason,
            "evidence": [unique[key] for key in sorted(unique)][:8],
        }

    if (
        (signal_doc.get("signals") or {}).get("has_open_self_registration") is True
        and signal.get("status") == "supporting"
        and recon_locations
    ):
        return result(True, False, "recon-supporting", recon_locations)
    matched = {
        (location["file"], location["line"])
        for finding in source_auth_findings
        if isinstance(finding, dict) and finding.get("check_id") == "AUTHZ-008"
        if (location := _location(finding.get("file"), finding.get("line"))) is not None
    }
    explicit, corroborated, candidates = [], [], []
    for route in routes:
        if not isinstance(route, dict) or not _registration_candidate(route):
            continue
        location = _location(route.get("handler_file"), route.get("handler_line"))
        if location is None:
            continue
        if _EXPLICIT_REGISTRATION.search(route["path"]):
            explicit.append(location)
        elif (location["file"], location["line"]) in matched:
            corroborated.append(location)
        else:
            candidates.append(location)
    if explicit:
        return result(True, False, "explicit-registration-post", explicit)
    if corroborated:
        return result(True, False, "authz-008-route", corroborated)
    if signal.get("status") == "candidate":
        candidates.extend(recon_locations)
    if candidates:
        return result(False, True, "unresolved-candidate", candidates)
    return result(False, False, "not-established", [])


@cache
def _input_validator(filename: str):
    schema = yaml.safe_load((Path(__file__).resolve().parents[1] / "schemas" / filename).read_text())
    return Draft202012Validator(schema)


def load_registration_inputs(output_dir: Path, repo_root: Path | None = None) -> tuple[list, list]:
    """Read optional scanner artifacts through their schemas and path guards."""
    from validate_fragment import repository_evidence_errors

    values = []
    for name, schema, key in (
        (".route-inventory.json", "route-inventory.schema.json", "routes"),
        (".source-auth-findings.json", "source-auth-findings.schema.yaml", "findings"),
    ):
        path = output_dir / name
        rows = []
        if is_safe_to_read(path, output_dir):
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
                if not _input_validator(schema).is_valid(doc) or "parse_error" in doc:
                    raise ValueError("invalid scanner artifact")
                for row in doc[key]:
                    loc = _location(row.get("handler_file", row.get("file")), row.get("handler_line", row.get("line")))
                    if loc and (
                        repo_root is None or not repository_evidence_errors([loc], repo_root, require_line=True)
                    ):
                        rows.append(row)
            except (ValueError, OSError) as exc:
                print(f"open registration: ignored {name}: {exc}", file=sys.stderr)
        values.append(rows)
    return values[0], values[1]


def overview_actor_slug(slug: str, meta: dict) -> str:
    """Project reach-equivalent actors for display, retaining privileged access."""
    if slug == "internet-user" and meta.get("open_user_registration") is True:
        return "internet-anon"
    if slug == "repo-read" and meta.get("public_source_repo") is True:
        return "internet-anon"
    return slug


def overview_actor_groups(
    yaml_data: dict, attack_paths_data: dict | None = None, attack_taxonomy: dict | None = None
) -> list[tuple[str, str]]:
    """Return source/target actor slugs for represented, evidence-backed folds.

    Finding vectors retain the original prerequisites after path actors have
    been projected. Consult only referenced findings when rendering a figure,
    so an unrelated finding cannot introduce a grouping explanation there.
    """
    meta = yaml_data.get("meta") or {}
    threats = [t for t in yaml_data.get("threats") or [] if isinstance(t, dict)]
    sources = set()
    if attack_paths_data is not None:
        paths = [p for p in attack_paths_data.get("attack_paths") or [] if isinstance(p, dict)]
        classes = {c.get("id"): c for c in (attack_taxonomy or {}).get("classes") or []}
        refs = set()
        for path in paths:
            actor = path.get("actor") or (classes.get(path.get("class")) or {}).get("default_actor") or "internet-anon"
            sources.add(actor)
            if overview_actor_slug(actor, meta) == "internet-anon":
                refs.update(
                    str(fid).upper().removeprefix("F-").removeprefix("T-") for fid in path.get("findings") or []
                )
        threats = [
            t
            for t in threats
            if str(t.get("id") or t.get("t_id") or "").upper().removeprefix("F-").removeprefix("T-") in refs
        ]
    sources.update(t.get("vektor") for t in threats)
    if yaml_data.get("actors"):
        from actor_presentation import projected_paths

        paths = attack_paths_data
        if paths is None:
            paths = {
                "attack_paths": [
                    {"actor": t.get("vektor") or "internet-anon", "findings": [t.get("id") or t.get("t_id")]}
                    for t in threats
                ]
            }
        sources = {p["actor"] for _, p in projected_paths(yaml_data, paths, attack_taxonomy or {})}

    return [
        (source, overview_actor_slug(source, meta))
        for source in ("internet-user", "repo-read")
        if source in sources and overview_actor_slug(source, meta) != source
    ]


def overview_actor_notes(
    yaml_data: dict, attack_paths_data: dict | None = None, attack_taxonomy: dict | None = None
) -> list[str]:
    """Explain the same actor folds in report prose and legacy diagrams."""
    groups = dict(overview_actor_groups(yaml_data, attack_paths_data, attack_taxonomy))
    notes = []
    if "internet-user" in groups:
        notes.append(
            "Regular self-registered users are grouped with anonymous internet attackers because registration is open."
        )
    if "repo-read" in groups:
        notes.append(
            "Repository readers are grouped with anonymous internet attackers because the source repository is public."
        )
    if notes:
        notes.append("Each finding retains its login and privilege requirements.")
    return notes


def detect(yaml_data: dict, routes: list | None = None, source_auth_findings: list | None = None) -> tuple[bool, str]:
    """Return the canonical decision, or apply the same owner to legacy inputs."""
    meta = yaml_data.get("meta") or {}
    if not isinstance(meta, dict):
        meta = {}
    pinned = meta.get("open_user_registration_pinned")
    if isinstance(pinned, bool):
        return pinned, f"pinned in meta (operator override = {pinned})"
    if meta.get("open_registration_source") == "actor-resolution" and isinstance(
        meta.get("open_user_registration"), bool
    ):
        return meta["open_user_registration"], "validated actor reach equivalence"

    resolution = resolve_open_registration({}, routes or [], source_auth_findings or [])
    # Historical models without an actor artifact retain their curated surface
    # fallback. Current runs always consume the authoritative resolution above.
    for entry in yaml_data.get("attack_surface") or []:
        if (
            isinstance(entry, dict)
            and _is_registration_entry(entry.get("entry_point") or "")
            and not entry.get("auth_required")
        ):
            return True, f"unauthenticated registration route: {entry['entry_point']}"
    return resolution["open"], (
        resolution["reason"]
        if resolution["open"] or resolution["disputed"]
        else "no unauthenticated registration route established"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: detect_open_registration.py <output_dir>", file=sys.stderr)
        return 2
    yaml_path = Path(argv[0]) / "threat-model.yaml"
    if not yaml_path.is_file():
        print(f"detect_open_registration: no yaml at {yaml_path}", file=sys.stderr)
        return 1
    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        print(f"detect_open_registration: parse failed: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        return 1

    routes, findings = load_registration_inputs(Path(argv[0]))
    open_reg, reason = detect(data, routes, findings)
    meta = data.setdefault("meta", {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    meta["open_user_registration"] = open_reg
    data["meta"] = meta

    yaml_path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=4096, default_flow_style=False),
        encoding="utf-8",
    )
    print(f"detect_open_registration: open_user_registration={open_reg}  ({reason})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
