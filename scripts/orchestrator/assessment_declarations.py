"""Repository-owned declarations in a combined multi-repository assessment.

A selected repository may carry ``.appsec/trust-boundaries.yaml``,
``.appsec/actors.yaml`` and ``docs/related-repos.yaml``. Their content is
untrusted data owned by that repository. Each file is validated with its
single-repository contract, stays attached to its owner and is namespaced so
two repositories cannot collide. A declaration may add or clarify; it never
confirms a control, never reaches another repository's components and never
adds a source root. A declaration that cannot be represented faithfully stops
the run with a message that names the file.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import yaml
from contexts import build_cross_repo_register, load_related_repos
from contexts.prepare_trust_boundary_context import REPO_SCHEMA, _resolve_endpoint
from jsonschema import Draft202012Validator
from model import resolve_actors
from runtime.multi_repo_scope import ScopeError, _git, _masked_bytes, _relative
from shared._atomic_io import atomic_write_json
from validators.validate_assessment_architecture import AssessmentArchitectureError, validate_source
from validators.validate_intermediate import (
    validate_actors_merged_static,
    validate_actors_repo,
    validate_actors_resolved,
)

from orchestrator.assessment_workspace import Namespaces

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
BOUNDARY_FILE = ".appsec/trust-boundaries.yaml"
ACTOR_FILE = ".appsec/actors.yaml"
RELATED_FILE = "docs/related-repos.yaml"
_ACTOR_ID = re.compile(r"^ACT-([DERX])-([0-9]{1,4})$")


class DeclarationError(ValueError):
    """A repository declaration cannot be represented in the combined assessment."""


def _declaring(scope, names: Namespaces, path: str):
    repos = sorted(scope.repositories, key=lambda row: names.prefix[row.repository_id])
    return [(names.prefix[repo.repository_id], repo) for repo in repos if path in repo.files]


def _load(label: str, repo, path: str):
    try:
        return yaml.safe_load(_masked_bytes(repo.files[path]).decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise DeclarationError(f"{label}/{path} is not valid YAML") from None


def _slugs(names: Namespaces) -> dict[str, str]:
    """A key-safe prefix per repository, unique even when labels slug alike."""
    base = {
        rid: re.sub(r"[^a-z0-9]+", "-", label.casefold()).strip("-")[:32].strip("-") or "repo"
        for rid, label in names.prefix.items()
    }
    counts = Counter(base.values())
    return {rid: slug if counts[slug] == 1 else f"{slug}-{rid[-6:]}" for rid, slug in base.items()}


# ---------------------------------------------------------------------------
# Trust-boundary declarations
# ---------------------------------------------------------------------------


def _boundary_documents(scope, names: Namespaces) -> list[tuple[str, object, dict, str]]:
    schema = Draft202012Validator(yaml.safe_load(REPO_SCHEMA.read_text(encoding="utf-8")))
    slugs = _slugs(names)
    documents, keys = [], set()
    for label, repo in _declaring(scope, names, BOUNDARY_FILE):
        data = _load(label, repo, BOUNDARY_FILE)
        error = next(iter(sorted(schema.iter_errors(data), key=lambda e: list(e.absolute_path))), None)
        if error is not None:
            raise DeclarationError(f"{label}/{BOUNDARY_FILE} violates its schema: {error.message[:200]}")
        own = [row["key"] for row in data["boundaries"]]
        if len(own) != len(set(own)):
            raise DeclarationError(f"{label}/{BOUNDARY_FILE} declares a boundary key twice")
        prefix = slugs[repo.repository_id]
        for key in own:
            qualified = f"{prefix}-{key}"
            if len(qualified) > 80 or qualified in keys:
                raise DeclarationError(
                    f"{label}/{BOUNDARY_FILE} key {key!r} has no unique repository-namespaced form of 80 characters"
                )
            keys.add(qualified)
        documents.append((label, repo, data, prefix))
    return documents


def declaration_summary(scope) -> dict:
    """Status, fingerprint and namespaced keys for the boundary assessment input."""
    documents = _boundary_documents(scope, Namespaces(scope))
    if not documents:
        return {"status": "missing", "fingerprint": None, "keys": []}
    owned = [[repo.repository_id, hashlib.sha256(repo.files[BOUNDARY_FILE]).hexdigest()] for _, repo, _, _ in documents]
    digest = hashlib.sha256(json.dumps(sorted(owned), separators=(",", ":")).encode()).hexdigest()
    keys = [f"{prefix}-{row['key']}" for _, _, data, prefix in documents for row in data["boundaries"]]
    return {"status": "present", "fingerprint": "sha256:" + digest, "keys": keys[:200]}


def _boundary_endpoint(label: str, key: str, value: str, own: dict, foreign: dict) -> str:
    if _resolve_endpoint(value, {})[0] == "external":
        return "external"
    by_local = [cid for cid, card in own.items() if card.get("local_id") == value]
    if len(by_local) == 1:
        return by_local[0]
    resolved, method, _ = _resolve_endpoint(value, own)
    if method in {"exact_id", "component_name"}:
        return resolved
    where = f"{label}/{BOUNDARY_FILE} boundary {key!r}"
    if method == "ambiguous" or len(by_local) > 1:
        raise DeclarationError(f"{where} names more than one component of {label}")
    if any(card.get("local_id") == value for card in foreign.values()) or _resolve_endpoint(value, foreign)[1] in {
        "exact_id",
        "component_name",
        "ambiguous",
    }:
        raise DeclarationError(f"{where} names a component of another repository; a declaration covers only its own")
    raise DeclarationError(f"{where} names no component of {label}")


def _boundary_evidence(scope, label: str, key: str, repo, item: dict) -> dict:
    path = item["file"]
    data = repo.files.get(path)
    row = {
        "repository_id": repo.repository_id,
        "file": path,
        # The repository contract permits a file-level citation.
        "line": item.get("line", 1),
        "sha256": hashlib.sha256(data).hexdigest() if data is not None else "",
    }
    try:
        validate_source(scope, row, path_key="file")
    except (AssessmentArchitectureError, ScopeError):
        raise DeclarationError(
            f"{label}/{BOUNDARY_FILE} boundary {key!r} cites evidence that is not a captured line of {label}"
        ) from None
    return row


def boundary_declarations(scope, components: dict) -> list[dict]:
    """Qualified declaration rows for ``promote_assessment_boundaries``.

    Endpoints resolve only against the declaring repository's components; the
    normalizer still marks every declared row ``repo-declared`` and inferred.
    """
    names = Namespaces(scope)
    cards = components["components"]
    rows = []
    for label, repo, data, prefix in _boundary_documents(scope, names):
        own = {card["id"]: card for card in cards if card["repository_ids"] == [repo.repository_id]}
        foreign = {card["id"]: card for card in cards if card["id"] not in own}
        for raw in data["boundaries"]:
            key = raw["key"]
            row = {
                "key": f"{prefix}-{key}",
                "name": raw["name"],
                "from": _boundary_endpoint(label, key, raw["from"], own, foreign),
                "to": _boundary_endpoint(label, key, raw["to"], own, foreign),
                "kind": raw["kind"],
                "assumption": raw["assumption"],
            }
            if raw.get("assumption_legs"):
                row["assumption_legs"] = copy.deepcopy(raw["assumption_legs"])
            if raw.get("evidence"):
                row["evidence"] = [_boundary_evidence(scope, label, key, repo, item) for item in raw["evidence"]]
            rows.append(row)
    return rows


# ---------------------------------------------------------------------------
# Actor configuration
# ---------------------------------------------------------------------------


def _free_actor_id(actor_id: str, taken: set[str]) -> str:
    kind = _ACTOR_ID.fullmatch(actor_id).group(1)
    number = 1
    while f"ACT-{kind}-{number:03d}" in taken:
        number += 1
    if number > 9999:
        raise DeclarationError("No free repository actor ID remains for a namespaced actor")
    return f"ACT-{kind}-{number:03d}"


def _actor_evidence(label: str, evidence: dict) -> dict:
    files = []
    for value in evidence.get("files") or []:
        try:
            _relative(value)
        except ScopeError:
            raise DeclarationError(f"{label}/{ACTOR_FILE} cites an actor evidence path outside {label}") from None
        files.append(f"{label}/{value}")
    return {**evidence, "files": files} if "files" in evidence else dict(evidence)


def _namespaced_actor(actor: dict, label: str, slug: str) -> dict:
    if isinstance(actor.get("label"), str):
        actor["label"] = f"{actor['label']}-{slug}"[:63].rstrip("-")
    if isinstance(actor.get("name"), str):
        actor["name"] = f"{actor['name']} ({label})"
    return actor


def actor_declarations(scope, names: Namespaces) -> dict | None:
    """Merge every repository's actor configuration into one resolver input.

    A repository actor ID declared by several repositories stays distinct: the
    first repository by label keeps the ID, the others receive a free ID of
    the same class, and every copy names its owner. An override of a shared
    default actor applies when the overriding repositories agree. Settings
    that remove analysis (a disable, ``inherit_org: false``, disabled
    discovery) apply only when every selected repository declares them.
    """
    files = []
    for label, repo in _declaring(scope, names, ACTOR_FILE):
        data = _load(label, repo, ACTOR_FILE)
        valid, errors = validate_actors_repo(data)
        if not valid:
            raise DeclarationError(f"{label}/{ACTOR_FILE} violates its schema: {'; '.join(errors[:3])[:300]}")
        files.append((label, repo.repository_id, data))
    if not files:
        return None
    selected = len(scope.repositories)
    slugs = _slugs(names)
    defaults = {actor["id"] for actor in resolve_actors.load_plugin_defaults(str(PLUGIN_ROOT))}
    declared = Counter(a["id"] for _, _, data in files for a in data.get("actors") or [] if a["id"] not in defaults)
    taken = set(defaults) | set(declared)
    for _, _, data in files:
        taken |= {row if isinstance(row, str) else row["id"] for row in data.get("disable") or []}
        taken |= set(data.get("enable") or [])

    actors: dict[str, dict] = {}
    owners: dict[str, list[str]] = {}
    overrides: dict[str, dict] = {}
    receipts: list[str] = []
    disables: dict[str, list[tuple[str, str | None]]] = {}
    applied_disables: list[dict] = []
    enable: list[str] = []
    for label, rid, data in files:
        mapping: dict[str, str] = {}
        owned: set[str] = set()
        for raw in data.get("actors") or []:
            actor = copy.deepcopy(raw)
            if "evidence" in actor:
                actor["evidence"] = _actor_evidence(label, actor["evidence"])
            actor_id = raw["id"]
            if actor_id in defaults:
                plain = {k: v for k, v in raw.items() if k != "evidence"}
                if actor_id in overrides and overrides[actor_id] != plain:
                    raise DeclarationError(
                        f"{', '.join(owners[actor_id])} and {label} override default actor {actor_id} differently "
                        f"in {ACTOR_FILE}; a combined assessment cannot apply both"
                    )
                overrides[actor_id] = plain
                if actor_id in actors and "evidence" in actor:
                    previous = actors[actor_id].setdefault("evidence", dict(actor["evidence"], files=[]))
                    previous["files"] = previous.get("files", []) + actor["evidence"].get("files", [])
                else:
                    actors.setdefault(actor_id, actor)
                owners.setdefault(actor_id, []).append(label)
                continue
            if declared[actor_id] > 1:
                actor = _namespaced_actor(actor, label, slugs[rid])
                if actor_id in actors:
                    actor["id"] = _free_actor_id(actor_id, taken)
                    taken.add(actor["id"])
                    receipts.append(
                        f"actors: {label} declares {actor_id} like another repository; assessed as {actor['id']}"
                    )
            mapping[actor_id] = actor["id"]
            owned.add(actor["id"])
            actors[actor["id"]] = actor
            owners[actor["id"]] = [label]
        for row in data.get("disable") or []:
            raw_id, reason = (row, None) if isinstance(row, str) else (row["id"], row.get("reason"))
            actor_id = mapping.get(raw_id, raw_id)
            if actor_id in owned:
                applied_disables.append({"id": actor_id, "reason": reason})
            elif actor_id in owners and actor_id not in defaults:
                receipts.append(f"actors: {label} cannot disable {actor_id}, which another repository declares")
            else:
                disables.setdefault(actor_id, []).append((label, reason))
        enable.extend(mapping.get(actor_id, actor_id) for actor_id in data.get("enable") or [])
    for actor_id, rows in sorted(disables.items()):
        if len(rows) == selected:
            reasons = [f"{label}: {reason}" for label, reason in rows if reason]
            applied_disables.append({"id": actor_id, "reason": "; ".join(reasons)[:400] or None})
        else:
            receipts.append(
                f"actors: {actor_id} stays assessed; only {', '.join(label for label, _ in rows)} disable it"
            )

    configured = [data for _, _, data in files]
    complete = len(files) == selected
    config: dict = {"actors": list(actors.values())}
    if applied_disables:
        config["disable"] = applied_disables
    if enable:
        config["enable"] = sorted(set(enable))
    if complete and all(data.get("inherit_org") is False for data in configured):
        config["inherit_org"] = False
    discovery = [data.get("discovery") or {} for data in configured] + [{}] * (selected - len(files))
    config["discovery"] = {
        "enabled": not all(row.get("enabled") is False for row in discovery),
        "max_proposed": max(row.get("max_proposed", 5) for row in discovery),
    }
    role_owners: dict[str, list[str]] = {}
    roles = _legitimate_roles(files, slugs, role_owners)
    if roles:
        config["legitimate_roles"] = roles
    valid, errors = validate_actors_repo(config)
    if not valid:
        raise DeclarationError(f"combined {ACTOR_FILE} cannot be represented: {'; '.join(errors[:3])[:300]}")
    receipts.extend(f"actors: legitimate role {role} declared by {', '.join(by)}" for role, by in role_owners.items())
    return {"config": config, "owners": owners, "receipts": receipts}


def _legitimate_roles(files, slugs: dict[str, str], owners: dict[str, list[str]]) -> list[dict]:
    roles: dict[str, dict] = {}
    for label, rid, data in files:
        for raw in data.get("legitimate_roles") or []:
            role = copy.deepcopy(raw)
            if role["id"] in roles and roles[role["id"]] != raw:
                role["id"] = f"ext-{slugs[rid]}-{raw['id'][4:]}"
                role["name"] = f"{raw['name']} ({label})"[:80]
                if len(role["id"]) > 100 or role["id"] in roles:
                    raise DeclarationError(f"{label}/{ACTOR_FILE} role {raw['id']} has no unique namespaced ID")
            roles.setdefault(role["id"], role)
            owners.setdefault(role["id"], []).append(label)
    if len(roles) > 16:
        raise DeclarationError(f"selected repositories declare more than 16 legitimate roles in {ACTOR_FILE}")
    return list(roles.values())


def install_actor_config(scope, names: Namespaces, root: Path) -> dict:
    """Write the merged actor configuration into the private combined root."""
    declared = actor_declarations(scope, names)
    if declared is None:
        return {"owners": {}, "receipts": []}
    target = Path(root) / ".appsec"
    target.mkdir(mode=0o700, exist_ok=True)
    (target / "actors.yaml").write_text(yaml.safe_dump(declared["config"], sort_keys=False), encoding="utf-8")
    return {"owners": declared["owners"], "receipts": declared["receipts"]}


def attribute_actor_owners(workspace: Path, owners: dict[str, list[str]]) -> None:
    """Name each declared actor's owning repository file in the resolver outputs."""
    if not owners:
        return
    for name, validate in (
        (".actors-resolved.json", validate_actors_resolved),
        (".actors-merged-static.json", validate_actors_merged_static),
    ):
        path = Path(workspace) / name
        document = json.loads(path.read_text(encoding="utf-8"))
        for key in ("resolved_actors", "catalog_actors"):
            for actor in document.get(key) or []:
                labels = owners.get(actor.get("id"))
                if labels:
                    actor["_provenance"]["source_file"] = ", ".join(f"{label}/{ACTOR_FILE}" for label in labels)
        if not validate(document)[0]:
            raise DeclarationError(f"attributed {name} violates its schema")
        atomic_write_json(path, document, sort_keys=False)


# ---------------------------------------------------------------------------
# Related-repository imports
# ---------------------------------------------------------------------------


def _remote_key(url: str) -> tuple[str, str] | None:
    url = url.strip()
    scp = re.fullmatch(r"[\w.-]+@([^:/]+):(.+)", url)
    if scp:
        host, path = scp.groups()
    else:
        parts = urllib.parse.urlsplit(url)
        if not parts.hostname:
            return None
        host, path = parts.hostname, parts.path
    path = path.strip("/").removesuffix(".git").casefold()
    return (host.casefold(), path) if path else None


def _remotes(repo) -> set[tuple[str, str]]:
    try:
        output = _git(repo.root, "remote", "-v").decode("utf-8", errors="replace")
    except ScopeError:
        return set()
    return {key for line in output.splitlines() if len(line.split()) >= 2 and (key := _remote_key(line.split()[1]))}


def _selected_target(scope, names: Namespaces, repo, reference: str, remotes) -> str | None:
    """Label of the selected repository a threat-model reference names, if any."""
    kind, _ = load_related_repos._resolve_tm_reference(reference, repo.root)  # noqa: SLF001
    if kind == "url":
        target = _remote_key(reference)
        if target is None:
            return None
        for other in scope.repositories:
            for host, path in remotes(other):
                if target[0] == host and (target[1] == path or target[1].startswith(path + "/")):
                    return names.prefix[other.repository_id]
        return None
    candidate = (Path(reference) if Path(reference).is_absolute() else repo.root / reference).resolve()
    for other in scope.repositories:
        if candidate == other.root or other.root in candidate.parents:
            return names.prefix[other.repository_id]
    return None


def _unread_local(entry: dict, kind: str) -> dict:
    """A kept local import outside the selected roots: named, never read."""
    expectations = {key: entry.get(key) for key in ("expected_auth", "expected_validation")}
    return {
        "name": entry["name"],
        "source": "declared",
        "interface": entry.get("interface"),
        "threat_model": {
            "status": "unavailable",
            "path": entry["threat_model"],
            "ref_kind": kind,
            "generated": None,
            "commit_sha": None,
            "components": [],
            "threats_total": 0,
            "threats_critical": 0,
            "threats_high": 0,
            "threats_open": 0,
            "fetch_detail": "not read: a combined assessment reads no local path outside the selected repositories",
        },
        "interface_findings": None,
        "consumer_declares": expectations if any(expectations.values()) else None,
        "upstream_properties": None,
        "expectation_mismatch": None,
    }


def related_register(scope, names: Namespaces, workspace: Path, cfg: dict) -> list[str]:
    """Write one ``.cross-repo-register.json`` of qualified imported context.

    An import naming a selected repository is dropped: the current source
    assessment of that repository is authoritative. Remote imports keep the
    URL guard; they require the allow-list unless the run is explicitly
    trusted. Local imports outside the selected roots are named, never read.
    """
    strict = cfg.get("trust_mode") != "trusted"
    schema = load_related_repos._load_schema()  # noqa: SLF001
    now = datetime.now(timezone.utc)
    cache: dict[str, set] = {}

    def remotes(repo):
        if repo.repository_id not in cache:
            cache[repo.repository_id] = _remotes(repo)
        return cache[repo.repository_id]

    entries, authoritative, receipts = [], [], []
    for label, repo in _declaring(scope, names, RELATED_FILE):
        payload = _load(label, repo, RELATED_FILE)
        errors = load_related_repos._validate(payload, schema)  # noqa: SLF001
        if not isinstance(payload, dict) or errors:
            raise DeclarationError(f"{label}/{RELATED_FILE} violates its schema: {'; '.join(errors[:3])[:300]}")
        records = []
        for entry in payload.get("related") or []:
            target = _selected_target(scope, names, repo, entry["threat_model"], remotes)
            if target is not None:
                authoritative.append({"name": entry["name"], "declared_by": label, "selected_repository": target})
                continue
            kind, _ = load_related_repos._resolve_tm_reference(entry["threat_model"], repo.root)  # noqa: SLF001
            if kind == "url":
                records.append(
                    load_related_repos._process_entry(  # noqa: SLF001
                        entry,
                        repo_root=repo.root,
                        cap=load_related_repos._DEFAULT_CAP,  # noqa: SLF001
                        http_timeout=load_related_repos._DEFAULT_TIMEOUT,  # noqa: SLF001
                        outdated_days=load_related_repos._DEFAULT_OUTDATED_DAYS,  # noqa: SLF001
                        now=now,
                        strict_urls=strict,
                    )
                )
            else:
                records.append(_unread_local(entry, kind))
        for row in build_cross_repo_register._normalise_declared({"related": records}):  # noqa: SLF001
            row["discovery_hint"] = f"{label}/{RELATED_FILE}"
            entries.append(row)
    counts = Counter(row["name"] for row in entries)
    for row in entries:
        if counts[row["name"]] > 1:
            row["name"] = f"{row['name']} ({row['discovery_hint'].split('/', 1)[0]})"
    if not entries and not authoritative:
        return []
    register = {
        "meta": {
            "register_version": 1,
            "generated_at": now.isoformat(),
            "sources": ["declared"] if entries else [],
            "skipped_sibling_discovery": True,
            "skip_reason": "combined assessment: imported context comes only from declared related repositories",
            "declared_present": True,
            "recon_summary_present": False,
            "authoritative_current": authoritative,
        },
        "entries": entries,
    }
    errors = build_cross_repo_register._validate(register)  # noqa: SLF001
    if errors:
        raise DeclarationError("combined cross-repository register violates its schema: " + "; ".join(errors[:3]))
    atomic_write_json(Path(workspace) / ".cross-repo-register.json", register, sort_keys=False)
    receipts.append(f"cross-repository register: {len(entries)} imported context entries")
    receipts.extend(
        f"cross-repository register: {row['declared_by']} imports {row['name']}; the current assessment of "
        f"{row['selected_repository']} is authoritative"
        for row in authoritative
    )
    return receipts
