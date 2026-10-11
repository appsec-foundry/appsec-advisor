"""Deterministic posture sidecars and actors for a combined assessment.

The single-repository pipeline writes these sidecars from one checkout; the
renderers, ``build_threat_model_yaml`` and the enrichment read them from the
output directory. Here each producer runs on one repository's frozen scanner
snapshot. Every repository path it emits is rewritten to the workspace form
``<label>/<path>`` and the per-repository outputs are merged into one
legacy-shaped sidecar. A producer that walks paths cannot run on the combined
root instead: it looks for a root-level Dockerfile, workflow directory,
manifest or rule anchor and would miss every namespaced repository.

No producer reads Git history, runs a repository command or reaches the
network. Configuration-scan findings with a source line reach the merged
threats through ``assessment_scanner_findings.scan`` and evidence review.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml
from analyzers import architecture_coverage_checks, database_privilege_separation, deployment_inventory
from analyzers.route_inventory import build_inventory
from jsonschema import Draft202012Validator
from runtime.assessment_host import ExchangeError
from runtime.multi_repo_scope import _relative
from shared._atomic_io import atomic_write_json
from validators.validate_intermediate import (
    validate_actors_discovered,
    validate_actors_resolved,
    validate_config_scan_findings,
)

from model import emit_known_bad_libs, emit_sca_practice, resolve_actors
from model.assessment_scanner_findings import config_scan
from model.emit_dep_update_activity import _walk_manifests

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = PLUGIN_ROOT / "schemas"
# The single-repository emitters receive the same fixed asset tier.
ASSET_TIER = "T2"
NO_IAC_STUB = {"parse_error": "skipped: no IaC surface detected", "findings": []}
MAX_ROUTE_CARDS = 100
MAX_COMPONENT_CARDS = 200
MAX_CARD_PATHS = 10

# Producers that run here but write no workspace sidecar of their own, and
# producers that do not apply to a combined assessment.
NOT_RUN_RECEIPTS = (
    "dependency-update activity: Git history is not read in a combined assessment; cadence recorded as unknown",
)
DEP_ACTIVITY_NOTE = "Git history is not read in a combined assessment — activity signal unavailable."

ACTOR_ADAPTATION = (
    "Return the actor-discovery document for the combined system of every selected repository. The context "
    "holds the active static actors, the finalized components, external entities, data flows and route cards. "
    "Propose an additional actor only for a distinct attacker access or authority position that no active "
    "static actor holds. Cite qualified source evidence (repository_id, file, line, sha256) that you retrieved "
    "for every confirmed or proposed actor. The controller sets the cache key and timestamp."
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _quiet():
    """The producers print progress; the controller owns progress output."""
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    return stack


def _read(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _schema(name: str) -> Draft202012Validator:
    path = SCHEMAS / name
    text = path.read_text(encoding="utf-8")
    return Draft202012Validator(json.loads(text) if path.suffix == ".json" else yaml.safe_load(text))


def _require_valid(validator: Draft202012Validator, document, label: str) -> None:
    if not validator.is_valid(document):
        raise ValueError(f"Combined {label} violates its schema")


class _Repo:
    """One repository's path rewriting into the workspace namespace."""

    def __init__(self, repo, names):
        self.rid = repo.repository_id
        self.files = repo.files
        self.names = names
        self.label = names.prefix[self.rid]

    def path(self, value: str, *, captured: bool) -> str:
        _relative(value)
        if captured and value not in self.files:
            raise ValueError("A posture producer cited a file outside its captured repository")
        return self.names.qualify(self.rid, value)

    def rewrite(self, value, keys: frozenset, lists: frozenset = frozenset(), *, captured: bool):
        """Copy ``value`` with every path under ``keys`` (strings) or ``lists`` namespaced."""
        if isinstance(value, list):
            return [self.rewrite(row, keys, lists, captured=captured) for row in value]
        if not isinstance(value, dict):
            return value
        row = {}
        for key, child in value.items():
            if key in keys and isinstance(child, str) and child:
                row[key] = self.path(child, captured=captured)
            elif key in lists and isinstance(child, list):
                row[key] = [self.path(item, captured=captured) for item in child]
            else:
                row[key] = self.rewrite(child, keys, lists, captured=captured)
        return row

    def text(self, value: str, pairs) -> str:
        """Namespace the ``file:line`` tokens an emitter copied into prose."""
        for file, line in sorted(pairs, key=lambda pair: -len(pair[0])):
            token = re.escape(f"{file}:{line}")
            value = re.sub(rf"(?<![\w./-]){token}(?!\d)", f"{self.label}/{file}:{line}", value)
        return value


# ---------------------------------------------------------------------------
# Architecture coverage (database privilege separation is its thorough input)
# ---------------------------------------------------------------------------


def _coverage(root: Path, output: Path, depth: str, rules: dict) -> dict:
    atomic_write_json(output / ".route-inventory.json", build_inventory(root))
    if depth == "thorough":
        argv = ["--repo-root", str(root), "--output-dir", str(output), "--assessment-depth", "thorough"]
        with _quiet():
            if database_privilege_separation._main(argv):
                raise ValueError("Database privilege separation failed on an admitted repository")
    with _quiet():
        return architecture_coverage_checks.run(root, output, rules, assessment_depth=depth)


def _merge_coverage(rows: list[tuple[_Repo, dict]]) -> dict:
    merged = {
        "version": 1,
        "generated_at": _now(),
        "rules_evaluated": [],
        "control_assessments": [],
        "threat_hypotheses": [],
        "anti_pattern_candidates": [],
        "warnings": [],
    }
    counters: dict[str, int] = {}
    for repo, document in rows:
        document = repo.rewrite(document, frozenset({"file"}), captured=True)
        # Hypothesis IDs are numbered per prefix; renumber them across repositories.
        renamed = {}
        for hypothesis in document["threat_hypotheses"]:
            prefix = hypothesis["hypothesis_id"].rsplit("-", 1)[0]
            counters[prefix] = counters.get(prefix, 0) + 1
            renamed[hypothesis["hypothesis_id"]] = f"{prefix}-{counters[prefix]:03d}"
            hypothesis["hypothesis_id"] = renamed[hypothesis["hypothesis_id"]]
        for assessment in document["control_assessments"]:
            if "hypothesis_ids" in assessment:
                assessment["hypothesis_ids"] = [renamed[key] for key in assessment["hypothesis_ids"]]
        for key in ("rules_evaluated", "control_assessments", "threat_hypotheses", "anti_pattern_candidates"):
            merged[key].extend(document[key])
        merged["warnings"].extend(f"{repo.label}: {text}" for text in document["warnings"])
    return merged


# ---------------------------------------------------------------------------
# Configuration scan sidecar (findings, supply-chain facts, uncovered IaC)
# ---------------------------------------------------------------------------

_FACT_PATHS = frozenset({"file", "dockerfile"})


def _merge_capability(values: list[dict]) -> dict:
    # A capability is present for the system only when every scanned
    # repository has it; one repository without it is a gap.
    result = {
        "present": all(row["present"] for row in values),
        "evidence": [item for row in values for item in row["evidence"]],
        "searched_files": [item for row in values for item in row["searched_files"]][:50],
        "searched_file_count": sum(row["searched_file_count"] for row in values),
    }
    for key in ("tools", "ecosystems_used", "ecosystems_covered"):
        if any(key in row for row in values):
            result[key] = sorted({item for row in values for item in row.get(key, [])})
    return result


def _merge_config(rows: list[tuple[_Repo, dict]], receipts: list[str]) -> dict:
    if not rows:
        return dict(NO_IAC_STUB)
    findings, uncovered, facts = [], [], []
    for repo, document in rows:
        absent = 0
        for finding in document["findings"]:
            finding = repo.rewrite(finding, frozenset({"file"}), frozenset({"searched_files"}), captured=False)
            finding["local_id"] = f"CFG-{len(findings) + 1:03d}"
            absent += finding.get("evidence_kind") == "absence" and not finding["searched_files"]
            findings.append(finding)
        if absent:
            receipts.append(
                f"config scan {repo.label}: {absent} absence finding(s) kept in the sidecar, not merged; "
                "they searched no captured file to anchor evidence review"
            )
        uncovered.extend(
            repo.rewrite(document.get("uncovered_iac", []), frozenset(), frozenset({"files"}), captured=False)
        )
        if "supply_chain_facts" in document:
            facts.append(
                repo.rewrite(document["supply_chain_facts"], _FACT_PATHS, frozenset({"searched_files"}), captured=False)
            )
    # inventory_source is omitted: each snapshot is a filesystem walk over
    # the captured Git inventory, which neither enum value describes.
    merged = {
        "version": 1,
        "generated_at": _now(),
        # Every repository evaluates the complete catalog, which the
        # validator requires this count to equal.
        "checks_run": rows[0][1]["checks_run"],
        "violations": sum(document["violations"] for _, document in rows),
        "findings": findings,
    }
    if facts:
        merged["supply_chain_facts"] = {
            "version": 1,
            **{key: [item for row in facts for item in row.get(key, [])] for key in ("workflows", "inputs", "outputs")},
            "capabilities": {
                key: _merge_capability([row["capabilities"][key] for row in facts])
                for key in ("sbom", "image_signing", "dependency_updates")
            },
        }
        if any("installs" in row for row in facts):
            merged["supply_chain_facts"]["installs"] = [item for row in facts for item in row.get("installs", [])]
    if uncovered:
        merged["uncovered_iac"] = uncovered
    return merged


# ---------------------------------------------------------------------------
# Deployment inventory (presentation data of the §2 figure)
# ---------------------------------------------------------------------------

_DEPLOYMENT_PATHS = frozenset({"dockerfile", "source", "file", "manifest"})
_DEPLOYMENT_CAPS = {"environments": 8, "ci": 8, "packages": 40}
_TOPOLOGY_CAPS = {"zones": 64, "workloads": 256, "zone_bridging": 256}


def _zones(document: dict, label: str) -> dict:
    """Keep equally named networks or namespaces of two repositories distinct."""
    compose = document.get("compose")
    if compose:
        for row in (compose, *compose["services"]):
            if "networks" in row:
                row["networks"] = [f"{label}/{name}" for name in row["networks"]]
    topology = document.get("topology")
    if topology:
        for zone in topology["zones"]:
            zone["name"] = f"{label}/{zone['name']}"
        for workload in topology["workloads"]:
            workload["zones"] = [f"{label}/{name}" for name in workload["zones"]]
    return document


def _merge_deployment(rows: list[tuple[_Repo, dict]], receipts: list[str]) -> dict:
    documents = [
        (repo, _zones(repo.rewrite(document, _DEPLOYMENT_PATHS, frozenset({"variants"}), captured=False), repo.label))
        for repo, document in rows
    ]
    merged: dict = {"schema_version": 1}
    for key in ("runtime", "compose"):
        present = [document[key] for _, document in documents if document[key]]
        # One figure shows one runtime image and one compose project.
        merged[key] = present[0] if len(present) == 1 else None
        if len(present) > 1:
            receipts.append(f"deployment inventory: {len(present)} repositories declare a {key}; none is shown")
    for key, cap in _DEPLOYMENT_CAPS.items():
        values = [item for _, document in documents for item in document[key]]
        merged[key] = values[:cap]
        if len(values) > cap:
            receipts.append(f"deployment inventory: {len(values) - cap} {key} entries beyond the figure limit omitted")
    dependencies = [document["dependencies"] for _, document in documents]
    declared = [row for row in dependencies if row["manifests"]]
    merged["dependencies"] = {
        "manifests": sum(row["manifests"] for row in dependencies),
        "declared": sum(row["declared"] for row in dependencies),
        "ranges": sum(row["ranges"] for row in dependencies),
        "lockfile": bool(declared) and all(row["lockfile"] for row in declared),
    }
    topologies = [document["topology"] for _, document in documents if document.get("topology")]
    if topologies:
        merged["topology"] = {}
        for key, cap in _TOPOLOGY_CAPS.items():
            values = [item for row in topologies for item in row[key]]
            merged["topology"][key] = values[:cap]
            if len(values) > cap:
                receipts.append(f"deployment inventory: {len(values) - cap} topology {key} beyond the limit omitted")
    return merged


# ---------------------------------------------------------------------------
# Supply-chain control rows and meta-findings
# ---------------------------------------------------------------------------


def _evidence_pairs(row: dict) -> set[tuple[str, int]]:
    pairs = {(item["file"], item["line"]) for item in row.get("evidence", [])}
    for sub in row.get("subcontrols", []):
        pairs |= {(item["file"], item["line"]) for item in sub.get("evidence", [])}
    return pairs


def _sca_row(repo: _Repo, row: dict) -> dict:
    pairs = _evidence_pairs(row)
    row = repo.rewrite(row, frozenset({"file"}), captured=True)
    for target in (row, *row.get("subcontrols", [])):
        for key in ("implementation", "assessment", "status_note"):
            if isinstance(target.get(key), str):
                target[key] = repo.text(target[key], pairs)
    # One row per repository; the label keeps two repositories' rows apart.
    row["control"] = f"{row['control']} ({repo.label})"
    return row


def _sca(root: Path, output: Path, repo: _Repo, seed: dict) -> tuple[list[dict], list[dict], dict]:
    """Return the repository's new control rows, linked checks per seed row and findings."""
    atomic_write_json(output / ".security-controls.json", seed)
    with _quiet():
        if emit_sca_practice.run(root, output, ASSET_TIER, PLUGIN_ROOT):
            raise ValueError("The supply-chain control producer failed on an admitted repository")
    controls = _read(output / ".security-controls.json")["security_controls"]
    original = [row for row in seed["security_controls"] if row.get("control") not in emit_sca_practice._OWN_ROWS]
    kept, rows = controls[: len(original)], controls[len(original) :]
    if [row.get("control") for row in kept] != [row.get("control") for row in original] or any(
        row.get("control") not in emit_sca_practice._OWN_ROWS for row in rows
    ):
        raise ValueError("The supply-chain control producer changed controls it does not own")
    findings = _read(output / ".sca-practice-findings.json")
    return [_sca_row(repo, row) for row in rows], [row.get("linked_checks") or [] for row in kept], findings


def _merge_meta_findings(rows: list[tuple[_Repo, dict]]) -> dict:
    """Fold equal findings of several repositories into one with all evidence.

    The yaml builder keeps one meta-finding per (source, title, category);
    a second repository's equal finding would otherwise lose its evidence.
    """
    merged: dict[tuple, dict] = {}
    for repo, document in rows:
        for finding in repo.rewrite(document["findings"], frozenset({"file"}), captured=True):
            key = (finding.get("source"), finding.get("title"), finding.get("category"))
            if key in merged:
                merged[key]["evidence"].extend(finding.get("evidence", []))
            else:
                merged[key] = finding
    return {"schema_version": 1, "findings": list(merged.values())}


def _known_bad(root: Path, output: Path) -> dict:
    with _quiet():
        if emit_known_bad_libs.run(root, output, ASSET_TIER, PLUGIN_ROOT):
            raise ValueError("The known-bad-library producer failed on an admitted repository")
    return _read(output / ".known-bad-libs-findings.json")


# ---------------------------------------------------------------------------
# Actors
# ---------------------------------------------------------------------------


def _resolve_actors(
    scope, names, workspace: Path, root: str, *, quick: bool, discovery: Path | None = None
) -> list[str]:
    """Resolve actors like the single-repository flow, without recon signals.

    The combined assessment proves signals present but never absent, and
    the resolver's booleans would deactivate actors on an unproven false.
    Without signals every conditional actor stays active with a warning.
    Every repository's actor configuration reaches the resolver as one
    merged, namespaced file in the private combined root.
    """
    from orchestrator import assessment_declarations

    declared = assessment_declarations.install_actor_config(scope, names, Path(root))
    profile = workspace / ".org-profile-effective.json"
    try:
        with _quiet():
            resolve_actors.resolve(
                plugin_root=str(PLUGIN_ROOT),
                repo_root=root,
                output_dir=str(workspace),
                org_profile_effective_path=str(profile) if profile.is_file() else None,
                discovery_output_path=str(discovery) if discovery else None,
                quick_mode=quick,
            )
    except (OSError, RuntimeError, yaml.YAMLError) as exc:
        raise ValueError("Actor resolution failed for the combined assessment") from exc
    valid, _ = validate_actors_resolved(_read(workspace / ".actors-resolved.json"))
    if not valid:
        raise ValueError("Combined actor resolution violates its schema")
    assessment_declarations.attribute_actor_owners(workspace, declared["owners"])
    return declared["receipts"]


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------


def run(scope, names, workspace: Path, cfg: dict, *, progress=lambda s: None) -> list[str]:
    """Write the posture sidecars and the static actor set into the workspace.

    Requires the workspace's ``.security-controls.json`` and its combined
    ``.route-inventory.json``; returns receipts of every omission.
    """
    depth = str(cfg.get("assessment_depth") or "standard")
    combined_root = str(cfg["repo_root"])
    receipts = list(NOT_RUN_RECEIPTS)
    if depth == "thorough":
        receipts.append("database privilege separation: evaluated per repository as architecture-coverage input")
    rules = architecture_coverage_checks._load_rules(None)
    controls_path = workspace / ".security-controls.json"
    seed = _read(controls_path)
    coverage, configs, deployments, sca_findings, known_bad, sca_rows = [], [], [], [], [], []
    linked = [set(row.get("linked_checks") or []) for row in seed["security_controls"]]
    original = [
        i for i, row in enumerate(seed["security_controls"]) if row.get("control") not in emit_sca_practice._OWN_ROWS
    ]
    manifests: list[str] = []
    scope.verify_unchanged()
    for view in sorted(scope.repositories, key=lambda row: row.repository_id):
        repo = _Repo(view, names)
        progress("Evaluating posture producers: " + repo.label)
        with scope.scanner_snapshot(repo.rid) as root, tempfile.TemporaryDirectory(prefix="appsec-posture-") as tmp:
            output = Path(tmp)
            coverage.append((repo, _coverage(root, output, depth, rules)))
            config = config_scan(root, depth)
            if config is None:
                receipts.append(f"config scan {repo.label}: no IaC surface; catalog not evaluated")
            else:
                configs.append((repo, config))
            document = deployment_inventory.build_inventory(root)
            # Presentation data, tolerated like the single-repository best effort.
            if deployment_inventory.validation_errors(document):
                receipts.append(f"deployment inventory {repo.label}: invalid; omitted from the figure")
            else:
                deployments.append((repo, document))
            rows, checks, findings = _sca(root, output, repo, copy.deepcopy(seed))
            sca_rows.extend(rows)
            for index, extra in zip(original, checks, strict=True):
                linked[index] |= set(extra)
            sca_findings.append((repo, findings))
            known_bad.append((repo, _known_bad(root, output)))
            manifests.extend(repo.path(path, captured=True) for path in _walk_manifests(root))
    scope.verify_unchanged()

    document = _merge_coverage(coverage)
    _require_valid(_schema("architecture-coverage.schema.json"), document, "architecture coverage")
    atomic_write_json(workspace / ".architecture-coverage.json", document)

    document = _merge_config(configs, receipts)
    if not validate_config_scan_findings(document)[0]:
        raise ValueError("Combined config scan violates its schema")
    atomic_write_json(workspace / ".config-scan-findings.json", document)

    document = _merge_deployment(deployments, receipts)
    errors = deployment_inventory.validation_errors(document)
    if errors:
        receipts.append("deployment inventory: combined inventory invalid; figure falls back to its diagram")
    else:
        atomic_write_json(workspace / ".deployment-inventory.json", document)

    controls = copy.deepcopy(seed)
    for row, checks in zip(controls["security_controls"], linked, strict=True):
        if checks:
            row["linked_checks"] = sorted(checks)
    controls["security_controls"].extend(sca_rows)
    _require_valid(_schema("fragments/security-controls.schema.json"), controls, "security controls")
    atomic_write_json(controls_path, controls)
    # No schema exists for the meta-finding sidecars; the yaml builder and the
    # output contract validate the meta_findings they become.
    atomic_write_json(workspace / ".sca-practice-findings.json", _merge_meta_findings(sca_findings))
    atomic_write_json(workspace / ".known-bad-libs-findings.json", _merge_meta_findings(known_bad))
    atomic_write_json(
        workspace / ".dep-update-activity.json",
        {
            "schema_version": 1,
            "window_days": 90,
            "total_manifest_commits": 0,
            "dep_update_commits": 0,
            "bot_authored_commits": 0,
            "merged_dep_prs": None,
            "manifests_seen": sorted(manifests),
            "cadence": "unknown",
            "evidence": [DEP_ACTIVITY_NOTE],
        },
    )

    progress("Resolving actors")
    receipts += _resolve_actors(scope, names, workspace, combined_root, quick=depth == "quick")
    receipts.append("actors resolved without recon signals; conditional actors stay active with a warning")
    return receipts


_EVIDENCE = {
    "type": "array",
    "minItems": 1,
    "maxItems": 4,
    "items": {
        "type": "object",
        "additionalProperties": False,
        "required": ["repository_id", "file", "line", "sha256"],
        "properties": {
            "repository_id": {"type": "string", "minLength": 1},
            "file": {"type": "string", "minLength": 1, "maxLength": 512},
            "line": {"type": "integer", "minimum": 1},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        },
    },
}


def discovery_contract() -> dict:
    """The actor-discovery contract with qualified evidence and no controller fields."""
    schema = yaml.safe_load((SCHEMAS / "actors-discovered.schema.yaml").read_text(encoding="utf-8"))
    actor = schema.pop("$defs")["discovery_actor"]
    schema.pop("$id", None)
    for key in ("discovery_cache_key", "generated_at"):
        schema["required"].remove(key)
        del schema["properties"][key]
    properties = schema["properties"]
    properties["proposed_additional"]["items"] = actor
    for row in (actor, properties["confirmed_relevant"]["items"]):
        row["required"].append("evidence")
        row["properties"]["evidence"] = copy.deepcopy(_EVIDENCE)
    Draft202012Validator.check_schema(schema)
    return schema


def _discovery_context(names, workspace: Path) -> tuple[dict, list[dict]]:
    def qualified(value: str) -> dict:
        rid, path = names.split(value)
        return {"repository_id": rid, "path": path}

    def anchor(value: str, line: int) -> dict | None:
        rid, path = names.split(value)
        digest = names.sha256(rid, path)
        return None if digest is None else {"repository_id": rid, "file": path, "line": line, "sha256": digest}

    components = _read(workspace / ".components.json")["components"]
    cards = [
        {
            "id": row["id"],
            "name": row["name"],
            "tier": row.get("tier"),
            "description": row.get("description", ""),
            "paths": [qualified(path) for path in row["paths"]],
        }
        for row in components
    ]
    flows = _read(workspace / ".data-flows.json")
    routes = _read(workspace / ".route-inventory.json").get("routes") or []
    static = _read(workspace / ".actors-merged-static.json").get("resolved_actors") or []
    context = {
        "active_static_actors": [
            {key: actor.get(key) for key in ("id", "label", "access", "trust_positions", "description")}
            for actor in static
        ],
        "components": [{**card, "paths": card["paths"][:MAX_CARD_PATHS]} for card in cards[:MAX_COMPONENT_CARDS]],
        "external_entities": [
            {key: row[key] for key in ("id", "name", "kind", "access", "description") if key in row}
            for row in flows.get("external_entities", [])
        ],
        "data_flows": [
            {key: row[key] for key in ("id", "from", "to", "label", "protocol", "data_classification", "direction")}
            for row in flows["data_flows"]
        ],
        "routes": [
            {
                "method": row["method"],
                "path": str(row["path"])[:180],
                "authn_signal": row["authn_signal"],
                "authz_signal": row["authz_signal"],
                "management_surface": row["management_surface"],
                "evidence": [ref] if (ref := anchor(row["handler_file"], row["handler_line"])) else [],
            }
            for row in routes[:MAX_ROUTE_CARDS]
        ],
    }
    return context, cards


def _legacy_discovery(artifact: dict, names, key: str) -> dict:
    """Drop qualified evidence into the legacy prose fields as namespaced anchors."""

    def cite(row: dict, field: str) -> dict:
        row = copy.deepcopy(row)
        anchors = ", ".join(f"{names.qualify(e['repository_id'], e['file'])}:{e['line']}" for e in row.pop("evidence"))
        row[field] = f"{row[field]} Evidence: {anchors}."
        return row

    return {
        "schema_version": 1,
        "discovery_cache_key": key,
        "generated_at": _now(),
        "confirmed_relevant": [cite(row, "relevance_evidence") for row in artifact["confirmed_relevant"]],
        "proposed_additional": [
            cite(row, "distinct_trust_position_evidence") for row in artifact["proposed_additional"]
        ],
        "inputs_questioned": copy.deepcopy(artifact["inputs_questioned"]),
        "coverage_rationale": artifact["coverage_rationale"],
    }


def discover_actors(scope, jobs, names, workspace: Path, cfg: dict, instructions) -> list[str]:
    """Run the tool-less actor-discovery job and re-resolve with its output."""
    from contexts import multi_repo_analysis as analysis

    if str(cfg.get("assessment_depth") or "standard") == "quick":
        return ["actor discovery skipped: quick depth"]
    if not _read(workspace / ".actors-resolved.json").get("discovery_enabled"):
        return ["actor discovery skipped: disabled by configuration"]
    context, cards = _discovery_context(names, workspace)
    allowed = analysis.source_selection(cards)

    def validate(artifact, ranges):
        analysis.validate_retrieved_sources(scope, artifact, ranges, allowed)

    artifact = jobs.execute(
        role="actor_discoverer",
        selector="actors",
        instructions=instructions("actor_discoverer", ACTOR_ADAPTATION),
        context=context,
        schema=discovery_contract(),
        allowed_sources=allowed,
        validate=validate,
    )
    key = "assessment-" + hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()[:32]
    discovered = _legacy_discovery(artifact, names, key)
    valid, _ = validate_actors_discovered(discovered)
    if not valid:
        raise ExchangeError("Actor discovery violates its contract")
    path = workspace / ".actors-discovered.json"
    atomic_write_json(path, discovered)
    _resolve_actors(scope, names, workspace, str(cfg["repo_root"]), quick=False, discovery=path)
    return [
        f"actor discovery: {len(discovered['proposed_additional'])} proposed, "
        f"{len(discovered['confirmed_relevant'])} confirmed"
    ]
